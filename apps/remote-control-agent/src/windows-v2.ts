/**
 * Windows native v2 agent, sharing the existing full paired-device tool surface.
 * Uses Windows user-logon tasks, the single-code protocol and signed WSS.
 * No auto-enrolment on service start, implicit re-key, or remote consent bypass.
 */
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { lstat, mkdir, readFile, writeFile, unlink } from "node:fs/promises";
import { existsSync } from "node:fs";
import { createInterface } from "node:readline/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { newEnrollment, saveNewPrivateKey, selectDeviceLabel } from "./v2-enrollment.ts";
import { recoverDeviceId, verifyApprovedDeviceId, DeviceSessionRejectedError } from "./v2-session-client.ts";
import { promptInstallMode } from "./install-mode.ts";
import { repairWindowsIdentity } from "./windows-identity-repair.ts";
import { setTimeout as delay } from "node:timers/promises";
import { maintainAuthenticatedDeviceSession } from "./v2-connection-lifecycle.ts";
import { readWindowsEvents, recordWindowsEvent } from "./windows-log.ts";
import type { BrowserBackend } from "./browser-backend.ts";
import { readDesktopGrant, enableDesktopGrantLocally, stopDesktopGrant } from "./desktop-grant.ts";

const TASK_SCRIPT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "scripts", "windows-user-task.ps1");
const SCRIPT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "scripts", "windows-private-store.ps1");
const ID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;

export function parseWindowsAgentArgs(argv: string[]): {
  action: "onboard" | "pair" | "re-pair" | "run" | "status" | "enable" | "disable" | "task-status" | "start" | "stop" | "logs" | "upgrade" | "rollback" | "desktop-enable" | "desktop-stop" | "desktop-status"; endpoint?: string; name?: string; version?: string; grant?: "temporary";
} {
  const action = argv[0];
  if (!["onboard", "pair", "re-pair", "run", "status", "enable", "disable", "task-status", "start", "stop", "logs", "upgrade", "rollback", "desktop-enable", "desktop-stop", "desktop-status"].includes(action ?? "")) {
    throw Error("Use pair, run or status.");
  }
  const options: { action: "onboard" | "pair" | "re-pair" | "run" | "status" | "enable" | "disable" | "task-status" | "start" | "stop" | "logs" | "upgrade" | "rollback" | "desktop-enable" | "desktop-stop" | "desktop-status"; endpoint?: string; name?: string; version?: string; grant?: "temporary" } = { action: action as "onboard" | "pair" | "re-pair" | "run" | "status" | "enable" | "disable" | "task-status" | "start" | "stop" | "logs" | "upgrade" | "rollback" | "desktop-enable" | "desktop-stop" | "desktop-status" };
  for (let index = 1; index < argv.length; index += 2) {
    const key = argv[index], value = argv[index + 1];
    if (!value || (key !== "--endpoint" && key !== "--name" && key !== "--version" && key !== "--grant") ||
        (key === "--endpoint" && options.endpoint !== undefined) ||
        (key === "--name" && options.name !== undefined) ||
        (key === "--version" && options.version !== undefined) ||
        (key === "--grant" && (options.grant !== undefined || value !== "temporary"))) {
      throw Error("Unknown, duplicate or missing option.");
    }
    if (key === "--endpoint") options.endpoint = value;
    else if (key === "--name") options.name = value;
    else if (key === "--grant") options.grant = "temporary";
    else options.version = value;
  }
  if (["status", "disable", "task-status", "start", "stop", "logs", "desktop-enable", "desktop-stop", "desktop-status"].includes(action ?? "")) {
    if (argv.length !== 1) throw Error("This command has no options.");
  } else if (action === "upgrade" || action === "rollback") {
    if (argv.length !== 3 || !options.version ||
        !/^v[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9.-]+)?$/.test(options.version) ||
        options.endpoint !== undefined || options.name !== undefined || options.grant !== undefined) {
      throw Error("Use upgrade/rollback --version vX.Y.Z.");
    }
  } else {
    if (options.version !== undefined) throw Error("Unexpected version flag.");
    if (!options.endpoint || (!["pair", "onboard", "re-pair"].includes(action ?? "") && (options.name !== undefined || options.grant !== undefined)) || (["onboard", "re-pair"].includes(action ?? "") && options.grant !== undefined)) {
      throw Error("An explicit Worker HTTPS endpoint is required.");
    }
    const url = new URL(options.endpoint);
    const loopback = url.protocol === "http:" && url.hostname === "127.0.0.1" && !!url.port;
    if ((!loopback && url.protocol !== "https:") || url.username || url.password ||
        url.search || url.hash || url.pathname !== "/" ||
        url.toString() !== options.endpoint) {
      throw Error("Untrusted Worker HTTPS origin.");
    }
  }
  if (options.name && (options.name.length > 64 || /[\x00-\x1f]/.test(options.name))) {
    throw Error("Invalid Windows device name.");
  }
  return options;
}

export function windowsAgentStore(localAppData: string | undefined): string {
  if (!localAppData || !path.win32.isAbsolute(localAppData) ||
      localAppData.startsWith("\\\\") || localAppData.startsWith("//") ||
      !/^[A-Za-z]:[\\/]/.test(localAppData)) {
    throw Error("A local Windows user profile is required.");
  }
  return path.win32.join(localAppData, "mcp-workers", "remote-control");
}

function assertPrivateStore(action: "Init" | "Check" | "Seal", directory: string, fileName?: "v2-identity.pem" | "v2-identity.pem.device-id" | "v2-identity.pem.device-id.pending" | "v2-identity.pem.install-mode" | "v2-identity.pem.activation-pending" | "desktop-grant.json" | "desktop-stop.json" | "receipts"): void {
  if (process.platform !== "win32") throw Error("Native Windows required.");
  const systemRoot = process.env.SystemRoot;
  if (!systemRoot || !path.win32.isAbsolute(systemRoot)) throw Error("Missing Windows runtime.");
  const powershell = path.win32.join(systemRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
  const result = spawnSync(powershell, [
    "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", SCRIPT,
    "-Action", action, "-Directory", directory, ...(fileName ? ["-FileName", fileName] : []),
  ], { encoding: "utf8", windowsHide: true, timeout: 12_000, stdio: "pipe" });
  // Do not echo ACL output (which can expose account names or profile paths).
  if (result.error || result.status !== 0) throw Error("Windows private identity ACL check refused.");
}

async function hasFile(filename: string): Promise<boolean> {
  try {
    const info = await lstat(filename);
    if (!info.isFile() || info.isSymbolicLink()) throw Error("Unsafe Windows identity.");
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  }
}

function runUserTask(action: "Enable" | "Start" | "Stop" | "Disable" | "Status" | "Switch", endpoint?: string, targetVersion?: string, direction?: "Upgrade" | "Rollback"): string {
  const windows = process.env.SystemRoot;
  if (!windows) throw Error("Missing Windows system directory.");
  const powershell = path.win32.join(windows, "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
  const result = spawnSync(powershell, [
    "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", TASK_SCRIPT,
    "-Action", action,
    ...(action === "Enable" ? ["-Node", process.execPath,
      "-Entry", fileURLToPath(import.meta.url), "-Endpoint", endpoint!] : []),
    ...(action === "Switch" ? ["-Version", targetVersion!, "-Direction", direction!] : []),
  ], { encoding: "utf8", windowsHide: true, timeout: 20_000 });
  if (result.error || result.status !== 0) throw Error("Native Windows user task refused.");
  return result.stdout.trim();
}

/**
 * Local package selection, not an MCP argument or configurable browser path.
 * Only the independently verified optional Windows preview artifact can
 * supply the manager; standard paired Agents cannot launch browsers.
 */
export async function createPackagedBrowserForWindows(
  agentStore: string,
  entryUrl = import.meta.url,
): Promise<BrowserBackend | undefined> {
  if (process.platform !== "win32") throw Error("Native Windows browser required.");
  const installedRoot = path.resolve(path.dirname(fileURLToPath(entryUrl)), "..", "..", "..");
  const manifestPath = path.join(installedRoot, "bundle.json");
  if (!existsSync(manifestPath)) return undefined; // source-only or old standard Agent
  const manifest = JSON.parse(await readFile(manifestPath, "utf8")) as Record<string, unknown>;
  if (manifest.browser_runtime === undefined) return undefined; // original package remains browser-free
  // Verify every installed file, including the independently pinned Playwright
  // bundle and compiled manager, before any browser can enter the WSS executor.
  const verifyUrl = new URL("../scripts/verify-windows-preview.mjs", entryUrl);
  const verifier = await import(verifyUrl.href) as {
    inspectWindowsPreview(dir: string): unknown;
  };
  verifier.inspectWindowsPreview(installedRoot);
  const candidateUrl = new URL("../candidates/browser-playwright.js", entryUrl);
  const candidate = await import(candidateUrl.href) as {
    PlaywrightBrowserManager?: new (options: {agentStore: string}) => BrowserBackend;
  };
  if (typeof candidate.PlaywrightBrowserManager !== "function")
    throw Error("Trusted packaged BrowserManager missing.");
  return new candidate.PlaywrightBrowserManager({agentStore});
}

/** Only an explicitly recorded permanent mode permits a new autostart task.
 * Legacy `pair --grant temporary` did not persist this mode; missing metadata
 * is not proof of a permanent grant, even after the key is verified. */
export function assertWindowsAutostartMode(mode: string | undefined): true {
  if (mode !== "permanent")
    throw Error("Only a recorded permanent Windows grant may enable an autostart task.");
  return true;
}

/** An activation marker distinguishes interrupted first setup from an owner-stopped task. */
export async function resumePendingWindowsActivation(
  pending: boolean, status: {installed: boolean; running: boolean},
  task: (action: "Enable" | "Start") => void, clear: () => Promise<void>,
): Promise<void> {
  if (!pending) return;
  if (typeof status.installed !== "boolean" || typeof status.running !== "boolean" ||
      (!status.installed && status.running)) throw Error("Invalid Windows task status.");
  if (!status.installed) task("Enable");
  if (!status.running) task("Start");
  // Do not clear before Start succeeds: a failed Start must remain resumable.
  await clear();
}

/** Never use a local device-id file alone to authorize task activation. */
export async function assertSignedWindowsGrant(
  endpoint: string, keyPath: string, localId: string,
  verifier: typeof verifyApprovedDeviceId = verifyApprovedDeviceId,
): Promise<string> {
  if (!ID.test(localId)) throw Error("Invalid local device ID.");
  const approvedId = await verifier(endpoint, keyPath);
  if (approvedId !== localId) throw Error("Stored device ID conflicts with signed owner grant.");
  return approvedId;
}

/** Reconnect an already-approved Temporary Agent without enrolling or scheduling. */
export async function startApprovedTemporaryAgent(
  endpoint: string, runner: (args: string[]) => Promise<void> = runWindowsAgent,
): Promise<void> {
  await runner(["run", "--endpoint", endpoint]);
}

/** Reconcile only a signed public-key grant mismatch or confirmed missing grant.
 * The user still must approve a new pending key using authenticated MCP.
 * No healthy task is stopped and no transient error triggers re-enrollment. */
export async function reconcileWindowsOnboard(options: {
  currentId: string;
  verify: () => Promise<string>;
  status: () => { installed: boolean; running: boolean };
  stop: () => void;
  rePair: () => Promise<void>;
  start: () => void;
}): Promise<"unchanged" | "restored"> {
  let approvedId: string | undefined;
  try { approvedId = await options.verify(); }
  catch (error) {
    if (!(error instanceof DeviceSessionRejectedError) || error.status !== 404) throw error;
  }
  if (approvedId === options.currentId) return "unchanged";
  const before = options.status();
  if (!before.installed) throw Error("Task not installed.");
  if (before.running) options.stop();
  const stopped = options.status();
  if (!stopped.installed || stopped.running) throw Error("Could not stop task. Identity unchanged.");
  await options.rePair();
  const after = options.status();
  if (!after.installed || after.running) throw Error("Task changed. Not started.");
  options.start();
  return "restored";
}

export async function runWindowsAgent(argv: string[]): Promise<void> {
  if (process.platform !== "win32" || process.arch !== "x64" ||
      !/^v24\./.test(process.version)) {
    throw Error("Windows x64 with Node.js 24 required for this preview.");
  }
  const options = parseWindowsAgentArgs(argv);
  const directory = windowsAgentStore(process.env.LOCALAPPDATA);
  assertPrivateStore("Init", directory);
  const keyPath = path.win32.join(directory, "v2-identity.pem");
  const exists = await hasFile(keyPath);
  const idExists = await hasFile(keyPath + ".device-id");
  if (idExists && !exists) throw Error("Orphaned device ID; preserve and inspect existing store.");
  assertPrivateStore("Check", directory);

  if (options.action === "desktop-status") {
    process.stdout.write(JSON.stringify(await readDesktopGrant(directory)) + "\n");
    return;
  }
  if (options.action === "desktop-stop") {
    await stopDesktopGrant(directory);
    assertPrivateStore("Seal", directory, "desktop-stop.json");
    assertPrivateStore("Check", directory);
    process.stdout.write("Desktop Stop enforced locally; remote Resume is unavailable.\n");
    return;
  }
  if (options.action === "desktop-enable") {
    if (!exists || !idExists) throw Error("A paired device is required before Desktop Grant.");
    if (!process.stdin.isTTY || !process.stdout.isTTY) {
      throw Error("Desktop Grant requires an owner-local interactive terminal.");
    }
    process.stdout.write(
      "Desktop Grant allows ChatGPT to see the full desktop, native apps and browser windows,\n" +
      "and send mouse and keyboard input. Browser MCP's separate approval does not gate this.\n" +
      "It is not an OS sandbox against Shell and cannot independently authorize high-impact actions.\n" +
      "Type ENABLE DESKTOP to grant access (all other input declines): ");
    const prompt = createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    let answer = "";
    try { answer = await prompt.question(""); } finally { prompt.close(); }
    if (answer !== "ENABLE DESKTOP") throw Error("Desktop Grant declined locally.");
    await enableDesktopGrantLocally(directory);
    assertPrivateStore("Seal", directory, "desktop-grant.json");
    assertPrivateStore("Check", directory);
    process.stdout.write("Desktop Grant enabled locally. Use desktop-stop to deny new actions.\n");
    return;
  }
  if (options.action === "task-status" || options.action === "disable" ||
      options.action === "start" || options.action === "stop") {
    const mapping = { "task-status": "Status", disable: "Disable", start: "Start", stop: "Stop" } as const;
    process.stdout.write(runUserTask(mapping[options.action]) + "\n");
    return;
  }
  if (options.action === "upgrade" || options.action === "rollback") {
    if (!exists || !idExists) throw Error("Approved local identity required to switch versions.");
    const originalId = (await readFile(keyPath + ".device-id", "utf8")).trim();
    if (!ID.test(originalId)) throw Error("Invalid local device ID.");
    const direction = options.action === "upgrade" ? "Upgrade" : "Rollback";
    process.stdout.write(runUserTask("Switch", undefined, options.version, direction) + "\n");
    return;
  }
  if (options.action === "logs") {
    process.stdout.write(readWindowsEvents(directory));
    return;
  }
  if (options.action === "status") {
    let device_id: string | null = null;
    if (idExists) {
      const raw = (await readFile(keyPath + ".device-id", "utf8")).trim();
      if (!ID.test(raw)) throw Error("Invalid local device ID.");
      device_id = raw;
    }
    process.stdout.write(JSON.stringify({
      platform: "win32", mode: "native-user-agent", identity_present: exists,
      device_id, remote_connection: "unconfirmed", shell: true, write_file: true,
    }, null, 2) + "\n");
    return;
  }
  if (options.action === "enable") {
    if (!exists) throw Error("Pair a native Windows device before enabling autostart.");
    const modePath = keyPath + ".install-mode";
    let grantMode: string | undefined;
    if (await hasFile(modePath)) {
      assertPrivateStore("Check", directory, "v2-identity.pem.install-mode");
      grantMode = (await readFile(modePath, "utf8")).trim();
    }
    // Refuse temporary/invalid mode *before* recovering any local ID or
    // changing the task; explicit rejection must have no local side effects.
    assertWindowsAutostartMode(grantMode);
    if (!idExists) {
      // Only an already-approved key can recover its original server-signed ID.
      // No second pairing code, key rotation, or cloud grant is created.
      await recoverDeviceId(options.endpoint!, keyPath);
      assertPrivateStore("Seal", directory, "v2-identity.pem.device-id");
      assertPrivateStore("Check", directory);
    }
    const deviceId = (await readFile(keyPath + ".device-id", "utf8")).trim();
    // The recovered-ID branch already verified a signed challenge, and an
    // existing ID must be checked afresh before enabling an autostart task.
    if (idExists) await assertSignedWindowsGrant(options.endpoint!, keyPath, deviceId);
    else if (!ID.test(deviceId)) throw Error("Invalid approved device ID.");
    process.stdout.write(runUserTask("Enable", options.endpoint) + "\n");
    return;
  }
  if (options.action === "re-pair") {
    if (!exists || !idExists) throw Error("Existing paired identity required.");
    const modePath = keyPath + ".install-mode";
    assertPrivateStore("Check", directory);
    // Older paired user-logon tasks predate install-mode metadata. The
    // task must still be validated, and new permanent grant requires fresh
    // owner approval. Explicit temporary mode can never use this path.
    if (await hasFile(modePath)) {
      assertWindowsAutostartMode((await readFile(modePath, "utf8")).trim());
    }
    const state = JSON.parse(runUserTask("Status")) as { installed: boolean; running: boolean };
    if (!state.installed || state.running) {
      throw Error("An installed, stopped user task is required for recovery.");
    }
    const originalId = (await readFile(keyPath + ".device-id", "utf8")).trim();
    if (!ID.test(originalId)) throw Error("Invalid stored device ID.");
    const result = await repairWindowsIdentity({
      endpoint: options.endpoint!, keyPath, currentId: originalId,
      name: selectDeviceLabel(options.name ?? os.hostname(), os.hostname()),
      seal: () => assertPrivateStore("Seal", directory, "v2-identity.pem.device-id.pending"),
      assertStopped: () => {
        const latest = JSON.parse(runUserTask("Status")) as { installed: boolean; running: boolean };
        if (!latest.installed || latest.running) {
          throw Error("Windows task changed while awaiting approval; local identity unchanged.");
        }
      },
      onPending: (code, fingerprint) => {
        process.stdout.write("Pairing code: " + code + "\n");
        process.stdout.write("Fingerprint: " + fingerprint + "\n");
        process.stdout.write("Approve in MCP.\n");
      },
    });
    assertPrivateStore("Check", directory);
    process.stdout.write(result === "restored"
      ? "Authorization restored.\n"
      : "Authorization valid.\n");
    return;
  }
  if (options.action === "onboard") {
    // Keep the installer separate from the authenticated MCP owner approval.
    // Existing identity recovery needs no local input; new enrollment does.
    // Owner approval remains mandatory on the authenticated MCP channel.
    if (!idExists && (!process.stdin.isTTY || !process.stdout.isTTY)) {
      throw Error("Interactive terminal required.");
    }
    // A healthy signed grant is a no-op. A confirmed missing or mismatched
    // public-key grant is repaired inside this same one-line install session,
    // with explicit owner MCP approval; never rotate or delete the old key.
    if (idExists) {
      const localId = (await readFile(keyPath + ".device-id", "utf8")).trim();
      if (!ID.test(localId)) throw Error("Invalid device ID.");
      const outcome = await reconcileWindowsOnboard({
        currentId: localId,
        verify: () => verifyApprovedDeviceId(options.endpoint!, keyPath),
        status: () => JSON.parse(runUserTask("Status")) as { installed: boolean; running: boolean },
        stop: () => { runUserTask("Stop"); },
        rePair: () => runWindowsAgent(["re-pair", "--endpoint", options.endpoint!]),
        start: () => { runUserTask("Start"); },
      });
      if (outcome === "restored") {
        process.stdout.write("Recovery complete. Start requested.\n");
        return;
      }
    }
    const modePath = keyPath + ".install-mode";
    const hasMode = await hasFile(modePath);
    if (exists && !hasMode && !idExists) {
      throw Error("Existing identity has no installer mode; use explicit management commands.");
    }
    let mode: "permanent" | "temporary";
    if (hasMode) {
      assertPrivateStore("Check", directory);
      const saved = (await readFile(modePath, "utf8")).trim();
      if (saved !== "permanent" && saved !== "temporary") throw Error("Invalid protected pairing mode.");
      mode = saved;
    } else {
      if (idExists) {
        const approved = (await readFile(keyPath + ".device-id", "utf8")).trim();
        if (!ID.test(approved)) throw Error("Invalid local device ID.");
        process.stdout.write("Device: " + approved + " (unchanged).\n");
        return;
      }
      mode = await promptInstallMode();
      // Mode is sealed before generating a key; retry cannot silently change grant type.
      await writeFile(modePath, mode + "\n", { flag: "wx", mode: 0o600 });
      assertPrivateStore("Seal", directory, "v2-identity.pem.install-mode");
    }
    const activationMarker = keyPath + ".activation-pending";
    if (idExists) {
      const approved = (await readFile(keyPath + ".device-id", "utf8")).trim();
      if (!ID.test(approved)) throw Error("Invalid local device ID.");
      if (mode === "permanent") {
        const pending = await hasFile(activationMarker);
        if (pending) {
          assertPrivateStore("Check", directory, "v2-identity.pem.activation-pending");
          if ((await readFile(activationMarker, "utf8")).trim() !== approved)
            throw Error("Activation marker conflicts with signed device identity.");
        }
        const status = JSON.parse(runUserTask("Status")) as {installed: boolean;running: boolean};
        await resumePendingWindowsActivation(pending, status,
          action => { runUserTask(action, options.endpoint); },
          () => unlink(activationMarker));
        if (pending) process.stdout.write("Recovered interrupted user-logon activation.\n");
        else if (!status.installed) process.stdout.write(
          "Existing device has no user-logon task; public installer will not re-enable it.\n");
      }
      process.stdout.write("Authorized: " + approved + " (online unverified).\n");
      if (mode === "temporary") {
        process.stdout.write("Temporary mode: reconnecting in foreground; no startup task or new grant.\n");
        await startApprovedTemporaryAgent(options.endpoint!);
      }
      return;
    }
    let approvedId: string | undefined;
    if (exists) {
      // A previous owner approval may have succeeded before local ID persistence.
      try { approvedId = await recoverDeviceId(options.endpoint!, keyPath); }
      catch (err) {
        if (!(err instanceof DeviceSessionRejectedError) || err.status !== 404) throw err;
      }
    }
    if (!approvedId) {
      // An interrupted pairing reuses its original private key and stored mode.
      // The server may reject an active conflicting pending request; never override it.
      const suggested = os.hostname();
      let name = options.name;
      if (name === undefined) {
        const rl = createInterface({ input: process.stdin, output: process.stdout, terminal: true });
        try { name = selectDeviceLabel(await rl.question(`Device name [${suggested}]: `), suggested); }
        finally { rl.close(); }
      }
      const args = ["pair", "--endpoint", options.endpoint!, "--name", name!];
      if (mode === "temporary") args.push("--grant", "temporary");
      await runWindowsAgent(args);
    }
    const deadline = Date.now() + 10 * 60_000;
    while (!approvedId && Date.now() < deadline) {
      try { approvedId = await recoverDeviceId(options.endpoint!, keyPath); break; }
      catch (err) {
        if (!(err instanceof DeviceSessionRejectedError) || err.status !== 404) throw err;
      }
      await delay(Math.min(5_000, Math.max(0, deadline - Date.now())));
    }
    if (!approvedId || !ID.test(approvedId)) {
      throw Error("Owner MCP approval not confirmed before deadline; identity retained for explicit retry.");
    }
    assertPrivateStore("Seal", directory, "v2-identity.pem.device-id");
    process.stdout.write("Authorized: " + approvedId + " (online unverified).\n");
    if (mode === "permanent") {
      // This record is written before first Enable, retained across failures,
      // and deleted only after successful Start. Its owner-only ACL and ID bind
      // recovery to the originally approved key, not a stopped healthy task.
      await writeFile(activationMarker, approvedId + "\n", {flag:"wx",mode:0o600});
      assertPrivateStore("Seal", directory, "v2-identity.pem.activation-pending");
      await resumePendingWindowsActivation(true, {installed:false,running:false},
        action => { runUserTask(action, options.endpoint); },
        () => unlink(activationMarker));
      process.stdout.write("Task started. Verify via MCP.\n");
    } else {
      process.stdout.write("Temporary mode: foreground until terminal closes; server grant expires after 24 hours.\n");
      await startApprovedTemporaryAgent(options.endpoint!);
    }
    return;
  }
  if (options.action === "pair") {
    if (idExists) throw Error("Already paired. Pairing never rotates an approved key.");
    const suggested = os.hostname();
    let name: string;
    if (options.name !== undefined) {
      name = selectDeviceLabel(options.name, "");
    } else {
      if (!process.stdin.isTTY || !process.stdout.isTTY) {
        throw Error("Interactive terminal required to select the device name; use --name explicitly.");
      }
      const prompt = createInterface({ input: process.stdin, output: process.stdout, terminal: true });
      try { name = selectDeviceLabel(await prompt.question(`Device name [${suggested}]: `), suggested); }
      finally { prompt.close(); }
    }
    const material = newEnrollment(name,
      exists ? await readFile(keyPath, "utf8") : undefined, options.grant ?? "permanent");
    if (!exists) {
      // The private directory already has a protected DACL. Exclusive create
      // prevents concurrent windows from overwriting a device's private key.
      await saveNewPrivateKey(keyPath, material.privateKeyPem);
      // An exclusive newly created file may still inherit an elevated Windows
      // default owner. Seal this exact file before any network pairing request.
      assertPrivateStore("Seal", directory, "v2-identity.pem");
      assertPrivateStore("Check", directory);
    }
    const response = await fetch(new URL("/agent/pair/start", options.endpoint), {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify(material.request), redirect: "error", signal: AbortSignal.timeout(10_000),
    });
    if (response.status !== 202) {
      throw Error("Pending pairing rejected; existing key preserved. No implicit re-pair.");
    }
    const fingerprint = createHash("sha256")
      .update(Buffer.from(material.request.public_key, "base64")).digest("hex").slice(0, 24);
    process.stdout.write("Pairing code: " + material.code + "\n" +
      "Fingerprint: " + fingerprint + "\n" +
      "Approve in MCP.\n");
    return;
  }
  if (!exists) throw Error("Device is not paired. Run pair explicitly.");
  if (!idExists) {
    // Recovery requires server-signed proof of the existing private key.
    // Missing local ID is never evidence to generate a replacement key.
    await recoverDeviceId(options.endpoint!, keyPath);
    assertPrivateStore("Seal", directory, "v2-identity.pem.device-id");
    assertPrivateStore("Check", directory);
  }
  const controller = new AbortController();
  const abort = () => controller.abort();
  process.on("SIGINT", abort);
  process.on("SIGTERM", abort);
  try {
    recordWindowsEvent(directory, "starting");
    process.stderr.write('{"service":"remote-control-windows-preview","event":"starting"}\n');
    // SQLite upgrade receipts must inherit a Windows owner-only DACL, not
    // rely on Node's POSIX 0700 mode (which is not an ACL on Windows).
    // Existing stores are checked, NEVER silently repaired or replaced.
    const receiptDirectory = path.win32.join(directory, "receipts");
    if (!existsSync(receiptDirectory)) {
      await mkdir(receiptDirectory);
      assertPrivateStore("Seal", directory, "receipts");
    }
    assertPrivateStore("Check", directory);
    const browser = await createPackagedBrowserForWindows(directory);
    await maintainAuthenticatedDeviceSession(options.endpoint!, keyPath, controller.signal, {
      receiptDirectory, desktopDirectory: directory,
      ...(browser ? { browser } : {}),
      onState: state => {
        recordWindowsEvent(directory, state);
        process.stderr.write(JSON.stringify({
        service: "remote-control-windows-preview", event: state,
      }) + "\n");
      },
    });
  } finally {
    recordWindowsEvent(directory, "stopping");
    process.off("SIGINT", abort);
    process.off("SIGTERM", abort);
  }
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  runWindowsAgent(process.argv.slice(2)).catch(() => {
    process.stderr.write("Windows Agent unavailable; existing identity was preserved.\n");
    process.exitCode = 1;
  });
}
