/**
 * Windows native, foreground-only v2 preview. No Linux systemd, service, Shell
 * or mutable operations. Uses the existing single-code protocol and signed WSS.
 * No auto-enrolment on service start, implicit re-key, or remote consent bypass.
 */
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { lstat, mkdir, readFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { newEnrollment, saveNewPrivateKey } from "./v2-enrollment.ts";
import { recoverDeviceId } from "./v2-session-client.ts";
import { maintainAuthenticatedDeviceSession } from "./v2-connection-lifecycle.ts";

const TASK_SCRIPT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "scripts", "windows-user-task.ps1");
const SCRIPT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "scripts", "windows-private-store.ps1");
const ID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;

export function parseWindowsAgentArgs(argv: string[]): {
  action: "pair" | "run" | "status" | "enable" | "disable" | "task-status" | "start" | "stop"; endpoint?: string; name?: string;
} {
  const action = argv[0];
  if (!["pair", "run", "status", "enable", "disable", "task-status", "start", "stop"].includes(action ?? "")) {
    throw Error("Use pair, run or status.");
  }
  const options: { action: "pair" | "run" | "status" | "enable" | "disable" | "task-status" | "start" | "stop"; endpoint?: string; name?: string } = { action: action as "pair" | "run" | "status" | "enable" | "disable" | "task-status" | "start" | "stop" };
  for (let index = 1; index < argv.length; index += 2) {
    const key = argv[index], value = argv[index + 1];
    if (!value || (key !== "--endpoint" && key !== "--name") ||
        (key === "--endpoint" && options.endpoint !== undefined) ||
        (key === "--name" && options.name !== undefined)) {
      throw Error("Unknown, duplicate or missing option.");
    }
    if (key === "--endpoint") options.endpoint = value;
    else options.name = value;
  }
  if (["status", "disable", "task-status", "start", "stop"].includes(action ?? "")) {
    if (argv.length !== 1) throw Error("This command has no options.");
  } else {
    if (!options.endpoint || (action !== "pair" && options.name !== undefined)) {
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

function assertPrivateStore(action: "Init" | "Check" | "Seal", directory: string, fileName?: "v2-identity.pem" | "v2-identity.pem.device-id"): void {
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

function runUserTask(action: "Enable" | "Start" | "Stop" | "Disable" | "Status", endpoint?: string): string {
  const windows = process.env.SystemRoot;
  if (!windows) throw Error("Missing Windows system directory.");
  const powershell = path.win32.join(windows, "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
  const result = spawnSync(powershell, [
    "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", TASK_SCRIPT,
    "-Action", action,
    ...(action === "Enable" ? ["-Node", process.execPath,
      "-Entry", fileURLToPath(import.meta.url), "-Endpoint", endpoint!] : []),
  ], { encoding: "utf8", windowsHide: true, timeout: 20_000 });
  if (result.error || result.status !== 0) throw Error("Native Windows user task refused.");
  return result.stdout.trim();
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

  if (options.action === "task-status" || options.action === "disable" ||
      options.action === "start" || options.action === "stop") {
    const mapping = { "task-status": "Status", disable: "Disable", start: "Start", stop: "Stop" } as const;
    process.stdout.write(runUserTask(mapping[options.action]) + "\n");
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
      platform: "win32", mode: "foreground-preview", identity_present: exists,
      device_id, remote_connection: "unconfirmed", shell: false, write_file: false,
    }, null, 2) + "\n");
    return;
  }
  if (options.action === "enable") {
    if (!exists || !idExists) throw Error("Approve a native Windows device before enabling autostart.");
    const deviceId = (await readFile(keyPath + ".device-id", "utf8")).trim();
    if (!ID.test(deviceId)) throw Error("Invalid approved device ID.");
    process.stdout.write(runUserTask("Enable", options.endpoint) + "\n");
    return;
  }
  if (options.action === "pair") {
    if (idExists) throw Error("Already paired. Pairing never rotates an approved key.");
    const material = newEnrollment(options.name || os.hostname(),
      exists ? await readFile(keyPath, "utf8") : undefined, "permanent");
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
      "Approve this pending key using authenticated MCP pairing_lookup / pairing_approve.\n" +
      "Then start: node --experimental-strip-types src/windows-v2.ts run --endpoint " + options.endpoint + "\n");
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
    process.stderr.write('{"service":"remote-control-windows-preview","event":"starting"}\n');
    await maintainAuthenticatedDeviceSession(options.endpoint!, keyPath, controller.signal, {
      readOnly: true, writeFile: false, shell: false,
      onState: state => process.stderr.write(JSON.stringify({
        service: "remote-control-windows-preview", event: state,
      }) + "\n"),
    });
  } finally {
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
