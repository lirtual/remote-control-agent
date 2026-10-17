/**
 * Linux v2 user-service installer, from a trusted checkout. No curl|sh,
 * sudo, Portal Bearer, Cloudflare token, or changes to deployed v1 services.
 *
 * node apps/remote-control-agent/scripts/install-v2.mjs --endpoint https://EXAMPLE/ [--name HOST] [--show-fingerprint]
 * node apps/remote-control-agent/scripts/install-v2.mjs --resume --endpoint https://EXAMPLE/
 * node apps/remote-control-agent/scripts/install-v2.mjs --upgrade --endpoint https://EXAMPLE/
 * node apps/remote-control-agent/scripts/install-v2.mjs --uninstall
 * node apps/remote-control-agent/scripts/install-v2.mjs --foreground --endpoint https://EXAMPLE/ --name TEST
 * node apps/remote-control-agent/scripts/install-v2.mjs --foreground --resume --endpoint https://EXAMPLE/
 */
import { spawnSync } from "node:child_process";
import { constants, existsSync, readFileSync } from "node:fs";
import { access, lstat, mkdir, open, readFile, readdir, rename, rm, rmdir } from "node:fs/promises";
import { createInterface } from "node:readline/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { beginDeviceEnrollment, PendingIdentityConflictError } from "../src/pair-device.ts";
import { confirmDeviceLocally } from "../src/confirm-device.ts";
import { recoverDeviceId, verifyApprovedDeviceId, DeviceSessionRejectedError } from "../src/v2-session-client.ts";
import { assertRemoteRevocation } from "../src/v2-repair.ts";

/** WSL2 runs the same Linux Agent; Windows is never an authentication peer. */
export function classifyLinuxKernel(release) {
  if (typeof release !== "string" || !release.trim()) {
    throw new Error("Unable to identify the Linux kernel.");
  }
  if (!/microsoft/i.test(release)) return "linux";
  // WSL1 cannot satisfy the Linux pidfd supervisor contract.
  return /wsl2/i.test(release) ? "wsl2" : "wsl1";
}

export const UNIT = "remote-control-v2-agent.service";
export const MARKER = "# Managed by mcp-workers v2 Linux installer; NOT the v1 Agent.";
const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const programRoot = path.resolve(packageRoot, "..", "..");
const manifestPath = path.join(programRoot, "bundle.json");
const portable = existsSync(manifestPath);
const entry = path.join(packageRoot, "src", "v2-main.ts");
const compilerScript = path.join(packageRoot, "scripts", "build-session-supervisor.mjs");
const IDENTITY_REL = path.join(".local", "share", "mcp-workers", "remote-control", "v2-identity.pem");
// Separate cloud grant and key; temporary enrollment never reads permanent identity.
const TEMP_IDENTITY_REL = path.join(".local", "share", "mcp-workers", "remote-control",
  "temporary", "v2-identity.pem");
const UINT = /^[a-zA-Z0-9._/+-]+$/;
const DEVICE_ID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;

export function choosePortableInstallMode(choice, cliArgs = []) {
  if (choice !== "1" && choice !== "2") {
    throw new Error("Choose Permanent or Temporary explicitly.");
  }
  if (choice === "1" && cliArgs.includes("--foreground")) {
    throw new Error("Permanent installation requires its own user service.");
  }
  return Object.freeze({
    grantType: choice === "2" ? "temporary" : "permanent",
    foreground: choice === "2",
  });
}

export function keyForInstallMode(home, mode) {
  if (!["permanent", "temporary"].includes(mode)) throw new Error("Invalid device grant mode.");
  return path.join(home, mode === "temporary" ? TEMP_IDENTITY_REL : IDENTITY_REL);
}

export function parseInstallArgs(argv) {
  const result = { action: "install", endpoint: undefined, name: undefined, foreground: false, showFingerprint: false };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--show-fingerprint") {
      if (result.showFingerprint) throw new Error("Duplicate fingerprint option.");
      result.showFingerprint = true;
    } else if (arg === "--foreground") {
      if (result.foreground) throw new Error("Duplicate foreground option.");
      result.foreground = true;
    } else if (arg === "--upgrade" || arg === "--uninstall" || arg === "--resume") {
      if (result.action !== "install") throw new Error("Choose one installer action.");
      result.action = arg.slice(2);
    } else if (arg === "--endpoint" || arg === "--name") {
      if (!argv[i + 1]) throw new Error("Missing required argument value.");
      result[arg.slice(2)] = argv[++i];
    } else {
      throw new Error("Unknown installer option.");
    }
  }
  if (result.showFingerprint && result.action !== "install") {
    throw new Error("Fingerprint display is available only for first pairing.");
  }
  if (result.foreground && (result.action === "uninstall" || result.action === "upgrade")) {
    throw new Error("Foreground supports first pairing or --resume only.");
  }
  if (result.action !== "uninstall" && !result.endpoint) {
    throw new Error("Provide --endpoint (a trusted HTTPS origin).");
  }
  if (result.action === "uninstall" && (result.endpoint || result.name)) {
    throw new Error("Uninstall accepts no endpoint or device label.");
  }
  if (result.name && (result.name.length > 64 || /[\x00-\x1f]/.test(result.name))) {
    throw new Error("Invalid device label.");
  }
  return result;
}

export function trustedEndpoint(value) {
  const url = new URL(value);
  if (url.protocol !== "https:" || url.username || url.password ||
      url.search || url.hash || url.pathname !== "/" ||
      !/^[a-z0-9.-]+$/i.test(url.hostname) || url.hostname.startsWith(".") ||
      !Number.isInteger(Number(url.port || "443"))) {
    throw new Error("The device must use a clean, trusted HTTPS origin.");
  }
  return url.origin + "/";
}

function systemdLiteral(value) {
  // Reject systemd expansion, injection, and ambiguous paths. No secrets.
  if (!UINT.test(value) || value.includes("..") || value.includes("%") ||
      value.includes("\\") || value.includes("\n")) {
    throw new Error("The checkout and user paths must contain no spaces or systemd escapes.");
  }
  return value;
}

export function renderV2Service({ node, home, repoRoot, endpoint, keyPath, entryExt = "ts" }) {
  if (!["ts", "js"].includes(entryExt)) throw new Error("Invalid Agent runtime entry.");
  const nodePath = systemdLiteral(node);
  const project = systemdLiteral(repoRoot);
  const identity = systemdLiteral(keyPath);
  if (!path.isAbsolute(nodePath) || !path.isAbsolute(project) ||
      !path.isAbsolute(identity) || !path.isAbsolute(home)) {
    throw new Error("Absolute installation paths are required.");
  }
  return [
    MARKER,
    "[Unit]",
    "Description=Remote Control v2 Agent (outbound WSS, independent of v1)",
    "StartLimitIntervalSec=0",
    "",
    "[Service]",
    "Type=simple",
    "WorkingDirectory=" + project + "/apps/remote-control-agent",
    "Environment=REMOTE_CONTROL_V2_ENDPOINT=" + trustedEndpoint(endpoint),
    "Environment=REMOTE_CONTROL_V2_KEY_PATH=" + identity,
    "UMask=0077",
    "ExecStartPre=/usr/bin/test -r " + identity,
    "ExecStartPre=/usr/bin/test -r " + identity + ".device-id",
    "ExecStartPre=/usr/bin/test -x " + project + "/apps/remote-control-agent/.build/session-supervisor",
    "ExecStart=" + nodePath + (entryExt === "ts" ? " --experimental-strip-types" : "") +
      " " + project + "/apps/remote-control-agent/src/v2-main." + entryExt,
    "Restart=on-failure",
    "RestartSec=15s",
    "TimeoutStopSec=15s",
    "",
    "[Install]",
    "WantedBy=default.target",
    "",
  ].join("\n");
}

/**
 * Fail-closed T08 upgrade gate: the currently published v2 runtime has
 * readOnly:true, writeFile:false and shell:false. This is the *only* profile
 * for which live managed Shell work is impossible by construction; no new
 * process IPC/state database is introduced. Any other profile must get a
 * separately reviewed authoritative in-process quiescence gate before upgrade.
 *
 * Existing systemd activation+rollback in installUnit() switches ONLY the
 * v2 program path; private Ed25519 keys, endpoint and SQLite remain intact.
 */
export async function assertSafePortableUpgrade(unit, home, newManifestPath) {
  if (!unit || !unit.startsWith(MARKER + "\n")) {
    throw new Error("Manual upgrade requires an owned v2 service.");
  }
  const settings = unit.split("\n");
  const working = settings.filter(line => line.startsWith("WorkingDirectory="));
  const starts = settings.filter(line => line.startsWith("ExecStart="));
  if (working.length !== 1 || starts.length !== 1) {
    throw new Error("Current v2 service has ambiguous executable ownership.");
  }
  const previousRoot = path.resolve(working[0].slice("WorkingDirectory=".length), "..", "..");
  const privatePrograms = path.join(home, ".local", "share", "mcp-workers", "remote-control", "programs");
  if (!previousRoot.startsWith(privatePrograms + path.sep) ||
      !starts[0].includes("ExecStart=" + path.join(previousRoot, "bin", "node") + " ") ||
      !starts[0].endsWith(path.join(previousRoot, "apps", "remote-control-agent", "src", "v2-main.js"))) {
    throw new Error("Cannot upgrade an unverified/checkout-based current v2 Agent.");
  }
  for (const root of [previousRoot, path.resolve(path.dirname(newManifestPath))]) {
    const meta = await lstat(root);
    if (!meta.isDirectory() || meta.isSymbolicLink() || meta.uid !== process.getuid() ||
        (meta.mode & 0o077) !== 0) {
      throw new Error("Unowned Agent program directory; manual review required.");
    }
    const manifestFile = path.join(root, "bundle.json");
    const metaFile = await lstat(manifestFile);
    if (!metaFile.isFile() || metaFile.isSymbolicLink() ||
        metaFile.uid !== process.getuid() || (metaFile.mode & 0o077) !== 0) {
      throw new Error("Untrusted program manifest.");
    }
    let manifest;
    try { manifest = JSON.parse(await readFile(manifestFile, "utf8")); }
    catch { throw new Error("Invalid Agent program manifest."); }
    if (manifest.artifact_schema !== 1 || manifest.device_protocol !== 2 ||
        manifest.receipt_schema !== 1 ||
        manifest.upgrade_profile !== "read-only-no-shell-v1") {
      throw new Error("Managed Sessions quiescence cannot be proven; upgrade blocked.");
    }
    const entrySource = await readFile(path.join(root,
      "apps", "remote-control-agent", "src", "v2-main.js"), "utf8");
    if (!/readOnly:\s*true,\s*writeFile:\s*false,\s*shell:\s*false,/.test(entrySource)) {
      throw new Error("Active/unknown Shell ownership may exist; upgrade blocked.");
    }
  }
  if (previousRoot === path.resolve(path.dirname(newManifestPath))) {
    throw new Error("Already running this program version; use ordinary install.");
  }
  return {oldProgram:previousRoot, newProgram:path.resolve(path.dirname(newManifestPath))};
}

/** The regular installer never silently retargets an installed v2 service. */
export function assertExistingServiceEndpoint(unit, endpoint) {
  const expected = "Environment=REMOTE_CONTROL_V2_ENDPOINT=" + trustedEndpoint(endpoint);
  if (!unit.split("\n").includes(expected)) {
    throw new Error("Existing v2 service endpoint differs; manual review required.");
  }
}

function run(binary, args) {
  const result = spawnSync(binary, args, { encoding: "utf8", timeout: 15_000 });
  if (result.error || result.status !== 0) {
    if (binary === "cc") throw new Error("Missing or unusable cc compiler.");
    if (binary === "systemctl") throw new Error("The systemd user manager or requested user service action is unavailable.");
    if (binary === "systemd-analyze") throw new Error("Missing or unusable systemd-analyze.");
    if (binary === process.execPath) throw new Error("Could not compile the existing C session supervisor.");
    throw new Error("A local prerequisite is unavailable.");
  }
}

async function exists(target) {
  try { return await lstat(target); }
  catch (error) {
    if (error.code === "ENOENT") return null;
    throw error;
  }
}

async function ownerOnly(file, expectedMode) {
  const stat = await lstat(file);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.uid !== process.getuid() ||
      (stat.mode & 0o777) !== expectedMode) {
    throw new Error("The existing private identity has unsafe ownership or permissions.");
  }
}

export function assertSupportedLinuxHost({ platform, arch, release, libc }) {
  if (platform !== "linux" || !["x64", "arm64"].includes(arch)) {
    throw new Error("Only Linux x86_64 and ARM64 Agents are supported.");
  }
  const host = classifyLinuxKernel(release);
  if (host === "wsl1") throw new Error("WSL1 is unsupported; use WSL2.");
  const kernel = /^([0-9]+)\.([0-9]+)(?:\.|-)/.exec(release);
  if (!kernel || Number(kernel[1]) < 6 ||
      (Number(kernel[1]) === 6 && Number(kernel[2]) < 9)) {
    throw new Error("Linux kernel 6.9+ is required for safe pidfd process-group signaling.");
  }
  // Initial portable Node 24 distribution is glibc-only. T04 must verify
  // actual prebuilt ABI compatibility for each published architecture.
  const version = /^([0-9]+)\.([0-9]+)$/.exec(libc || "");
  if (!version || Number(version[1]) < 2 ||
      (Number(version[1]) === 2 && Number(version[2]) < 28)) {
    throw new Error("This Agent needs glibc 2.28+; musl/unverified libc is unsupported.");
  }
  return host;
}

export function assertNativeSupervisorProbe(binary, invoke = spawnSync) {
  const result = invoke(binary, ["--probe"], {
    detached: true, stdio: "ignore", timeout: 5000,
  });
  if (result.error || result.status !== 0) {
    throw new Error("Required pidfd process-group capability is unavailable; refusing pairing.");
  }
}

async function preflight(action, foreground) {
  if (process.platform !== "linux" || process.getuid?.() === 0 ||
      Number(process.versions.node.split(".")[0]) !== 24) {
    throw new Error("Install as a non-root Linux user with Node.js 24.");
  }
  systemdLiteral(process.execPath);
  systemdLiteral(packageRoot);
  const release = await readFile("/proc/sys/kernel/osrelease", "utf8");
  // Uninstall remains possible when the original host no longer supports
  // its v2 executable. Do not strand an existing user service.
  if (action === "uninstall") return classifyLinuxKernel(release);
  const host = assertSupportedLinuxHost({ platform: process.platform,
    arch: process.arch, release,
    libc: process.report?.getReport?.().header.glibcVersionRuntime });
  if (!foreground) run("systemctl", ["--user", "show-environment"]);
  if (!foreground) run("systemd-analyze", ["--user", "--version"]);
  if (portable) {
    // T04 archive verification must precede this first execution. Run only
    // the bundled Node24, signed program contents and precompiled supervisor.
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
    if (manifest.artifact_schema !== 1 ||
        manifest.target !== "linux-" + process.arch + "-glibc" ||
        manifest.node !== process.version ||
        path.resolve(process.execPath) !== path.join(programRoot, "bin/node") ||
        !/^[0-9]+\.[0-9]+$/.test(manifest.glibc_min ?? "")) {
      throw new Error("Portable runtime mismatch; no pairing attempted.");
    }
    const activeLibc = process.report.getReport().header.glibcVersionRuntime;
    const required = manifest.glibc_min.split(".").map(Number);
    const actual = (activeLibc ?? "0.0").split(".").map(Number);
    if (actual[0] < required[0] ||
        (actual[0] === required[0] && actual[1] < required[1])) {
      throw new Error("Release glibc ABI is unsupported on this device.");
    }
    const native = path.join(packageRoot, ".build", "session-supervisor");
    await ownerOnly(native, 0o700);
    assertNativeSupervisorProbe(native);
  } else {
    // Existing reviewed checkout-only development path.
    run("cc", ["--version"]);
    run(process.execPath, [compilerScript]);
    assertNativeSupervisorProbe(path.join(packageRoot, ".build", "session-supervisor"));
  }
  return host;
}

async function readOwnedUnit(file) {
  const meta = await exists(file);
  if (!meta) return null;
  if (!meta.isFile() || meta.isSymbolicLink() || meta.uid !== process.getuid()) {
    throw new Error("Refusing to replace a non-owned or linked systemd unit.");
  }
  const text = await readFile(file, "utf8");
  if (!text.startsWith(MARKER + "\n")) {
    throw new Error("An unrelated systemd service already occupies the v2 service name.");
  }
  return text;
}

async function atomicUnitWrite(unitPath, content) {
  const temporary = unitPath + "." + process.pid + ".tmp.service";
  const file = await open(temporary, "wx", 0o600);
  try {
    await file.writeFile(content, "utf8");
    await file.sync();
  } finally { await file.close(); }
  try {
    run("systemd-analyze", ["--user", "verify", temporary]);
    await rename(temporary, unitPath);
  } catch (error) {
    await rm(temporary, { force: true });
    throw error;
  }
}

export async function installUnit(unitPath, content, previous) {
  await atomicUnitWrite(unitPath, content);
  try {
    run("systemctl", ["--user", "daemon-reload"]);
    run("systemctl", ["--user", previous ? "restart" : "enable", ...(previous ? [] : ["--now"]), UNIT]);
    run("systemctl", ["--user", "is-active", "--quiet", UNIT]);
  } catch {
    // Never leave an installed half-started v2 service on first installation.
    if (!previous) {
      try { run("systemctl", ["--user", "disable", "--now", UNIT]); } catch { /* unavailable */ }
      await rm(unitPath, { force: true });
    } else {
      await atomicUnitWrite(unitPath, previous);
      try {
        run("systemctl", ["--user", "daemon-reload"]);
        run("systemctl", ["--user", "restart", UNIT]);
      } catch { /* Preserve the old unit even if local service is unhealthy. */ }
    }
    try { run("systemctl", ["--user", "daemon-reload"]); } catch { /* unavailable */ }
    throw new Error("The v2 user service could not be activated; original v1 services were not touched.");
  }
}

async function launchForeground({ endpoint, keyPath }) {
  // Reuse the exact same signed-WSS Agent entrypoint as the systemd unit.
  // Import keeps SIGINT/SIGTERM handling in v2-main and no extra process,
  // job runner, local port or unattended supervisor is installed.
  process.env.REMOTE_CONTROL_V2_ENDPOINT = endpoint;
  process.env.REMOTE_CONTROL_V2_KEY_PATH = keyPath;
  await import(portable ? "../src/v2-main.js" : "../src/v2-main.ts");
}

/**
 * Shared manual local challenge. Only the Agent holds the original pairing
 * code in memory, and it never asks the user to repeat it.
 */
async function pairFreshPending(options, keyPath, stdin, stdout, reuseExistingKey) {
  if (!stdin.isTTY || !stdout.isTTY) {
    throw new Error("Pairing requires a local interactive device terminal.");
  }
  const enrollment = await beginDeviceEnrollment(
    options.name ?? os.hostname(), options.endpoint, keyPath, fetch, reuseExistingKey,
    options.grantType ?? "permanent");
  const terminal = createInterface({ input: stdin, output: stdout, terminal: true });
  try {
    stdout.write("Pending 10-minute pairing code: " + enrollment.code + "\n");
    if (options.showFingerprint) {
      stdout.write("Local public key fingerprint (optional check): " + enrollment.fingerprint + "\n");
    }
    stdout.write("In authenticated MCP: pairing_lookup, then pairing_prepare. Enter only the 12-character challenge here.\n");
    let challenge;
    for (let attempt = 0; attempt < 3; attempt++) {
      const typed = (await terminal.question("12-character MCP confirmation challenge: ")).trim().toUpperCase();
      if (/^[A-Z2-7]{12}$/.test(typed)) {
        challenge = typed;
        break;
      }
      if (attempt < 2) stdout.write("Challenge must be 12 characters (A-Z, 2-7). Try again.\n");
    }
    if (!challenge) throw new Error("Invalid local challenge format.");
    await confirmDeviceLocally(enrollment.code, challenge, options.endpoint, keyPath);
  } finally { terminal.close(); }
}

/**
 * Promote already-paired staging files, preserving revoked identity for
 * review. No network or service actions here, so rollback is testable using
 * temporary owner-only files without touching any installed Agent.
 */

/**
 * Durable, local-only marker written after the owner approved the fresh key
 * and before stopping v2. IDs only: no key, Portal token or replay queue.
 */
const promotionMarker = keyPath => keyPath + ".re-pair-transition";
async function syncParent(filePath) {
  const dir = await open(path.dirname(filePath), "r");
  try { await dir.sync(); } finally { await dir.close(); }
}
export async function beginRevokedPromotion(keyPath, oldId, newId) {
  if (!DEVICE_ID.test(oldId) || !DEVICE_ID.test(newId) || oldId === newId) {
    throw new Error("Invalid promotion identities.");
  }
  const marker = promotionMarker(keyPath);
  if (await exists(marker)) throw new Error("An interrupted identity promotion must be recovered first.");
  const temporary = marker + "." + process.pid + ".tmp";
  const file = await open(temporary, "wx", 0o600);
  try {
    await file.writeFile(JSON.stringify({ version: 1, old_id: oldId, new_id: newId }) + "\n");
    await file.sync();
  } finally { await file.close(); }
  try {
    await rename(temporary, marker);
    await syncParent(marker);
  } catch (error) {
    await rm(temporary, { force: true });
    throw error;
  }
}

/** Recover only the five exact prefixes of the four original renames. */
export async function resumeRevokedPromotion(options, keyPath, previous, {
  verifyRevoked = assertRemoteRevocation,
  verifyApproved = verifyApprovedDeviceId,
  stopService = () => run("systemctl", ["--user", "stop", UNIT]),
  moveFile = rename,
} = {}) {
  const marker = promotionMarker(keyPath);
  await ownerOnly(marker, 0o600);
  let txn;
  try { txn = JSON.parse(await readFile(marker, "utf8")); }
  catch { throw new Error("Invalid interrupted identity promotion; manual review required."); }
  if (!txn || Object.keys(txn).sort().join(",") !== "new_id,old_id,version" ||
      txn.version !== 1 || typeof txn.old_id !== "string" ||
      typeof txn.new_id !== "string" || !DEVICE_ID.test(txn.old_id) ||
      !DEVICE_ID.test(txn.new_id) || txn.old_id === txn.new_id) {
    throw new Error("Invalid interrupted identity promotion; manual review required.");
  }
  const idPath = keyPath + ".device-id";
  const stage = keyPath + ".re-pair-new";
  const stageId = stage + ".device-id";
  const archive = path.join(path.dirname(keyPath), "revoked-" + txn.old_id);
  const archivedKey = path.join(archive, "identity.pem");
  const archivedId = path.join(archive, "identity.pem.device-id");
  const files = [keyPath, idPath, stage, stageId, archivedKey, archivedId];
  const present = await Promise.all(files.map(async file => Boolean(await exists(file))));
  const phases = [
    [true, true, true, true, false, false],
    [false, true, true, true, true, false],
    [false, false, true, true, true, true],
    [true, false, false, true, true, true],
    [true, true, false, false, true, true],
  ];
  const phase = phases.findIndex(shape => shape.every((value, i) => value === present[i]));
  if (phase < 0) throw new Error("Interrupted identity files are inconsistent; manual review required.");
  const meta = await exists(archive);
  if (meta && (!meta.isDirectory() || meta.isSymbolicLink() ||
      meta.uid !== process.getuid() || (meta.mode & 0o777) !== 0o700)) {
    throw new Error("Revoked identity archive has unsafe permissions.");
  }
  if (phase > 0 && !meta) throw new Error("Revoked identity archive is missing.");
  if (phase === 0 && meta && (await readdir(archive)).length > 0) {
    throw new Error("Unexpected revoked archive contents; manual review required.");
  }
  for (let i = 0; i < files.length; i++) if (present[i]) await ownerOnly(files[i], 0o600);
  const oldKey = phase === 0 ? keyPath : archivedKey;
  const oldIdFile = phase < 2 ? idPath : archivedId;
  const newKey = phase < 3 ? stage : keyPath;
  const newIdFile = phase < 4 ? stageId : idPath;
  if ((await readFile(oldIdFile, "utf8")).trim() !== txn.old_id ||
      (await readFile(newIdFile, "utf8")).trim() !== txn.new_id) {
    throw new Error("Interrupted promotion device IDs do not match; manual review required.");
  }
  // Recheck both cloud identities even if the marker claims pairing succeeded.
  await verifyRevoked(options.endpoint, oldKey, txn.old_id);
  if (await verifyApproved(options.endpoint, newKey) !== txn.new_id) {
    throw new Error("Staged replacement is not approved; manual review required.");
  }
  if (previous) stopService();
  if (phase < 4) {
    if (phase === 0 && meta) await rmdir(archive); // empty only, never recursive
    await promoteRevokedIdentity(keyPath, txn.old_id, moveFile, phase);
  }
  return { newId: txn.new_id, resumedAt: phase };
}
async function finishRevokedPromotion(keyPath) {
  const marker = promotionMarker(keyPath);
  if (!await exists(marker)) return;
  await ownerOnly(marker, 0o600);
  await rm(marker);
  await syncParent(marker);
}

export async function promoteRevokedIdentity(keyPath, oldId, moveFile = rename, resumeAt = 0) {
  if (!DEVICE_ID.test(oldId) || !Number.isInteger(resumeAt) || resumeAt < 0 || resumeAt > 3) {
    throw new Error("Invalid prior device identity.");
  }
  const idPath = keyPath + ".device-id";
  const stage = keyPath + ".re-pair-new";
  const archive = path.join(path.dirname(keyPath), "revoked-" + oldId);
  const archivedKey = path.join(archive, "identity.pem");
  const archivedId = path.join(archive, "identity.pem.device-id");
  const required = [
    [keyPath, idPath, stage, stage + ".device-id"],
    [archivedKey, idPath, stage, stage + ".device-id"],
    [archivedKey, archivedId, stage, stage + ".device-id"],
    [archivedKey, archivedId, keyPath, stage + ".device-id"],
  ][resumeAt];
  for (const file of required) await ownerOnly(file, 0o600);
  if (resumeAt === 0) {
    if (await exists(archive)) throw new Error("Old identity archive already exists.");
    await mkdir(archive, {mode: 0o700});
  }
  const moved = [];
  async function move(from, to) {
    await moveFile(from, to);
    moved.push([to, from]);
    // Persist each prefix before attempting the next rename. A terminated
    // installer therefore leaves a classifiable on-disk prefix, not a guess.
    await syncParent(from);
    if (path.dirname(from) !== path.dirname(to)) await syncParent(to);
  }
  const steps = [
    [keyPath, path.join(archive, "identity.pem")],
    [idPath, path.join(archive, "identity.pem.device-id")],
    [stage, keyPath],
    [stage + ".device-id", idPath],
  ];
  try {
    for (const [from, to] of steps.slice(resumeAt)) await move(from, to);
  } catch (error) {
    let rollbackFailed = false;
    for (const [from, to] of moved.reverse()) {
      try { await rename(from, to); }
      catch { rollbackFailed = true; }
    }
    // Only rmdir, never recursive rm: remove a leftover empty archive on
    // complete rollback, but preserve any nonempty/uncertain state for review.
    if (!rollbackFailed && resumeAt === 0) {
      try { await rmdir(archive); } catch { /* Nonempty/uncertain, preserve. */ }
    }
    throw error;
  }
  return archive;
}

/** Explicit replacement after a signed negative approval check and fresh owner challenge. */
async function rePairRevokedDevice(options, keyPath, previous, stdin, stdout) {
  const idPath = keyPath + ".device-id";
  if (!await exists(keyPath) || !await exists(idPath)) {
    throw new Error("Re-pair requires the old local private key and device ID.");
  }
  await ownerOnly(keyPath, 0o600);
  await ownerOnly(idPath, 0o600);
  const oldId = (await readFile(idPath, "utf8")).trim();
  // Fail closed: an owner-issued revoke must be durable and cryptographically
  // verified before old identity files or the service can be touched.
  await assertRemoteRevocation(options.endpoint, keyPath, oldId);
  if (!stdin.isTTY || !stdout.isTTY) throw new Error("Re-pair requires an interactive device terminal.");
  stdout.write("Old device ID is not currently approved; independent owner confirmation is required for a new key.\n");

  // Create/confirm the new identity in a separate staging file. The
  // revoked key and its original .device-id remain intact until pairing
  // has succeeded, including across Ctrl+C, expiry and lost HTTP replies.
  const stage = keyPath + ".re-pair-new";
  const stageExists = await exists(stage);
  const stageId = await exists(stage + ".device-id");
  if (stageId && !stageExists) throw new Error("Incomplete staged identity requires manual review.");
  if (stageExists) await ownerOnly(stage, 0o600);
  if (stageId) await ownerOnly(stage + ".device-id", 0o600);
  let paired = false;
  if (stageExists) {
    try {
      await recoverDeviceId(options.endpoint, stage);
      paired = true;
    } catch (error) {
      if (stageId || !(error instanceof DeviceSessionRejectedError && error.status === 404)) {
        throw error;
      }
      stdout.write("Resuming unapproved staged replacement with its existing private key.\n");
    }
  }
  if (!paired) await pairFreshPending(options, stage, stdin, stdout, Boolean(stageExists));
  await ownerOnly(stage, 0o600);
  await ownerOnly(stage + ".device-id", 0o600);
  const nextId = (await readFile(stage + ".device-id", "utf8")).trim();
  if (!/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(nextId) || nextId === oldId) {
    throw new Error("New device identity was not verified.");
  }

  // Stop only the owned v2 service AFTER new cloud approval and BEFORE
  // touching the old identity files.
  await beginRevokedPromotion(keyPath, oldId, nextId);
  await resumeRevokedPromotion(options, keyPath, previous);
  stdout.write("Revoked identity archived locally; new device ID paired. Activating v2 only.\n");
}

/**
 * Classify identity during an operator-invoked install without rotating any key.
 * A signed negative status does not prove historic ID-key binding or grant
 * authorization. A recovery 404 alone never permits replacing local identity.
 */
/**
 * Cloud approval may succeed before the device's ID fsync. Signed recovery
 * identifies the already-approved ID, without generating a new grant.
 */
export async function persistRecoveredDeviceId(keyPath, recoveredId) {
  if (!DEVICE_ID.test(recoveredId)) throw new Error("Invalid recovered device ID.");
  await ownerOnly(keyPath, 0o600);
  const target = keyPath + ".device-id";
  if (await exists(target)) {
    await ownerOnly(target, 0o600);
    if ((await readFile(target, "utf8")).trim() !== recoveredId) {
      throw new Error("Local and recovered device identities conflict.");
    }
    return;
  }
  const f = await open(target, constants.O_CREAT | constants.O_EXCL |
    constants.O_WRONLY | constants.O_NOFOLLOW, 0o600);
  try {
    await f.writeFile(recoveredId + "\n", "utf8");
    await f.sync();
  } finally { await f.close(); }
  await syncParent(target);
}

export async function inspectInstallIdentity(options, keyPath, previous, {
  recover = recoverDeviceId, verifyRevoked = assertRemoteRevocation,
} = {}) {
  const existingKey = Boolean(await exists(keyPath));
  const existingId = Boolean(await exists(keyPath + ".device-id"));
  if (existingId && !existingKey) throw new Error("A local device ID exists without its private key.");
  if (previous && !existingKey) throw new Error("Installed v2 service identity is missing; manual review required.");
  if (!existingKey) return "new";
  await ownerOnly(keyPath, 0o600);
  if (existingId) await ownerOnly(keyPath + ".device-id", 0o600);
  try {
    const recoveredId = await recover(options.endpoint, keyPath);
    if (existingId) {
      const actualId = (await readFile(keyPath + ".device-id", "utf8")).trim();
      if (actualId !== recoveredId) throw new Error("Local and server device identities conflict.");
    } else {
      await persistRecoveredDeviceId(keyPath, recoveredId);
    }
    return "approved";
  } catch (error) {
    if (existingId) {
      // Only a definitive server rejection may trigger the independent signed
      // tombstone probe. Offline/timeout/5xx or a local identity mismatch fail closed.
      if (!(error instanceof DeviceSessionRejectedError) ||
          ![401, 403, 404].includes(error.status)) throw error;
      const oldId = (await readFile(keyPath + ".device-id", "utf8")).trim();
      await verifyRevoked(options.endpoint, keyPath, oldId);
      return "revoked";
    }
    if (!previous && error instanceof DeviceSessionRejectedError && error.status === 404) {
      return "pending";
    }
    throw error;
  }
}


/** Hold a kernel flock through the full interactive CLI, released even on SIGKILL. */
export async function runLockedInstallerCli(argv, {
  home = os.homedir(), invoke = spawnSync, node = process.execPath,
} = {}) {
  // An internal marker avoids recursive wrapping. It does not confer rights;
  // the authenticated device key and owner challenge remain independent.
  if (process.env.RC_V2_INSTALL_FLOCKED === "1") {
    await runInstaller(argv, { home });
    return 0;
  }
  const dir = path.join(home, ".local", "share", "mcp-workers", "remote-control");
  const lockPath = path.join(dir, "v2-installer.lock");
  await mkdir(dir, { recursive: true, mode: 0o700 });
  const d = await lstat(dir);
  if (!d.isDirectory() || d.isSymbolicLink() || d.uid !== process.getuid() ||
      (d.mode & 0o077) !== 0) {
    throw new Error("The private identity directory must be owner-only.");
  }
  try {
    const lock = await open(lockPath, "wx", 0o600);
    await lock.close();
  } catch (error) {
    if (error.code !== "EEXIST") throw error;
  }
  await ownerOnly(lockPath, 0o600);
  const result = invoke("flock", [
    "-n", "-E", "75", "-F", lockPath, node, "--experimental-strip-types",
    fileURLToPath(import.meta.url), ...argv,
  ], {
    stdio: "inherit",
    env: { ...process.env, RC_V2_INSTALL_FLOCKED: "1" },
  });
  if (result.error) throw new Error("A local installer lock prerequisite is unavailable.");
  if (result.signal) throw new Error("Installer was interrupted; identity files were preserved.");
  if (result.status === 75) throw new Error("Another v2 installer is already running.");
  // The child has already printed its sanitized error; do not print another.
  if (result.status !== 0) return result.status ?? 1;
  return 0;
}

export async function runInstaller(args, {
  home = os.homedir(), stdin = process.stdin, stdout = process.stdout,
  startForeground = launchForeground,
} = {}) {
  const options = parseInstallArgs(args);
  if (portable && ["uninstall", "resume"].includes(options.action)) {
    throw new Error("Portable uninstall/resume requires separately reviewed lifecycle CLI.");
  }
  if (portable && options.action === "upgrade" && (!stdin.isTTY || !stdout.isTTY)) {
    throw new Error("Manual portable upgrade requires a real local terminal.");
  }
  if (portable && options.action === "install") {
    if (!stdin.isTTY || !stdout.isTTY) {
      throw new Error("Portable pairing requires a real interactive target-terminal TTY.");
    }
    const prompt = createInterface({input:stdin,output:stdout,terminal:true});
    try {
      stdout.write("Remote Control v2 — read-only by default. Worker endpoint: " +
        trustedEndpoint(options.endpoint) + "\nTarget label: " +
        (options.name ?? os.hostname()) + "\n");
      const choice=(await prompt.question("Choose 1 = Permanent (systemd); 2 = Temporary (24h): ")).trim();
      // Mode choice binds the signed Agent pending request and owner MCP review.
      Object.assign(options, choosePortableInstallMode(choice, args));
      stdout.write(choice === "2"
        ? "Temporary: foreground only; cloud expires 24 hours after owner approval. Terminal stop is not a cloud revoke.\n"
        : "Permanent: only the installer-owned v2 user service is started.\n");
    } finally {prompt.close();}
  }
  const unitPath = path.join(home, ".config", "systemd", "user", UNIT);
  const keyPath = keyForInstallMode(home, options.grantType ?? "permanent");
  systemdLiteral(home);
  const host = await preflight(options.action, options.foreground);
  if (options.action !== "uninstall") trustedEndpoint(options.endpoint);
  if (host === "wsl2" && !options.foreground && options.action !== "uninstall") {
    stdout.write("WSL2 detected. This systemd user service cannot wake a stopped WSL distribution. " +
      "After Windows restart, open the distribution and verify the v2 service; " +
      "while WSL is stopped, the device is unavailable. See docs/remote-control/WSL2-V2-LIFECYCLE.md.\n");
  }
  const previous = await readOwnedUnit(unitPath);
  // Ordinary repeat install must not silently accept a different Worker target.
  // Explicit --upgrade remains the separate path for intentional endpoint changes.
  if (previous && (options.action === "install" || options.action === "upgrade") &&
      options.grantType !== "temporary") {
    assertExistingServiceEndpoint(previous, options.endpoint);
  }
  // A distinct temporary Agent may coexist with the installed permanent unit.
  if (options.foreground && previous && options.grantType !== "temporary") {
    throw new Error("Foreground refuses to compete with an existing v2 systemd unit.");
  }

  if (options.action === "uninstall") {
    if (!previous) throw new Error("The dedicated v2 service is not installed.");
    run("systemctl", ["--user", "disable", "--now", UNIT]);
    await rm(unitPath);
    run("systemctl", ["--user", "daemon-reload"]);
    stdout.write("Removed the v2 user service. Local keys retained; revoke the device from MCP separately.\n");
    return;
  }
  if ((options.action === "resume" && previous) || (options.action === "upgrade" && !previous)) {
    throw new Error("Existing v2 service requires --upgrade; an absent service requires a first install.");
  }
  await mkdir(path.dirname(keyPath), { recursive: true, mode: 0o700 });
  const privateDirectory = await lstat(path.dirname(keyPath));
  if (!privateDirectory.isDirectory() || privateDirectory.isSymbolicLink() ||
      privateDirectory.uid !== process.getuid() || (privateDirectory.mode & 0o077) !== 0) {
    throw new Error("The private identity directory must be owner-only.");
  }

  if (options.action === "resume") {
    if (!(await exists(keyPath)) || !(await exists(keyPath + ".device-id"))) {
      throw new Error("Resume requires a completed local confirmation and an absent v2 service.");
    }
  }

  if (options.action !== "install" && await exists(promotionMarker(keyPath))) {
    throw new Error("Finish the interrupted identity promotion using the ordinary install command first.");
  }
  if (options.action === "install") {
    if (await exists(promotionMarker(keyPath))) {
      if (options.foreground || !stdin.isTTY || !stdout.isTTY) {
        throw new Error("Interrupted identity promotion requires a local interactive terminal.");
      }
      const resumed = await resumeRevokedPromotion(options, keyPath, previous);
      stdout.write("Verified interrupted identity promotion for " + resumed.newId + ".\n");
    } else {
      const state = await inspectInstallIdentity(options, keyPath, previous);
      if (state === "revoked") {
        // Only an interactive installer can recover a revoked installation.
        // Foreground mode cannot replace an identity belonging to a systemd unit.
        if (options.foreground) throw new Error("Revoked foreground identity requires manual review.");
        await rePairRevokedDevice(options, keyPath, previous, stdin, stdout);
      } else if (state === "approved") {
        if (previous && options.grantType !== "temporary") {
          // A repeat install may complete an interrupted owned v2 activation.
          // Never restart v1 or replace this approved local identity.
          try { run("systemctl", ["--user", "is-active", "--quiet", UNIT]); }
          catch {
            run("systemctl", ["--user", "daemon-reload"]);
            run("systemctl", ["--user", "start", UNIT]);
            run("systemctl", ["--user", "is-active", "--quiet", UNIT]);
          }
          stdout.write("v2 user service already installed; approved identity preserved.\n");
          return;
        }
        stdout.write("Existing approved identity recovered; continuing v2 installation.\n");
      } else {
        if (!stdin.isTTY || !stdout.isTTY) throw new Error("First pairing needs the device's interactive terminal.");
        if (state === "pending") stdout.write("Previous pairing not completed; retrying with the same private key.\n");
        await pairFreshPending(options, keyPath, stdin, stdout, state === "pending");
      }
    }
  }
  await ownerOnly(keyPath, 0o600);
  await ownerOnly(keyPath + ".device-id", 0o600);
  if (options.foreground) {
    stdout.write("v2 " + (options.grantType === "temporary" ? "temporary 24-hour" : "foreground") +
      " identity ready. Starting foreground Agent. Closing the terminal or stopping WSL2 disconnects it; no service is installed and no cloud revoke is implied.\n");
    await startForeground({ endpoint: trustedEndpoint(options.endpoint), keyPath });
    return;
  }
  await mkdir(path.dirname(unitPath), { recursive: true, mode: 0o700 });
  const rendered = renderV2Service({
    node: process.execPath, home, repoRoot: path.resolve(packageRoot, "..", ".."),
    endpoint: options.endpoint, keyPath, entryExt: portable ? "js" : "ts",
  });
  if (portable && options.action === "upgrade") {
    await assertSafePortableUpgrade(previous, home, manifestPath);
  }
  await installUnit(unitPath, rendered, previous);
  await finishRevokedPromotion(keyPath);
  stdout.write("v2 user service active. Use list_devices and an approved nonsensitive read fixture to verify connectivity.\n");
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  runLockedInstallerCli(process.argv.slice(2)).then(code => {
    process.exitCode = code;
  }).catch(error => {
    // Only print fixed, hard-coded classifications; never echo external
    // exception messages, endpoint query strings or private credential data.
    const safeErrors = [
      "Install as a non-root Linux user with Node.js 24.",
      "Missing or unusable cc compiler.",
      "The systemd user manager or requested user service action is unavailable.",
      "Missing or unusable systemd-analyze.",
      "Could not compile the existing C session supervisor.",
      "WSL1 is not supported; use WSL2 with systemd.",
      "Foreground supports first pairing or --resume only.",
      "An approved or revoked identity cannot be enrolled again.",
      "The existing private identity has unsafe ownership or permissions.",
      "A local device ID exists without its private key.",
      "Local and server device identities conflict.",
      "Pending enrollment could not be completed.",
      "Incomplete staged identity requires manual review.",
      "Installed v2 service identity is missing; manual review required.",
      "Existing v2 service endpoint differs; manual review required.",
      "Revoked foreground identity requires manual review.",
      "New device identity was not verified.",
      "Old identity archive already exists.",
      "A local installer lock prerequisite is unavailable.",
      "Another v2 installer is already running.",
      "Installer was interrupted; identity files were preserved.",
    ];
    const detail = error instanceof PendingIdentityConflictError
      ? "Existing device key is already approved or revoked. Never reuse it; ask the owner for explicit fresh-key pairing. "
      : error instanceof DeviceSessionRejectedError
        ? "Device identity is unavailable or revoked. Do not reset its key automatically. "
        : error instanceof Error && safeErrors.includes(error.message)
          ? error.message + " " : "Pairing state is uncertain; existing identity files were preserved. ";
    process.stderr.write(detail +
      "v2 installation/upgrade/removal failed; no v1 service was changed.\n");
    process.exitCode = 1;
  });
}
