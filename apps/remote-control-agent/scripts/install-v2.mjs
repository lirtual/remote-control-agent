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
import { createConnection } from "node:net";
import { DatabaseSync } from "node:sqlite";
import { constants, existsSync, readFileSync } from "node:fs";
import { access, lstat, mkdir, open, readFile, readlink, readdir, rename, rm, rmdir, symlink } from "node:fs/promises";
import { createInterface } from "node:readline/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { beginDeviceEnrollment, PendingIdentityConflictError } from "../src/pair-device.ts";
import { selectDeviceLabel } from "../src/v2-enrollment.ts";
import { promptInstallMode } from "../src/install-mode.ts";
import { setTimeout as sleep } from "node:timers/promises";
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

export const UNIT = "remote-control-agent.service";
export const MARKER = "# Managed by Remote Control Agent installer.";
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
    "Description=Remote Control Agent (signed outbound WSS)",
    "StartLimitIntervalSec=0",
    "",
    "[Service]",
    "Type=simple",
    "WorkingDirectory=" + project + "/apps/remote-control-agent",
    "Environment=REMOTE_CONTROL_AGENT_ENDPOINT=" + trustedEndpoint(endpoint),
    "Environment=REMOTE_CONTROL_AGENT_KEY_PATH=" + identity,
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
async function hasPathNoFollow(file) {
  try { await lstat(file); return true; }
  catch (error) {
    if (error?.code === "ENOENT") return false;
    throw error;
  }
}

async function assertReceiptDatabaseCompatible(home, expectedSchema = 1) {
  const directory = path.join(home, ".local", "state", "mcp-workers", "remote-control-agent");
  const receiptPath = path.join(directory, "operation-receipts.sqlite");
  let directoryInfo;
  try { directoryInfo = await lstat(directory); }
  catch (error) {
    // A fresh read-only v2 install may never have created receipt state.
    // There is no persisted history to preserve if the directory itself is absent.
    if (error?.code === "ENOENT") return;
    throw new Error("Receipt database directory cannot be inspected; upgrade blocked.");
  }
  if (!directoryInfo.isDirectory() || directoryInfo.isSymbolicLink() ||
      directoryInfo.uid !== process.getuid() || (directoryInfo.mode & 0o077) !== 0) {
    throw new Error("Receipt database directory ownership or permissions are unsafe; upgrade blocked.");
  }
  let handle;
  try { handle = await open(receiptPath, constants.O_RDONLY | constants.O_NOFOLLOW); }
  catch (error) {
    if (error?.code === "ENOENT") {
      // Missing SQLite is safe only when no legacy receipt file or migration backup exists.
      for (const legacyPath of [
        path.join(directory, "operation-receipts.json"),
        path.join(directory, "operation-receipts.pre-sqlite.json"),
      ]) {
        let legacyExists;
        try { legacyExists = await hasPathNoFollow(legacyPath); }
        catch { throw new Error("Legacy receipt data cannot be inspected; upgrade blocked."); }
        if (legacyExists) {
          throw new Error("Legacy receipt data exists without SQLite database; upgrade blocked.");
        }
      }
      return;
    }
    throw new Error("Receipt database cannot be opened safely; upgrade blocked.");
  }
  try {
    const meta = await handle.stat();
    if (!meta.isFile() || meta.uid !== process.getuid() ||
        (meta.mode & 0o077) !== 0 || meta.nlink !== 1) {
      throw new Error("Receipt database ownership or permissions are unsafe; upgrade blocked.");
    }
    const header = Buffer.alloc(100);
    const { bytesRead } = await handle.read(header, 0, header.length, 0);
    if (bytesRead < 100 ||
        header.subarray(0, 15).toString("ascii") !== "SQLite format 3" || header[15] !== 0) {
      throw new Error("Receipt database is not a valid SQLite file; upgrade blocked.");
    }
    // SQLite stores PRAGMA user_version as a big-endian uint32 at bytes 60–63.
    // ReceiptStore currently accepts version 0 (uninitialized) and version 1.
    // Read only the immutable header: the running Agent holds SQLite's exclusive lock.
    const version = header.readUInt32BE(60);
    if (version !== 0 && version !== expectedSchema) {
      throw new Error("Receipt database schema is incompatible; upgrade blocked.");
    }
  } finally {
    await handle.close();
  }
}
export async function assertSafePortableUpgrade(unit, home, newManifestPath) {
  if (!unit || !unit.startsWith(MARKER + "\n")) {
    throw new Error("Manual upgrade requires an owned Agent service.");
  }
  // The local freeze socket must belong to THIS exact permanent identity,
  // not merely another same-user Agent or a service with a similar label.
  const installed = assertCanonicalV2UnitTemplate(unit, home);
  if (installed.keyPath !== keyForInstallMode(home, "permanent"))
    throw new Error("Upgrade service identity binding differs; refusing quiescence probe.");
  const settings = unit.split("\n");
  const working = settings.filter(line => line.startsWith("WorkingDirectory="));
  const starts = settings.filter(line => line.startsWith("ExecStart="));
  if (working.length !== 1 || starts.length !== 1) {
    throw new Error("Current Agent service has ambiguous executable ownership.");
  }
  const previousRoot = path.resolve(working[0].slice("WorkingDirectory=".length), "..", "..");
  const privatePrograms = path.join(home, ".local", "share", "mcp-workers", "remote-control", "programs");
  if (!previousRoot.startsWith(privatePrograms + path.sep) ||
      !starts[0].includes("ExecStart=" + path.join(previousRoot, "bin", "node") + " ") ||
      !starts[0].endsWith(path.join(previousRoot, "apps", "remote-control-agent", "src", "v2-main.js"))) {
    throw new Error("Cannot upgrade an unverified or checkout-based Agent.");
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
    // A full-tools predecessor must consent via its own in-process admission
    // barrier. A v0.1.11 predecessor without that handshake fails closed.
    const previous = root === previousRoot;
    const profile = manifest.upgrade_profile;
    if (manifest.artifact_schema !== 1 || manifest.device_protocol !== 2 ||
        manifest.receipt_schema !== 1 ||
        (previous
          ? !["read-only-no-shell-v1", "paired-full-v1"].includes(profile)
          : profile !== "paired-full-v1")) {
      throw new Error("Unsupported existing Agent upgrade profile.");
    }
    const entrySource = await readFile(path.join(root,
      "apps", "remote-control-agent", "src", "v2-main.js"), "utf8");
    const readOnly = profile === "read-only-no-shell-v1" &&
      /readOnly:\s*true,\s*writeFile:\s*false,\s*shell:\s*false,/.test(entrySource);
    const full = profile === "paired-full-v1" &&
      /V2_RUNTIME_PROFILE\s*=\s*"paired-full-v1"/.test(entrySource) &&
      !/(?:readOnly|writeFile|shell)\s*:/.test(entrySource);
    if (!readOnly && !full) {
      throw new Error("Active/unknown Shell ownership or unverified managed profile; upgrade blocked.");
    }
  }
  if (previousRoot === path.resolve(path.dirname(newManifestPath))) {
    throw new Error("Already running this program version; use ordinary install.");
  }
  await assertReceiptDatabaseCompatible(home, 1);
  const priorManifest=JSON.parse(await readFile(path.join(previousRoot, "bundle.json"), "utf8"));
  return {oldProgram:previousRoot, newProgram:path.resolve(path.dirname(newManifestPath)),
    needsFreeze:priorManifest.upgrade_profile==="paired-full-v1",
    // Only this exact legacy v2 release predates the local freeze handshake.
    // Its one-time transition must be made offline by the device owner.
    legacyOffline:priorManifest.upgrade_profile==="paired-full-v1" &&
      priorManifest.version==="v0.1.11" &&
      priorManifest.target==="linux-"+process.arch+"-glibc" &&
      path.basename(previousRoot)==="v0.1.11-linux-"+process.arch+"-glibc"};
}

/**
 * Local-only upgrade consent, sent to the currently RUNNING Agent.
 * Absence of the socket or a busy/unknown response refuses the upgrade.
 */
export async function requestUpgradeConsent(keyPath, action, {dial=createConnection}={}){
  if(!["freeze","release"].includes(action))throw Error("Invalid upgrade action");
  const file=path.join(path.dirname(keyPath),"upgrade.sock");
  const meta=await lstat(file);
  if(!meta.isSocket()||meta.uid!==process.getuid()||(meta.mode&0o077)!==0)
    throw Error("Untrusted local upgrade socket");
  return await new Promise((resolve,reject)=>{
    const socket=dial(file);
    let reply="",settled=false;
    const done=(error,value)=>{
      if(settled)return;
      settled=true;socket.destroy();
      if(error)reject(error);else resolve(value);
    };
    socket.setTimeout(3000,()=>done(Error("Upgrade consent timed out")));
    socket.on("error",error=>done(error));
    socket.on("connect",()=>socket.write(action+"\n"));
    socket.on("data",data=>{
      reply+=data.toString("utf8");
      if(reply.length>32){done(Error("Invalid upgrade consent response"));return;}
      if(reply.endsWith("\n")){
        if(!["ready\n","busy\n","released\n"].includes(reply))
          done(Error("Invalid upgrade consent response"));
        else done(null,reply.trim());
      }
    });
    socket.on("close",()=>{if(!settled)done(Error("Upgrade consent connection closed"));});
  });
}

/** One-time local cutover for the immutable v0.1.11 that has no freeze socket.
 * This cannot establish the state of old Shell work. The owner MUST stop the
 * service from a genuine local terminal in a maintenance window beforehand.
 * No v1 service, device identity or operation receipt is modified here.
 */
export async function confirmLegacyV0111OfflineCutover({
  home=os.homedir(),keyPath=keyForInstallMode(home,"permanent"),
  stdin=process.stdin,stdout=process.stdout,
  invoke=spawnSync,ask=null,
}={}) {
  if (!stdin.isTTY || !stdout.isTTY)
    throw new Error("Legacy Agent offline cutover requires a real local terminal.");
  if (keyPath!==keyForInstallMode(home,"permanent"))
    throw new Error("Unexpected permanent identity for offline cutover.");
  const checkStopped=()=>{
    const result=invoke("systemctl",[
      "--user","show",UNIT,"--property=ActiveState,SubState,MainPID","--no-pager",
    ],{encoding:"utf8",timeout:5000});
    if(result.error||result.status!==0||typeof result.stdout!=="string")
      throw new Error("Cannot verify the stopped Agent service.");
    const lines=result.stdout.trim().split("\n");
    if(lines.length!==3 || !lines.includes("MainPID=0") ||
       !lines.includes("ActiveState=inactive") || !lines.includes("SubState=dead") ||
       new Set(lines).size!==3) {
      throw new Error("Legacy Agent must be manually stopped before offline cutover.");
    }
  };
  const checkReceipts=()=>{
    const file=path.join(home,".local/state/mcp-workers/remote-control-agent/operation-receipts.sqlite");
    let database;
    try {
      database=new DatabaseSync(file,{readOnly:true,timeout:0});
      const row=database.prepare("PRAGMA quick_check").get();
      if(row?.quick_check!=="ok")throw Error("SQLite integrity not confirmed.");
    } catch {
      throw new Error("SQLite receipts are locked, missing or invalid; cutover blocked.");
    } finally { database?.close(); }
  };
  checkStopped();
  checkReceipts();
  const raw=(await readFile(keyPath+".device-id","utf8")).trim();
  if(!DEVICE_ID.test(raw))throw new Error("Existing device ID is not valid.");
  stdout.write("One-time v0.1.11 offline cutover for device "+raw+".\n");
  stdout.write("Old Agent has no in-process Shell quiescence proof. Confirm all work is finished.\n");
  stdout.write("Service must remain stopped until the verified new Agent starts. SQLite and identity are retained.\n");
  let answer;
  if(ask)answer=await ask("Type OFFLINE-AGENT-UPGRADE to confirm: ");
  else {
    const rl=createInterface({input:stdin,output:stdout,terminal:true});
    try { answer=await rl.question("Type OFFLINE-AGENT-UPGRADE to confirm: "); }
    finally { rl.close(); }
  }
  if(answer?.trim()!=="OFFLINE-AGENT-UPGRADE")
    throw new Error("Owner did not confirm one-time offline cutover.");
  // Re-check after the prompt. Do not auto-stop the live Agent.
  checkStopped();
  checkReceipts();
  return {deviceId:raw};
}

/** Repeat-install is same-version only. A different installed service
 * must use explicit pinned rca upgrade and its rollback gate. */
export function assertRepeatInstallSameVersion(unit, root, {home, keyPath} = {}) {
  if (!unit || !unit.startsWith(MARKER + "\n")) {
    throw new Error("An unowned Agent service cannot be reused.");
  }
  const values=unit.split("\n").filter(line=>line.startsWith("ExecStart="));
  const expected="ExecStart="+path.join(root,"bin/node")+" "+
    path.join(root,"apps/remote-control-agent/src/v2-main.js");
  if(values.length!==1||values[0]!==expected){
    throw new Error("Existing Agent runs another version; use reviewed rca upgrade.");
  }
  if (home && keyPath) {
    // The same-version CLI may enable/start the existing service after a crash.
    // Validate the entire installer-owned unit and its actual private key
    // binding first, not just a plausible ExecStart and trusted endpoint.
    let parsed;
    try { parsed = assertCanonicalV2UnitTemplate(unit, home); }
    catch { throw new Error("Existing Agent service is noncanonical; manual review required."); }
    if (parsed.root !== path.resolve(root) || parsed.keyPath !== keyPath) {
      throw new Error("Existing Agent service identity or program differs; manual review required.");
    }
  }
}

/** The regular installer never silently retargets an installed v2 service. */
export function assertExistingServiceEndpoint(unit, endpoint) {
  const expected = "Environment=REMOTE_CONTROL_AGENT_ENDPOINT=" + trustedEndpoint(endpoint);
  if (!unit.split("\n").includes(expected)) {
    throw new Error("Existing Agent service endpoint differs; manual review required.");
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
    throw new Error("An unrelated systemd service already occupies the Agent service name.");
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
    // fsync the containing directory so the old-unit backup/name survives
    // a host crash, not just an ordinary process SIGKILL.
    await syncParent(unitPath);
  } catch (error) {
    await rm(temporary, { force: true });
    throw error;
  }
}

function assertCanonicalV2UnitTemplate(unit, home) {
  if (!unit || !unit.startsWith(MARKER + "\n")) {
    throw new Error("Interrupted upgrade backup is not an owned Agent unit.");
  }
  const settings = unit.split("\n");
  const working = settings.filter(line => line.startsWith("WorkingDirectory="));
  const starts = settings.filter(line => line.startsWith("ExecStart="));
  if (working.length !== 1 || starts.length !== 1) {
    throw new Error("Interrupted upgrade backup has ambiguous executable ownership.");
  }
  const root = path.resolve(working[0].slice("WorkingDirectory=".length), "..", "..");
  const programs = path.join(home, ".local", "share", "mcp-workers", "remote-control", "programs");
  const expectedStart = "ExecStart=" + path.join(root, "bin", "node") + " " +
    path.join(root, "apps", "remote-control-agent", "src", "v2-main.js");
  if (!root.startsWith(programs + path.sep) || starts[0] !== expectedStart) {
    throw new Error("Interrupted upgrade backup does not reference a versioned Agent.");
  }
  // Require the exact installer-generated service, not merely a matching
  // ExecStart with arbitrary extra systemd directives in a stale backup.
  const endpoint = settings.filter(line => line.startsWith("Environment=REMOTE_CONTROL_AGENT_ENDPOINT="));
  const keys = settings.filter(line => line.startsWith("Environment=REMOTE_CONTROL_AGENT_KEY_PATH="));
  if (endpoint.length !== 1 || keys.length !== 1) {
    throw new Error("Interrupted upgrade backup has ambiguous endpoint or identity.");
  }
  const endpointValue = endpoint[0].slice("Environment=REMOTE_CONTROL_AGENT_ENDPOINT=".length);
  const keyValue = keys[0].slice("Environment=REMOTE_CONTROL_AGENT_KEY_PATH=".length);
  let canonical;
  try {
    canonical = renderV2Service({node:path.join(root, "bin", "node"), home,
      repoRoot:root, endpoint:endpointValue, keyPath:keyValue, entryExt:"js"});
  } catch {
    throw new Error("Interrupted upgrade backup has invalid service settings.");
  }
  if (unit !== canonical) {
    throw new Error("Interrupted upgrade backup differs from the managed service template.");
  }
  return {root, endpoint:endpointValue, keyPath:keyValue};
}

async function assertRecoverablePreviousUnit(unit, home) {
  const {root, endpoint:endpointValue, keyPath:keyValue} = assertCanonicalV2UnitTemplate(unit, home);
  const rootInfo = await lstat(root);
  if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink() ||
      rootInfo.uid !== process.getuid() || (rootInfo.mode & 0o077) !== 0) {
    throw new Error("Previous Agent directory is not safe to recover.");
  }
  const manifestPath = path.join(root, "bundle.json");
  const manifestInfo = await lstat(manifestPath);
  if (!manifestInfo.isFile() || manifestInfo.isSymbolicLink() ||
      manifestInfo.uid !== process.getuid() || (manifestInfo.mode & 0o077) !== 0) {
    throw new Error("Previous Agent manifest is not safe to recover.");
  }
  let manifest;
  try { manifest = JSON.parse(await readFile(manifestPath, "utf8")); }
  catch { throw new Error("Previous Agent manifest is invalid."); }
  if (manifest.artifact_schema !== 1 || manifest.device_protocol !== 2 ||
      manifest.receipt_schema !== 1 ||
      !["read-only-no-shell-v1", "paired-full-v1"].includes(manifest.upgrade_profile) ||
      manifest.target !== "linux-" + process.arch + "-glibc" ||
      path.basename(root) !== manifest.version + "-" + manifest.target) {
    throw new Error("Previous Agent version cannot be safely recovered.");
  }
  const entry = path.join(root, "apps", "remote-control-agent", "src", "v2-main.js");
  const entryInfo = await lstat(entry);
  if (!entryInfo.isFile() || entryInfo.isSymbolicLink() ||
      entryInfo.uid !== process.getuid() || (entryInfo.mode & 0o077) !== 0 ||
      !(
        manifest.upgrade_profile==="read-only-no-shell-v1"
          ? /readOnly:\s*true,\s*writeFile:\s*false,\s*shell:\s*false,/.test(await readFile(entry, "utf8"))
          : /V2_RUNTIME_PROFILE\s*=\s*"paired-full-v1"/.test(await readFile(entry,"utf8"))
      )) {
    throw new Error("Previous Agent does not prove a reviewed runtime profile.");
  }
  return {root, endpoint:endpointValue, keyPath:keyValue};
}

/**
 * Recover an interrupted program switch from a durable copy of the prior unit.
 * If the prior unit is already restored, only ensure that service is active.
 */
async function clearCompletedUpgradeBackup(backupPath) {
  await rm(backupPath);
  // Deletion is part of commit: a host crash must not resurrect a stale
  // previous-version backup and trigger an unwanted rollback on next launch.
  await syncParent(backupPath);
}

export async function recoverInterruptedUpgrade({home=os.homedir(), unitPath} = {}) {
  unitPath ??= path.join(home, ".config", "systemd", "user", UNIT);
  const backupPath = unitPath + ".upgrade-backup";
  const backupInfo = await exists(backupPath);
  if (!backupInfo) return false;
  if (!backupInfo.isFile() || backupInfo.isSymbolicLink() ||
      backupInfo.uid !== process.getuid() || (backupInfo.mode & 0o077) !== 0 ||
      backupInfo.nlink !== 1) {
    throw new Error("Interrupted upgrade backup is unsafe; manual review required.");
  }
  let previous;
  try { previous = await readFile(backupPath, "utf8"); }
  catch { throw new Error("Interrupted upgrade backup cannot be read; manual review required."); }
  const oldUnit = await assertRecoverablePreviousUnit(previous, home);
  let current;
  try { current = await readOwnedUnit(unitPath); }
  catch { throw new Error("Current Agent unit cannot be verified; recovery backup preserved."); }
  if (!current) throw new Error("Current Agent unit is missing; recovery backup preserved.");
  // A crashed activation may reference a staged program that is not yet
  // runnable. Validate its exact systemd template, but do not require the
  // interrupted new binary to exist in order to restore the old one.
  try { assertCanonicalV2UnitTemplate(current, home); }
  catch { throw new Error("Current Agent unit is noncanonical; recovery backup preserved."); }
  // A recovered binary must keep the same approved cloud endpoint and device
  // identity. Reject drift before touching systemd or deleting the backup.
  const settings = current.split("\n");
  for (const [name, expected] of [
    ["REMOTE_CONTROL_AGENT_ENDPOINT", oldUnit.endpoint],
    ["REMOTE_CONTROL_AGENT_KEY_PATH", oldUnit.keyPath],
  ]) {
    const values = settings.filter(line => line.startsWith("Environment=" + name + "="));
    if (values.length !== 1 || values[0] !== "Environment=" + name + "=" + expected) {
      throw new Error("Interrupted upgrade changes the endpoint or device identity; manual review required.");
    }
  }
  try {
    if (current !== previous) await atomicUnitWrite(unitPath, previous);
    // Always restart the previous executable. An active PID alone does not
    // prove it matches the restored unit after an interrupted restart.
    run("systemctl", ["--user", "daemon-reload"]);
    run("systemctl", ["--user", "restart", UNIT]);
    run("systemctl", ["--user", "is-active", "--quiet", UNIT]);
    await clearCompletedUpgradeBackup(backupPath);
    return true;
  } catch {
    throw new Error("Interrupted upgrade recovery failed; previous service backup was preserved.");
  }
}

export async function installUnit(unitPath, content, previous) {
  const backupPath = unitPath + ".upgrade-backup";
  if (previous) {
    if (await exists(backupPath)) {
      throw new Error("Interrupted upgrade backup exists; recovery is required before another switch.");
    }
    await atomicUnitWrite(backupPath, previous);
  }
  try {
    await atomicUnitWrite(unitPath, content);
    run("systemctl", ["--user", "daemon-reload"]);
    run("systemctl", ["--user", previous ? "restart" : "enable", ...(previous ? [] : ["--now"]), UNIT]);
    run("systemctl", ["--user", "is-active", "--quiet", UNIT]);
    if (previous) await clearCompletedUpgradeBackup(backupPath);
  } catch {
    // If SIGKILL bypasses this catch, recoverInterruptedUpgrade uses the same
    // durable backup on the next install/upgrade invocation.
    if (!previous) {
      try { run("systemctl", ["--user", "disable", "--now", UNIT]); } catch { /* unavailable */ }
      await rm(unitPath, { force: true });
    } else {
      try {
        const current = await readOwnedUnit(unitPath);
        if (current !== previous) await atomicUnitWrite(unitPath, previous);
        run("systemctl", ["--user", "daemon-reload"]);
        run("systemctl", ["--user", "restart", UNIT]);
        run("systemctl", ["--user", "is-active", "--quiet", UNIT]);
        await clearCompletedUpgradeBackup(backupPath);
      } catch { /* Keep the durable backup for a later recovery attempt. */ }
    }
    try { run("systemctl", ["--user", "daemon-reload"]); } catch { /* unavailable */ }
    throw new Error("The Agent service could not be activated; previous services were not touched.");
  }
}

/** Proof of incomplete *first* activation, never inferred from an inactive unit.
 * Store only the approved device ID in the existing owner-only identity dir. */
export async function hasInitialActivation(marker, deviceId) {
  if (!DEVICE_ID.test(deviceId)) throw Error("Invalid approved device ID for activation.");
  const meta = await exists(marker);
  if (!meta) return false;
  if (!meta.isFile() || meta.isSymbolicLink() || meta.uid !== process.getuid() ||
      (meta.mode & 0o777) !== 0o600 || meta.nlink !== 1) {
    throw Error("Unsafe first-activation marker; manual review required.");
  }
  if ((await readFile(marker, "utf8")) !== deviceId + "\n") {
    throw Error("First-activation marker conflicts with approved device identity.");
  }
  return true;
}
export async function beginInitialActivation(marker, deviceId) {
  if (await hasInitialActivation(marker, deviceId)) return;
  const file = await open(marker, "wx", 0o600);
  try { await file.writeFile(deviceId + "\n"); await file.sync(); }
  finally { await file.close(); }
  await syncParent(marker);
}
export async function clearInitialActivation(marker) {
  await rm(marker);
  await syncParent(marker);
}

/** Repeated install never revives an owner-stopped unit without the protected marker. */
export function ensureApprovedPermanentService(invoke = run, pending = false) {
  try { invoke("systemctl", ["--user", "is-active", "--quiet", UNIT]); return true; }
  catch { /* Not active; only recover a verifiable first-activation marker. */ }
  if (!pending) return null;
  invoke("systemctl", ["--user", "daemon-reload"]);
  invoke("systemctl", ["--user", "enable", UNIT]);
  invoke("systemctl", ["--user", "start", UNIT]);
  invoke("systemctl", ["--user", "is-active", "--quiet", UNIT]);
  return false;
}

async function launchForeground({ endpoint, keyPath }) {
  // Reuse the exact same signed-WSS Agent entrypoint as the systemd unit.
  // Import keeps SIGINT/SIGTERM handling in v2-main and no extra process,
  // job runner, local port or unattended supervisor is installed.
  process.env.REMOTE_CONTROL_AGENT_ENDPOINT = endpoint;
  process.env.REMOTE_CONTROL_AGENT_KEY_PATH = keyPath;
  await import(portable ? "../src/v2-main.js" : "../src/v2-main.ts");
}

/**
 * One-code pairing: the owner enters the locally displayed code into the
 * authenticated MCP, then explicitly calls pairing_approve for that key/mode.
 * The existing session-recovery endpoint only returns a device ID after this
 * Agent has signed a fresh server nonce with the matching private key.
 * Polling does not call any owner MCP tool or grant a device by itself.
 */
export async function awaitOwnerMcpApproval(endpoint, keyPath, {
  claim = recoverDeviceId,
  delay = (ms) => sleep(ms),
  deadlineMs = 10 * 60_000,
  intervalMs = 5_000,
  now = Date.now,
} = {}) {
  const deadline = now() + deadlineMs;
  while (now() < deadline) {
    try {
      return await claim(endpoint, keyPath);
    } catch (error) {
      // An unapproved pending key is 404. Other failures are not evidence
      // that the owner has approved this pairing; fail without rotating keys.
      if (!(error instanceof DeviceSessionRejectedError) || error.status !== 404) {
        throw error;
      }
    }
    const remaining = deadline - now();
    if (remaining <= 0) break;
    await delay(Math.min(intervalMs, remaining));
  }
  throw new Error("MCP pairing was not approved within the code lifetime. Re-run the same installer safely.");
}

async function pairFreshPending(options, keyPath, stdin, stdout, reuseExistingKey) {
  if (!stdin.isTTY || !stdout.isTTY) {
    throw new Error("Pairing requires a local interactive device terminal.");
  }
  // Ask only while creating a fresh pending grant; already-approved installs do not prompt.
  const suggested = os.hostname();
  let name;
  if (options.name !== undefined) {
    name = selectDeviceLabel(options.name, "");
  } else {
    const prompt = createInterface({ input: stdin, output: stdout, terminal: true });
    try { name = selectDeviceLabel(await prompt.question(`Device name [${suggested}]: `), suggested); }
    finally { prompt.close(); }
  }
  const enrollment = await beginDeviceEnrollment(
    name, options.endpoint, keyPath, fetch, reuseExistingKey,
    options.grantType ?? "permanent");
  stdout.write("Pairing code (10 min): " + enrollment.code + "\n");
  if (options.showFingerprint) {
    stdout.write("Local public key fingerprint (optional check): " + enrollment.fingerprint + "\n");
  }
  stdout.write("Use MCP pairing_lookup, then explicitly pairing_approve for the exact key and mode.\n");
  stdout.write("Waiting for approval; no local challenge is needed.\n");
  await awaitOwnerMcpApproval(options.endpoint, keyPath);
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
  stdout.write("Previous identity archived; new device paired. Starting Agent.\n");
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
  if (previous && !existingKey) throw new Error("Installed Agent identity is missing; manual review required.");
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


/** Read-only check: reject a foreign short command before ANY pairing/approval.
 * Also refuses untrusted launcher parents even when an old binary is present.
 */
export async function preflightManagerLauncher(home, program) {
  const target = path.join(program, "apps/remote-control-agent/scripts/rca.sh");
  const file = await lstat(target);
  if (!file.isFile() || file.isSymbolicLink() || file.uid !== process.getuid() ||
      !(file.mode & 0o100) || file.mode & 0o077) {
    throw new Error("Reviewed Agent manager executable is missing or unsafe.");
  }
  const parent = path.join(home, ".local");
  const bin = path.join(parent, "bin");
  for (const directory of [home, parent, bin]) {
    try {
      const stat = await lstat(directory);
      if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== process.getuid()) {
        throw new Error("Untrusted user-local launcher directory.");
      }
    } catch (error) {
      if (error.code !== "ENOENT" || directory === home) throw error;
    }
  }
  const launcher = path.join(bin, "rca");
  const installedRoot = path.join(home, ".local/share/mcp-workers/remote-control/programs");
  try {
    const current = await lstat(launcher);
    if (!current.isSymbolicLink()) {
      throw new Error("A foreign rca command already exists.");
    }
    const destination = await readlink(launcher);
    if (!destination.startsWith(installedRoot + path.sep) ||
        !/^v[0-9]+[.][0-9]+[.][0-9]+(?:-[a-z0-9.-]+)?-linux-(?:x64|arm64)-glibc[/]apps[/]remote-control-agent[/]scripts[/](?:manage-v2[.]py|rca[.]sh)$/.test(
          destination.slice(installedRoot.length + 1))) {
      throw new Error("Existing launcher is not owned by the versioned Agent.");
    }
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
}

/** Publish only our own user-local launcher. Never overwrite foreign commands.
 * Called after successful service activation, not at download or pairing time.
 */
export async function installManagerLauncher(home, program) {
  await preflightManagerLauncher(home, program);
  const parent = path.join(home, ".local");
  const bin = path.join(parent, "bin");
  for (const directory of [home, parent, bin]) {
    let stat;
    try { stat = await lstat(directory); }
    catch (error) {
      if (error.code !== "ENOENT" || directory === home) throw error;
      await mkdir(directory, {mode:0o700});
      stat = await lstat(directory);
    }
    if (!stat.isDirectory() || stat.isSymbolicLink() ||
        stat.uid !== process.getuid()) {
      throw new Error("Untrusted user-local launcher directory.");
    }
  }
  const target = path.join(program, "apps/remote-control-agent/scripts/rca.sh");
  const file = await lstat(target);
  if (!file.isFile() || file.isSymbolicLink() || file.uid !== process.getuid() ||
      !(file.mode & 0o100) || file.mode & 0o077) {
    throw new Error("Reviewed Agent manager executable is missing or unsafe.");
  }
  const launcher = path.join(bin, "rca");
  const installedRoot = path.join(home, ".local/share/mcp-workers/remote-control/programs");
  try {
    const current = await lstat(launcher);
    if (!current.isSymbolicLink()) {
      throw new Error("A foreign rca command already exists.");
    }
    const destination = await readlink(launcher);
    if (!destination.startsWith(installedRoot + path.sep) ||
        !/^v[0-9]+[.][0-9]+[.][0-9]+(?:-[a-z0-9.-]+)?-linux-(?:x64|arm64)-glibc[/]apps[/]remote-control-agent[/]scripts[/](?:manage-v2[.]py|rca[.]sh)$/.test(
          destination.slice(installedRoot.length + 1))) {
      throw new Error("Existing launcher is not owned by the versioned Agent.");
    }
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  const temporary = path.join(bin, ".rca-" + process.pid);
  await symlink(target, temporary);
  try { await rename(temporary, launcher); }
  finally { await rm(temporary, {force:true}); }
  // User-local Bash convenience only. No modification of unknown/symlinked rc files.
  const rc=path.join(home, ".bashrc");
  try {
    const stat=await lstat(rc);
    if (stat.isFile() && !stat.isSymbolicLink() && stat.uid===process.getuid() &&
        stat.nlink === 1 && (stat.mode & 0o200) !== 0 &&
        (stat.mode & 0o022) === 0 && stat.size <= 1024*1024) {
      const contents=await readFile(rc,"utf8");
      if (!contents.includes("# rca local CLI")) {
        const fd=await open(rc,constants.O_WRONLY | constants.O_APPEND | constants.O_NOFOLLOW);
        try { await fd.writeFile("\n# rca local CLI\nexport PATH=\"$HOME/.local/bin:$PATH\"\n"); }
        finally { await fd.close(); }
      }
    }
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  return launcher;
}

/** Print one CLI path and only the PATH action this terminal may need. */
export function printPortableCliHint(stdout, launcher, home, currentPath = process.env.PATH ?? "") {
  stdout.write("CLI: " + launcher + "\n");
  if (!currentPath.split(path.delimiter).includes(path.join(home, ".local", "bin"))) {
    stdout.write('To use rca here: export PATH="$HOME/.local/bin:$PATH"\n');
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
  if (result.status === 75) throw new Error("Another Agent installer is already running.");
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
    const existingUnit = await readOwnedUnit(path.join(home, ".config", "systemd", "user", UNIT));
    const existingId = await exists(keyForInstallMode(home, "permanent") + ".device-id");
    if (existingUnit && existingId) {
      // The validated ordinary install path below checks version, key, grant,
      // endpoint and live service without showing a new-enrollment menu.
      options.grantType = "permanent";
      options.foreground = false;
    } else {
    if (!stdin.isTTY || !stdout.isTTY) {
      throw new Error("Portable pairing requires a real interactive target-terminal TTY.");
    }
    stdout.write("Remote Control Agent " +
      JSON.parse(readFileSync(manifestPath, "utf8")).version + "\n");
    stdout.write("Suggested device name: " + (options.name ?? os.hostname()) + "\n");
    const mode = await promptInstallMode(stdin,stdout);
    Object.assign(options, choosePortableInstallMode(mode === "permanent" ? "1" : "2", args));
    if (mode === "temporary") {
      stdout.write("Temporary: cloud grant expires in 24h; terminal stop is not a revoke.\n");
    }
    }
  }
  const unitPath = path.join(home, ".config", "systemd", "user", UNIT);
  const keyPath = keyForInstallMode(home, options.grantType ?? "permanent");
  systemdLiteral(home);
  const host = await preflight(options.action, options.foreground);
  await recoverInterruptedUpgrade({home, unitPath});
  if (options.action !== "uninstall") trustedEndpoint(options.endpoint);
  // Read-only collision gate BEFORE creating a device key or pending cloud grant.
  if (portable && options.action !== "uninstall") {
    await preflightManagerLauncher(home, path.resolve(packageRoot, "..", ".."));
  }
  // WSL2 lifecycle reminder is shown once, after successful activation.
  const previous = await readOwnedUnit(unitPath);
  // Temporary foreground identities never own the permanent user service.
  const identityPrevious = options.grantType === "temporary" ? null : previous;
  // Ordinary repeat install must not silently accept a different Worker target.
  // Explicit --upgrade remains the separate path for intentional endpoint changes.
  if (previous && (options.action === "install" || options.action === "upgrade") &&
      options.grantType !== "temporary") {
    assertExistingServiceEndpoint(previous, options.endpoint);
  }
  if (portable && previous && options.action==="install" &&
      options.grantType!=="temporary"){
    assertRepeatInstallSameVersion(previous,programRoot,{home,keyPath});
  }
  // A distinct temporary Agent may coexist with the installed permanent unit.
  if (options.foreground && previous && options.grantType !== "temporary") {
    throw new Error("An installed Agent service is already active; foreground refused.");
  }

  if (options.action === "uninstall") {
    if (!previous) throw new Error("The Agent service is not installed.");
    run("systemctl", ["--user", "disable", "--now", UNIT]);
    await rm(unitPath);
    run("systemctl", ["--user", "daemon-reload"]);
    stdout.write("Agent service removed. Local identity retained; revoke the device separately.\n");
    return;
  }
  if ((options.action === "resume" && previous) || (options.action === "upgrade" && !previous)) {
    throw new Error("Existing Agent requires --upgrade; a missing Agent requires install.");
  }
  await mkdir(path.dirname(keyPath), { recursive: true, mode: 0o700 });
  const privateDirectory = await lstat(path.dirname(keyPath));
  if (!privateDirectory.isDirectory() || privateDirectory.isSymbolicLink() ||
      privateDirectory.uid !== process.getuid() || (privateDirectory.mode & 0o077) !== 0) {
    throw new Error("The private identity directory must be owner-only.");
  }

  if (options.action === "resume") {
    if (!(await exists(keyPath)) || !(await exists(keyPath + ".device-id"))) {
      throw new Error("Resume requires prior confirmation and an absent Agent service.");
    }
  }

  if (options.action !== "install" && await exists(promotionMarker(keyPath))) {
    throw new Error("Finish the interrupted identity promotion using the ordinary install command first.");
  }
  if (options.action === "install") {
    if (await exists(promotionMarker(keyPath))) {
      if ((options.foreground && options.grantType !== "temporary") || !stdin.isTTY || !stdout.isTTY) {
        throw new Error("Interrupted identity promotion requires a local interactive terminal.");
      }
      const resumed = await resumeRevokedPromotion(options, keyPath, identityPrevious);
      stdout.write("Verified interrupted identity promotion for " + resumed.newId + ".\n");
    } else {
      const state = await inspectInstallIdentity(options, keyPath, identityPrevious);
      if (state === "revoked") {
        // Only an interactive installer can recover a revoked installation.
        // Do not migrate a managed permanent identity through foreground mode;
        // a separate revoked Temporary key can be replaced after new MCP approval.
        if (options.foreground && options.grantType !== "temporary") {
          throw new Error("Revoked non-temporary foreground identity requires manual review.");
        }
        await rePairRevokedDevice(options, keyPath, identityPrevious, stdin, stdout);
      } else if (state === "approved") {
        if (previous && options.grantType !== "temporary") {
          // A repeat install may complete an interrupted owned v2 activation.
          // Never restart v1 or replace this approved local identity.
          const marker = keyPath + ".activation-pending";
          const deviceId = (await readFile(keyPath + ".device-id", "utf8")).trim();
          const pending = await hasInitialActivation(marker, deviceId);
          const alreadyActive = ensureApprovedPermanentService(run, pending);
          if (pending) await clearInitialActivation(marker);
          if (alreadyActive === null) {
            stdout.write("Existing approved service is stopped; repeat install will not restart it.\n");
            return;
          }
          if (portable) {
            // Healthy repeats never overwrite ~/.local/bin/rca or ~/.bashrc.
            const launcher = alreadyActive
              ? path.join(home, ".local", "bin", "rca")
              : await installManagerLauncher(home,path.resolve(packageRoot, "..", ".."));
            printPortableCliHint(stdout, launcher, home);
          }
          stdout.write("Ready: Agent active; identity retained.\n");
          if (host === "wsl2") stdout.write("WSL2: stopped distribution = offline.\n");
          return;
        }
        stdout.write("Approved identity recovered; continuing installation.\n");
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
    // A verified Temporary promotion needs no systemd activation to finalize.
    await finishRevokedPromotion(keyPath);
    if (portable) {
      const launcher=await installManagerLauncher(home,path.resolve(packageRoot,"..",".."));
      printPortableCliHint(stdout, launcher, home);
    }
    stdout.write("Starting " + (options.grantType === "temporary" ? "temporary (24h)" : "foreground") +
      " Agent; terminal stop disconnects, not revokes.\n");
    await startForeground({ endpoint: trustedEndpoint(options.endpoint), keyPath });
    return;
  }
  await mkdir(path.dirname(unitPath), { recursive: true, mode: 0o700 });
  const rendered = renderV2Service({
    node: process.execPath, home, repoRoot: path.resolve(packageRoot, "..", ".."),
    endpoint: options.endpoint, keyPath, entryExt: portable ? "js" : "ts",
  });
  let consentAttempted = false;
  if (portable && options.action === "upgrade") {
    const safety = await assertSafePortableUpgrade(previous, home, manifestPath);
    if (safety.legacyOffline) {
      // Never remotely stop v0.1.11 or manufacture a quiescence ACK.
      // The user has already stopped it from their own terminal.
      await confirmLegacyV0111OfflineCutover({home,keyPath,stdin,stdout});
    } else if (safety.needsFreeze) {
      let consent;
      try {
        consent = await requestUpgradeConsent(keyPath, "freeze");
        if (consent !== "ready") throw Error("Agent has active or uncertain work; upgrade blocked.");
        consentAttempted = true;
      } catch {
        // A lost ACK might have frozen this Agent; release it if uncertain.
        // A definitive busy response must NOT release somebody else's freeze.
        if (consent !== "busy")
          await requestUpgradeConsent(keyPath, "release").catch(()=>{});
        throw Error("Cannot prove Agent quiescence; upgrade blocked.");
      }
    }
  }
  const firstActivation = !previous && !options.foreground;
  const activationMarker = keyPath + ".activation-pending";
  if (firstActivation) {
    const deviceId = (await readFile(keyPath + ".device-id", "utf8")).trim();
    await beginInitialActivation(activationMarker, deviceId);
  }
  try {
    await installUnit(unitPath, rendered, previous);
    if (firstActivation) await clearInitialActivation(activationMarker);
  } finally {
    // When activation fails before service stop, let the old Agent resume.
    // After successful restart the old socket disappears and release is a no-op.
    if (consentAttempted) await requestUpgradeConsent(keyPath, "release").catch(()=>{});
  }
  await finishRevokedPromotion(keyPath);
  if (portable) {
    const launcher=await installManagerLauncher(home,path.resolve(packageRoot, "..", ".."));
    stdout.write("Ready: Agent active.\n");
    printPortableCliHint(stdout, launcher, home);
    if (host === "wsl2") stdout.write("WSL2: stopped distribution = offline.\n");
  }
  if (!portable) {
    stdout.write("Agent active. Verify MCP connectivity.\n");
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  runLockedInstallerCli(process.argv.slice(2)).then(async code => {
    process.exitCode = code;

  }).catch(error => {
    // Upgrade failures need local-service guidance, not the pairing-specific
    // fallback used for enrollment failures. Keep output fixed and sanitized.
    if (process.argv.slice(2).includes("--upgrade")) {
      process.stderr.write("Upgrade failed. Inspect the Agent service before retrying.\n");
      process.exitCode = 1;
      return;
    }
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
      "Installed Agent identity is missing; manual review required.",
      "Existing Agent service endpoint differs; manual review required.",
      "Revoked foreground identity requires manual review.",
      "New device identity was not verified.",
      "Old identity archive already exists.",
      "A local installer lock prerequisite is unavailable.",
      "Another Agent installer is already running.",
      "Installer was interrupted; identity files were preserved.",
    ];
    const detail = error instanceof PendingIdentityConflictError
      ? "Existing device key is already approved or revoked. Never reuse it; ask the owner for explicit fresh-key pairing. "
      : error instanceof DeviceSessionRejectedError
        ? "Device identity is unavailable or revoked. Do not reset its key automatically. "
        : error instanceof Error && safeErrors.includes(error.message)
          ? error.message + " " : "Pairing state is uncertain; existing identity files were preserved. ";
    process.stderr.write(detail +
      "Agent operation failed. Previous services were not changed.\n");
    process.exitCode = 1;
  });
}
