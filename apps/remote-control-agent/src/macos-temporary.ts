/**
 * #658: unpublished native macOS ARM64 *temporary foreground* candidate.
 * No installer, LaunchAgent, permanent grant, Shell supervisor or auto-renewal.
 * The owner must explicitly authorize the existing signed pending key in MCP.
 */
import { lstat, mkdir } from "node:fs/promises";
import { realpathSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { beginDeviceEnrollment } from "./pair-device.ts";
import { promptInstallMode } from "./install-mode.ts";
import { selectDeviceLabel } from "./v2-enrollment.ts";
import { DeviceSessionRejectedError, recoverDeviceId } from "./v2-session-client.ts";
import { maintainAuthenticatedDeviceSession } from "./v2-connection-lifecycle.ts";

export function requireNativeMac(platform = process.platform, arch = process.arch, release = os.release()): void {
  if (platform !== "darwin" || arch !== "arm64" ||
      !/^\d+\./.test(release) || Number.parseInt(release,10) < 24 ||
      process.getuid?.() === 0) {
    throw new Error("Preview requires macOS 15+ ARM64 under an unprivileged local user.");
  }
}

export function parseTemporaryMacArgs(argv: string[]): { endpoint: string; name?: string; resume: boolean; retryPairing: boolean } {
  let endpoint: string | undefined;
  let name: string | undefined;
  let resume = false;
  let retryPairing = false;
  for (let i=0; i<argv.length; i++) {
    if (argv[i] === "--resume" && !resume && !retryPairing) resume=true;
    else if (argv[i] === "--retry-pairing" && !retryPairing && !resume) retryPairing=true;
    else if (argv[i] === "--endpoint" && !endpoint && argv[i+1]) endpoint=argv[++i];
    else if (argv[i] === "--name" && !name && argv[i+1]) name=argv[++i];
    else throw new Error("Invalid macOS temporary preview arguments.");
  }
  if (!endpoint) throw Error("Specify the existing trusted HTTPS Agent endpoint.");
  const base = new URL(endpoint);
  if (base.protocol !== "https:" || base.username || base.password ||
      base.search || base.hash || base.pathname !== "/" || !base.hostname ||
      (base.port && base.port !== "443")) throw Error("Expected a trusted HTTPS origin.");
  if (name !== undefined) selectDeviceLabel(name, "");
  return {endpoint:base.origin+"/",name,resume,retryPairing};
}

export async function privateDirectory(home: string, segments: string[]): Promise<string> {
  let cursor = home;
  for (const [index,segment] of segments.entries()) {
    cursor=path.join(cursor,segment);
    try { await mkdir(cursor,{mode:0o700}); }
    catch (error) { if ((error as NodeJS.ErrnoException).code!=="EEXIST") throw error; }
    const stat=await lstat(cursor);
    if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid!==process.getuid?.() ||
        (index>=2 ? (stat.mode & 0o077)!==0 : (stat.mode & 0o022)!==0)) throw Error("Unsafe macOS identity or receipt directory.");
  }
  return cursor;
}

export async function privateFileIfPresent(filename: string): Promise<boolean> {
  try {
    const stat=await lstat(filename);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.uid!==process.getuid?.() ||
        (stat.mode & 0o777)!==0o600) throw Error("Unsafe macOS key or ID file.");
    return true;
  } catch(error) {
    if ((error as NodeJS.ErrnoException).code==="ENOENT") return false;
    throw error;
  }
}

/** The same signed one-code approval deadline and 404-only retry rule as Linux. */
export async function awaitTemporaryApproval(
  endpoint: string, keyPath: string, signal: AbortSignal,
  deadline: number, claim = recoverDeviceId, now = Date.now,
  wait = (ms: number) => new Promise<void>(resolve => setTimeout(resolve,ms)),
): Promise<string> {
  while (now() < deadline) {
    signal.throwIfAborted();
    try { return await claim(endpoint,keyPath,fetch,signal); }
    catch (error) {
      if (!(error instanceof DeviceSessionRejectedError) || error.status!==404) throw error;
    }
    await wait(Math.min(5000,Math.max(0,deadline-now())));
  }
  throw Error("MCP owner approval expired. Temporary grant was not created.");
}

export async function runTemporaryMac(argv = process.argv.slice(2)): Promise<void> {
  requireNativeMac();
  if (!process.stdin.isTTY || !process.stdout.isTTY)
    throw Error("Temporary pairing requires an interactive owner terminal.");
  const {endpoint,name,resume,retryPairing}=parseTemporaryMacArgs(argv);
  process.umask(0o077);
  const controller=new AbortController();
  const cancel=()=>controller.abort();
  process.once("SIGINT",cancel);process.once("SIGTERM",cancel);
  try {
    const home=os.homedir();
    const stateRoot=await privateDirectory(home,[".local","share","mcp-workers","remote-control","temporary"]);
    const receipts=await privateDirectory(home,[".local","state","mcp-workers","remote-control-agent"]);
    const key=path.join(stateRoot,"v2-identity.pem");
    const hasKey=await privateFileIfPresent(key);
    const hasId=await privateFileIfPresent(key+".device-id");
    if (hasId && !hasKey) throw Error("Orphaned device ID. Manual inspection required.");
    if (!resume) {
      if (retryPairing ? (!hasKey || hasId) : hasKey) {
        throw Error(retryPairing
          ? "Retry requires an unapproved existing key without a device ID."
          : "Existing temporary identity: use --resume or explicitly --retry-pairing; never overwrite keys.");
      }
      process.stdout.write(retryPairing
        ? "Explicit pairing retry: old pending codes become invalid; the same private key is retained.\n"
        : "Unpublished macOS ARM64 preview: only Temporary (24h) is available.\n");
      if (await promptInstallMode()!=="temporary")
        throw Error("Permanent macOS mode is not implemented by this candidate.");
      const enrollment=await beginDeviceEnrollment(
        selectDeviceLabel(name??"",os.hostname()),endpoint,key,fetch,retryPairing,"temporary");
      process.stdout.write("Pairing code (10 min): "+enrollment.code+"\n");
      process.stdout.write("Fingerprint: "+enrollment.fingerprint+"\n");
      process.stdout.write("Approve this temporary key and code explicitly in authenticated MCP.\n");
      await awaitTemporaryApproval(endpoint,key,controller.signal,enrollment.expiresAt);
    } else {
      if (!hasKey) throw Error("No previous temporary identity to resume.");
      // Recovery proves the exact pre-existing Ed25519 identity. It never renews
      // the fixed server-side 24h grant or creates a new pending pairing code.
      await recoverDeviceId(endpoint,key,fetch,controller.signal);
    }
    if (!await privateFileIfPresent(key+".device-id"))
      throw Error("Owner approval did not persist a safe device ID.");
    process.stdout.write("Temporary Agent approved; connecting signed WSS. Ctrl+C disconnects only.\n");
    await maintainAuthenticatedDeviceSession(endpoint,key,controller.signal,{
      receiptDirectory:receipts,
      onState: state=>process.stderr.write(JSON.stringify({service:"remote-control-agent",event:state})+"\n"),
    });
  } finally {
    process.off("SIGINT",cancel);process.off("SIGTERM",cancel);
  }
}
if (process.argv[1] && realpathSync(process.argv[1])===fileURLToPath(import.meta.url)) {
  try {await runTemporaryMac();}
  catch(error) {
    process.stderr.write("macOS preview unavailable: "+(error instanceof Error?error.message:"unknown")+".\n");
    process.exitCode=1;
  }
}
