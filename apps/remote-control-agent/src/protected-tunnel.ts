/** Owner-pinned Windows protected Quick Tunnel and fail-closed process lifecycle. */
import { Buffer } from "node:buffer";
import { spawn, spawnSync, type ChildProcess, type SpawnOptions } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { closeSync, fsyncSync, lstatSync, openSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { startHandoffController } from "./handoff-controller.ts";
import type { BrowserBackend } from "./browser-backend.ts";
import type { HumanAccess } from "./browser-handoff.ts";

export interface ProtectedTunnelConfig { configurationDirectory: string; email: string; cloudflared_path: string; cloudflared_sha256: string }


export function supportsProtectedQuickTunnel(version: string, help: string): boolean {
  const match = /\bcloudflared version (\d+)\.(\d+)\.(\d+)\b/.exec(version);
  if (!match) return false;
  const [year,month,patch] = match.slice(1).map(Number) as [number,number,number];
  return (year > 2026 || year === 2026 && (month > 9 || month === 9 && patch >= 3)) &&
    /(?:^|\s)--allowed-mail(?:[\s=,]|$)/m.test(help);
}

/** Owner-managed private deployment file; no MCP-supplied mailbox or executable. */
export function verifyWindowsHandoffPrerequisites(directory: string, aclCheck: () => void): ProtectedTunnelConfig {
  if (process.platform !== "win32") throw Error("native_windows_required");
  aclCheck();
  const configPath = path.join(directory,"browser-handoff-config.json");
  const file = lstatSync(configPath);
  if (!file.isFile() || file.isSymbolicLink() || file.size > 4096) throw Error("handoff_config_invalid");
  const config = JSON.parse(readFileSync(configPath,"utf8")) as Record<string,unknown>;
  if (Object.keys(config).sort().join(",") !== "cloudflared_path,cloudflared_sha256,email" ||
      typeof config.email !== "string" || !/^[A-Za-z0-9.!#$%&'+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/.test(config.email) || config.email.length > 254 ||
      typeof config.cloudflared_path !== "string" || !path.win32.isAbsolute(config.cloudflared_path) ||
      !/^[A-Za-z]:\\/.test(config.cloudflared_path) ||
      typeof config.cloudflared_sha256 !== "string" || !/^[a-f0-9]{64}$/.test(config.cloudflared_sha256)) throw Error("handoff_config_invalid");
  const executable = lstatSync(config.cloudflared_path);
  if (!executable.isFile() || executable.isSymbolicLink() || executable.size > 150_000_000 ||
      createHash("sha256").update(readFileSync(config.cloudflared_path)).digest("hex") !== config.cloudflared_sha256)
    throw Error("cloudflared_integrity_unverified");
  const run = (args: string[]) => {
    const result = spawnSync(config.cloudflared_path as string,args,{encoding:"utf8",timeout:5000,maxBuffer:256_000,windowsHide:true});
    if (result.error || result.status !== 0) throw Error("cloudflared_capability_unverified");
    return result.stdout + result.stderr;
  };
  if (!supportsProtectedQuickTunnel(run(["--version"]),run(["tunnel","--help"])))
    throw Error("cloudflared_protected_flag_unavailable");
  return {configurationDirectory:directory,email:config.email,cloudflared_path:config.cloudflared_path,cloudflared_sha256:config.cloudflared_sha256};
  // Integrity is pinned by the owner to an official Cloudflare distribution.
  // No download, installation, config rewrite, or unprotected fallback here.
}

export type HandoffEvidenceKind = "directory" | "pending" | "child" | "tunnel";

/** Seal only fixed Agent-owned receipt paths through the existing private-store ACL contract. */
export function sealWindowsRuntimeMarker(receiptsDirectory: string, kind: HandoffEvidenceKind): void {
  if (process.platform !== "win32" || !process.env.LOCALAPPDATA || !process.env.SystemRoot) {
    throw Error("native_windows_required");
  }
  const root = path.win32.join(process.env.LOCALAPPDATA, "mcp-workers", "remote-control");
  const expected = path.win32.join(root, "receipts");
  if (path.win32.normalize(receiptsDirectory).toLowerCase() !== expected.toLowerCase())
    throw Error("unexpected_handoff_store");
  const names: Record<HandoffEvidenceKind,string> = {
    directory: "receipts",
    pending: "receipts\\browser-handoff-pending.json",
    child: "receipts\\browser-handoff-child.json",
    tunnel: "receipts\\browser-handoff-tunnel.yml",
  };
  const script = fileURLToPath(new URL("../scripts/windows-private-store.ps1", import.meta.url));
  const ps = path.win32.join(process.env.SystemRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
  const result = spawnSync(ps, ["-NoProfile","-NonInteractive","-ExecutionPolicy","Bypass",
    "-File",script,"-Action","Seal","-Directory",root,"-FileName",names[kind]], {
      encoding:"utf8", windowsHide:true, timeout:12_000, maxBuffer:8192,
    });
  if (result.error || result.status !== 0) throw Error("handoff_private_acl_unverified");
}

export const CHILD_MARKER = "browser-handoff-child.json";
interface ChildIdentity { pid: number; executable: string; started: string; commandHash: string }
function durableRecord(file: string, value: unknown, exclusive = false): void {
  const fd = openSync(file, exclusive ? "wx" : "w", 0o600);
  try { writeFileSync(fd,JSON.stringify(value)); fsyncSync(fd); } finally { closeSync(fd); }
}

// No interpolated shell values. CIM and the process handle must agree before a kill.
function windowsChild(identity: {pid:number} | ChildIdentity, stop: boolean): ChildIdentity | null {
  if (process.platform !== "win32" || !process.env.SystemRoot || !/^[A-Za-z]:\\/.test(process.env.SystemRoot)) throw Error("native_windows_required");
  const script = `
$ErrorActionPreference='Stop'
$x=[Console]::In.ReadToEnd() | ConvertFrom-Json
$c=Get-CimInstance Win32_Process -Filter ('ProcessId = '+[int]$x.pid)
if ($null -eq $c) { 'null'; exit 0 }
$p=[System.Diagnostics.Process]::GetProcessById([int]$x.pid)
$started=$p.StartTime.ToUniversalTime().Ticks.ToString()
$sha=[System.Security.Cryptography.SHA256]::Create()
$hash=([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes([string]$c.CommandLine)))).Replace('-','').ToLowerInvariant()
if (-not $c.ExecutablePath -or -not $c.CommandLine) { exit 2 }
if ($x.stop) {
 if ($c.ExecutablePath -cne $x.executable -or $started -cne $x.started -or $hash -cne $x.commandHash) { exit 3 }
 $p.Kill()
 if (-not $p.WaitForExit(5000)) { exit 4 }
 'null'
} else { @{pid=[int]$x.pid; executable=[string]$c.ExecutablePath; started=$started; commandHash=$hash} | ConvertTo-Json -Compress }
`;
  const result = spawnSync(path.win32.join(process.env.SystemRoot,"System32","WindowsPowerShell","v1.0","powershell.exe"),
    ["-NoProfile","-NonInteractive","-Command",script],{input:JSON.stringify({...identity,stop}),encoding:"utf8",timeout:8000,maxBuffer:8192,windowsHide:true});
  if (result.error || result.status !== 0) throw Error("tunnel_child_identity_unknown");
  return JSON.parse(result.stdout.trim()) as ChildIdentity | null;
}
const HELPER_SHA256 = "cddb0bbcb9b4a51f6b6c0418deacbcf2e98d563c26172f4712df57580c1d9070";
export function windowsTunnelLauncher(platform = process.platform as string): {executable:string;args:string[]} {
  if (platform !== "win32" || !process.env.SystemRoot || !/^[A-Za-z]:\\/.test(process.env.SystemRoot))
    throw Error("native_windows_required");
  const helper=fileURLToPath(new URL("../scripts/windows-handoff-tunnel.ps1",import.meta.url));
  const stat=lstatSync(helper);
  if (!stat.isFile() || stat.isSymbolicLink() || createHash("sha256").update(readFileSync(helper,"utf8").replace(/\r\n/g,"\n")).digest("hex") !== HELPER_SHA256)
    throw Error("handoff_supervisor_integrity_unverified");
  return {executable:path.win32.join(process.env.SystemRoot,"System32","WindowsPowerShell","v1.0","powershell.exe"),
    args:["-NoProfile","-NonInteractive","-File",helper]};
}
function confirmWindowsCleanup(directory:string, action:"Stop"|"Recover"): "confirmed" | "uncertain" {
  try {
    const launcher=windowsTunnelLauncher();
    const owner=action === "Stop" ? windowsChild({pid:process.pid},false) : null;
    if (action === "Stop" && !owner) return "uncertain";
    const result=spawnSync(launcher.executable,[...launcher.args,"-Action",action],{
      input:JSON.stringify({marker:path.join(directory,CHILD_MARKER),owner_pid:owner?.pid,owner_started:owner?.started}),
      encoding:"utf8",timeout:15_000,maxBuffer:8192,windowsHide:true});
    return !result.error && result.status===0 && result.stdout.trim()==="confirmed" ? "confirmed" : "uncertain";
  } catch { return "uncertain"; }
}
/** Unknown intent/identity is durable evidence; never infer success from a kill request. */
export async function cleanupOrphanTunnel(directory: string): Promise<"confirmed" | "uncertain"> {
  const file=path.join(directory,CHILD_MARKER);
  try {
    try { const stat=lstatSync(file); if (!stat.isFile() || stat.isSymbolicLink() || stat.size>4096) return "uncertain"; }
    catch(error) { if ((error as NodeJS.ErrnoException).code==="ENOENT") return "confirmed"; throw error; }
    if (confirmWindowsCleanup(directory,"Recover") !== "confirmed") return "uncertain";
    try { unlinkSync(path.join(directory,"browser-handoff-tunnel.yml")); }
    catch(error) { if ((error as NodeJS.ErrnoException).code!=="ENOENT") throw error; }
    return "confirmed";
  } catch { return "uncertain"; }
}

/** Accept only a complete JSON log message containing exactly the tunnel origin. */
export function tunnelOriginFromLog(line: string): string | undefined {
  if (line.length > 8192) return undefined;
  try {
    const record = JSON.parse(line) as {message?:unknown;level?:unknown};
    if (record.level !== "info" || typeof record.message !== "string") return undefined;
    const match = /^\s*\|?\s*(https:\/\/([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)\.trycloudflare\.com)\s*\|?\s*$/.exec(record.message);
    if (!match || match[2] === "login") return undefined;
    return match[1];
  } catch { return undefined; }
}
/** Mirrors Cloudflare's quicktunnelauth/state.go; a generic redirect is never proof. */
export function isProtectedChallenge(response: Pick<Response,"status" | "headers">, origin: string, probePath: string): boolean {
  try {
    const redirect = new URL(response.headers.get("location") ?? "");
    const state = redirect.searchParams.get("state");
    if (response.status !== 302 || redirect.origin !== "https://login.trycloudflare.com" || redirect.pathname !== "/authorize" ||
        redirect.username || redirect.password || redirect.hash || redirect.searchParams.size !== 2 ||
        redirect.searchParams.get("hostname") !== new URL(origin).hostname || !state || !/^[A-Za-z0-9_-]{43}$/.test(state) ||
        response.headers.get("cache-control") !== "private, no-store" || response.headers.get("referrer-policy") !== "no-referrer") return false;
    const cookies = response.headers.getSetCookie();
    const cookie = cookies.find(c => c.startsWith(`__Secure-cloudflared-qt-auth-state-${state}=`));
    if (!cookie || !/; Secure(?:;|$)/i.test(cookie) || !/; HttpOnly(?:;|$)/i.test(cookie) ||
        !/; SameSite=None(?:;|$)/i.test(cookie) || !/; Path=\/\.cloudflared\/qt-auth\/callback(?:;|$)/.test(cookie) || /; Domain=/i.test(cookie)) return false;
    const value = cookie.slice(cookie.indexOf("=")+1).split(";")[0]!;
    const parts=value.split(".");
    if (parts.length !== 2 || !/^[A-Za-z0-9_-]{43}$/.test(parts[1]!)) return false;
    const payload=JSON.parse(Buffer.from(parts[0]!,"base64url").toString("utf8")) as Record<string,unknown>;
    return payload.state === state && payload.hostname === new URL(origin).hostname && payload.return_path === probePath &&
      typeof payload.exp === "number" && payload.exp > Date.now()/1000 && payload.exp <= Date.now()/1000+605;
  } catch { return false; }
}

const nativeRuntime = {
  platform:process.platform as string,
  controller:startHandoffController,
  launch:(_executable:string,args:string[],options:SpawnOptions,expiresAt:number,config:ProtectedTunnelConfig):ChildProcess=>{
    const launcher=windowsTunnelLauncher();
    const directory=String(options.cwd);
    const owner=windowsChild({pid:process.pid},false);
    if (!owner) throw Error("tunnel_owner_identity_unknown");
    // Persist owner identity before starting the supervisor. Missing supervisor stays blocked.
    durableRecord(path.join(directory,CHILD_MARKER),{version:1,owner,supervisor:null});
    const supervisor=spawn(launcher.executable,launcher.args,{...options,stdio:["pipe","pipe","pipe"]});
    const localUrl=new URL(args[args.indexOf("--url")+1]!);
    supervisor.stdin!.on("error",()=>{}); // Spawn failure is reported by the process error event.
    supervisor.stdin!.end(JSON.stringify({directory,config_directory:config.configurationDirectory,marker:path.join(directory,CHILD_MARKER),
      owner_pid:owner.pid,owner_started:owner.started,port:Number(localUrl.port),expires_at:expiresAt,config}));
    return supervisor;
  },
  confirm:(directory:string)=>confirmWindowsCleanup(directory,"Stop"),
  send:fetch,
};

export function createManagedHandoff(options: {
  directory: string; config: ProtectedTunnelConfig; browser: BrowserBackend; deviceId: string; sessionId: string;
  connected: () => void; explicitReturn: () => Promise<unknown>;
}, runtime = nativeRuntime): HumanAccess & { start(): Promise<{url:string;expiresAt:number}> } {
  let closed=false, enabled=false, ownsMarker=false, launchAttempted=false, child: ChildProcess | undefined;
  let controller: Awaited<ReturnType<typeof startHandoffController>> | undefined;
  let origin: string | undefined, setup: Promise<{url:string;expiresAt:number}> | undefined;
  let monitor: ReturnType<typeof setInterval> | undefined;
  let cleanup: Promise<"confirmed" | "uncertain"> | undefined, timer: ReturnType<typeof setTimeout> | undefined;
  const file=path.join(options.directory,CHILD_MARKER);
  const check = () => { if (closed || !child || child.exitCode !== null || child.signalCode !== null) throw Error("tunnel_unavailable"); };
  const close = (): Promise<"confirmed" | "uncertain"> => {
    closed=true; enabled=false; clearTimeout(timer); clearInterval(monitor);
    // Local invalidation happens synchronously, including while startup is in flight.
    const localClose=controller?.close();
    return cleanup ??= (async () => {
      await setup?.catch(() => {});
      let outcome: "confirmed" | "uncertain" = "confirmed";
      if (child && child.exitCode === null && child.signalCode === null) {
        const exited=new Promise<boolean>(resolve => {
          child!.once("exit",()=>resolve(true));
          const t=setTimeout(()=>resolve(false),6000); t.unref();
        });
        try { child.kill(); if (!await exited) outcome="uncertain"; } catch { outcome="uncertain"; }
      }
      if (launchAttempted && !child) outcome="uncertain";
      if (child) {try {if(runtime.confirm(options.directory)!=="confirmed")outcome="uncertain";}catch{outcome="uncertain";}}
      // A successfully spawned child must actually exit; a kill request is not confirmation.
      if (child?.pid && child.exitCode === null && child.signalCode === null) outcome="uncertain";
      if (await (localClose ?? controller?.close() ?? Promise.resolve("confirmed")) !== "confirmed") outcome="uncertain";
      if (outcome === "confirmed" && ownsMarker) {
        for (const temporary of [file,path.join(options.directory,"browser-handoff-tunnel.yml")]) {
          try { unlinkSync(temporary); } catch (e) { if ((e as NodeJS.ErrnoException).code !== "ENOENT") outcome="uncertain"; }
        }
      }
      return outcome;
    })();
  };
  return {close, start:() => {
    if (setup) return Promise.reject(Error("handoff_start_already_requested"));
    return setup = (async () => {
    if (runtime.platform !== "win32" || closed) throw Error("native_windows_required");
    // Mint once, with a conservative absolute deadline covering preparation too.
    const expiresAt=Date.now()+900_000;
    const probe=Buffer.from(randomBytes(32)).toString("base64url"), probePath="/__handoff_probe/"+probe;
    controller=await runtime.controller({browser:options.browser,deviceId:options.deviceId,sessionId:options.sessionId,
      expiresAt,readinessProbe:probe,origin:()=>origin,active:()=>enabled && !closed && child?.exitCode===null && child?.signalCode===null,
      connected:options.connected,explicitReturn:options.explicitReturn});
    if (closed) throw Error("handoff_closed");
    const local=await runtime.send(`http://127.0.0.1:${controller.port}${probePath}`,{redirect:"manual",signal:AbortSignal.timeout(3000)});
    const proof=await local.json() as Record<string,unknown>;
    if (local.status!==200 || proof.probe!==probe || proof.device_id!==options.deviceId || proof.session_id!==options.sessionId) throw Error("loopback_unverified");
    if (closed) throw Error("handoff_closed");
    // Persist intent BEFORE spawn: even a crash between spawn and recording PID stays blocked.
    durableRecord(file,{spawn_pending:true},true);
    ownsMarker=true;
    if (runtime === nativeRuntime) sealWindowsRuntimeMarker(options.directory,"child");
    // An explicit empty configuration prevents default ingress/logging overrides.
    const emptyConfig=path.join(options.directory,"browser-handoff-tunnel.yml");
    const configFd=openSync(emptyConfig,"wx",0o600);
    try {writeFileSync(configFd,"{}\n");fsyncSync(configFd);} finally {closeSync(configFd);}
    if (runtime === nativeRuntime) sealWindowsRuntimeMarker(options.directory,"tunnel");
    launchAttempted=true;
    child=runtime.launch(options.config.cloudflared_path,["tunnel","--config",emptyConfig,"--no-autoupdate","--output","json","--url",`http://127.0.0.1:${controller.port}`,
      "--allowed-mail",options.config.email],{stdio:["ignore","pipe","pipe"],windowsHide:true,
        // Do not inherit TUNNEL_* configuration or the user's default .cloudflared directory.
        cwd:options.directory,env:Object.assign(Object.create(null) as NodeJS.ProcessEnv,{SystemRoot:process.env.SystemRoot,PATH:path.win32.join(process.env.SystemRoot ?? "C:\\Windows","System32"),
          USERPROFILE:options.directory,HOME:options.directory,TEMP:options.directory,TMP:options.directory})},expiresAt,options.config);
    child.on("error",()=>{closed=true;enabled=false;void controller?.close();});
    child.once("exit",()=>{closed=true;enabled=false;void controller?.close();});
    const found = new Promise<string>((resolve,reject) => {
      let total=0, settled=false;
      const finish=(error?:Error,value?:string) => {if(settled)return;settled=true;clearTimeout(timeout);if(error)reject(error);else resolve(value!);};
      const timeout=setTimeout(()=>finish(Error("tunnel_url_timeout")),20_000);
      for (const stream of [child!.stdout,child!.stderr]) {
        let buffer="";
        stream!.on("data",(data:Buffer) => {
          total+=data.length;
          if(total>256_000) { enabled=false;closed=true;void controller?.close();finish(Error("tunnel_log_limit"));void close();return; }
          buffer+=Buffer.from(data).toString("utf8");
          if(buffer.length>8192 && !buffer.includes("\n")) {finish(Error("tunnel_log_line_limit"));return;}
          let end:number;
          while((end=buffer.indexOf("\n"))>=0) {
            const url=tunnelOriginFromLog(buffer.slice(0,end));buffer=buffer.slice(end+1);
            if(url)finish(undefined,url);
          }
        });
      }
      child!.once("error",()=>finish(Error("tunnel_spawn_failed")));
      child!.once("exit",()=>finish(Error("tunnel_exited")));
    });
    // Install the rejection handler before querying the OS synchronously.
    void found.catch(()=>{});
    if (!child.pid) throw Error("tunnel_spawn_failed");
    origin=await found; check();
    let proven=false;
    // Newly created trycloudflare.com names can take time to become reachable.
    // Wait only a bounded interval; never enable input before both protections prove.
    const readinessDeadline=Math.min(expiresAt,Date.now()+35_000);
    for (let attempt=0;attempt<30 && Date.now()<readinessDeadline;attempt++) {
      check();
      let unsafeProtection=false;
      try {
        const timeout=()=>AbortSignal.timeout(Math.max(1,Math.min(5000,readinessDeadline-Date.now())));
        const response=await runtime.send(origin+probePath,{redirect:"manual",credentials:"omit",signal:timeout()});
        proven=isProtectedChallenge(response,origin,probePath);
        // An actual unauthenticated HTTP response is not a DNS propagation error.
        if (!proven && response.status<500) unsafeProtection=true;
        if (proven) {
          const unsafe=await runtime.send(origin+probePath,{method:"POST",redirect:"manual",credentials:"omit",signal:timeout()});
          proven=unsafe.status===401;
          if (!proven && unsafe.status<500) unsafeProtection=true;
          await unsafe.body?.cancel();
        }
        await response.body?.cancel();
      } catch { proven=false; }
      if (proven || unsafeProtection) break;
      const remaining=readinessDeadline-Date.now();
      if (remaining>0) await new Promise(resolve=>setTimeout(resolve,Math.min(1000,remaining)));
    }
    check();
    if (!proven || options.browser.status()?.session_id !== options.sessionId || Date.now()>=expiresAt) throw Error("protected_tunnel_challenge_unverified");
    enabled=true;
    monitor=setInterval(()=>{
      if (options.browser.status()?.session_id !== options.sessionId) void close();
    },250);monitor.unref();
    timer=setTimeout(()=>{void close();},Math.max(0,expiresAt-Date.now()));timer.unref();
    return {url:origin+"/?handoff_token="+controller.token,expiresAt};
  })();
  }};
}
