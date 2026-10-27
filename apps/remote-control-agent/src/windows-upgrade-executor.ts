/** Windows-only remote upgrade staging and launch.
 * Only the authenticated, DO-claimed Agent upgrade receipt may call this.
 * Reuses the *installed* immutable StageOnly verifier, never a network script.
 * The detached WMI child uses the same SID and no new Task or service.
 */
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { open, readFile, writeFile, lstat } from "node:fs/promises";
import path from "node:path";
import { parseRemoteUpgradeDispatch } from "./remote-upgrade-admission.ts";

const OP = /^(?!\.{1,2}$)[A-Za-z0-9._:-]{1,128}$/;
const STAGE_TIMEOUT_MS = 180_000;

export interface UpgradeLaunchHooks {
  stage?: (exe: string, args: string[]) => Promise<void>;
  wmi?: (exe: string, args: string[]) => Promise<void>;
}
export interface NativeUpgradePaths {
  installedRoot: string;
  stateRoot: string;
  systemRoot: string;
}
function noShellMeta(value: string): boolean {
  return !/[\r\n"'\x00-\x1f]/.test(value) && value.length <= 512;
}
async function nativeFile(filename: string): Promise<void> {
  const entry = await lstat(filename);
  if (!entry.isFile() || entry.isSymbolicLink()) throw Error("Unsafe upgrade package file.");
}
async function runPowerShell(exe: string,args: string[],timeout=STAGE_TIMEOUT_MS): Promise<void> {
  await new Promise<void>((resolve,reject)=>{
    const child = spawn(exe,args,{shell:false,windowsHide:true,stdio:"ignore",env:process.env});
    const timer = setTimeout(()=>child.kill(),timeout);
    child.once("error",()=>{clearTimeout(timer);reject(Error("Native upgrade runner could not launch."));});
    child.once("close",(code,signal)=>{
      clearTimeout(timer);
      code===0 && !signal ? resolve() : reject(Error("Native upgrade runner did not complete."));
    });
  });
}
export async function stageAndLaunchApprovedWindowsUpgrade(
  untrusted: unknown, paths: NativeUpgradePaths, hooks: UpgradeLaunchHooks={},
):Promise<"launched"> {
  const op = parseRemoteUpgradeDispatch(untrusted);
  if (!op || !("windows_asset_sha256" in op.target) ||
      process.platform!=="win32" || process.arch!=="x64" ||
      !path.win32.isAbsolute(paths.installedRoot) ||
      !path.win32.isAbsolute(paths.stateRoot) ||
      !path.win32.isAbsolute(paths.systemRoot) ||
      ![paths.installedRoot,paths.stateRoot,paths.systemRoot].every(noShellMeta)) {
    throw Error("Untrusted Windows upgrade context.");
  }
  const programs = path.win32.join(paths.stateRoot,"programs");
  const expected = path.win32.join(programs,op.current_version+"-windows-x64");
  if (path.win32.normalize(paths.installedRoot).toLowerCase()!==expected.toLowerCase()) {
    throw Error("Upgrade origin is not the installed native version.");
  }
  const source = path.win32.join(paths.installedRoot,
    "apps","remote-control-agent","scripts","windows-stage-install.ps1");
  const watchdog = path.win32.join(paths.installedRoot,
    "apps","remote-control-agent","scripts","windows-upgrade-once.ps1");
  const verifier = path.win32.join(paths.installedRoot,
    "apps","remote-control-agent","scripts","verify-windows-preview.mjs");
  const node = path.win32.join(paths.installedRoot,"bin","node.exe");
  const powershell = path.win32.join(paths.systemRoot,
    "System32","WindowsPowerShell","v1.0","powershell.exe");
  for (const file of [source,watchdog,verifier,node,powershell]) await nativeFile(file);
  const manifest = JSON.parse(await readFile(path.win32.join(paths.installedRoot,"bundle.json"),"utf8")) as
    {version?:unknown;hashes?:Record<string,unknown>};
  if(manifest.version!==op.current_version || !manifest.hashes ||
      typeof manifest.hashes!=="object" ||
      !Object.hasOwn(manifest.hashes,"apps/remote-control-agent/scripts/windows-upgrade-once.ps1")) {
    throw Error("Native origin bundle does not contain reviewed one-shot upgrader.");
  }
  // Verify SHA-256 of every installed executable/script with the bundled
  // manifest verifier; no unexpected replacements or symlink-based escalation.
  // The old installed runtime must pass its complete manifest audit before
  // executing the staged installer or the independent watchdog script.
  await runPowerShell(node,[verifier,paths.installedRoot],30_000);
  await (hooks.stage ?? runPowerShell)(powershell,[
    "-NoProfile","-NonInteractive","-ExecutionPolicy","Bypass","-File",source,
    "-StageOnly","-Version",op.target.tag,
    "-PinnedCommit",op.target.commit,"-PinnedReleaseSha256",op.target.windows_asset_sha256,
  ]);
  // Fail BEFORE creating a pending receipt or stopping any Task if the
  // immutable target lacks the entire owner-one-shot reconnect protocol.
  // Earlier published Windows releases intentionally do not advertise it.
  const targetRoot=path.win32.join(programs,op.target.tag+"-windows-x64");
  const targetManifest=JSON.parse(
    await readFile(path.win32.join(targetRoot,"bundle.json"),"utf8")
  ) as {version?:unknown;upgrade_protocol?:unknown};
  if(targetManifest.version!==op.target.tag ||
     targetManifest.upgrade_protocol!=="owner-one-shot-v1") {
    throw Error("Reviewed target does not support remote rollback watchdog.");
  }
  const receiptDir=path.win32.join(paths.stateRoot,"receipts");
  const info=await lstat(receiptDir);
  if(!info.isDirectory() || info.isSymbolicLink())throw Error("Unsafe native receipt directory.");
  const key=createHash("sha256").update(op.operation_id,"utf8").digest("hex");
  const pending=path.win32.join(receiptDir,"upgrade-pending-"+key+".json");
  // Atomic owner-only create + fsync before WMI launch; a timeout preserves
  // guarded evidence rather than authorizing a blind retry.
  const evidence=JSON.stringify({operation_id:op.operation_id,
    target_version:op.target.tag,source_version:op.current_version});
  const file=await open(pending,"wx",0o600);
  try { await file.writeFile(evidence,"utf8"); await file.sync(); }
  finally { await file.close(); }
  // Only AFTER immutable release staging succeeded may a separate same-user
  // WMI child switch the user's existing Task.
  const childLine = '"' + powershell + '" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' +
    watchdog + '" -OperationId ' + op.operation_id + " -OriginalVersion " + op.current_version +
    " -TargetVersion " + op.target.tag;
  // PowerShell single-quoted source literal is safe because every embedded
  // filesystem path and user-controlled value was bounded and quote-free.
  const escaped = childLine.replaceAll("'","''");
  const expression = "$ErrorActionPreference='Stop';" +
    "$created=Invoke-CimMethod -ClassName Win32_Process -MethodName Create " +
    "-Arguments @{CommandLine='"+escaped+"'};" +
    "if($created.ReturnValue -ne 0 -or $created.ProcessId -le 0){exit 1};" +
    "$child=Get-CimInstance Win32_Process -Filter ('ProcessId = '+$created.ProcessId) -ErrorAction SilentlyContinue;" +
    "if(-not $child){exit 1};" +
    "$owner=(Invoke-CimMethod -InputObject $child -MethodName GetOwnerSid -ErrorAction Stop).Sid;" +
    "if($owner -cne [Security.Principal.WindowsIdentity]::GetCurrent().User.Value){exit 1}";
  await (hooks.wmi ?? runPowerShell)(powershell,[
    "-NoProfile","-NonInteractive","-Command",expression,
  ]);
  return "launched";
}

/** Authenticated new-version WSS only: create a local proof once. WMI
 * watchdog still validates exact operation/target and native Task state.
 * Worker must independently verify newly reported signed device version.
 */
export async function acknowledgeAuthenticatedUpgrade(
  receiptDir:string, runningVersion:string | undefined,
  isAdmitted:(operationId:string)=>Promise<boolean>,
):Promise<number> {
  if(process.platform!=="win32" || !runningVersion ||
     !/^v[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9.-]+)?$/.test(runningVersion))return 0;
  const {readdir}=await import("node:fs/promises");
  let files:string[];
  try { files=await readdir(receiptDir); } catch { return 0; }
  let acknowledged=0;
  for(const file of files.filter(x=>/^upgrade-pending-[a-f0-9]{64}\.json$/.test(x)).slice(0,64)) {
    try{
      const p=path.win32.join(receiptDir,file);
      const st=await lstat(p);
      if(!st.isFile() || st.isSymbolicLink() || st.size>2048)continue;
      const pending=JSON.parse(await readFile(p,"utf8")) as {operation_id?:unknown;target_version?:unknown};
      if(typeof pending.operation_id!=="string" || !OP.test(pending.operation_id) ||
         file!=="upgrade-pending-"+createHash("sha256").update(pending.operation_id).digest("hex")+".json" ||
         pending.target_version!==runningVersion ||
         !await isAdmitted(pending.operation_id))continue;
      const key=createHash("sha256").update(pending.operation_id).digest("hex");
      const proof=path.win32.join(receiptDir,"upgrade-auth-"+key+".json");
      const body=JSON.stringify({operation_id:pending.operation_id,
        target_version:runningVersion,status:"authenticated_wss"});
      await writeFile(proof,body,{flag:"wx",mode:0o600});
      acknowledged++;
    }catch{ /* Unexpected evidence is never treated as a signed reconnect. */ }
  }
  return acknowledged;
}

/** A signed live Agent may reconcile an already fsynced watchdog outcome.
 * The file is an effect observation, not permission to retry an upgrade.
 */
export async function readNativeUpgradeOutcome(
  receiptDir:string, operationId:string, runningVersion:string | undefined,
):Promise<"completed" | "rolled_back" | null> {
  if(process.platform!=="win32" || !OP.test(operationId) || !runningVersion) return null;
  const key=createHash("sha256").update(operationId).digest("hex");
  const name=path.win32.join(receiptDir,"upgrade-outcome-"+key+".json");
  try {
    const entry=await lstat(name);
    if(!entry.isFile() || entry.isSymbolicLink() || entry.size>2048) return null;
    const row=JSON.parse(await readFile(name,"utf8")) as {
      operation_id?:unknown;original_version?:unknown;target_version?:unknown;status?:unknown;
    };
    if(row.operation_id!==operationId ||
       !/^v[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9.-]+)?$/.test(String(row.original_version)) ||
       !/^v[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9.-]+)?$/.test(String(row.target_version)))return null;
    if(row.status==="completed" && row.target_version===runningVersion) {
      const proof=path.win32.join(receiptDir,"upgrade-auth-"+key+".json");
      const signed=JSON.parse(await readFile(proof,"utf8")) as {
        operation_id?:unknown;target_version?:unknown;status?:unknown;
      };
      if(signed.operation_id===operationId && signed.target_version===runningVersion &&
         signed.status==="authenticated_wss") return "completed";
    }
    if(row.status==="rolled_back" && row.original_version===runningVersion)return "rolled_back";
  }catch{ /* Missing/truncated/stale local outcomes stay guarded. */ }
  return null;
}
