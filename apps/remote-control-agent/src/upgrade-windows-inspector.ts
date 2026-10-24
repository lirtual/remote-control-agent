/**
 * Native Windows task-structure inspection for future upgrade recovery.
 *
 * This proves only that the current user owns a running task configured to
 * launch the expected installed program. It does NOT attest running process
 * identity, private-key ACL, Release archive bytes, or authenticated WSS.
 */
import {spawnSync} from "node:child_process";
import {readFile} from "node:fs/promises";
import path from "node:path";
import type {UpgradeRequest} from "./upgrade-authorization.ts";

export interface WindowsTaskSnapshot {
  taskName:string; state:number; sid:string;
  execute:string; arguments:string; workingDirectory:string;
  principal:string; actionCount:number;
}
export interface WindowsTaskStructureEvidence {
  readonly taskRunning:boolean;
  readonly taskActionMatches:boolean;
  readonly bundleManifestMatches:boolean;
}
const SID=/^S-1-5-21-(?:[0-9]+-){3}[0-9]+$/;
function safeEndpoint(value:string):boolean {
  try{
    const url=new URL(value);
    return url.protocol==="https:"&&!url.username&&!url.password&&
      !url.port&&!url.search&&!url.hash&&url.pathname==="/"&&
      value===url.origin+"/"&&/^[a-z0-9.-]+$/i.test(url.hostname);
  }catch{return false;}
}
export function inspectWindowsTaskStructure(
  task:WindowsTaskSnapshot,root:string,sid:string,endpoint:string,
):Readonly<WindowsTaskStructureEvidence>{
  const absent={taskRunning:false,taskActionMatches:false,bundleManifestMatches:false};
  if(!SID.test(sid)||!safeEndpoint(endpoint)||
    !path.win32.isAbsolute(root)||
    root!==path.win32.normalize(root)||
    task.sid!==sid||task.principal!==sid||
    task.taskName!=="RCA-Remote-Control-v2-"+sid.replace(/-/g,"_")||
    task.actionCount!==1)return absent;
  const entry=path.win32.join(root,"apps","remote-control-agent","src","windows-v2.js");
  const taskEntryDir=path.win32.dirname(entry);
  const expected={
    exe:path.win32.join(root,"bin","rca-background.exe"),
    args:'"'+entry+'" run --endpoint "'+endpoint+'"',
    working:taskEntryDir,
  };
  if(task.execute!==expected.exe||task.arguments!==expected.args||
    task.workingDirectory!==expected.working)return absent;
  return {taskRunning:task.state===4,taskActionMatches:true,bundleManifestMatches:false};
}
/** All commands are fixed; neither target version nor endpoint reaches PowerShell. */
export function readWindowsUserTaskSnapshot():WindowsTaskSnapshot {
  if(process.platform!=="win32")throw Error("Native Windows required");
  const systemRoot=process.env.SystemRoot;
  if(!systemRoot||!path.win32.isAbsolute(systemRoot))throw Error("Missing Windows system root");
  const powershell=path.win32.join(systemRoot,"System32","WindowsPowerShell","v1.0","powershell.exe");
  const script=[
    "$ErrorActionPreference='Stop'",
    "$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value",
    "$name='RCA-Remote-Control-v2-'+$sid.Replace('-','_')",
    "$task=Get-ScheduledTask -TaskName $name -ErrorAction Stop",
    "$actions=@($task.Actions)",
    "if($actions.Count -ne 1){throw 'Unexpected task actions'}",
    "$p=[pscustomobject]@{taskName=$task.TaskName;state=[int]$task.State;sid=$sid;",
    "execute=[string]$actions[0].Execute;arguments=[string]$actions[0].Arguments;",
    "workingDirectory=[string]$actions[0].WorkingDirectory;",
    "principal=[string]$task.Principal.UserId;actionCount=$actions.Count}",
    "$p|ConvertTo-Json -Compress -Depth 3",
  ].join(";")+";";
  const r=spawnSync(powershell,["-NoProfile","-NonInteractive","-EncodedCommand",
    Buffer.from(script,"utf16le").toString("base64")],
    {encoding:"utf8",timeout:8000,maxBuffer:8192,windowsHide:true});
  if(r.error||r.signal||r.status!==0)throw Error("Windows user task inspection unavailable");
  const parsed=JSON.parse(r.stdout.replace(/^\uFEFF/,"").trim()) as Record<string,unknown>;
  const fields=["taskName","state","sid","execute","arguments","workingDirectory","principal","actionCount"];
  if(Object.keys(parsed).length!==fields.length||fields.some(key=>!Object.hasOwn(parsed,key))||
    fields.some(key=>typeof parsed[key]!==(["state","actionCount"].includes(key)?"number":"string")))
    throw Error("Invalid Windows user task snapshot");
  return parsed as unknown as WindowsTaskSnapshot;
}
export async function inspectWindowsLocalUpgradeTask(
  request:Readonly<UpgradeRequest>,
):Promise<Readonly<WindowsTaskStructureEvidence>>{
  const missing={taskRunning:false,taskActionMatches:false,bundleManifestMatches:false};
  if(process.platform!=="win32"||process.arch!=="x64"||
    request.target_platform!=="windows-x64")return missing;
  const store=process.env.LOCALAPPDATA;
  if(!store||!path.win32.isAbsolute(store))return missing;
  const root=path.win32.join(store,"mcp-workers","remote-control","programs",
    request.target_version+"-windows-x64");
  try {
    const task=readWindowsUserTaskSnapshot();
    const m=/^"([^"]+)" run --endpoint "(https:\/\/[^"]+)"$/.exec(task.arguments);
    if(!m)return missing;
    const current=inspectWindowsTaskStructure(task,root,task.sid,m[2]!);
    if(!current.taskActionMatches)return missing;
    const manifest=JSON.parse(await readFile(path.win32.join(root,"bundle.json"),"utf8")) as Record<string,unknown>;
    return {...current,bundleManifestMatches:
      manifest.name==="remote-control-agent"&&manifest.version===request.target_version&&
      manifest.target==="windows-x64"&&manifest.device_protocol===2&&
      manifest.receipt_schema===1&&manifest.upgrade_profile==="paired-full-v1"};
  }catch{return missing;}
}
