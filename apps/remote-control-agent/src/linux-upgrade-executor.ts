/**
 * Signed owner-DO Linux admission -> existing immutable StageOnly bootstrap
 * -> short-lived same-user systemd watchdog. No Shell, pairing or release URL
 * is supplied by an MCP caller. Not usable by published v0.1.22, which lacks
 * a reviewed owner-one-shot-v1 runtime manifest and StageOnly.
 */
import {spawn} from "node:child_process";
import {lstat} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import {parseRemoteUpgradeDispatch} from "./remote-upgrade-admission.ts";
import {launchDetachedLinuxUpgrade} from "../scripts/linux-upgrade-detached.mjs";

const STAGE_LIMIT_MS=180_000;
type LinuxLauncher=typeof launchDetachedLinuxUpgrade;
type VerifiedStage=(exe:string,args:string[])=>Promise<void>;

async function runVerifiedStage(exe:string,args:string[]):Promise<void>{
  await new Promise<void>((resolve,reject)=>{
    const child=spawn(exe,args,{shell:false,stdio:"ignore",
      env:{...process.env,PYTHONPATH:"",PYTHONSTARTUP:"",PYTHONINSPECT:""}});
    const timer=setTimeout(()=>child.kill("SIGKILL"),STAGE_LIMIT_MS);
    let settled=false;
    const finish=(error?:Error)=>{
      if(settled)return;
      settled=true;clearTimeout(timer);
      if(error)reject(error);else resolve();
    };
    child.once("error",()=>finish(Error("Pinned Linux bootstrap unavailable.")));
    child.once("close",(status,signal)=>
      finish(status===0&&!signal ? undefined : Error("Immutable Linux staging unconfirmed.")));
  });
}

export async function stageAndLaunchApprovedLinuxUpgrade(
  untrusted:unknown,
  {
    installedRoot,home=os.homedir(),endpoint,
    readAdmission,stage=runVerifiedStage,launch=launchDetachedLinuxUpgrade,
  }:{
    installedRoot:string;home?:string;endpoint:string;
    readAdmission:(operationId:string)=>Promise<boolean>;
    stage?:VerifiedStage;launch?:LinuxLauncher;
  },
):Promise<"launched">{
  const request=parseRemoteUpgradeDispatch(untrusted);
  const uid=process.getuid?.();
  if(!request||!("linux_asset_sha256" in request.target)||
     process.platform!=="linux"||typeof uid!=="number"||uid===0||
     !["x64","arm64"].includes(process.arch)||
     request.target.linux_arch!==process.arch||
     typeof home!=="string"||!path.isAbsolute(home)||
     home!==path.resolve(home)||
     typeof installedRoot!=="string"||!path.isAbsolute(installedRoot)||
     typeof readAdmission!=="function"||
     !/^https:\/\/[^\s/@?#:]+\/$/.test(endpoint))
    throw Error("Untrusted signed Linux upgrade launcher context.");

  const programs=path.join(home,".local/share/mcp-workers/remote-control/programs");
  const source=path.join(programs,
    request.current_version+"-linux-"+process.arch+"-glibc");
  const target=path.join(programs,
    request.target.tag+"-linux-"+process.arch+"-glibc");
  if(path.normalize(installedRoot)!==source)
    throw Error("Installed Linux Agent origin differs from approved program.");
  for(const directory of [programs,source]){
    const stat=await lstat(directory);
    if(!stat.isDirectory()||stat.isSymbolicLink()||
       stat.uid!==uid||(stat.mode&0o077)!==0)
      throw Error("Untrusted installed Linux program directory.");
  }
  const script=path.join(source,"apps/remote-control-agent/scripts/bootstrap-v2.py");
  const stat=await lstat(script);
  if(!stat.isFile()||stat.isSymbolicLink()||stat.nlink!==1||
     stat.uid!==uid||(stat.mode&0o077)!==0)
    throw Error("Untrusted immutable Linux bootstrap script.");
  // The historical SQLite admission has already been durably claimed by
  // the WSS handler; re-read it before ANY download or native launch.
  if(!await readAdmission(request.operation_id))
    throw Error("No exact durable owner-approved Agent operation.");
  const args=[script,"--stage-only","--tag",request.target.tag,
    "--commit",request.target.commit,
    "--endpoint",endpoint,
    "--asset-sha256",request.target.linux_asset_sha256];
  await stage("/usr/bin/python3",args);
  // StageOnly may return only after checking the immutable GitHub commit,
  // architecture-specific asset SHA, archive and reviewed target manifest.
  // Launcher's second check verifies native owner-only staged files and
  // writes its own fsynced non-replay record BEFORE systemd-run.
  const launched=await launch({
    home,operationId:request.operation_id,deviceId:request.device_id,
    currentVersion:request.current_version,targetVersion:request.target.tag,
    assertAdmission:async binding=>
      binding.operationId===request.operation_id &&
      binding.deviceId===request.device_id &&
      binding.currentVersion===request.current_version &&
      binding.targetVersion===request.target.tag &&
      await readAdmission(request.operation_id),
    verifyPinnedTarget:async binding=>
      binding.operationId===request.operation_id &&
      binding.deviceId===request.device_id &&
      binding.currentVersion===request.current_version &&
      binding.targetVersion===request.target.tag &&
      binding.targetRoot===target,
  });
  if(launched.status!=="launched"||launched.operationId!==request.operation_id)
    throw Error("Detached Linux upgrade launch not confirmed.");
  return "launched";
}
