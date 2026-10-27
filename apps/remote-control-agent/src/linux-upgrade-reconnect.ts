/**
 * Native Linux #39: the NEW running Agent may record a one-shot success proof
 * only after its signed WSS handshake to the existing paired Worker succeeded.
 * An on-disk "upgrade-run" alone never authorizes a service switch.
 *
 * No Linux bundle advertises owner-one-shot-v1 yet. This routine is inert
 * until a separately reviewed immutable Release supports the full protocol.
 */
import {createHash} from "node:crypto";
import {constants} from "node:fs";
import {lstat,open,readdir,readFile} from "node:fs/promises";
import path from "node:path";
import {fileURLToPath} from "node:url";

const ID=/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const OP=/^(?!\.{1,2}$)[A-Za-z0-9._:-]{1,128}$/;
const VERSION=/^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
const HASH=/^[a-f0-9]{64}$/;
const DEFAULT_MANIFEST=fileURLToPath(new URL("../../../bundle.json",import.meta.url));
function ownerOnly(st:import("node:fs").Stats,dir=false):boolean {
  return st.uid===process.getuid?.() && !st.isSymbolicLink() &&
    (dir?st.isDirectory():st.isFile()) &&
    (st.mode&0o077)===0&&(dir||st.nlink===1);
}
async function readPrivate(file:string):Promise<Buffer>{
  const first=await lstat(file);
  if(!ownerOnly(first)||first.size<2||first.size>4096)
    throw Error("Untrusted Linux one-shot evidence.");
  const fd=await open(file,constants.O_RDONLY|constants.O_NOFOLLOW);
  try{
    const actual=await fd.stat();
    if(!ownerOnly(actual)||actual.ino!==first.ino||actual.size!==first.size)
      throw Error("Linux one-shot evidence changed during verification.");
    return await fd.readFile();
  }finally{await fd.close();}
}
async function saveOneTimeProof(file:string,entry:object,directory:string):Promise<void>{
  const handle=await open(file,constants.O_WRONLY|constants.O_CREAT|
    constants.O_EXCL|constants.O_NOFOLLOW,0o600);
  try{await handle.writeFile(JSON.stringify(entry),"utf8");await handle.sync();}
  finally{await handle.close();}
  const parent=await open(directory,constants.O_RDONLY|constants.O_DIRECTORY);
  try{await parent.sync();}finally{await parent.close();}
}
/** The test-only manifestPath hook never comes from a socket or MCP argument. */
export async function acknowledgeAuthenticatedLinuxUpgrade({
  stateDirectory,deviceId,runningVersion,isAdmitted,
  manifestPath=DEFAULT_MANIFEST,
}:{
  stateDirectory:string;
  deviceId:string;
  runningVersion:string;
  isAdmitted:(operationId:string)=>Promise<boolean>;
  manifestPath?:string;
}):Promise<number>{
  if(process.platform!=="linux"||process.getuid?.()===0||
     !["x64","arm64"].includes(process.arch)||
     typeof stateDirectory!=="string"||!path.isAbsolute(stateDirectory)||
     !ID.test(deviceId)||!VERSION.test(runningVersion)||
     typeof isAdmitted!=="function")return 0;
  try{
    const dir=await lstat(stateDirectory);
    if(!ownerOnly(dir,true))return 0;
    const manifestBytes=await readPrivate(manifestPath);
    const manifest=JSON.parse(manifestBytes.toString("utf8")) as Record<string,unknown>;
    if(manifest.name!=="remote-control-agent"||
       manifest.version!==runningVersion||
       manifest.target!=="linux-"+process.arch+"-glibc"||
       manifest.upgrade_profile!=="paired-full-v1"||
       manifest.upgrade_protocol!=="owner-one-shot-v1"||
       manifest.device_protocol!==2||manifest.receipt_schema!==1)return 0;
    const manifestDigest=createHash("sha256").update(manifestBytes).digest("hex");
    const candidates=(await readdir(stateDirectory))
      .filter(x=>/^upgrade-run-[a-f0-9]{64}\.json$/.test(x)).slice(0,64);
    let accepted=0;
    for(const name of candidates){
      try{
        const record=JSON.parse((await readPrivate(path.join(stateDirectory,name)))
          .toString("utf8")) as Record<string,unknown>;
        // An extra or missing marker field, including a same-version claim,
        // is never proof of an approved version transition. Keep exactly the
        // durable schema written by the reviewed old-version launcher.
        const expectedKeys=["operation_id","device_id","current_version",
          "target_version","current_manifest_sha256","target_manifest_sha256"];
        if(Object.keys(record).sort().join("|")!==expectedKeys.sort().join("|")||
           typeof record.operation_id!=="string"||!OP.test(record.operation_id)||
           name!=="upgrade-run-"+createHash("sha256")
             .update(record.operation_id).digest("hex")+".json"||
           record.device_id!==deviceId||
           record.target_version!==runningVersion||
           !HASH.test(String(record.target_manifest_sha256))||
           record.target_manifest_sha256!==manifestDigest||
           typeof record.current_version!=="string"||
           !VERSION.test(record.current_version)||
           record.current_version===runningVersion||
           !HASH.test(String(record.current_manifest_sha256))||
           !await isAdmitted(record.operation_id))continue;
        const key=createHash("sha256").update(record.operation_id).digest("hex");
        await saveOneTimeProof(path.join(stateDirectory,"upgrade-auth-"+key+".json"),{
          operation_id:record.operation_id,
          device_id:deviceId,target_version:runningVersion,
          status:"authenticated_wss",
        },stateDirectory);
        accepted++;
      }catch{ /* A malformed or preexisting proof never validates a switch. */ }
    }
    return accepted;
  }catch{ return 0; }
}


/**
 * A new, authenticated Linux runtime may reconcile its existing SQLite
 * upgrade receipt only after BOTH the independent watchdog's terminal success
 * AND the local signed-WSS proof exist for the SAME durable execution claim.
 * File names are operation digests, never remotely supplied paths.
 *
 * A watchdog's needs_attention, an absent/partial outcome, or a changed OS
 * version leaves the original receipt guarded as unknown; no auto retry.
 */
export async function readLinuxUpgradeOutcome(
  stateDirectory:string,operationId:string,runningVersion:string,
  signedDeviceId:string,
):Promise<"completed"|null>{
  if(process.platform!=="linux"||process.getuid?.()===0||
     !["x64","arm64"].includes(process.arch)||
     typeof stateDirectory!=="string"||!path.isAbsolute(stateDirectory)||
     typeof operationId!=="string"||!OP.test(operationId)||
     !ID.test(signedDeviceId)||!VERSION.test(runningVersion))return null;
  const exact=(entry:unknown,keys:string[]):entry is Record<string,unknown> =>
    !!entry && typeof entry==="object" && !Array.isArray(entry) &&
    Object.keys(entry).sort().join("|")===keys.slice().sort().join("|");
  try{
    if(!ownerOnly(await lstat(stateDirectory),true))return null;
    const digest=createHash("sha256").update(operationId,"utf8").digest("hex");
    const load=async(type:string):Promise<unknown> =>
      JSON.parse((await readPrivate(path.join(stateDirectory,
        "upgrade-"+type+"-"+digest+".json"))).toString("utf8"));
    const outcome=await load("outcome");
    const run=await load("run");
    const claim=await load("exec");
    const proof=await load("auth");
    if(!exact(outcome,["operation_id","device_id","original_version",
          "target_version","status"])||
       !exact(run,["operation_id","device_id","current_version","target_version",
          "current_manifest_sha256","target_manifest_sha256"])||
       !exact(claim,["operation_id","device_id","target_version"])||
       !exact(proof,["operation_id","device_id","target_version","status"]))
      return null;
    if(outcome.operation_id!==operationId||
       outcome.device_id!==signedDeviceId||
       outcome.status!=="completed"||
       outcome.target_version!==runningVersion||
       outcome.original_version!==run.current_version||
       run.operation_id!==operationId||run.device_id!==signedDeviceId||
       run.target_version!==runningVersion||
       typeof run.current_version!=="string"||
       !VERSION.test(run.current_version)||
       run.current_version===runningVersion||
       typeof run.current_manifest_sha256!=="string"||
       !HASH.test(run.current_manifest_sha256)||
       typeof run.target_manifest_sha256!=="string"||
       !HASH.test(run.target_manifest_sha256)||
       claim.operation_id!==operationId||claim.device_id!==signedDeviceId||
       claim.target_version!==runningVersion||
       proof.operation_id!==operationId||proof.device_id!==signedDeviceId||
       proof.target_version!==runningVersion||
       proof.status!=="authenticated_wss")return null;
    return "completed";
  }catch{return null;}
}
