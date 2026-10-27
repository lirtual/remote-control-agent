/**
 * Linux owner-one-shot-v1 reconnect proof. The caller MUST already have
 * completed a fresh signed Worker WSS authentication for signedDeviceId.
 * No network, systemd, downgrade or download occurs here.
 *
 * Older published Linux bundles never advertise the upgrade_protocol and
 * the lifecycle gate never calls this function on such releases.
 */
import {createHash} from "node:crypto";
import {constants} from "node:fs";
import {lstat,open,readFile,readdir} from "node:fs/promises";
import path from "node:path";

const ID=/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const OP=/^(?!\.{1,2}$)[A-Za-z0-9._:-]{1,128}$/;
const VERSION=/^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
const HASH=/^[a-f0-9]{64}$/;
const nameFor=id=>createHash("sha256").update(id,"utf8").digest("hex");
function privateMeta(stat,dir=false){
  return stat.uid===process.getuid?.()&&!stat.isSymbolicLink()&&
    (dir?stat.isDirectory():stat.isFile())&&(stat.mode&0o077)===0&&
    (dir||stat.nlink===1);
}
function exactKeys(row,keys){
  return row&&typeof row==="object"&&!Array.isArray(row)&&
    Object.keys(row).sort().join("|")===keys.slice().sort().join("|");
}
async function safeRead(file){
  const meta=await lstat(file);
  if(!privateMeta(meta)||meta.size<1||meta.size>2048)
    throw Error("Unsafe Linux owner upgrade metadata");
  const fd=await open(file,constants.O_RDONLY|constants.O_NOFOLLOW);
  try{
    const now=await fd.stat();
    if(!privateMeta(now)||now.ino!==meta.ino||now.size!==meta.size)
      throw Error("Changed Linux owner upgrade evidence");
    return await fd.readFile();
  }finally{await fd.close();}
}
/**
 * isAdmitted(operationId) must consult the existing SQLite receipt, and
 * accept only the SAME owner's locally admitted/running/unknown upgrade.
 *
 * The effective bundle manifest path is trusted by the installed runtime,
 * not taken from an MCP command. A forged manifest path is not an API input.
 */
export async function acknowledgeAuthenticatedLinuxUpgrade({
  stateDirectory,runningVersion,signedDeviceId,manifestPath,isAdmitted,
}:{
  stateDirectory:string;runningVersion:string|undefined;
  signedDeviceId:string;manifestPath:string;
  isAdmitted:(operationId:string)=>Promise<boolean>;
}):Promise<number>{
  if(process.platform!=="linux"||process.getuid?.()===0||
     !["x64","arm64"].includes(process.arch)||
     !VERSION.test(runningVersion??"")||!ID.test(signedDeviceId)||
     typeof stateDirectory!=="string"||!path.isAbsolute(stateDirectory)||
     typeof manifestPath!=="string"||!path.isAbsolute(manifestPath)||
     typeof isAdmitted!=="function")return 0;
  try{
    if(!privateMeta(await lstat(stateDirectory),true))return 0;
    const manifestBytes=await safeRead(manifestPath);
    const manifest=JSON.parse(manifestBytes.toString("utf8")) as {
      name?:unknown;version?:unknown;target?:unknown;upgrade_protocol?:unknown;
      upgrade_profile?:unknown;device_protocol?:unknown;receipt_schema?:unknown;
    };
    if(manifest.name!=="remote-control-agent"||manifest.version!==runningVersion||
       manifest.target!=="linux-"+process.arch+"-glibc"||
       manifest.upgrade_protocol!=="owner-one-shot-v1"||
       manifest.upgrade_profile!=="paired-full-v1"||
       manifest.device_protocol!==2||manifest.receipt_schema!==1)return 0;
    const manifestSha=createHash("sha256").update(manifestBytes).digest("hex");
    let acknowledged=0;
    const candidates=(await readdir(stateDirectory))
      .filter(x=>/^upgrade-run-[a-f0-9]{64}\.json$/.test(x)).slice(0,64);
    for(const filename of candidates){
      try{
        const row=JSON.parse((await safeRead(path.join(stateDirectory,filename))).toString("utf8"));
        if(!exactKeys(row,["operation_id","device_id","current_version",
            "target_version","current_manifest_sha256","target_manifest_sha256"])||
           typeof row.operation_id!=="string"||!OP.test(row.operation_id)||
           filename!=="upgrade-run-"+nameFor(row.operation_id)+".json"||
           row.device_id!==signedDeviceId||
           !VERSION.test(row.current_version)||
           row.current_version===runningVersion||
           row.target_version!==runningVersion||
           !HASH.test(row.current_manifest_sha256)||
           row.target_manifest_sha256!==manifestSha||
           !await isAdmitted(row.operation_id))continue;
        const proof=path.join(stateDirectory,"upgrade-auth-"+nameFor(row.operation_id)+".json");
        const output=await open(proof,constants.O_WRONLY|constants.O_CREAT|
          constants.O_EXCL|constants.O_NOFOLLOW,0o600);
        try{
          await output.writeFile(JSON.stringify({
            operation_id:row.operation_id,device_id:signedDeviceId,
            target_version:runningVersion,status:"authenticated_wss",
          }),"utf8");
          await output.sync();
        }finally{await output.close();}
        acknowledged++;
      }catch{
        // No replacement or recovery from malformed/foreign/stale evidence.
      }
    }
    if(acknowledged>0){
      const parent=await open(stateDirectory,constants.O_RDONLY|constants.O_DIRECTORY);
      try{await parent.sync();}finally{await parent.close();}
    }
    return acknowledged;
  }catch{return 0;}
}
