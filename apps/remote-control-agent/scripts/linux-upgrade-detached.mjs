/**
 * #39 Linux one-shot *launcher prerequisite*, not a callable remote upgrade.
 * Start a short-lived user systemd service in its own cgroup: the original
 * Agent's systemd service may be restarted without killing the watchdog.
 *
 * No WSS dispatch imports this file. The fixed independent watchdog is not
 * present in released packages; absent file/admission/pin proof fails closed.
 * A systemd-run success is only "launched", NEVER "upgraded".
 */
import {spawnSync} from "node:child_process";
import {createHash} from "node:crypto";
import {constants} from "node:fs";
import {lstat,open,readFile} from "node:fs/promises";
import os from "node:os";
import path from "node:path";

const OP=/^(?!\.{1,2}$)[A-Za-z0-9._:-]{1,128}$/;
const ID=/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const VERSION=/^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/;
const APP="apps/remote-control-agent";
export const ONE_SHOT_MAX_SECONDS=420;

function successor(target,current){
  const a=VERSION.exec(target),b=VERSION.exec(current);
  if(!a||!b) return false;
  for(let i=1;i<4;i++){
    const next=BigInt(a[i]),prior=BigInt(b[i]);
    if(next!==prior)return next>prior;
  }
  return false;
}
function owned(meta,dir=false,executable=false){
  return meta.uid===process.getuid()&&!meta.isSymbolicLink()&&
    (dir?meta.isDirectory():meta.isFile())&&
    (meta.mode&0o077)===0&&
    (dir||meta.nlink===1)&&(!executable||(meta.mode&0o100)!==0);
}
async function requireOwned(file,dir=false,executable=false){
  if(!owned(await lstat(file),dir,executable))
    throw Error("Untrusted owner-only Linux upgrade path.");
}
function programRoot(home,version,arch){
  return path.join(home,".local/share/mcp-workers/remote-control/programs",
    version+"-linux-"+arch+"-glibc");
}
export function oneShotLinuxUnit(operationId){
  if(typeof operationId!=="string"||!OP.test(operationId))
    throw Error("Invalid one-shot operation ID.");
  const digest=createHash("sha256").update(operationId,"utf8").digest("hex");
  return Object.freeze({unit:"rca-upgrade-"+digest.slice(0,32),
    marker:"upgrade-run-"+digest+".json"});
}
function invokeSystemd(binary,args){
  return spawnSync(binary,args,{shell:false,encoding:"utf8",timeout:15000,
    maxBuffer:8192,stdio:["ignore","pipe","pipe"]});
}

/**
 * In-process only. Both callbacks are MANDATORY, trusted and independent:
 * assertAdmission reads the already-signed durable local Agent receipt;
 * verifyPinnedTarget validates a fixed, immutable, architecture-specific
 * release before this stage (not a caller-supplied URL or SHA).
 *
 * This launcher can neither stage an asset nor declare WSS success.
 * Later implementation must supply the bundled fixed watchdog script and
 * a signed reconnect acceptance path before connecting an MCP dispatch.
 */
export async function launchDetachedLinuxUpgrade({
  home=os.homedir(),operationId,deviceId,currentVersion,targetVersion,
  assertAdmission,verifyPinnedTarget,invoke=invokeSystemd,
}={}){
  if(process.platform!=="linux"||typeof process.getuid!=="function"||
     process.getuid()===0||!["x64","arm64"].includes(process.arch))
    throw Error("Non-root native Linux x64/ARM64 owner required.");
  if(typeof home!=="string"||home!==path.resolve(home)||
     home!==path.normalize(home)||!home.startsWith("/")||
     !/^\/[A-Za-z0-9_./-]+$/.test(home)||home.includes("/../")||
     !ID.test(deviceId)||!successor(targetVersion,currentVersion)||
     typeof assertAdmission!=="function"||typeof verifyPinnedTarget!=="function")
    throw Error("Untrusted local one-shot Linux upgrade admission.");
  const {unit,marker}=oneShotLinuxUnit(operationId);
  const arch=process.arch;
  const current=programRoot(home,currentVersion,arch);
  const target=programRoot(home,targetVersion,arch);
  const state=path.join(home,".local/state/mcp-workers/remote-control-agent");
  const identity=path.join(home,".local/share/mcp-workers/remote-control/v2-identity.pem");
  const runner=path.join(current,APP,"scripts/linux-upgrade-watchdog.mjs");
  const node=path.join(current,"bin/node");
  await requireOwned(current,true);
  await requireOwned(target,true);
  await requireOwned(state,true);
  await requireOwned(identity);
  await requireOwned(identity+".device-id");
  await requireOwned(runner);
  await requireOwned(node,false,true);
  const originalId=(await readFile(identity+".device-id","utf8")).trim();
  if(originalId!==deviceId)throw Error("Linux upgrade pairing changed.");
  for(const [dir,version] of [[current,currentVersion],[target,targetVersion]]){
    const bundle=path.join(dir,"bundle.json");
    await requireOwned(bundle);
    const manifest=JSON.parse(await readFile(bundle,"utf8"));
    if(manifest.name!=="remote-control-agent"||manifest.version!==version||
       manifest.target!=="linux-"+arch+"-glibc"||
       manifest.upgrade_profile!=="paired-full-v1"||
       manifest.device_protocol!==2||manifest.receipt_schema!==1||
       manifest.upgrade_protocol!=="owner-one-shot-v1")
      throw Error("Unreviewed Linux one-shot bundle.");
  }
  if(await assertAdmission(Object.freeze({operationId,deviceId,currentVersion,
     targetVersion}))!==true)throw Error("No durable owner-approved Linux admission.");
  if(await verifyPinnedTarget(Object.freeze({operationId,deviceId,currentVersion,
     targetVersion,targetRoot:target}))!==true)
    throw Error("Unverified immutable Linux upgrade target.");
  const attempt=path.join(state,marker);
  // Durable no-replay record BEFORE asking the user manager to start. A failed
  // systemd-run remains uncertain and cannot automatically replay.
  const file=await open(attempt,constants.O_WRONLY|constants.O_CREAT|
    constants.O_EXCL|constants.O_NOFOLLOW,0o600);
  try{
    await file.writeFile(JSON.stringify({operation_id:operationId,device_id:deviceId,
      current_version:currentVersion,target_version:targetVersion}),"utf8");
    await file.sync();
  }finally{await file.close();}
  const parent=await open(state,constants.O_RDONLY|constants.O_DIRECTORY);
  try{await parent.sync();}finally{await parent.close();}
  const args=["--user","--no-block","--collect","--quiet",
    "--service-type=exec","--unit="+unit,
    "--property=RuntimeMaxSec="+ONE_SHOT_MAX_SECONDS,
    "--property=UMask=0077",
    "--setenv=NODE_OPTIONS=","--setenv=NODE_PATH=",
    "--",node,runner,"--operation-id",operationId];
  const outcome=await invoke("/usr/bin/systemd-run",args);
  if(!outcome||outcome.error||outcome.signal||outcome.status!==0)
    throw Error("One-shot user systemd start uncertain; preserved replay guard.");
  return Object.freeze({status:"launched",operationId,unit});
}
