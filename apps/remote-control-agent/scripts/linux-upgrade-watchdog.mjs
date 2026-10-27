/**
 * #39: single-use same-owner Linux systemd watchdog.
 * This source is deliberately NOT part of existing published Linux bundles:
 * only a future reviewed immutable owner-one-shot-v1 release can activate it.
 * It never downloads assets, takes a shell command, or authorizes an upgrade.
 */
import {createHash} from "node:crypto";
import {constants} from "node:fs";
import {open,lstat,readFile} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import {fileURLToPath} from "node:url";
import {setTimeout as sleep} from "node:timers/promises";
import {HISTORICAL_UNIT,upgradeExistingSignedService}
  from "./upgrade-existing-service.mjs";

const OP=/^(?!\.{1,2}$)[A-Za-z0-9._:-]{1,128}$/;
const ID=/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const VERSION=/^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
const APP="apps/remote-control-agent";
const MAX_PROOF_MS=90_000;
const statePath=home=>path.join(home,".local/state/mcp-workers/remote-control-agent");
const rootPath=(home,version)=>path.join(home,
  ".local/share/mcp-workers/remote-control/programs",
  version+"-linux-"+process.arch+"-glibc");
export const hashOperation=operationId=>
  createHash("sha256").update(operationId,"utf8").digest("hex");

function owned(st,dir=false){
  return st.uid===process.getuid() && !st.isSymbolicLink() &&
    (dir?st.isDirectory():st.isFile()) && (st.mode&0o077)===0 &&
    (dir||st.nlink===1);
}
async function privateMeta(file,dir=false){
  const st=await lstat(file);
  if(!owned(st,dir)) throw Error("Unsafe owner-only upgrade evidence.");
  return st;
}
async function readPrivateJson(file){
  const st=await privateMeta(file);
  if(st.size===0||st.size>2048)throw Error("Unsafe upgrade evidence size.");
  const f=await open(file,constants.O_RDONLY|constants.O_NOFOLLOW);
  try{
    const current=await f.stat();
    if(!owned(current)||current.ino!==st.ino||current.size!==st.size)
      throw Error("Upgrade evidence changed during read.");
    return JSON.parse(await f.readFile({encoding:"utf8"}));
  }finally{await f.close();}
}
async function exists(file){
  try{await lstat(file);return true;}catch(e){
    if(e.code==="ENOENT")return false;
    throw e;
  }
}
function exactKeys(obj,keys){
  return obj&&typeof obj==="object"&&!Array.isArray(obj)&&
    Object.keys(obj).sort().join("|")===keys.slice().sort().join("|");
}
export async function readLinuxUpgradeAttempt({home=os.homedir(),operationId}={}){
  if(process.platform!=="linux"||process.getuid?.()===0||
     !["x64","arm64"].includes(process.arch)||
     typeof operationId!=="string"||!OP.test(operationId)||
     typeof home!=="string"||home!==path.resolve(home)||home!==path.normalize(home))
    throw Error("Untrusted Linux watchdog invocation.");
  const state=statePath(home);
  await privateMeta(state,true);
  const hash=hashOperation(operationId);
  const record=await readPrivateJson(path.join(state,"upgrade-run-"+hash+".json"));
  if(!exactKeys(record,["operation_id","device_id","current_version","target_version",
       "current_manifest_sha256","target_manifest_sha256"])||
     record.operation_id!==operationId||!ID.test(record.device_id)||
     !VERSION.test(record.current_version)||!VERSION.test(record.target_version)||
     !/^[a-f0-9]{64}$/.test(record.current_manifest_sha256)||
     !/^[a-f0-9]{64}$/.test(record.target_manifest_sha256))
    throw Error("Invalid durable one-shot operation evidence.");
  const source=rootPath(home,record.current_version);
  const currentRunner=path.join(source,APP,"scripts/linux-upgrade-watchdog.mjs");
  const actualRunner=path.resolve(fileURLToPath(import.meta.url));
  if(actualRunner!==currentRunner)throw Error("Watchdog did not start from approved existing program.");
  await privateMeta(source,true);
  const target=rootPath(home,record.target_version);
  await privateMeta(target,true);
  await privateMeta(currentRunner);
  for(const [root,digest,version] of [
    [source,record.current_manifest_sha256,record.current_version],
    [target,record.target_manifest_sha256,record.target_version],
  ]){
    const name=path.join(root,"bundle.json");
    const m=await readPrivateJson(name);
    if(m.name!=="remote-control-agent"||m.version!==version||
       m.target!=="linux-"+process.arch+"-glibc"||
       m.upgrade_profile!=="paired-full-v1"||
       m.upgrade_protocol!=="owner-one-shot-v1"||
       m.device_protocol!==2||m.receipt_schema!==1||
       createHash("sha256").update(await readFile(name)).digest("hex")!==digest)
      throw Error("Linux one-shot manifest changed after approved launch.");
  }
  const identity=path.join(home,".local/share/mcp-workers/remote-control/v2-identity.pem");
  await privateMeta(identity);
  await privateMeta(identity+".device-id");
  if((await readFile(identity+".device-id","utf8")).trim()!==record.device_id)
    throw Error("Device identity differs from durable admission.");
  const unitFile=path.join(home,".config/systemd/user",HISTORICAL_UNIT);
  await privateMeta(unitFile);
  const unit=await readFile(unitFile,"utf8");
  const lines=unit.split("\n").filter(x=>
    /^Environment=REMOTE_CONTROL_(?:AGENT|V2)_ENDPOINT=/.test(x));
  if(lines.length!==1)throw Error("Ambiguous existing signed Agent service endpoint.");
  const endpoint=lines[0].slice(lines[0].indexOf("_ENDPOINT=")+"_ENDPOINT=".length);
  const url=new URL(endpoint);
  if(url.protocol!=="https:"||url.username||url.password||url.port||
     url.search||url.hash||url.pathname!=="/"||endpoint!==url.origin+"/")
    throw Error("Untrusted existing Agent endpoint.");
  return Object.freeze({...record,home,state,endpoint,hash});
}
/** A proof is only created after a fresh signed Worker WSS handshake by the
 * NEW Agent runtime. The old same-owner watchdog must reject preexisting
 * proofs before any systemd switch: an earlier attempt is never reusable.
 */
export async function matchingLinuxProof(file,expected){
  try{
    const row=await readPrivateJson(file);
    return exactKeys(row,["operation_id","device_id","target_version","status"])&&
      row.operation_id===expected.operationId&&
      row.device_id===expected.deviceId&&
      row.target_version===expected.version&&
      row.status==="authenticated_wss";
  }catch{return false;}
}
export async function waitForLinuxSignedProof(file,expected,{
  now=Date.now,wait=ms=>sleep(ms),
  maxMs=MAX_PROOF_MS,
}={}){
  if(!Number.isSafeInteger(maxMs)||maxMs<1||maxMs>MAX_PROOF_MS)
    throw Error("Unbounded Linux WSS verification.");
  const expires=now()+maxMs;
  while(now()<expires){
    if(await matchingLinuxProof(file,expected))return true;
    await wait(Math.min(1000,Math.max(1,expires-now())));
  }
  return false;
}
/**
 * The launcher already wrote one durable, single-use attempt. In contrast to
 * systemctl "active", success requires exact post-switch signed WSS evidence.
 * A failed/missing proof invokes the existing original-unit rollback path.
 * Unknown rollback is explicitly NOT upgraded; the backup is not erased.
 */
export async function runLinuxOneShotWatchdog({
  home=os.homedir(),operationId,
  upgrade=upgradeExistingSignedService,
  waitForProof=waitForLinuxSignedProof,
  readAttempt=readLinuxUpgradeAttempt,
}={}){
  const op=await readAttempt({home,operationId});
  const proof=path.join(op.state,"upgrade-auth-"+op.hash+".json");
  const outcome=path.join(op.state,"upgrade-outcome-"+op.hash+".json");
  if(await exists(proof)||await exists(outcome))
    throw Error("Existing proof or outcome forbids new Linux Task switch.");
  // systemd-run's unit collision is not a durable replay barrier: systemd may
  // collect the transient unit after an interrupted watchdog. A separate
  // fsynced exclusive claim keeps a restarted runner from switching twice.
  // An interrupted claim is UNKNOWN and must be reconciled, never retried.
  const claim=path.join(op.state,"upgrade-exec-"+op.hash+".json");
  const claimFile=await open(claim,constants.O_WRONLY|constants.O_CREAT|
    constants.O_EXCL|constants.O_NOFOLLOW,0o600);
  try{
    await claimFile.writeFile(JSON.stringify({operation_id:operationId,
      device_id:op.device_id,target_version:op.target_version}),"utf8");
    await claimFile.sync();
  }finally{await claimFile.close();}
  const claimDir=await open(op.state,constants.O_RDONLY|constants.O_DIRECTORY);
  try{await claimDir.sync();}finally{await claimDir.close();}
  let status="needs_attention";
  let signedProofAccepted=false;
  try{
    const result=await upgrade({
      home,newRoot:rootPath(home,op.target_version),endpoint:op.endpoint,
      upgradeOperationId:operationId,
      verifySignedReconnect:async binding=>{
        if(binding.operationId!==operationId||binding.deviceId!==op.device_id||
           binding.version!==op.target_version||binding.service!==HISTORICAL_UNIT)
          return false;
        signedProofAccepted=(await waitForProof(proof,binding))===true;
        return signedProofAccepted;
      },
    });
    // Neither a successful systemctl call nor a mock that returns without
    // invoking the signed callback is allowed to produce completion evidence.
    if(!signedProofAccepted||result?.status!=="active"||
       result.deviceId!==op.device_id||result.version!==op.target_version||
       result.service!==HISTORICAL_UNIT||result.identityPreserved!==true)
      throw Error("Signed Linux upgrade result remains unverified.");
    status="completed";
  }catch{
    // Existing upgrader tries rollback and protects the original-unit backup
    // when rollback is uncertain. Do NOT infer verified rollback from an error.
  }
  const payload={operation_id:operationId,device_id:op.device_id,
    original_version:op.current_version,target_version:op.target_version,status};
  const f=await open(outcome,constants.O_WRONLY|constants.O_CREAT|
    constants.O_EXCL|constants.O_NOFOLLOW,0o600);
  try{await f.writeFile(JSON.stringify(payload),"utf8");await f.sync();}
  finally{await f.close();}
  const d=await open(op.state,constants.O_RDONLY|constants.O_DIRECTORY);
  try{await d.sync();}finally{await d.close();}
  return Object.freeze({status});
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  if(process.argv.length!==4||process.argv[2]!=="--operation-id"){
    process.stderr.write("Linux one-shot invocation rejected.\n");
    process.exitCode=1;
  }else{
    runLinuxOneShotWatchdog({operationId:process.argv[3]})
      .then(result=>{if(result.status!=="completed")process.exitCode=1;})
      .catch(()=>{process.stderr.write("Linux one-shot upgrade requires attended reconciliation.\n");process.exitCode=1;});
  }
}
