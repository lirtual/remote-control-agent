/**
 * Direct upgrade of an already-owned signed WSS Agent using its EXISTING
 * systemd service name. No three-service conversion, Tunnel dependency,
 * new identity, enrollment, or migration confirmation.
 */
import {spawnSync} from "node:child_process";
import {constants} from "node:fs";
import {lstat,readFile,open,rename,rm} from "node:fs/promises";
import {createHash} from "node:crypto";
import path from "node:path";
import os from "node:os";
import {fileURLToPath} from "node:url";
import {requestUpgradeConsent} from "./install-v2.mjs";

export const HISTORICAL_UNIT="remote-control-v2-agent.service";
const CANONICAL_UNIT="remote-control-agent.service";
const LEGACY_MARKER="# Managed by mcp-workers v2 Linux installer; NOT the v1 Agent.";
const MODERN_MARKER="# Managed by Remote Control Agent installer.";
const LEGACY_DESCRIPTION="Remote Control v2 Agent (outbound WSS, independent of v1)";
const DESCRIPTION="Remote Control Agent (signed outbound WSS)";
const APP="apps/remote-control-agent";
const VERSION=/^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
const DEVICE_ID=/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;
const OPERATION_ID=/^(?!\.{1,2}$)[A-Za-z0-9._:-]{1,128}$/;

function owned(meta,dir=false){
  if(meta.uid!==process.getuid()||meta.isSymbolicLink()||
    (dir?!meta.isDirectory():!meta.isFile())||
    (meta.mode&0o077)!==0||(!dir&&meta.nlink!==1))
    throw Error("Untrusted owned Agent installation");
}
function safeEndpoint(endpoint){
  const url=new URL(endpoint);
  if(url.protocol!=="https:"||url.username||url.password||url.search||url.hash||
    url.port||url.pathname!=="/"||endpoint!==url.origin+"/"||
    !/^[a-z0-9.-]+$/i.test(url.hostname))throw Error("Untrusted service endpoint");
  return endpoint;
}
function newer(a,b){
  const next=VERSION.exec(a),old=VERSION.exec(b);
  if(!next||!old)throw Error("Only stable pinned releases can be upgraded");
  for(let i=1;i<=3;i++){
    if(BigInt(next[i])!==BigInt(old[i]))return BigInt(next[i])>BigInt(old[i]);
  }
  return false;
}
function rendered(root,home,endpoint,modern=true,modernEnvironment=true){
  const key=path.join(home,".local/share/mcp-workers/remote-control/v2-identity.pem");
  const env=modernEnvironment?"REMOTE_CONTROL_AGENT":"REMOTE_CONTROL_V2";
  return [
    modern?MODERN_MARKER:LEGACY_MARKER,
    "[Unit]",
    "Description="+(modern?DESCRIPTION:LEGACY_DESCRIPTION),
    "StartLimitIntervalSec=0","",
    "[Service]","Type=simple",
    "WorkingDirectory="+path.join(root,APP),
    "Environment="+env+"_ENDPOINT="+endpoint,
    "Environment="+env+"_KEY_PATH="+key,
    "UMask=0077",
    "ExecStartPre=/usr/bin/test -r "+key,
    "ExecStartPre=/usr/bin/test -r "+key+".device-id",
    "ExecStartPre=/usr/bin/test -x "+path.join(root,APP,".build/session-supervisor"),
    "ExecStart="+path.join(root,"bin/node")+" "+path.join(root,APP,"src/v2-main.js"),
    "Restart=on-failure","RestartSec=15s","TimeoutStopSec=15s","",
    "[Install]","WantedBy=default.target","",
  ].join("\n");
}
export function inspectInstalledSignedUnit(unit,{home,endpoint,newRoot}){
  safeEndpoint(endpoint);
  const base=path.join(home,".local/share/mcp-workers/remote-control/programs");
  const m=/^WorkingDirectory=(.+)$/m.exec(unit||"");
  if(!m)throw Error("Installed signed Agent service missing");
  const oldRoot=path.resolve(m[1],"../..");
  if(path.dirname(oldRoot)!==base||!path.isAbsolute(home)||home!==path.normalize(home))
    throw Error("Agent program is not in the pinned private version directory");
  const oldName=path.basename(oldRoot),newName=path.basename(newRoot);
  const arch=process.arch==="x64"?"linux-x64-glibc":
    process.arch==="arm64"?"linux-arm64-glibc":null;
  if(!arch||path.dirname(newRoot)!==base||
     !oldName.endsWith("-"+arch)||!newName.endsWith("-"+arch)||
     !newer(newName.slice(0,-arch.length-1),oldName.slice(0,-arch.length-1)))
    throw Error("Upgrade must advance the same Linux architecture and version");
  if(![
    rendered(oldRoot,home,endpoint,false,false), // published pre-canonical unit
    rendered(oldRoot,home,endpoint,false,true),  // existing direct-upgraded unit
    rendered(oldRoot,home,endpoint,true,true),   // future upgrades of this unit
  ].includes(unit))throw Error("Foreign or modified signed Agent unit; refusing upgrade");
  return Object.freeze({oldRoot,newRoot,unitName:HISTORICAL_UNIT,
    newUnit:rendered(newRoot,home,endpoint,true,true),
    identity:path.join(home,".local/share/mcp-workers/remote-control/v2-identity.pem")});
}
function system(args){
  const result=spawnSync("systemctl",["--user",...args],{encoding:"utf8",timeout:45000});
  if(result.error||result.signal||result.status!==0)
    throw Error("Owner-local systemd operation failed: "+args[0]);
  return result.stdout.trim();
}
async function writeExclusive(file,content){
  const f=await open(file,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600);
  try{await f.writeFile(content);await f.sync();}finally{await f.close();}
}
async function syncParent(file){
  const d=await open(path.dirname(file),constants.O_RDONLY|constants.O_DIRECTORY);
  try{await d.sync();}finally{await d.close();}
}
async function atomicWrite(file,content){
  const stage=file+".upgrade-stage";
  await writeExclusive(stage,content);
  await rename(stage,file);await syncParent(file);
}
async function safeExisting(file){
  let stat;
  try{stat=await lstat(file);}
  catch(e){if(e.code==="ENOENT")return false;throw e;}
  owned(stat);return true;
}
async function compatibleReceipts(home){
  const directory=path.join(home,".local/state/mcp-workers/remote-control-agent");
  const receipt=path.join(directory,"operation-receipts.sqlite");
  let stat;
  try{stat=await lstat(receipt);}
  catch(e){if(e.code==="ENOENT")return;throw e;}
  owned(stat);
  const f=await open(receipt,constants.O_RDONLY|constants.O_NOFOLLOW);
  try{
    const header=Buffer.alloc(100);
    const {bytesRead}=await f.read(header,0,100,0);
    if(bytesRead!==100||header.subarray(0,16).toString("ascii")!=="SQLite format 3\0"||
       ![0,1].includes(header.readUInt32BE(60)))
      throw Error("Incompatible durable receipts; upgrade refused");
  }finally{await f.close();}
}
async function exactIdentity(key){
  for(const p of [key,key+".device-id"])owned(await lstat(p));
  const id=(await readFile(key+".device-id","utf8")).trim();
  if(!DEVICE_ID.test(id))throw Error("Invalid approved device identity");
  return {id,digest:createHash("sha256").update(await readFile(key)).digest("hex")};
}
async function safeProgram(root,{remoteTarget=false}={}){
  owned(await lstat(root),true);
  owned(await lstat(path.join(root,"bundle.json")));
  const manifest=JSON.parse(await readFile(path.join(root,"bundle.json"),"utf8"));
  if(manifest.name!=="remote-control-agent"||manifest.version+"-"+manifest.target!==path.basename(root)||
     manifest.upgrade_profile!=="paired-full-v1"||manifest.receipt_schema!==1||
     manifest.device_protocol!==2||
     (remoteTarget&&manifest.upgrade_protocol!=="owner-one-shot-v1"))
    throw Error("Untrusted packaged Agent profile or remote-upgrade protocol");
  for(const relative of ["bin/node",APP+"/src/v2-main.js",APP+"/.build/session-supervisor"])
    owned(await lstat(path.join(root,relative)));
}
export async function upgradeExistingSignedService({
  home=os.homedir(),newRoot,endpoint,
  systemctl=system,freeze=requestUpgradeConsent,
  // Optional, locally supplied by a future independent one-shot updater.
  // Never derived from MCP arguments or an Agent-provided version string.
  verifySignedReconnect,upgradeOperationId,
}={}){
  if(process.platform!=="linux"||process.getuid()===0)throw Error("Linux non-root owner required");
  if(verifySignedReconnect!==undefined&&
     (typeof verifySignedReconnect!=="function"||
      typeof upgradeOperationId!=="string"||!OPERATION_ID.test(upgradeOperationId)))
    throw Error("Invalid locally verified one-shot upgrade acceptance");
  if(verifySignedReconnect===undefined&&upgradeOperationId!==undefined)
    throw Error("Unbound one-shot upgrade operation");
  const unitDir=path.join(home,".config/systemd/user");
  const unitPath=path.join(unitDir,HISTORICAL_UNIT);
  const backup=unitPath+".upgrade-backup";
  if(await safeExisting(path.join(unitDir,CANONICAL_UNIT)))
    throw Error("Canonical service exists; do not alter unrelated unit");
  if(await safeExisting(backup)||await safeExisting(unitPath+".upgrade-stage"))
    throw Error("Interrupted direct upgrade: preserve backup for review");
  owned(await lstat(unitPath));
  const previous=await readFile(unitPath,"utf8");
  const plan=inspectInstalledSignedUnit(previous,{home,newRoot,endpoint});
  if(await safeExisting(unitPath+".d"))throw Error("Unexpected service drop-in");
  await safeProgram(plan.oldRoot);
  await safeProgram(plan.newRoot,{remoteTarget:!!verifySignedReconnect});
  await compatibleReceipts(home);
  const identity=await exactIdentity(plan.identity);
  const status=systemctl(["show",HISTORICAL_UNIT,"-p","ActiveState","-p","SubState","-p","MainPID"]);
  const active=/^ActiveState=active$/m.test(status);
  const offline=/^ActiveState=inactive$/m.test(status)&&
    /^SubState=dead$/m.test(status)&&/^MainPID=0$/m.test(status);
  if(!active&&!offline)throw Error("Agent state uncertain; upgrade refused");
  let frozen=false;
  if(active){
    const answer=await freeze(plan.identity,"freeze");
    if(answer!=="ready"){
      if(answer!=="busy")await freeze(plan.identity,"release").catch(()=>{});
      throw Error("Agent has active or uncertain operations; upgrade refused");
    }
    frozen=true;
  }
  try{
    if((await exactIdentity(plan.identity)).digest!==identity.digest ||
      (await readFile(unitPath,"utf8"))!==previous)
      throw Error("Approved device changed before upgrade");
    await writeExclusive(backup,previous);await syncParent(backup);
    try{
      await atomicWrite(unitPath,plan.newUnit);
      systemctl(["daemon-reload"]);
      systemctl(["restart",HISTORICAL_UNIT]);
      systemctl(["is-active","--quiet",HISTORICAL_UNIT]);
      const same=await exactIdentity(plan.identity);
      if(same.id!==identity.id||same.digest!==identity.digest)
        throw Error("Device identity changed during upgrade");
      // Remote one-shot mode retains the original unit backup until the
      // trusted same-owner updater has verified a NEW signed WSS session.
      // systemctl is-active alone is never a remote success receipt.
      const targetVersion=path.basename(plan.newRoot).split("-linux-")[0];
      if(verifySignedReconnect){
        // The actual signed-session check belongs to the independent
        // same-user watchdog. Bound even a stalled callback, and never delete
        // the backup on timeout; the ordinary local upgrade path is unchanged.
        let timeout;
        let verified;
        try{
          verified=await Promise.race([
            Promise.resolve().then(()=>verifySignedReconnect({
              operationId:upgradeOperationId,deviceId:identity.id,
              version:targetVersion,service:HISTORICAL_UNIT,
            })),
            new Promise(resolve=>{timeout=setTimeout(()=>resolve(false),90_000);}),
          ]);
        }finally{clearTimeout(timeout);}
        if(verified!==true)throw Error("New signed Agent reconnect not verified");
        systemctl(["is-active","--quiet",HISTORICAL_UNIT]);
        const after=await exactIdentity(plan.identity);
        if(after.id!==identity.id||after.digest!==identity.digest)
          throw Error("Device identity changed after reconnect");
        if(await readFile(unitPath,"utf8")!==plan.newUnit)
          throw Error("Agent unit changed after signed reconnect");
      }
      await rm(backup);await syncParent(backup);
      return {status:"active",deviceId:identity.id,service:HISTORICAL_UNIT,
        version:targetVersion,identityPreserved:true};
    }catch(error){
      try{
        await atomicWrite(unitPath,previous);
        systemctl(["daemon-reload"]);
        systemctl(["restart",HISTORICAL_UNIT]);
        systemctl(["is-active","--quiet",HISTORICAL_UNIT]);
        await rm(backup);await syncParent(backup);
      }catch{
        throw Error("Upgrade failed; rollback uncertain; backup retained for manual recovery");
      }
      throw error;
    }
  }finally{
    if(frozen)await freeze(plan.identity,"release").catch(()=>{});
  }
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  upgradeExistingSignedService({newRoot:process.argv[2],endpoint:process.argv[3]})
    .then(result=>process.stdout.write("Ready: Agent "+result.version+"; existing identity retained.\n"))
    .catch(()=>{process.stderr.write("Direct Agent upgrade failed; current service and backup require inspection.\n");process.exitCode=1;});
}
