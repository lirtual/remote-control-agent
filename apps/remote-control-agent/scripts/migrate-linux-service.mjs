/**
 * Owner-local, one-time migration from the verified historical Linux unit
 * to the canonical Remote Control Agent service. Never called by an MCP tool.
 * This module deliberately does not rotate keys, pair, or access credentials.
 */
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { constants } from "node:fs";
import { access, chmod, lstat, mkdir, open, readFile, readdir, rename, rmdir, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";
import { renderV2Service } from "./install-v2.mjs";

const APP="apps/remote-control-agent";
const NEW="remote-control-agent.service";
const OLD="remote-control-v2-agent.service";
const TUNNEL="remote-control-tunnel.service";
const OLD_MARKER="# Managed by mcp-workers v2 Linux installer; NOT the v1 Agent.";
const NEW_MARKER="# Managed by Remote Control Agent installer.";
const LEGACY_MARKER="# Installed from docs/remote-control/systemd/remote-control-agent.service.example";
const TUNNEL_MARKER="# Installed from docs/remote-control/systemd/remote-control-tunnel.service.example";
const UUID=/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;

function exactField(unit, name) {
  const rows=unit.split("\n").filter(line=>line.startsWith(name+"="));
  if(rows.length!==1)throw Error("Ambiguous unit field: "+name);
  return rows[0].slice(name.length+1);
}
function sha(data){return createHash("sha256").update(data).digest("hex");}
function ownerFile(meta, mode) {
  if(!meta.isFile() || meta.isSymbolicLink() || meta.uid!==process.getuid() ||
     meta.nlink!==1 || (meta.mode&0o777)!==mode)
    throw Error("Untrusted owner unit or identity");
}
function releaseVersion(name){
  const m=/^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)-linux-(x64|arm64)-glibc$/.exec(name);
  if(!m)throw Error("Untrusted Linux Agent release directory");
  return {parts:m.slice(1,4).map(Number),arch:m[4]};
}
function newerRelease(next,previous){
  for(let i=0;i<3;i++)if(next[i]!==previous[i])return next[i]>previous[i];
  return false;
}
function serviceOrigin(origin) {
  const u=new URL(origin);
  if(u.protocol!=="https:"||u.username||u.password||u.search||u.hash||
     u.port||origin!==u.origin+"/")throw Error("Invalid signed Worker origin");
  return origin;
}
/** This migration retires exactly the observed historical user units, not
 * arbitrary services carrying the same comment or Description. */
function proveHistoricalUnits(legacyUnit,tunnelUnit,home) {
  const origin=/^# Installed from docs\/remote-control\/systemd\/remote-control-agent\.service\.example\n# at ([a-f0-9]{40})\. Placeholders substituted on host\.\n/;
  const match=origin.exec(legacyUnit);
  if(!match)throw Error("Unknown historical loopback unit");
  const revision=match[1];
  const root=path.join(home,".local/share/mcp-workers/remote-control-agent",revision);
  const node=path.join(home,".local/share/mcp-workers/node/v24.21.0/bin/node");
  const legacy=[
    LEGACY_MARKER,
    "# at "+revision+". Placeholders substituted on host.",
    "# Runtime pin: Node v24.21.0 and agent tree "+revision.slice(0,7)+". The live process is left running.",
    "[Unit]",
    "Description=Remote Control native Agent (loopback, user service)",
    "StartLimitIntervalSec=0","",
    "[Service]","Type=simple",
    "WorkingDirectory="+path.join(root,APP),
    "Environment=REMOTE_CONTROL_AGENT_HOST=127.0.0.1",
    "Environment=REMOTE_CONTROL_AGENT_PORT=9477",
    "EnvironmentFile=%h/.config/mcp-workers/remote-control-agent.env",
    "UMask=0077",
    "ExecStartPre=/usr/bin/test -x "+path.join(root,APP,".build/session-supervisor"),
    "ExecStart="+node+" --experimental-strip-types src/main.ts",
    "Restart=always","RestartSec=15s","",
    "[Install]","WantedBy=default.target","",
  ].join("\n");
  const start=exactField(tunnelUnit,"ExecStart");
  const matchTunnel=/^(.+) tunnel --protocol http2 run --token-file (\/[^ \n]+)$/.exec(start);
  if(!matchTunnel ||
     matchTunnel[1]!==path.join(home,".local/bin/cloudflared"))
    throw Error("Unknown historical Tunnel executable");
  const token=matchTunnel[2];
  const tokenRoot=path.join(home,".local/share/remote-control-t02");
  if(path.dirname(token)!==tokenRoot || path.normalize(token)!==token ||
     token.includes(".."))
    throw Error("Unknown historical Tunnel token path");
  const tunnel=[
    TUNNEL_MARKER,
    "# at "+revision+". Placeholders substituted on host.",
    "[Unit]",
    "Description=Remote Control Cloudflare Tunnel (user service)",
    "Wants=remote-control-agent.service",
    "After=remote-control-agent.service",
    "StartLimitIntervalSec=0","",
    "[Service]","Type=simple","UMask=0077",
    "ExecStart="+path.join(home,".local/bin/cloudflared")+" tunnel --protocol http2 run --token-file "+token,
    "Restart=always","RestartSec=15s","",
    "[Install]","WantedBy=default.target","",
  ].join("\n");
  if(legacyUnit!==legacy || tunnelUnit!==tunnel)
    throw Error("Historical loopback or Tunnel unit differs from reviewed template");
}
function proveOldWssUnit(unit,home) {
  if(!unit.startsWith(OLD_MARKER+"\n"))throw Error("Signed Agent legacy unit ownership mismatch");
  const start=exactField(unit,"ExecStart");
  const working=exactField(unit,"WorkingDirectory");
  const root=path.resolve(working,"../..");
  const programs=path.join(home,".local/share/mcp-workers/remote-control/programs");
  const release=releaseVersion(path.basename(root));
  if(path.dirname(root)!==programs ||
     !newerRelease(release.parts,[0,1,11]) ||
     start!==path.join(root,"bin/node")+" "+path.join(root,APP,"src/v2-main.js"))
    throw Error("Cannot prove reviewed predecessor program");
  const endpoint=serviceOrigin(exactField(unit,"Environment=REMOTE_CONTROL_V2_ENDPOINT"));
  const key=path.join(home,".local/share/mcp-workers/remote-control/v2-identity.pem");
  if(exactField(unit,"Environment=REMOTE_CONTROL_V2_KEY_PATH")!==key)
    throw Error("Existing device identity binding mismatch");
  const rendered=renderV2Service({
    home,repoRoot:root,node:path.join(root,"bin/node"),
    endpoint,keyPath:key,entryExt:"js",
  });
  const historical=rendered.replace(NEW_MARKER,OLD_MARKER)
    .replace("Description=Remote Control Agent (signed outbound WSS)",
      "Description=Remote Control v2 Agent (outbound WSS, independent of v1)")
    .replace("REMOTE_CONTROL_AGENT_ENDPOINT","REMOTE_CONTROL_V2_ENDPOINT")
    .replace("REMOTE_CONTROL_AGENT_KEY_PATH","REMOTE_CONTROL_V2_KEY_PATH");
  if(unit!==historical)throw Error("Unexpected signed Agent legacy service directives");
  return {root,endpoint,key,release};
}

export function planServiceCutover({home,legacyUnit,tunnelUnit,signedUnit,candidateRoot,deviceId}) {
  if(process.getuid()===0)throw Error("Root cannot migrate user Agents");
  if(!path.isAbsolute(home)||home!==path.normalize(home))throw Error("Unsafe home");
  if(!UUID.test(deviceId))throw Error("Invalid exact paired device ID");
  proveHistoricalUnits(legacyUnit,tunnelUnit,home);
  const old=proveOldWssUnit(signedUnit,home);
  const programs=path.join(home,".local/share/mcp-workers/remote-control/programs");
  const candidate=releaseVersion(path.basename(candidateRoot));
  if(path.dirname(candidateRoot)!==programs || candidate.arch!==old.release.arch ||
     !newerRelease(candidate.parts,old.release.parts))
    throw Error("Candidate must be a newer verified Release for the same CPU");
  const canonical=renderV2Service({home,repoRoot:candidateRoot,
    node:path.join(candidateRoot,"bin/node"),endpoint:old.endpoint,keyPath:old.key,entryExt:"js"});
  return Object.freeze({home,legacyUnit,tunnelUnit,signedUnit,candidateRoot,
    deviceId,identity:old.key,canonical,unitDir:path.join(home,".config/systemd/user"),
    backupDir:path.join(home,".local/share/mcp-workers/remote-control/cutover-backup")});
}

function defaultSystemctl(args){
  const r=spawnSync("systemctl",["--user",...args],{encoding:"utf8",timeout:12000});
  if(r.error||r.signal||r.status!==0)throw Error("Local systemd action failed: "+args[0]);
  return (r.stdout||"").trim();
}
export function assertOffline(systemctl=defaultSystemctl) {
  for(const unit of [NEW,OLD,TUNNEL]){
    const state=systemctl(["show",unit,"-p","ActiveState","-p","SubState","-p","MainPID","--no-pager"]);
    if(!state.split("\n").includes("ActiveState=inactive") ||
       !state.split("\n").includes("SubState=dead") ||
       !state.split("\n").includes("MainPID=0"))
      throw Error("All old Agents and Tunnel must be stopped from local terminal");
  }
}
async function exactLocalFile(p, expected, mode){
  const st=await lstat(p);ownerFile(st,mode);
  const bytes=await readFile(p);
  if(bytes.toString("utf8")!==expected)throw Error("Unit changed since preflight");
}
async function secureSave(p,data){
  const f=await open(p,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,0o600);
  try{await f.writeFile(data);await f.sync();}finally{await f.close();}
}
async function syncDir(p){const h=await open(p,constants.O_RDONLY|constants.O_DIRECTORY);
  try{await h.sync();}finally{await h.close();}
}
async function identityDigest(key,deviceId) {
  for(const p of [key,key+".device-id"]){ownerFile(await lstat(p),0o600);}
  const value=(await readFile(key+".device-id","utf8")).trim();
  if(value!==deviceId)throw Error("Local identity is not the expected approved device");
  return sha(await readFile(key));
}
async function verifyReceipts(home){
  const filename=path.join(home,".local/state/mcp-workers/remote-control-agent/operation-receipts.sqlite");
  let meta;try{meta=await lstat(filename);}catch(e){if(e.code==="ENOENT")return;throw e;}
  ownerFile(meta,0o600);
  const db=new DatabaseSync(filename,{readOnly:true,timeout:0});
  try{
    if(db.prepare("PRAGMA quick_check").get()?.quick_check!=="ok" ||
       ![0,1].includes(db.prepare("PRAGMA user_version").get()?.user_version))
      throw Error("Receipt history is not safe for migration");
  }finally{db.close();}
}
async function exactSnapshot(plan){
  await verifyReceipts(plan.home);
  for(const [name,data,mode] of [
    [NEW,plan.legacyUnit,0o644],[OLD,plan.signedUnit,0o600],[TUNNEL,plan.tunnelUnit,0o644]
  ]){
    const unit=path.join(plan.unitDir,name);
    await exactLocalFile(unit,data,mode);
    try{await lstat(unit+".d");throw Error("Unit has unreviewed systemd drop-ins");}
    catch(e){if(e.code!=="ENOENT")throw e;}
  }
  const root=await lstat(plan.candidateRoot);
  if(!root.isDirectory()||root.isSymbolicLink()||root.uid!==process.getuid()||
     (root.mode&0o077)!==0)throw Error("New immutable program directory is not owner-private");
  ownerFile(await lstat(path.join(plan.candidateRoot,"bundle.json")),0o600);
  const manifest=JSON.parse(await readFile(path.join(plan.candidateRoot,"bundle.json"),"utf8"));
  if(manifest.name!=="remote-control-agent" ||
     path.basename(plan.candidateRoot)!==manifest.version+"-"+manifest.target ||
     manifest.upgrade_profile!=="paired-full-v1" ||
     manifest.device_protocol!==2)throw Error("Unverified candidate bundle manifest");
  ownerFile(await lstat(path.join(plan.candidateRoot,APP,"src/v2-main.js")),0o600);
  return identityDigest(plan.identity,plan.deviceId);
}

/** A crash during backup preparation leaves no installed unit changed.
 * Only remove a private, known partial snapshot after the exact original
 * services and identity have independently passed preflight again. */
async function discardPartialPreparation(pending,expected) {
  let dir;
  try{dir=await lstat(pending);}
  catch(e){if(e.code==="ENOENT")return;throw e;}
  if(!dir.isDirectory()||dir.isSymbolicLink()||
     dir.uid!==process.getuid()||(dir.mode&0o777)!==0o700)
    throw Error("Untrusted interrupted backup preparation");
  for(const name of await readdir(pending)){
    if(!Object.hasOwn(expected,name))
      throw Error("Unexpected interrupted backup member");
    const member=path.join(pending,name);
    ownerFile(await lstat(member),0o600);
    const observed=await readFile(member);
    const expectedBytes=Buffer.from(expected[name]);
    if(observed.length>expectedBytes.length||
       !expectedBytes.subarray(0,observed.length).equals(observed))
      throw Error("Interrupted backup differs from reviewed originals");
  }
  for(const name of await readdir(pending))await rm(path.join(pending,name));
  await rmdir(pending);
  await syncDir(path.dirname(pending));
}

/** Only runs after all three services were explicitly stopped locally.
 * Saves owner-only exact backups before replacing the canonical unit name.
 * On activation failure restores old units; power-loss recovery is --rollback.
 */
export async function applyServiceCutover(plan,{systemctl=defaultSystemctl}={}){
  assertOffline(systemctl);
  const idHash=await exactSnapshot(plan);
  const journal={phase:"prepared",device_id:plan.deviceId,
    old_hash:sha(plan.signedUnit),new_hash:sha(plan.canonical),
    loopback_hash:sha(plan.legacyUnit),tunnel_hash:sha(plan.tunnelUnit),
    identity_sha256:idHash};
  const expected={
    [NEW]:plan.legacyUnit,[OLD]:plan.signedUnit,
    [TUNNEL]:plan.tunnelUnit,
    "journal.json":JSON.stringify(journal)+"\n",
  };
  const pending=plan.backupDir+".preparing";
  // A committed journal must never be overwritten or replayed.
  try{await lstat(plan.backupDir);throw Error("Existing migration backup; manual recovery required");}
  catch(e){if(e.code!=="ENOENT")throw e;}
  await discardPartialPreparation(pending,expected);
  await mkdir(pending,{mode:0o700});
  const dir=await lstat(pending);
  if(!dir.isDirectory()||dir.isSymbolicLink()||dir.uid!==process.getuid()||
     (dir.mode&0o777)!==0o700)throw Error("Unsafe migration preparation directory");
  for(const [name,data] of Object.entries(expected))
    await secureSave(path.join(pending,name),data);
  await syncDir(pending);
  // Commit the complete private snapshot atomically before changing any unit.
  await rename(pending,plan.backupDir);
  await syncDir(path.dirname(plan.backupDir));
  let modified=false;
  try{
    assertOffline(systemctl);
    if(await identityDigest(plan.identity,plan.deviceId)!==idHash)
      throw Error("Device identity changed before cutover");
    const staged=path.join(plan.unitDir,".remote-control-agent.migrate.tmp");
    await secureSave(staged,plan.canonical);
    await rename(staged,path.join(plan.unitDir,NEW));
    modified=true;
    await syncDir(plan.unitDir);
    systemctl(["disable",OLD]);
    systemctl(["disable",TUNNEL]);
    systemctl(["daemon-reload"]);
    systemctl(["enable","--now",NEW]);
    systemctl(["is-active","--quiet",NEW]);
    if(await identityDigest(plan.identity,plan.deviceId)!==idHash)
      throw Error("Identity changed during cutover");
    await secureSave(path.join(plan.backupDir,"activated"),sha(plan.canonical)+"\n");
    await syncDir(plan.backupDir);
    return {status:"locally_activated",device_id:plan.deviceId,
      signed_wss:"requires_independent_MCP_verification",backup_retained:true};
  }catch(e){
    // Nothing outside the three named user services, their unit files,
    // and private one-time journal can be changed.
    if(modified){
      try{
        systemctl(["disable","--now",NEW]);
        // Never truncate the installed unit in-place: interruption in the
        // rollback itself must leave either the canonical or the exact old unit.
        const restore=path.join(plan.unitDir,".remote-control-agent.restore.tmp");
        await secureSave(restore,plan.legacyUnit);
        await chmod(restore,0o644);
        await rename(restore,path.join(plan.unitDir,NEW));
        await syncDir(plan.unitDir);
        systemctl(["daemon-reload"]);
        systemctl(["start",NEW]);
        systemctl(["enable","--now",OLD]);
        systemctl(["enable","--now",TUNNEL]);
      }catch{
        throw Error("Cutover failed; rollback uncertain; preserve all backup evidence");
      }
    }
    throw e;
  }
}


/** Local-terminal recovery after a crash or an operator-requested rollback.
 * The new service must be stopped first. Unknown unit and identity changes
 * refuse restoration rather than overwriting another user's service.
 */
export async function rollbackServiceCutover({home=os.homedir(),systemctl=defaultSystemctl}={}){
  if(process.getuid()===0)throw Error("Root cannot roll back user Agents");
  const unitDir=path.join(home,".config/systemd/user");
  const backup=path.join(home,".local/share/mcp-workers/remote-control/cutover-backup");
  const b=await lstat(backup);
  if(!b.isDirectory()||b.isSymbolicLink()||b.uid!==process.getuid()||
     (b.mode&0o777)!==0o700)throw Error("Untrusted private migration journal");
  const readBackup=async file=>{
    const p=path.join(backup,file);ownerFile(await lstat(p),0o600);
    return readFile(p,"utf8");
  };
  const journal=JSON.parse(await readBackup("journal.json"));
  if(journal.phase!=="prepared"||!UUID.test(journal.device_id))
    throw Error("Invalid migration journal");
  const [loopback,signed,tunnel]=await Promise.all(
    [NEW,OLD,TUNNEL].map(readBackup));
  if(sha(loopback)!==journal.loopback_hash||
     sha(signed)!==journal.old_hash||
     sha(tunnel)!==journal.tunnel_hash)
    throw Error("Migration backup differs from recorded hashes");
  const key=path.join(home,".local/share/mcp-workers/remote-control/v2-identity.pem");
  if(await identityDigest(key,journal.device_id)!==journal.identity_sha256)
    throw Error("Migration identity changed; manual recovery required");
  assertOffline(systemctl);
  const current=path.join(unitDir,NEW);
  const st=await lstat(current);
  ownerFile(st,(await readFile(current,"utf8"))===loopback?0o644:0o600);
  const currentText=await readFile(current,"utf8");
  if(![journal.new_hash,journal.loopback_hash].includes(sha(currentText)))
    throw Error("Canonical unit has unreviewed changes");
  for(const [file,expected,mode] of [[OLD,signed,0o600],[TUNNEL,tunnel,0o644]])
    await exactLocalFile(path.join(unitDir,file),expected,mode);
  const stage=path.join(unitDir,".remote-control-agent.rollback.tmp");
  await secureSave(stage,loopback);
  await chmod(stage,0o644);
  // The canonical unit is inactive; this disables autostart before restoring
  // the exact old owner unit and restarting only the previous local services.
  systemctl(["disable",NEW]);
  await rename(stage,current);
  await syncDir(unitDir);
  systemctl(["daemon-reload"]);
  systemctl(["start",NEW]);
  systemctl(["enable","--now",OLD]);
  systemctl(["enable","--now",TUNNEL]);
  return {status:"legacy_restored",device_id:journal.device_id,backup_retained:true};
}

export async function inspectServiceCutover({home=os.homedir(),candidateRoot,systemctl=defaultSystemctl}={}){
  const unitDir=path.join(home,".config/systemd/user");
  const read=async name=>readFile(path.join(unitDir,name),"utf8");
  const key=path.join(home,".local/share/mcp-workers/remote-control/v2-identity.pem");
  const id=(await readFile(key+".device-id","utf8")).trim();
  const plan=planServiceCutover({home,legacyUnit:await read(NEW),
    tunnelUnit:await read(TUNNEL),signedUnit:await read(OLD),candidateRoot,deviceId:id});
  await exactSnapshot(plan);
  assertOffline(systemctl);
  return plan;
}

if(process.argv[1] && path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  (async()=>{
    if(!process.stdin.isTTY||!process.stdout.isTTY)
      throw Error("Migration requires the physical owner terminal");
    if(process.argv.length===3&&process.argv[2]==="--rollback"){
      const {createInterface}=await import("node:readline/promises");
      const cli=createInterface({input:process.stdin,output:process.stdout,terminal:true});
      let answer;try{answer=await cli.question("Type ROLLBACK-REMOTE-CONTROL (all services must be stopped): ");}
      finally{cli.close();}
      if(answer!=="ROLLBACK-REMOTE-CONTROL")throw Error("Rollback not confirmed");
      process.stdout.write(JSON.stringify(await rollbackServiceCutover())+"\n");
      return;
    }
    if(process.argv.length!==4||process.argv[2]!=="--apply")
      throw Error("Usage: migrate-linux-service.mjs --apply <new-root> or --rollback");
    const candidateRoot=path.resolve(process.argv[3]);
    const plan=await inspectServiceCutover({candidateRoot});
    process.stdout.write("Offline service cutover: "+OLD+" -> "+NEW+"\n");
    process.stdout.write("Device identity remains: "+plan.deviceId+"\n");
    process.stdout.write("Legacy Tunnel and loopback unit are retired locally; no Cloudflare DNS changes.\n");
    const {createInterface}=await import("node:readline/promises");
    const cli=createInterface({input:process.stdin,output:process.stdout,terminal:true});
    let answer;try{answer=await cli.question("Type MIGRATE-REMOTE-CONTROL to authorize: ");}
    finally{cli.close();}
    if(answer!=="MIGRATE-REMOTE-CONTROL")throw Error("Owner did not approve cutover");
    process.stdout.write(JSON.stringify(await applyServiceCutover(plan))+"\n");
  })().catch(()=>{process.stderr.write("Service migration unavailable; inspect local unit state and private backups.\n");process.exitCode=1;});
}