/** #657 explicit, one-shot owner-authorized macOS remote upgrade.
 * Called only by the reviewed, SHA-pinned public macOS installer. No daemon. */
import {randomUUID} from "node:crypto";
import {spawnSync} from "node:child_process";
import {cp,lstat,mkdir,readFile,rm,writeFile} from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import {realpathSync} from "node:fs";
import {fileURLToPath} from "node:url";
import {
  checked,checkCandidate,localMacAction,ownerCliText,parsePlist,
  launchctlServiceState,verifiedEndpoint,freeze,
} from "./macos-local.mjs";

const ROOT=path.join(".local","share","mcp-workers","remote-control");
const LABEL="org.mcp-workers.remote-control-agent";
const ID=/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const SHA=/^[a-f0-9]{40}$/;
const run=(binary,args)=>spawnSync(binary,args,{encoding:"utf8",timeout:15000,maxBuffer:32768});
async function exists(p){try{return await lstat(p);}catch(e){if(e.code==="ENOENT")return null;throw e;}}
async function ownedDirectory(dir){
  if(!(await exists(dir)))await mkdir(dir,{mode:0o700});
  await checked(dir,{dir:true});
}
function nativeOwner(){
  return process.platform==="darwin" && ["arm64","x64"].includes(process.arch) &&
    Number.parseInt(os.release(),10)>=24 && process.getuid?.()>0;
}
export function remoteJobLabel(id){
  if(!ID.test(id))throw Error("Invalid one-shot upgrade operation.");
  return "org.mcp-workers.rca-upgrade-"+id.replaceAll("-","");
}
// launchctl submit restarts failed jobs (confirmed by the real Mac incident).
// A private, launch-on-load plist with LaunchOnlyOnce prevents any replay even
// when the detached worker exits nonzero or when the same owner logs in again.
export function remoteJobPlist(id,node,worker,dir){
  const label=remoteJobLabel(id);
  const escape=s=>s.replaceAll("&","&amp;").replaceAll("<","&lt;")
    .replaceAll(">","&gt;").replaceAll('"',"&quot;").replaceAll("'","&apos;");
  if(![node,worker,dir].every(s=>path.isAbsolute(s)))
    throw Error("Absolute owner-private job paths required.");
  const arg=x=>"<string>"+escape(x)+"</string>";
  return '<?xml version="1.0" encoding="UTF-8"?>\n'+
    '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '+
    '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'+
    '<plist version="1.0"><dict>\n'+
    '<key>Label</key>'+arg(label)+'\n'+
    '<key>ProgramArguments</key><array>'+
    [node,worker,"worker",id].map(arg).join("")+'</array>\n'+
    '<key>RunAtLoad</key><true/>\n'+
    '<key>KeepAlive</key><false/>\n'+
    '<key>LaunchOnlyOnce</key><true/>\n'+
    '<key>StandardOutPath</key>'+arg(path.join(dir,"stdout.log"))+'\n'+
    '<key>StandardErrorPath</key>'+arg(path.join(dir,"stderr.log"))+'\n'+
    '</dict></plist>\n';
}
export function verifiedLaunchdJob(id,uid,pid,invoke=run,parentPid=process.ppid){
  if(!ID.test(id)||!Number.isInteger(uid)||uid<=0||
     !Number.isInteger(pid)||pid<=1||parentPid!==1)return false;
  const r=invoke("/bin/launchctl",["print","gui/"+uid+"/"+remoteJobLabel(id)]);
  return !r.error && r.status===0 &&
    new RegExp("(?:^|\\n)\\s*pid = "+pid+"(?:\\n|$)").test(String(r.stdout??""));
}
// Explicit remote upgrades must move forward; the public Release pin is not
// authority to downgrade a newer already-installed owner Agent.
export function forwardMacVersion(current,next){
  const re=/^v([0-9]+)\.([0-9]+)\.([0-9]+)(?:-([a-z0-9.-]+))?-darwin-(arm64|x64)$/;
  const a=re.exec(current),b=re.exec(next);
  if(!a||!b||a[5]!==b[5])return false;
  for(let i=1;i<=3;i++){
    const x=BigInt(a[i]),y=BigInt(b[i]);
    if(x!==y)return y>x;
  }
  if(!a[4])return false; // A stable version cannot be replaced by an rc.
  if(!b[4])return true;  // The official stable release supersedes the rc.
  const old=a[4].split("."),fresh=b[4].split(".");
  for(let i=0;i<Math.max(old.length,fresh.length);i++){
    if(i>=old.length)return true;
    if(i>=fresh.length)return false;
    const n=/^[0-9]+$/;
    const x=old[i],y=fresh[i];
    if(x===y)continue;
    if(n.test(x)&&n.test(y))return BigInt(y)>BigInt(x);
    if(n.test(x))return true;  // SemVer numeric prerelease sorts lower.
    if(n.test(y))return false;
    return y>x;
  }
  return false;
}
async function trustedExisting(home,endpoint,bundle,sourceSha,invoke=run){
  if(!nativeOwner())throw Error("Native same-user macOS required.");
  verifiedEndpoint(endpoint);
  if(!SHA.test(sourceSha))throw Error("Reviewed source commit required.");
  await checked(home,{dir:true,privateOnly:false});
  const base=path.join(home,ROOT),mac=path.join(base,"macos");
  const programs=path.join(mac,"programs");
  for(const dir of [base,mac,programs])await checked(dir,{dir:true});
  const key=path.join(base,"v2-identity.pem"),device=key+".device-id";
  await checked(key,{mode:0o600});await checked(device,{mode:0o600});
  if(!ID.test((await readFile(device,"utf8")).trim()))
    throw Error("Existing permanent identity required.");
  const saved=path.join(mac,"endpoint");
  await checked(saved,{mode:0o600});
  if((await readFile(saved,"utf8")).trim()!==endpoint)
    throw Error("Endpoint identity mismatch.");
  const plist=path.join(home,"Library","LaunchAgents",LABEL+".plist");
  await checked(plist,{mode:0o600});
  const old= parsePlist(await readFile(plist,"utf8"),programs,endpoint);
  const cli=path.join(home,".local","bin","rca");
  await checked(cli,{mode:0o700});
  if((await readFile(cli,"utf8"))!==ownerCliText(old.root))
    throw Error("Unrecognized installed local CLI.");
  for(const key of ["stopped","switch.json"]){
    if(await checked(path.join(mac,key),{mode:0o600,optional:true}))
      throw Error("Owner-stop or unresolved upgrade; remote switch forbidden.");
  }
  const receipts=path.join(home,".local","state","mcp-workers","remote-control-agent","operation-receipts.sqlite");
  await checked(receipts,{mode:0o600});
  const live=invoke("/bin/launchctl",["print","gui/"+process.getuid()+"/"+LABEL]);
  if(live.error||live.status!==0)
    throw Error("Existing LaunchAgent not confirmed running.");
  const pidMatch=String(live.stdout??"").match(/(?:^|\n)\s*pid = ([1-9][0-9]*)(?:\n|$)/);
  if(!pidMatch)throw Error("Active LaunchAgent PID unconfirmed.");
  const conn=path.join(base,"macos-connection.json");
  await checked(conn,{mode:0o600});
  const c=JSON.parse(await readFile(conn,"utf8"));
  // The authenticated connection marker is written on connection, not on
  // every heartbeat; validate the live launchd PID instead of a short TTL.
  if(c.generation!==old.generation||c.state!=="connected"||
     c.pid!==Number(pidMatch[1])||!Number.isFinite(Date.parse(c.at))||
     Date.parse(c.at)>Date.now()+10000)
    throw Error("LaunchAgent and signed WSS connection record inconsistent.");
  const version=await checkCandidate(bundle,sourceSha);
  if(!forwardMacVersion(path.basename(old.root),version))
    throw Error("Remote downgrade or non-forward version is not permitted.");
  if(await exists(path.join(programs,version)))
    throw Error("Target already staged; inspect before replay.");
  return {base,mac,programs,version,old};
}
// The submitting Remote Control command is still an in-flight operation for a
// short interval after launchctl accepts the one-shot job. Wait only for the
// read-only "busy" admission result; never retry an uncertain response or the
// actual upgrade/switch. Freeze remains atomic in the original Agent.
export async function awaitCallerQuiescence(freezeAgent,key,{
  attempts=30,pause=ms=>new Promise(resolve=>setTimeout(resolve,ms)),
}={}){
  for(let i=0;i<attempts;i++){
    const result=await freezeAgent(key);
    if(result!=="busy")return result;
    if(i+1<attempts)await pause(250);
  }
  return "busy";
}
async function record(file,contents){
  await writeFile(file,JSON.stringify(contents)+"\n",{flag:"wx",mode:0o600});
}
export async function dispatchRemoteMacUpgrade({home=os.homedir(),bundle,sourceSha,endpoint,invoke=run}={}){
  process.umask(0o077);
  const t=await trustedExisting(home,endpoint,bundle,sourceSha,invoke);
  const id=randomUUID(),label=remoteJobLabel(id);
  const tasks=path.join(t.mac,"remote-upgrades");
  await ownedDirectory(tasks);
  const active=path.join(tasks,"active.json");
  if(await exists(active))throw Error("Unreconciled remote upgrade operation; inspect before retry.");
  const dir=path.join(tasks,id);
  await mkdir(dir,{mode:0o700});await checked(dir,{dir:true});
  const staged=path.join(dir,"bundle");
  // Write the single durable idempotency marker before staging and submission.
  await record(active,{id,label,version:t.version,state:"preparing"});
  await cp(bundle,staged,{recursive:true,force:false,errorOnExist:true});
  await checked(staged,{dir:true});
  if(await checkCandidate(staged,sourceSha)!==t.version)
    throw Error("Staged candidate identity mismatch.");
  await record(path.join(dir,"context.json"),{id,label,version:t.version,
    sourceSha,endpoint,state:"owner_authorized_remote_upgrade"});
  const node=path.join(staged,"bin","node");
  const worker=path.join(staged,"apps","remote-control-agent","scripts","macos-remote-upgrade.mjs");
  await checked(node,{mode:0o700});await checked(worker,{mode:0o600});
  // bootstrap loads an owner-private once-only launchd job outside the
  // Agent-managed Shell. Unlike submit, failure must never restart it.
  const job=path.join(dir,"job.plist");
  // The job is XML, not a JSON receipt. Preserve raw plist bytes.
  await writeFile(job,remoteJobPlist(id,node,worker,dir),{flag:"wx",mode:0o600});
  await checked(job,{mode:0o600});
  const sent=invoke("/bin/launchctl",["bootstrap","gui/"+process.getuid(),job]);
  if(sent.error||sent.signal||sent.status!==0)
    throw Error("Detached launchd submission unconfirmed; preserve operation for inspection.");
  return {status:"launched",operation_id:id,version:t.version,
    verification:"independent signed WSS and unchanged identity required"};
}
export async function runRemoteMacUpgrade(id,{home=os.homedir(),invoke=run,ppid=process.ppid,online,freezeAgent}={}){
  if(!nativeOwner()||!verifiedLaunchdJob(id,process.getuid(),process.pid,invoke,ppid))
    throw Error("Not an authorized one-shot owner launchd job.");
  const tasks=path.join(home,ROOT,"macos","remote-upgrades");
  const dir=path.join(tasks,id);
  await checked(tasks,{dir:true});await checked(dir,{dir:true});
  const resultFile=path.join(dir,"result.json");
  if(await exists(resultFile))throw Error("Upgrade already attempted; do not replay.");
  const marker=path.join(tasks,"active.json"),context=path.join(dir,"context.json");
  await checked(marker,{mode:0o600});await checked(context,{mode:0o600});
  const state=JSON.parse(await readFile(marker,"utf8"));
  const plan=JSON.parse(await readFile(context,"utf8"));
  if(state.id!==id||state.label!==remoteJobLabel(id)||
     plan.id!==id||plan.label!==state.label||plan.version!==state.version||
     plan.state!=="owner_authorized_remote_upgrade"||!SHA.test(plan.sourceSha))
    throw Error("One-shot upgrade context is inconsistent.");
  const bundle=path.join(dir,"bundle");
  // The existing approved native upgrade freezes operations and rolls back
  // uncertain activation; its only bypass is this verified launchd context.
  try{
    const existingFreeze=freezeAgent??freeze;
    const handoff=(key,command)=>command
      ?existingFreeze(key,command)
      :awaitCallerQuiescence(existingFreeze,key);
    const out=await localMacAction("upgrade",{home,bundle,
      sourceSha:plan.sourceSha,endpoint:plan.endpoint,invoke,online,
      freezeAgent:handoff,ask:async()=>true});
    if(out.status!=="connected_observed"||out.version!==plan.version)
      throw Error("Signed activation not confirmed.");
    await record(resultFile,{status:"connected_observed",version:out.version,id});
    // A verified completed worker may clear the admission marker. Audited
    // per-operation result and task files remain for independent review.
    if((JSON.parse(await readFile(marker,"utf8"))).id===id)await rm(marker);
    return {status:"connected_observed",version:out.version,id};
  }catch{
    await record(resultFile,{status:"needs_attention",id});
    throw Error("Detached upgrade needs inspection; no blind retry.");
  }
}
async function main(){
  const [action,...args]=process.argv.slice(2);
  if(action==="worker"&&args.length===1){
    process.stdout.write(JSON.stringify(await runRemoteMacUpgrade(args[0]))+"\n");return;
  }
  if(action==="dispatch"&&args.length===6&&args[0]==="--bundle"&&
     args[2]==="--source-sha"&&args[4]==="--endpoint"){
    process.stdout.write(JSON.stringify(await dispatchRemoteMacUpgrade({
      bundle:args[1],sourceSha:args[3],endpoint:args[5]}))+"\n");return;
  }
  throw Error("Unsupported remote upgrade action.");
}
if(process.argv[1]&&realpathSync(process.argv[1])===
  realpathSync(fileURLToPath(import.meta.url))){
  try{await main();}catch{
    process.stderr.write("Remote macOS upgrade blocked; inspect owner state.\n");
    process.exitCode=1;
  }
}
