/** #660 reviewed offline, owner-only macOS LaunchAgent install/upgrade candidate. */
import {createConnection} from "node:net";
import {randomUUID} from "node:crypto";
import {spawnSync} from "node:child_process";
import {cp,lstat,mkdir,readFile,rename,rm,writeFile} from "node:fs/promises";
import {realpathSync} from "node:fs";
import path from "node:path";
import os from "node:os";
import {fileURLToPath,pathToFileURL} from "node:url";
const LABEL="org.mcp-workers.remote-control-agent";
const ID=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const SHA=/^[a-f0-9]{40}$/, VERSION=/^v\d+\.\d+\.\d+(?:-[a-z0-9.-]+)?$/;
const ROOT=[".local","share","mcp-workers","remote-control"];
export function verifiedEndpoint(raw){
  if(typeof raw!=="string")throw Error("Missing trusted HTTPS endpoint.");
  const u=new URL(raw);
  if(u.protocol!=="https:"||u.username||u.password||u.search||u.hash||
    u.pathname!=="/"||u.port||u.origin+"/"!==raw)throw Error("Untrusted Worker endpoint.");
  return raw;
}
async function statMaybe(name){try{return await lstat(name);}catch(e){if(e.code==="ENOENT")return null;throw e;}}
export async function checked(name,{dir=false,mode,optional=false,privateOnly=true}={}){
  const st=await statMaybe(name);
  if(!st){if(optional)return false;throw Error("Missing owned path.");}
  if(st.isSymbolicLink()||st.uid!==process.getuid?.()||
    (dir?!st.isDirectory():!st.isFile())||
    (st.mode&(privateOnly?0o077:0o022))!==0||
    (!dir&&st.nlink!==1)||(mode!==undefined&&(st.mode&0o777)!==mode))
    throw Error("Unsafe owner, type or mode.");
  return true;
}
async function directories(home,parts){
  let cursor=home;
  for(const [i,part] of parts.entries()){
    cursor=path.join(cursor,part);
    try{await mkdir(cursor,{mode:0o700});}catch(e){if(e.code!=="EEXIST")throw e;}
    await checked(cursor,{dir:true,privateOnly:i>=2});
  }
  return cursor;
}
export function plistText({node,entry,endpoint,generation}){
  verifiedEndpoint(endpoint);
  if(!ID.test(generation))throw Error("Invalid generation.");
  const esc=s=>s.replaceAll("&","&amp;").replaceAll("<","&lt;")
    .replaceAll(">","&gt;").replaceAll('"',"&quot;").replaceAll("'","&apos;");
  return '<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0"><dict>\n'+
    '<key>Label</key><string>'+LABEL+'</string>\n'+
    '<key>ProgramArguments</key><array>'+
    [node,entry,"--service","--endpoint",endpoint,"--generation",generation]
      .map(x=>'<string>'+esc(x)+'</string>').join("")+'</array>\n'+
    '<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>\n</dict></plist>\n';
}
export function parsePlist(xml,programs,endpoint,arch=process.arch){
  const tokens=[...xml.matchAll(/<string>([^<>]*)<\/string>/g)].map(m=>m[1]
    .replaceAll("&apos;","'").replaceAll("&quot;",'"').replaceAll("&gt;",">")
    .replaceAll("&lt;","<").replaceAll("&amp;","&"));
  if(tokens.length!==8||tokens[0]!==LABEL||tokens[3]!=="--service"||
    tokens[4]!=="--endpoint"||tokens[5]!==endpoint||
    tokens[6]!=="--generation"||!ID.test(tokens[7])||
    !xml.includes("<key>RunAtLoad</key><true/>")||
    !xml.includes("<key>KeepAlive</key><true/>"))
    throw Error("Foreign or ambiguous LaunchAgent.");
  const node=tokens[1],entry=tokens[2],root=path.dirname(path.dirname(node));
  const name=path.basename(root);
  const suffix="-darwin-"+arch;
  if(!["x64","arm64"].includes(arch)||path.dirname(root)!==programs||
    !name.endsWith(suffix)||!VERSION.test(name.slice(0,-suffix.length))||
    node!==path.join(root,"bin/node")||
    entry!==path.join(root,"apps/remote-control-agent/src/macos-permanent.js"))
    throw Error("LaunchAgent points outside owned candidate.");
  if(xml!==plistText({node,entry,endpoint,generation:tokens[7]}))
    throw Error("Unexpected LaunchAgent configuration.");
  return {root,generation:tokens[7]};
}
export function candidateName(meta,sha,arch=process.arch){
  if(!SHA.test(sha)||meta.source_commit!==sha||!VERSION.test(meta.version)||
    !["arm64","x64"].includes(arch)||meta.target!=="darwin-"+arch||
    meta.artifact_schema!==1||
    meta.device_protocol!==2||meta.receipt_schema!==1||
    meta.candidate_profile!=="darwin-permanent-local-v1"||
    meta.native_supervisor!=="darwin-owned-group-v1"||
    !Array.isArray(meta.modules)||!meta.modules.includes("macos-permanent.ts"))
    throw Error("Unexpected source commit, architecture or manifest.");
  return meta.version+"-darwin-"+arch;
}
export async function checkCandidate(bundle,sha){
  if(!path.isAbsolute(bundle))throw Error("Bundle must be absolute.");
  await checked(bundle,{dir:true});
  const manifest=path.join(bundle,"bundle.json");
  await checked(manifest,{mode:0o600});
  const name=candidateName(JSON.parse(await readFile(manifest,"utf8")),sha);
  for(const [relative,mode] of [
    ["bin/node",0o700],["apps/remote-control-agent/.build/darwin-session-supervisor",0o700],
    ["apps/remote-control-agent/src/macos-permanent.js",0o600],
    ["apps/remote-control-agent/src/v2-session-client.js",0o600],
    ["apps/remote-control-agent/scripts/macos-local.mjs",0o600]
  ])await checked(path.join(bundle,relative),{mode});
  return name;
}
const run=(command,args)=>spawnSync(command,args,{encoding:"utf8",timeout:10000,maxBuffer:65536});
const launch=(args,invoke)=>{const r=invoke("/bin/launchctl",args);return !r.error&&r.status===0;};
// print can fail for reasons other than deregistration. Only the observed
// launchd "not found" result proves this user service has been removed.
export function launchctlServiceState(service,invoke){
  const r=invoke("/bin/launchctl",["print",service]);
  if(!r.error&&r.status===0)return "present";
  if(!r.error&&r.status===113&&/Could not find service/.test(String(r.stderr??"")))
    return "absent";
  return "unknown";
}
// bootout may acknowledge while launchd is still asynchronously removing its
// registration. Two read-only absent observations, bounded to 10 s; never
// repeat bootstrap blindly, and never confuse an unknown state with absence.
export async function awaitLaunchctlUnregistered(service,invoke,
  pause=ms=>new Promise(resolve=>setTimeout(resolve,ms))){
  let absent=0;
  for(let i=0;i<40;i++){
    const state=launchctlServiceState(service,invoke);
    if(state==="unknown")throw Error("LaunchAgent deregistration state unknown.");
    if(state==="absent"){
      if(++absent===2)return true;
    }else absent=0;
    if(i<39)await pause(250);
  }
  return false;
}
// A successful bootout merely acknowledges a launchd request. A subsequent
// bootstrap must not race the old registration's asynchronous removal.
export async function stopLaunchdForSwitch(service,invoke,pause,bootout=true){
  if(bootout&&!launch(["bootout",service],invoke))
    throw Error("LaunchAgent bootout unconfirmed.");
  if(!await awaitLaunchctlUnregistered(service,invoke,pause))
    throw Error("LaunchAgent deregistration not confirmed.");
}
export async function freeze(key,command="freeze"){
  const socketPath=path.join(path.dirname(key),"upgrade.sock");
  await checked(socketPath,{optional:false}).catch(async e=>{
    const st=await statMaybe(socketPath);
    if(!st||!st.isSocket()||st.uid!==process.getuid?.()||(st.mode&0o077)!==0)throw e;
  });
  return await new Promise((resolve,reject)=>{
    const socket=createConnection(socketPath);let finished=false,buffer="";
    const done=(err,result)=>{
      if(finished)return;finished=true;clearTimeout(timer);socket.destroy();
      if(err)reject(err);else resolve(result);
    };
    const timer=setTimeout(()=>done(Error("Freeze timeout.")),3000);
    socket.on("connect",()=>socket.write(command+"\n"));
    socket.on("data",chunk=>{buffer+=String(chunk);if(buffer.includes("\n"))done(null,buffer.trim());});
    socket.on("error",err=>done(err));
    socket.on("end",()=>done(null,buffer.trim()));
  });
}
export async function ownedWrite(file,content,replace=false,mode=0o600,parentPrivate=true){
  // Keep sensitive RCA directories private; LaunchAgents/bin only forbid outside writes.
  await checked(path.dirname(file),{dir:true,privateOnly:parentPrivate});
  if(replace)await checked(file,{mode});
  else if(await statMaybe(file))throw Error("Owned file already exists.");
  const temp=path.join(path.dirname(file),".new-"+randomUUID());
  await writeFile(temp,content,{flag:"wx",mode});
  try{await rename(temp,file);}catch(e){await rm(temp,{force:true});throw e;}
}
// Local CLI is a version-pinned, owner-private dispatch only. Upgrades must
// still use the separately reviewed, SHA-pinned offline installer.
export function ownerCliText(root){
  const quote=value=>"'"+value.replaceAll("'","'\"'\"'")+"'";
  const node=path.join(root,"bin/node");
  const manager=path.join(root,"apps/remote-control-agent/scripts/macos-local.mjs");
  return '#!/bin/sh\nset -eu\ncase "${1:-}" in\n'+
    '  status|stop|start) [ "$#" -eq 1 ] || exit 2 ;;\n'+
    '  *) echo "Use the reviewed macOS installer for install/upgrade." >&2; exit 2 ;;\n'+
    'esac\nexec '+quote(node)+' '+quote(manager)+' "$1"\n';
}
async function approved(key){
  if(!await checked(key,{optional:true,mode:0o600})||
     !await checked(key+".device-id",{optional:true,mode:0o600}))return false;
  return ID.test((await readFile(key+".device-id","utf8")).trim());
}
export async function observeOnline(identity,generation,now=Date.now){
  const start=now(),file=path.join(identity,"macos-connection.json");
  for(let i=0;i<50;i++){
    if(await checked(file,{optional:true,mode:0o600})){
      const r=JSON.parse(await readFile(file,"utf8"));
      if(r.generation===generation&&r.state==="connected"&&Date.parse(r.at)>=start-3000)return true;
      if(r.generation===generation&&r.state==="rejected")return false;
    }
    await new Promise(resolve=>setTimeout(resolve,200));
  }
  return false;
}
export function acceptsOwnerConfirmation(input){
  return /^(?:y|yes)$/i.test(input.trim());
}
async function confirm(question){
  if(!process.stdin.isTTY||!process.stdout.isTTY)throw Error("Owner terminal required.");
  process.stdout.write(question+" Confirm [y/N]: ");
  return await new Promise(resolve=>{
    process.stdin.resume();
    process.stdin.once("data",data=>{
      process.stdin.pause();resolve(acceptsOwnerConfirmation(String(data)));
    });
  });
}
/** Host mutation only after local owner consent and a pinned source candidate. */
export async function localMacAction(action,{home=os.homedir(),bundle,sourceSha,endpoint,
  invoke=run,ask=confirm,online=observeOnline,freezeAgent=freeze,ownerIntent,
  runTemporary=spawnSync,terminal=()=>!!(process.stdin.isTTY&&process.stdout.isTTY),
  pauseLaunchd=ms=>new Promise(resolve=>setTimeout(resolve,ms))}={}){
  if(!["install","upgrade","status","stop","start","temporary"].includes(action))
    throw Error("Unsupported local action.");
  if(process.platform!=="darwin"||!["arm64","x64"].includes(process.arch)||
    Number.parseInt(os.release(),10)<24||process.getuid?.()===0)
    throw Error("Native unprivileged macOS 15+ ARM64 or x64 required.");
  process.umask(0o077);
  if(action==="temporary"){
    // Reuse the signed 24-hour foreground Agent: no LaunchAgent, no service
    // state mutation and no extra permanent identity or registration.
    if(!terminal())throw Error("Owner terminal required for temporary pairing.");
    if(!bundle||!sourceSha||!endpoint)throw Error("Reviewed temporary candidate required.");
    const origin=verifiedEndpoint(endpoint);
    await checkCandidate(bundle,sourceSha);
    const node=path.join(bundle,"bin/node");
    const entry=path.join(bundle,"apps/remote-control-agent/src/macos-temporary.js");
    await checked(entry,{mode:0o600});
    const result=runTemporary(node,[entry,"--endpoint",origin,"--bootstrap-selected"],
      {stdio:"inherit"});
    if(result.error||result.signal||result.status!==0)
      throw Error("Temporary Agent ended without confirmed success.");
    return {status:"temporary_session_ended"};
  }
  await checked(home,{dir:true,privateOnly:false});
  const identity=await directories(home,ROOT);
  const receipts=await directories(home,[".local","state","mcp-workers","remote-control-agent"]);
  await checked(path.join(receipts,"operation-receipts.sqlite"),{optional:true,mode:0o600});
  const macos=await directories(home,[...ROOT,"macos"]);
  const programs=await directories(home,[...ROOT,"macos","programs"]);
  const localBin=await directories(home,[".local","bin"]);
  const cli=path.join(localBin,"rca");
  const agents=await directories(home,["Library","LaunchAgents"]);
  const plist=path.join(agents,LABEL+".plist");
  const stopMark=path.join(macos,"stopped"), journal=path.join(macos,"switch.json");
  if(await checked(journal,{optional:true,mode:0o600}))
    throw Error("Unresolved upgrade journal: manual reconciliation required.");
  const old=await checked(plist,{optional:true,mode:0o600})
    ?await readFile(plist,"utf8"):null;
  const endpointFile=path.join(macos,"endpoint");
  const stored=await checked(endpointFile,{optional:true,mode:0o600})
    ?(await readFile(endpointFile,"utf8")).trim():null;
  if(stored)verifiedEndpoint(stored);
  if(endpoint)verifiedEndpoint(endpoint);
  if(stored&&endpoint!==undefined&&stored!==endpoint)
    throw Error("Endpoint identity cannot change during upgrade.");
  const bound=endpoint??stored;
  const current=old?parsePlist(old,programs,bound):null;
  const previousCli=await checked(cli,{optional:true,mode:0o700})
    ?await readFile(cli,"utf8"):null;
  // Never replace a foreign executable, symlink or mismatched owner version.
  if(previousCli!==null&&(!current||previousCli!==ownerCliText(current.root)))
    throw Error("Foreign or inconsistent local rca executable.");
  if(current){
    for(const rel of ["", "bin", "apps", "apps/remote-control-agent",
        "apps/remote-control-agent/src"])
      await checked(path.join(current.root,rel),{dir:true});
    for(const rel of ["bin/node","apps/remote-control-agent/src/macos-permanent.js"])
      await checked(path.join(current.root,rel),{mode:rel==="bin/node"?0o700:0o600});
  }
  const stopped=await checked(stopMark,{optional:true,mode:0o600});
  const service="gui/"+process.getuid()+"/"+LABEL,domain="gui/"+process.getuid();
  const key=path.join(identity,"v2-identity.pem");
  const signedIntent=async(action)=>{
    if(ownerIntent)return ownerIntent(action);
    if(!current||!bound||!await approved(key))throw Error("Approved permanent identity required.");
    const modulePath=path.join(current.root,"apps/remote-control-agent/src/v2-session-client.js");
    await checked(modulePath,{mode:0o600});
    const {sendSignedOwnerIntent}=await import(pathToFileURL(modulePath).href);
    if(typeof sendSignedOwnerIntent!=="function")throw Error("Candidate does not support owner intent.");
    return sendSignedOwnerIntent(bound,key,action);
  };
  if(action==="status")return {
    installed:!!current,version:current?path.basename(current.root):null,
    local_service:current?(stopped?"stopped_requested_unverified":"present_unverified"):"not_installed",
    cloud_approval:"unconfirmed",signed_wss:"unconfirmed",
    last_online:"unconfirmed",receipts:"preserved_unverified",
  };
  if(action==="stop"){
    if(!current||!await approved(key))throw Error("Existing approved LaunchAgent required.");
    if(!await ask("Intentionally stop this user LaunchAgent?"))throw Error("Owner declined.");
    // Durable OFF intent precedes service shutdown; even crash/reboot/upgrade respects it.
    await ownedWrite(stopMark,"stopped\n",stopped);
    let cloud="unconfirmed";
    try {await signedIntent('stop');cloud="confirmed";}catch{/* Local OFF still required. */}
    const serviceState=launchctlServiceState(service,invoke);
    if(serviceState==="unknown")throw Error("LaunchAgent state uncertain; owner STOP retained.");
    if(serviceState==="present"){
      if(!launch(["bootout",service],invoke))
        throw Error("Service bootout uncertain; owner STOP intent retained.");
      if(!await awaitLaunchctlUnregistered(service,invoke,pauseLaunchd))
        throw Error("LaunchAgent removal pending; owner STOP intent retained.");
    }
    return {status:"intentionally_stopped",cloud};
  }
  if(action==="start"){
    if(!current||!stopped||!await approved(key))throw Error("No deliberately stopped approved LaunchAgent.");
    if((await readFile(stopMark,"utf8"))!=="stopped\n")throw Error("Unsafe persisted owner STOP.");
    if(!await ask("Resume the previously stopped LaunchAgent?"))throw Error("Owner declined.");
    if(launchctlServiceState(service,invoke)!=="absent")
      throw Error("LaunchAgent registration not confirmed absent; owner STOP retained.");
    await signedIntent('stop'); // reconcile offline Stop first without extending cloud deadline
    const permitted=await signedIntent('resume');
    if(permitted.status!=="resume_pending")throw Error("Signed cloud Resume not authorized.");
    await rm(stopMark);
    try{
      const boot=invoke("/bin/launchctl",["bootstrap",domain,plist]);
      if(boot.error||boot.status!==0)
        throw Error("LaunchAgent bootstrap failed (exit="+
          (Number.isInteger(boot.status)?boot.status:"unknown")+").");
      if(!await online(identity,current.generation))throw Error("Signed WSS activation unconfirmed.");
    }catch(error){
      const state=launchctlServiceState(service,invoke);
      // Retain the user's OFF request even if launchd cleanup is uncertain.
      await ownedWrite(stopMark,"stopped\n");
      if(state==="unknown")throw Error("UNKNOWN stopped-state recovery; owner inspection required.");
      if(state==="present"&&!launch(["bootout",service],invoke))
        throw Error("UNKNOWN stopped-state recovery; owner inspection required.");
      if(!await awaitLaunchctlUnregistered(service,invoke,pauseLaunchd))
        throw Error("UNKNOWN stopped-state recovery; owner inspection required.");
      throw error;
    }
    return {status:"connected_observed",cloud:"signed_WSS_observed"};
  }
  if(!bundle||!sourceSha||!bound)throw Error("Reviewed candidate, source and endpoint required.");
  if(action==="install"&&current)throw Error("Existing identity requires upgrade.");
  if(stopped&&current&&launch(["print",service],invoke))
    throw Error("Stopped marker conflicts with an active service; inspect locally.");
  if(action==="upgrade"&&!current)throw Error("No existing permanent LaunchAgent.");
  const version=await checkCandidate(bundle,sourceSha);
  const nextRoot=path.join(programs,version);
  if(await statMaybe(nextRoot))throw Error("Reviewed candidate already staged; never overwrite. " +
    "Inspect existing state and use a separately verified newer candidate; " +
    "the existing permanent identity and receipts remain unchanged.");
  if(!await ask("Install "+version+" into this personal Mac account?"))throw Error("Owner declined.");
  if(action==="upgrade"&&!await approved(key))
    throw Error("Approved key missing; never automatically re-pair.");
  // Stage the verified candidate side by side; never overwrite old binaries.
  const stage=path.join(programs,".staging-"+randomUUID());
  await cp(bundle,stage,{recursive:true,errorOnExist:true,force:false});
  await checked(stage,{dir:true});
  await rename(stage,nextRoot);
  if(!await approved(key)){
    if(action!=="install")throw Error("Upgrade cannot create a new identity.");
    const pair=spawnSync(path.join(nextRoot,"bin/node"),[
      path.join(nextRoot,"apps/remote-control-agent/src/macos-permanent.js"),
      "--endpoint",bound],{stdio:"inherit",timeout:660000});
    if(pair.error||pair.status!==0||!await approved(key))
      throw Error("Owner approval incomplete; staged candidate remains offline.");
  }
  const active=!!current&&!stopped&&launch(["print",service],invoke);
  if(current&&!stopped&&!active)throw Error("Service state uncertain; refuse upgrade.");
  let frozen=false;
  if(active){
    if(await freezeAgent(key)!=="ready")throw Error("Busy or uncertain Agent; refuse switch.");
    frozen=true;
  }
  const generation=randomUUID();
  const next=plistText({
    node:path.join(nextRoot,"bin/node"),
    entry:path.join(nextRoot,"apps/remote-control-agent/src/macos-permanent.js"),
    endpoint:bound,generation,
  });
  let journalCreated=false,oldStopped=false,newLoaded=false,cliWritten=false;
  let failureStage="write-switch-journal";
  try{
    await ownedWrite(journal,JSON.stringify({
      version,previous:old,generation,stopped,phase:"switch_pending"})+"\n");
    journalCreated=true;
    if(active){
      failureStage="stop-old-service";
      if(!launch(["bootout",service],invoke))throw Error("Old service bootout failed.");
      oldStopped=true;
      failureStage="wait-old-service-unregistered";
      await stopLaunchdForSwitch(service,invoke,pauseLaunchd,false);
    }
    failureStage="write-launchagent";
    await ownedWrite(plist,next,!!old,0o600,false);
    failureStage="write-endpoint";
    if(!stored)await ownedWrite(endpointFile,bound+"\n");
    if(!stopped){
      failureStage="launchagent-bootstrap";
      if(!launch(["bootstrap",domain,plist],invoke))
        throw Error("New LaunchAgent bootstrap failed.");
      newLoaded=true;
      failureStage="signed-wss-activation";
      if(!await online(identity,generation))throw Error("New signed WSS activation unconfirmed.");
    }
    failureStage="write-cli";
    await ownedWrite(cli,ownerCliText(nextRoot),previousCli!==null,0o700,false);
    cliWritten=true;
    failureStage="finalize-journal";
    await rm(journal);
    return {status:stopped?"stopped_preserved":"connected_observed",version,generation,
      cli};
  }catch(error){
    if(!journalCreated&&frozen){
      try{await freezeAgent(key,"release");}catch{/* only safe to reconcile */}
    }
    if(!journalCreated)throw error;
    try{
      if(cliWritten){
        if(previousCli!==null)await ownedWrite(cli,previousCli,true,0o700,false);
        else await rm(cli);
      }
      if(newLoaded){
        await stopLaunchdForSwitch(service,invoke,pauseLaunchd);
      }else if(oldStopped){
        // A failed bootstrap can still leave a registration asynchronously
        // arriving. Never overwrite the plist and bootstrap old over it.
        const state=launchctlServiceState(service,invoke);
        if(state==="unknown")throw Error("Uncertain new-service registration.");
        await stopLaunchdForSwitch(service,invoke,pauseLaunchd,state==="present");
      }
      if(old)await ownedWrite(plist,old,true,0o600,false);
      else if(await checked(plist,{optional:true,mode:0o600}))await rm(plist);
      if(oldStopped){
        if(!launch(["bootstrap",domain,plist],invoke)||
           !await online(identity,current.generation))
          throw Error("Old signed service not restored.");
      }else if(frozen){
        await freezeAgent(key,"release");
      }
      await rm(journal);
    }catch{
      throw Error("UNKNOWN rollback: journal, key and receipts retained for manual inspection.");
    }
    // Do not expose arbitrary OS exception text that may include sensitive paths.
    const reason=error instanceof Error&&error.message==="Unsafe owner, type or mode."
      ?"unsafe-owner-or-mode":"operation-failed";
    const recovery=old?"prior LaunchAgent restored where verified"
      :"new LaunchAgent configuration rolled back";
    throw Error((action==="install"?"Install":"Upgrade")+" blocked at "+failureStage+
      " ("+reason+"); "+recovery+". Identity, receipts and staged candidate retained.");
  }
}
async function main(){
  const [action,...params]=process.argv.slice(2);
  const args={};
  for(let i=0;i<params.length;i+=2){
    if(!["--bundle","--source-sha","--endpoint"].includes(params[i])||
      !params[i+1]||Object.hasOwn(args,params[i]))throw Error("Invalid local action parameters.");
    args[params[i]]=params[i+1];
  }
  const result=await localMacAction(action,{
    bundle:args["--bundle"],sourceSha:args["--source-sha"],endpoint:args["--endpoint"]});
  process.stdout.write(JSON.stringify(result)+"\n");
}
// On macOS, $TMPDIR commonly starts with /var while Node's ESM loader
// canonicalizes it to /private/var. Compare canonical paths so a reviewed
// installer never exits 0 without invoking the owner action.
if(process.argv[1]&&realpathSync(process.argv[1])===
    realpathSync(fileURLToPath(import.meta.url))){
  try{await main();}catch(e){
    process.stderr.write("macOS local action blocked: "+
      (e instanceof Error?e.message:"unknown")+".\n");process.exitCode=1;
  }
}
