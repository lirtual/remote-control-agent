/** #660 reviewed offline, owner-only macOS LaunchAgent install/upgrade candidate. */
import {createConnection} from "node:net";
import {randomUUID} from "node:crypto";
import {spawnSync} from "node:child_process";
import {cp,lstat,mkdir,readFile,rename,rm,writeFile} from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import {fileURLToPath} from "node:url";
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
async function checkCandidate(bundle,sha){
  if(!path.isAbsolute(bundle))throw Error("Bundle must be absolute.");
  await checked(bundle,{dir:true});
  const manifest=path.join(bundle,"bundle.json");
  await checked(manifest,{mode:0o600});
  const name=candidateName(JSON.parse(await readFile(manifest,"utf8")),sha);
  for(const [relative,mode] of [
    ["bin/node",0o700],["apps/remote-control-agent/.build/darwin-session-supervisor",0o700],
    ["apps/remote-control-agent/src/macos-permanent.js",0o600],
    ["apps/remote-control-agent/scripts/macos-local.mjs",0o600]
  ])await checked(path.join(bundle,relative),{mode});
  return name;
}
const run=(command,args)=>spawnSync(command,args,{encoding:"utf8",timeout:10000,maxBuffer:65536});
const launch=(args,invoke)=>{const r=invoke("/bin/launchctl",args);return !r.error&&r.status===0;};
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
async function ownedWrite(file,content,replace=false){
  await checked(path.dirname(file),{dir:true});
  if(replace)await checked(file,{mode:0o600});
  else if(await statMaybe(file))throw Error("Owned file already exists.");
  const temp=path.join(path.dirname(file),".new-"+randomUUID());
  await writeFile(temp,content,{flag:"wx",mode:0o600});
  try{await rename(temp,file);}catch(e){await rm(temp,{force:true});throw e;}
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
async function confirm(question){
  if(!process.stdin.isTTY||!process.stdout.isTTY)throw Error("Owner terminal required.");
  process.stdout.write(question+" Enter YES: ");
  return await new Promise(resolve=>{
    process.stdin.resume();
    process.stdin.once("data",data=>{process.stdin.pause();resolve(String(data).trim()==="YES");});
  });
}
/** Host mutation only after local owner consent and a pinned source candidate. */
export async function localMacAction(action,{home=os.homedir(),bundle,sourceSha,endpoint,
  invoke=run,ask=confirm,online=observeOnline,freezeAgent=freeze}={}){
  if(!["install","upgrade","status","stop","start"].includes(action))
    throw Error("Unsupported local action.");
  if(process.platform!=="darwin"||!["arm64","x64"].includes(process.arch)||
    Number.parseInt(os.release(),10)<24||process.getuid?.()===0)
    throw Error("Native unprivileged macOS 15+ ARM64 or x64 required.");
  process.umask(0o077);
  await checked(home,{dir:true,privateOnly:false});
  const identity=await directories(home,ROOT);
  const receipts=await directories(home,[".local","state","mcp-workers","remote-control-agent"]);
  await checked(path.join(receipts,"operation-receipts.sqlite"),{optional:true,mode:0o600});
  const macos=await directories(home,[...ROOT,"macos"]);
  const programs=await directories(home,[...ROOT,"macos","programs"]);
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
  if(action==="status")return {
    installed:!!current,version:current?path.basename(current.root):null,
    local_service:current?(stopped?"stopped_requested_unverified":"present_unverified"):"not_installed",
    cloud_approval:"unconfirmed",signed_wss:"unconfirmed",
    last_online:"unconfirmed",receipts:"preserved_unverified",
  };
  if(action==="stop"){
    if(!current)throw Error("LaunchAgent absent.");
    if(!await ask("Intentionally stop this user LaunchAgent?"))throw Error("Owner declined.");
    if(launch(["print",service],invoke)&&!launch(["bootout",service],invoke))
      throw Error("Service bootout uncertain; no stopped marker created.");
    await ownedWrite(stopMark,"stopped\n",stopped);
    return {status:"intentionally_stopped"};
  }
  if(action==="start"){
    if(!current||!stopped)throw Error("No deliberately stopped owned service.");
    if(!await ask("Resume the previously stopped LaunchAgent?"))throw Error("Owner declined.");
    if(!launch(["bootstrap",domain,plist],invoke))
      throw Error("LaunchAgent bootstrap failed.");
    if(!await online(identity,current.generation)){
      if(!launch(["bootout",service],invoke))
        throw Error("UNKNOWN stopped-state recovery; owner inspection required.");
      throw Error("Signed WSS activation unconfirmed; prior stopped state retained.");
    }
    await rm(stopMark);
    return {status:"connected_observed"};
  }
  if(!bundle||!sourceSha||!bound)throw Error("Reviewed candidate, source and endpoint required.");
  if(action==="install"&&current)throw Error("Existing identity requires upgrade.");
  if(stopped&&current&&launch(["print",service],invoke))
    throw Error("Stopped marker conflicts with an active service; inspect locally.");
  if(action==="upgrade"&&!current)throw Error("No existing permanent LaunchAgent.");
  const version=await checkCandidate(bundle,sourceSha);
  const nextRoot=path.join(programs,version);
  if(await statMaybe(nextRoot))throw Error("Version directory already exists; no overwrite.");
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
  let journalCreated=false,oldStopped=false,newLoaded=false;
  try{
    await ownedWrite(journal,JSON.stringify({
      version,previous:old,generation,stopped,phase:"switch_pending"})+"\n");
    journalCreated=true;
    if(active){
      if(!launch(["bootout",service],invoke))throw Error("Old service bootout failed.");
      oldStopped=true;
    }
    await ownedWrite(plist,next,!!old);
    if(!stored)await ownedWrite(endpointFile,bound+"\n");
    if(!stopped){
      if(!launch(["bootstrap",domain,plist],invoke))
        throw Error("New LaunchAgent bootstrap failed.");
      newLoaded=true;
      if(!await online(identity,generation))throw Error("New signed WSS activation unconfirmed.");
    }
    await rm(journal);
    return {status:stopped?"stopped_preserved":"connected_observed",version,generation};
  }catch(error){
    if(!journalCreated&&frozen){
      try{await freezeAgent(key,"release");}catch{/* only safe to reconcile */}
    }
    if(!journalCreated)throw error;
    try{
      if(newLoaded&&!launch(["bootout",service],invoke))
        throw Error("New service cannot be stopped.");
      if(old)await ownedWrite(plist,old,true);
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
    throw Error("Upgrade blocked; previous service restored where verified.");
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
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
  try{await main();}catch(e){
    process.stderr.write("macOS local action blocked: "+
      (e instanceof Error?e.message:"unknown")+".\n");process.exitCode=1;
  }
}
