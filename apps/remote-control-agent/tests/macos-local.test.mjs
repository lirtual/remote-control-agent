import assert from "node:assert/strict";
import {randomUUID} from "node:crypto";
import {chmod,cp,lstat,mkdir,mkdtemp,readFile,rm,symlink,writeFile} from "node:fs/promises";
import {spawnSync} from "node:child_process";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {acceptsOwnerConfirmation,awaitLaunchctlUnregistered,candidateName,checked,launchctlServiceState,localMacAction,ownedWrite,ownerCliText,parsePlist,plistText,verifiedEndpoint} from
  "../scripts/macos-local.mjs";
import {parsePermanentMacArgs} from "../src/macos-permanent.ts";
const ID="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
const ENDPOINT="https://rca.example.test/";
const bundle=process.env.RCA_MACOS_BUNDLE_ROOT;

test("#661 macOS owner installer dispatch must not silently skip a symlinked/aliased entry path",async t=>{
  const root=await mkdtemp(path.join(os.tmpdir(),"rca-mac-entry-alias-"));
  t.after(()=>rm(root,{recursive:true,force:true}));
  const canonical=path.resolve(import.meta.dirname,"../scripts/macos-local.mjs");
  const aliased=path.join(root,"macos-local.mjs");
  await symlink(canonical,aliased);
  const r=spawnSync(process.execPath,[aliased,"unsupported-action"],{
    encoding:"utf8",timeout:5000});
  assert.equal(r.status,1,"aliased executable must actually run the owner action");
  assert.match(r.stderr,/macOS local action blocked: Unsupported local action/);
});

test("#660 owner confirmation is case-insensitive, empty input denies",()=>{
  for(const value of ["y","Y","yes","YES"," Yes "])
    assert.equal(acceptsOwnerConfirmation(value),true);
  for(const value of ["","n","NO","maybe","approve","yess"])
    assert.equal(acceptsOwnerConfirmation(value),false);
});

test("#660 launch locations permit owner 0755 but not group/other writes",async t=>{
  const root=await mkdtemp(path.join(os.tmpdir(),"rca-parent-mode-"));
  t.after(()=>rm(root,{recursive:true,force:true}));
  for(const name of ["LaunchAgents","bin"]){
    const dir=path.join(root,name);
    await mkdir(dir,{mode:0o755});
    await chmod(dir,0o755);
    const file=path.join(dir,"owned-file");
    await assert.rejects(ownedWrite(file,"first",false,0o600),/Unsafe owner/);
    await ownedWrite(file,"first",false,0o600,false);
    assert.equal(await readFile(file,"utf8"),"first");
    assert.equal((await lstat(file)).mode&0o777,0o600);
    await chmod(dir,0o777);
    await assert.rejects(ownedWrite(file,"second",true,0o600,false),/Unsafe owner/);
    assert.equal(await readFile(file,"utf8"),"first");
  }
});

test("#660 launchctl check distinguishes a missing service from an unknown failure",()=>{
  const absent={status:113,stderr:'Bad request. Could not find service "rca"'};
  assert.equal(launchctlServiceState('gui/501/rca',()=>absent),'absent');
  assert.equal(launchctlServiceState('gui/501/rca',()=>({status:0})),'present');
  assert.equal(launchctlServiceState('gui/501/rca',()=>({status:5,stderr:'EIO'})),'unknown');
});

test("#660 stop waits for two observed launchd deregistration checks",async()=>{
  let reads=0,waits=0;
  const invoke=(command,args)=>{
    assert.equal(args[0],'print');
    reads++;
    return reads<4?{status:0}:{status:113,stderr:'Could not find service'};
  };
  assert.equal(await awaitLaunchctlUnregistered('gui/501/rca',invoke,
    async()=>{waits++;}),true);
  assert.equal(reads,5);
  assert.equal(waits,4);
  await assert.rejects(awaitLaunchctlUnregistered('gui/501/rca',
    ()=>({status:5}),async()=>{}),/state unknown/);
  assert.equal(await awaitLaunchctlUnregistered('gui/501/rca',
    ()=>({status:0}),async()=>{}),false);
});

test("#660 owner-local rca executable quotes paths and refuses unverified commands",async t=>{
  const root="/Users/o'neill;touch BAD/programs/v0.0.0-ci-darwin-arm64";
  const script=ownerCliText(root);
  const temp=await mkdtemp(path.join(os.tmpdir(),"rca660-cli-"));
  t.after(()=>rm(temp,{recursive:true,force:true}));
  const file=path.join(temp,"rca");
  await writeFile(file,script,{mode:0o700});
  assert.equal(spawnSync("/bin/sh",["-n",file]).status,0);
  for(const action of ["upgrade","install","status",""]) {
    const args=action? [action] : [];
    const r=spawnSync("/bin/sh",[file,...args],{encoding:"utf8"});
    // 'status' is permitted but points to a nonexistent reviewed test binary.
    if(action==="status")assert.notEqual(r.status,0);
    else assert.equal(r.status,2);
  }
  assert.match(script,/status\|stop\|start/);
  assert.ok(script.includes("o'\"'\"'neill"));
});

test("#660 permanent service accepts only exact approved existing grant and managed generation",()=>{
  const approved=parsePermanentMacArgs(["--service","--endpoint",ENDPOINT,"--generation",ID]);
  assert.equal(approved.service,true);
  assert.equal(approved.endpoint,ENDPOINT);
  for(const args of [
    ["--service","--endpoint",ENDPOINT],
    ["--service","--endpoint",ENDPOINT,"--retry-pairing","--generation",ID],
    ["--service","--endpoint",ENDPOINT,"--name","foreign","--generation",ID],
    ["--service","--endpoint",ENDPOINT,"--generation","bad"],
  ])assert.throws(()=>parsePermanentMacArgs(args));
  assert.throws(()=>verifiedEndpoint("http://rca.example.test/"));
  assert.throws(()=>verifiedEndpoint("https://example.test/path"));
});

test("#660 LaunchAgent plist is strictly owned, deterministic and rejects foreign mutations",()=>{
  const programs="/Users/test/.local/share/mcp-workers/remote-control/macos/programs";
  const root=path.join(programs,"v0.0.0-ci-darwin-arm64");
  const node=path.join(root,"bin/node");
  const entry=path.join(root,"apps/remote-control-agent/src/macos-permanent.js");
  const xml=plistText({node,entry,endpoint:ENDPOINT,generation:ID});
  assert.deepEqual(parsePlist(xml,programs,ENDPOINT,"arm64"),{root,generation:ID});
  const intelRoot=path.join(programs,"v0.0.0-ci-darwin-x64");
  const intelXml=plistText({node:path.join(intelRoot,"bin/node"),
    entry:path.join(intelRoot,"apps/remote-control-agent/src/macos-permanent.js"),
    endpoint:ENDPOINT,generation:ID});
  assert.deepEqual(parsePlist(intelXml,programs,ENDPOINT,"x64"),
    {root:intelRoot,generation:ID});
  assert.throws(()=>parsePlist(intelXml,programs,ENDPOINT,"arm64"));
  for(const other of [
    xml.replace("/bin/node","/bin/sh"),
    xml.replace("KeepAlive</key><true/>","KeepAlive</key><false/>"),
    xml.replace("</dict>","<key>Disabled</key><true/></dict>"),
  ])assert.throws(()=>parsePlist(other,programs,ENDPOINT,"arm64"));
});

test("#660 candidate provenance requires exact pinned source and no change of protocol",()=>{
  const meta={version:"v0.0.0-ci",target:"darwin-arm64",source_commit:"a".repeat(40),
    artifact_schema:1,device_protocol:2,receipt_schema:1,
    candidate_profile:"darwin-permanent-local-v1",
    native_supervisor:"darwin-owned-group-v1",modules:["macos-permanent.ts"]};
  assert.equal(candidateName(meta,"a".repeat(40),"arm64"),"v0.0.0-ci-darwin-arm64");
  assert.equal(candidateName({...meta,target:"darwin-x64"},"a".repeat(40),"x64"),"v0.0.0-ci-darwin-x64");
  assert.throws(()=>candidateName(meta,"a".repeat(40),"x64"));
  assert.throws(()=>candidateName(meta,"b".repeat(40),"arm64"));
  assert.throws(()=>candidateName({...meta,target:"linux-x64-glibc"},"a".repeat(40),"arm64"));
  assert.throws(()=>candidateName({...meta,device_protocol:3},"a".repeat(40),"arm64"));
});

const native=process.platform==="darwin"&&["arm64","x64"].includes(process.arch)&&!!bundle;
async function fixture(t){
  const root=await mkdtemp(path.join(os.tmpdir(),"rca660-test-"));
  const home=path.join(root,"home");
  await mkdir(home,{mode:0o700});
  const identity=path.join(home,".local/share/mcp-workers/remote-control");
  await mkdir(identity,{recursive:true,mode:0o700});
  // The fixture is an already explicitly authorized permanent identity;
  // no remote pairing and NO real launchctl commands are performed by tests.
  const key=path.join(identity,"v2-identity.pem");
  await writeFile(key,"synthetic-private-key",{mode:0o600});
  await writeFile(key+".device-id",ID+"\n",{mode:0o600});
  const manifest=JSON.parse(await readFile(path.join(bundle,"bundle.json"),"utf8"));
  t.after(async()=>rm(root,{recursive:true,force:true,maxRetries:5,retryDelay:20}));
  return {root,home,identity,sourceSha:manifest.source_commit,version:manifest.version,
    commands:[],invoke:(command,args)=>{assert.equal(command,"/bin/launchctl");
      const entry=args.join(" ");return {status:0,stdout:entry};}};
}
test("#662 temporary bootstrap reuses foreground runtime without LaunchAgent writes",{skip:!native},async t=>{
  const f=await fixture(t), calls=[];
  const opts={home:f.home,bundle,sourceSha:f.sourceSha,endpoint:ENDPOINT,
    terminal:()=>true,runTemporary:(file,args,settings)=>{
      calls.push({file,args,settings});return {status:0};}};
  const result=await localMacAction("temporary",opts);
  assert.equal(result.status,"temporary_session_ended");
  assert.equal(calls.length,1);
  assert.equal(calls[0].file,path.join(bundle,"bin/node"));
  assert.deepEqual(calls[0].args,[
    path.join(bundle,"apps/remote-control-agent/src/macos-temporary.js"),
    "--endpoint",ENDPOINT,"--bootstrap-selected"]);
  assert.deepEqual(calls[0].settings,{stdio:"inherit"});
  await assert.rejects(readFile(path.join(f.home,
    "Library/LaunchAgents/org.mcp-workers.remote-control-agent.plist")),{code:"ENOENT"});
  await assert.rejects(localMacAction("temporary",{...opts,sourceSha:"b".repeat(40)}),
    /Unexpected source commit/);
  await assert.rejects(localMacAction("temporary",{...opts,terminal:()=>false}),
    /Owner terminal required/);
  await assert.rejects(localMacAction("temporary",{...opts,runTemporary:()=>({status:2})}),
    /without confirmed success/);
});

test("#660 native offline install → stopped state → upgrade without restart",{
  skip:!native},async t=>{
  const f=await fixture(t);
  const opts={home:f.home,bundle,sourceSha:f.sourceSha,endpoint:ENDPOINT,
    invoke:f.invoke,ask:async()=>true,online:async()=>true,
    ownerIntent:async()=>({status:'stopped',idle_expires_at:Date.now()+14*86_400_000}),
    freezeAgent:async()=>{throw Error("Stopped service must not freeze");}};
  const first=await localMacAction("install",opts);
  assert.equal(first.status,"connected_observed");
  const cli=path.join(f.home,".local/bin/rca");
  const firstRoot=path.join(f.identity,"macos/programs",f.version+"-darwin-"+process.arch);
  assert.equal(first.cli,cli);
  assert.equal(await readFile(cli,"utf8"),ownerCliText(firstRoot));
  assert.equal((await lstat(cli)).mode&0o777,0o700);
  assert.equal(spawnSync("/bin/sh",["-n",cli]).status,0);
  assert.equal(spawnSync("/bin/sh",[cli,"upgrade"]).status,2,
    "raw, unpinned local CLI upgrade must be refused");
  const state=await localMacAction("status",{home:f.home,invoke:f.invoke});
  assert.equal(state.installed,true);
  let unloaded=false;
  await localMacAction("stop",{...opts,pauseLaunchd:async()=>{},invoke:(command,args)=>{
    f.commands.push(args[0]);
    if(args[0]==="bootout")unloaded=true;
    return args[0]==="print"&&unloaded
      ?{status:113,stderr:"Could not find service"}:{status:0};}});
  const alt=path.join(f.root,"second");
  await cp(bundle,alt,{recursive:true});
  const manifestFile=path.join(alt,"bundle.json");
  const manifest=JSON.parse(await readFile(manifestFile,"utf8"));
  manifest.version="v0.0.1-ci";
  await writeFile(manifestFile,JSON.stringify(manifest)+"\n",{mode:0o600});
  f.commands.length=0;
  const result=await localMacAction("upgrade",{...opts,bundle:alt,
    invoke:(command,args)=>{f.commands.push(args[0]);
      return {status:args[0]==="print"?1:0};}});
  assert.equal(result.status,"stopped_preserved");
  assert.equal(await readFile(cli,"utf8"),
    ownerCliText(path.join(f.identity,"macos/programs","v0.0.1-ci-darwin-"+process.arch)));
  assert.deepEqual(f.commands,["print"],
    "intentionally stopped service may only be checked, never auto-launched");
  assert.equal((await localMacAction("status",{home:f.home,invoke:f.invoke})).local_service,
    "stopped_requested_unverified");
  assert.equal((await readFile(path.join(f.identity,"v2-identity.pem.device-id"),"utf8")).trim(),ID);
});

test("#660 first install bootstrap refusal preserves approved device and staged bundle",{
  skip:!native},async t=>{
  const f=await fixture(t);
  const opts={home:f.home,bundle,sourceSha:f.sourceSha,endpoint:ENDPOINT,
    invoke:(command,args)=>({status:args[0]==="bootstrap"?1:0}),
    ask:async()=>true,online:async()=>true};
  const keyId=path.join(f.identity,"v2-identity.pem.device-id");
  const previous=await readFile(keyId,"utf8");
  await assert.rejects(localMacAction("install",opts),/Install blocked at launchagent-bootstrap/);
  assert.equal(await readFile(keyId,"utf8"),previous);
  for(const relative of ["Library/LaunchAgents/org.mcp-workers.remote-control-agent.plist",
    ".local/bin/rca",".local/share/mcp-workers/remote-control/macos/switch.json"])
    await assert.rejects(readFile(path.join(f.home,relative)),{code:"ENOENT"});
  const staged=path.join(f.identity,"macos/programs",f.version+"-darwin-"+process.arch);
  assert.equal((await lstat(staged)).isDirectory(),true);
  await assert.rejects(localMacAction("install",opts),/already staged; never overwrite/);
});

test("#660 native upgrade busy/activation failure retains identity and rolls back",{
  skip:!native},async t=>{
  const f=await fixture(t);
  const base={home:f.home,bundle,sourceSha:f.sourceSha,endpoint:ENDPOINT,
    invoke:f.invoke,ask:async()=>true,online:async()=>true};
  await localMacAction("install",base);
  const alt=path.join(f.root,"update");
  await cp(bundle,alt,{recursive:true});
  const manifestFile=path.join(alt,"bundle.json");
  const m=JSON.parse(await readFile(manifestFile,"utf8"));
  m.version="v0.0.1-ci";
  await writeFile(manifestFile,JSON.stringify(m)+"\n",{mode:0o600});
  const opts={...base,bundle:alt,freezeAgent:async()=> "busy"};
  await assert.rejects(localMacAction("upgrade",opts),/Busy or uncertain/);
  assert.equal((await localMacAction("status",{home:f.home,invoke:f.invoke})).version,
    f.version+"-darwin-"+process.arch);
  // Busy attempt safely staged the second version; explicit human inspection
  // is required before repeat, rather than overwriting it blindly.
  assert.equal((await readFile(path.join(f.identity,"v2-identity.pem.device-id"),"utf8")).trim(),ID);
});

test("#660 native refuses unsafe identity, LaunchAgent and file links",{
  skip:!native},async t=>{
  const f=await fixture(t);
  await chmod(path.join(f.identity,"v2-identity.pem"),0o644);
  const opts={home:f.home,bundle,sourceSha:f.sourceSha,endpoint:ENDPOINT,
    invoke:f.invoke,ask:async()=>true,online:async()=>true};
  await assert.rejects(localMacAction("install",opts),/Unsafe owner/);
});

test("#660 native activation failure restores prior reviewed LaunchAgent and identity",{
  skip:!native},async t=>{
  const f=await fixture(t);
  const actions=[];
  const mock=(command,args)=>{actions.push(args[0]);return {status:0};};
  const first={home:f.home,bundle,sourceSha:f.sourceSha,endpoint:ENDPOINT,
    invoke:mock,ask:async()=>true,online:async()=>true};
  await localMacAction("install",first);
  // Verify real-world 0755 parent modes do not block rollback restoration.
  await chmod(path.join(f.home,"Library/LaunchAgents"),0o755);
  await chmod(path.join(f.home,".local/bin"),0o755);
  const plist=path.join(f.home,"Library/LaunchAgents/org.mcp-workers.remote-control-agent.plist");
  const before=await readFile(plist,"utf8");
  const cli=path.join(f.home,".local/bin/rca");
  const beforeCli=await readFile(cli,"utf8");
  const alt=path.join(f.root,"rollback-candidate");
  await cp(bundle,alt,{recursive:true});
  const manifestFile=path.join(alt,"bundle.json");
  const meta=JSON.parse(await readFile(manifestFile,"utf8"));
  meta.version="v0.0.1-ci";
  await writeFile(manifestFile,JSON.stringify(meta)+"\n",{mode:0o600});
  let onlineCalls=0;
  await assert.rejects(localMacAction("upgrade",{
    ...first,bundle:alt,freezeAgent:async()=> "ready",
    online:async()=>++onlineCalls===2,
  }),/Upgrade blocked at signed-wss-activation/);
  assert.match(actions.join(","),/bootout,bootstrap,bootout,bootstrap/);
  assert.equal(await readFile(plist,"utf8"),before);
  assert.equal(await readFile(cli,"utf8"),beforeCli);
  assert.equal((await readFile(path.join(f.identity,"v2-identity.pem.device-id"),"utf8")).trim(),ID);
  await assert.rejects(readFile(path.join(f.home,
    ".local/share/mcp-workers/remote-control/macos/switch.json")),{code:"ENOENT"});
});

test("#660 local rca path cannot overwrite foreign files or symlinks",{skip:!native},async t=>{
  const f=await fixture(t);
  const opts={home:f.home,bundle,sourceSha:f.sourceSha,endpoint:ENDPOINT,
    invoke:f.invoke,ask:async()=>true,online:async()=>true};
  const dir=path.join(f.home,".local/bin"),cli=path.join(dir,"rca");
  await mkdir(dir,{recursive:true,mode:0o700});
  await writeFile(cli,"#!/bin/sh\necho foreign\n",{mode:0o700});
  await assert.rejects(localMacAction("install",opts),/Foreign or inconsistent local rca/);
  assert.equal(await readFile(cli,"utf8"),"#!/bin/sh\necho foreign\n");
  await rm(cli);
  await symlink(path.join(f.identity,"v2-identity.pem"),cli);
  await assert.rejects(localMacAction("install",opts),/Unsafe owner/);
  assert.equal((await readFile(path.join(f.identity,"v2-identity.pem.device-id"),"utf8")).trim(),ID);
});

test("#660 native suspicious LaunchAgent symlink refused before any mutation",{
  skip:!native},async t=>{
  const f=await fixture(t);
  const opts={home:f.home,bundle,sourceSha:f.sourceSha,endpoint:ENDPOINT,
    invoke:f.invoke,ask:async()=>true,online:async()=>true};
  await localMacAction("install",opts);
  const plist=path.join(f.home,"Library/LaunchAgents/org.mcp-workers.remote-control-agent.plist");
  await rm(plist);
  await symlink(path.join(f.identity,"v2-identity.pem"),plist);
  await assert.rejects(localMacAction("status",opts),/Unsafe owner/);
  assert.equal(await readFile(path.join(f.identity,"v2-identity.pem"),"utf8"),"synthetic-private-key");
});


test('#660 native failed bootstrap records exit code and preserves STOP and key',{
  skip:!native},async t=>{
  const f=await fixture(t),identity=path.join(f.identity,'v2-identity.pem.device-id');
  const device=await readFile(identity,'utf8');
  let registered=false,bootstraps=0;
  const invoke=(command,args)=>{
    if(args[0]==='print')return registered?{status:0}
      :{status:113,stderr:'Could not find service'};
    if(args[0]==='bootstrap'){
      if(++bootstraps===1){registered=true;return {status:0};}
      return {status:5,stderr:'Bootstrap failed: 5: Input/output error'};
    }
    if(args[0]==='bootout'){registered=false;return {status:0};}
    return {status:0};
  };
  const opts={home:f.home,bundle,sourceSha:f.sourceSha,endpoint:ENDPOINT,
    invoke,ask:async()=>true,online:async()=>true,pauseLaunchd:async()=>{},
    ownerIntent:async(action)=>({status:action==='resume'?'resume_pending':'stopped'})};
  await localMacAction('install',opts);
  assert.equal((await localMacAction('stop',opts)).status,'intentionally_stopped');
  await assert.rejects(localMacAction('start',opts),/bootstrap failed \(exit=5\)/);
  assert.equal(await readFile(path.join(f.identity,'macos/stopped'),'utf8'),'stopped\n');
  assert.equal(await readFile(identity,'utf8'),device);
  assert.equal(registered,false);
});

test('#666 native owner Stop/Resume preserves same identity and demands signed activation',{
 skip:!native},async t=>{
 const f=await fixture(t),calls=[];
 const opts={home:f.home,bundle,sourceSha:f.sourceSha,endpoint:ENDPOINT,
   invoke:(command,args)=>{calls.push('launch:'+args[0]);return args[0]==='print'
     ?{status:113,stderr:'Could not find service'}:{status:0}},
  ask:async()=>true,online:async()=>true,
  ownerIntent:async(action)=>{calls.push('cloud:'+action);
   return {status:action==='stop'?'stopped':'resume_pending',idle_expires_at:Date.now()+14*86_400_000}}};
 await localMacAction('install',opts);
 await localMacAction('stop',opts);
 const marker=path.join(f.identity,'macos','stopped');
 assert.equal(await readFile(marker,'utf8'),'stopped\n');
 assert.equal((await localMacAction('status',opts)).local_service,'stopped_requested_unverified');
 assert.equal((await localMacAction('start',opts)).status,'connected_observed');
 await assert.rejects(readFile(marker),{code:'ENOENT'});
 assert.deepEqual(calls.filter(x=>x.startsWith('cloud:')),['cloud:stop','cloud:stop','cloud:resume']);
 assert.equal((await readFile(path.join(f.identity,'v2-identity.pem.device-id'),'utf8')).trim(),ID);
});
