import assert from "node:assert/strict";
import {test} from "node:test";
import {mkdtempSync,mkdirSync,writeFileSync,readFileSync,rmSync} from "node:fs";
import {tmpdir} from "node:os";
import path from "node:path";
import {inspectInstalledSignedUnit,upgradeExistingSignedService,HISTORICAL_UNIT} from "../scripts/upgrade-existing-service.mjs";

function unit(root,home,endpoint,{legacy=false,oldEnv=false}={}){
  const key=path.join(home,".local/share/mcp-workers/remote-control/v2-identity.pem");
  const pre=oldEnv?"REMOTE_CONTROL_V2":"REMOTE_CONTROL_AGENT";
  return [
    legacy?"# Managed by mcp-workers v2 Linux installer; NOT the v1 Agent.":"# Managed by Remote Control Agent installer.",
    "[Unit]",
    "Description="+(legacy?"Remote Control v2 Agent (outbound WSS, independent of v1)":"Remote Control Agent (signed outbound WSS)"),
    "StartLimitIntervalSec=0","",
    "[Service]","Type=simple",
    "WorkingDirectory="+path.join(root,"apps/remote-control-agent"),
    "Environment="+pre+"_ENDPOINT="+endpoint,
    "Environment="+pre+"_KEY_PATH="+key,
    "UMask=0077",
    "ExecStartPre=/usr/bin/test -r "+key,
    "ExecStartPre=/usr/bin/test -r "+key+".device-id",
    "ExecStartPre=/usr/bin/test -x "+path.join(root,"apps/remote-control-agent/.build/session-supervisor"),
    "ExecStart="+path.join(root,"bin/node")+" "+path.join(root,"apps/remote-control-agent/src/v2-main.js"),
    "Restart=on-failure","RestartSec=15s","TimeoutStopSec=15s","",
    "[Install]","WantedBy=default.target","",
  ].join("\n");
}
const linuxTest=process.platform==="linux"?test:test.skip;
const target=process.arch==="arm64"?"linux-arm64-glibc":"linux-x64-glibc";
const endpoint="https://rca.example.net/";
const uuid="af666663-b30c-4b3d-ad85-c8047dc3516b";
function fixture({legacy=false,oldEnv=false}={}){
 const home=mkdtempSync(path.join(tmpdir(),"rca-direct-upgrade-"));
 const dir=path.join(home,".config/systemd/user");
 const base=path.join(home,".local/share/mcp-workers/remote-control");
 const programs=path.join(base,"programs");
 const oldRoot=path.join(programs,"v0.1.20-"+target);
 const newRoot=path.join(programs,"v0.1.21-"+target);
 for(const root of [oldRoot,newRoot]){
  mkdirSync(path.join(root,"bin"),{recursive:true,mode:0o700});
  mkdirSync(path.join(root,"apps/remote-control-agent/src"),{recursive:true,mode:0o700});
  mkdirSync(path.join(root,"apps/remote-control-agent/.build"),{recursive:true,mode:0o700});
  for(const name of ["bin/node","apps/remote-control-agent/src/v2-main.js","apps/remote-control-agent/.build/session-supervisor"])
   writeFileSync(path.join(root,name),"test",{mode:0o600});
  writeFileSync(path.join(root,"bundle.json"),JSON.stringify({
   name:"remote-control-agent",version:path.basename(root).split("-linux-")[0],target,
   device_protocol:2,receipt_schema:1,upgrade_profile:"paired-full-v1"
  }),{mode:0o600});
 }
 mkdirSync(dir,{recursive:true,mode:0o700});
 mkdirSync(base,{recursive:true,mode:0o700});
 const unitPath=path.join(dir,HISTORICAL_UNIT);
 const oldUnit=unit(oldRoot,home,endpoint,{legacy,oldEnv});
 writeFileSync(unitPath,oldUnit,{mode:0o600});
 const key=path.join(base,"v2-identity.pem");
 writeFileSync(key,"identity stays",{mode:0o600});
 writeFileSync(key+".device-id",uuid+"\n",{mode:0o600});
 return {home,unitPath,oldRoot,newRoot,oldUnit,key,cleanup:()=>rmSync(home,{recursive:true,force:true})};
}
linuxTest("old signed and direct-upgraded units are exactly recognized without loopback and Tunnel",()=>{
 const f=fixture({legacy:true,oldEnv:true});
 try{
  assert.equal(inspectInstalledSignedUnit(f.oldUnit,{home:f.home,endpoint,newRoot:f.newRoot}).oldRoot,f.oldRoot);
  const newer=unit(f.oldRoot,f.home,endpoint,{legacy:true,oldEnv:false});
  assert.equal(inspectInstalledSignedUnit(newer,{home:f.home,endpoint,newRoot:f.newRoot}).oldRoot,f.oldRoot);
  const canonicalText=unit(f.oldRoot,f.home,endpoint);
  assert.equal(inspectInstalledSignedUnit(canonicalText,{home:f.home,endpoint,newRoot:f.newRoot}).oldRoot,f.oldRoot);
  assert.throws(()=>inspectInstalledSignedUnit(f.oldUnit+"ExecStopPost=/bin/true\n",{home:f.home,endpoint,newRoot:f.newRoot}),/Foreign/);
  assert.throws(()=>inspectInstalledSignedUnit(f.oldUnit,{home:f.home,endpoint:"https://evil.example/",newRoot:f.newRoot}),/Foreign/);
  assert.throws(()=>inspectInstalledSignedUnit(f.oldUnit,{home:f.home,endpoint,newRoot:f.oldRoot}),/advance/);
 }finally{f.cleanup();}
});
linuxTest("offline direct upgrade preserves identity and receipt-independent service and atomically removes backup",async()=>{
 const f=fixture({legacy:true,oldEnv:false});
 try{
  const sys=[];
  const systemctl=args=>{
   sys.push(args.join(" "));
   if(args[0]==="show")return "ActiveState=inactive\nSubState=dead\nMainPID=0";
   return "";
  };
  const result=await upgradeExistingSignedService({home:f.home,newRoot:f.newRoot,endpoint,systemctl,
   freeze:()=>{throw Error("offline upgrade must not freeze")}});
  assert.equal(result.status,"active");
  assert.equal(result.deviceId,uuid);
  assert.deepEqual(sys,[
   "show "+HISTORICAL_UNIT+" -p ActiveState -p SubState -p MainPID",
   "daemon-reload","restart "+HISTORICAL_UNIT,"is-active --quiet "+HISTORICAL_UNIT,
  ]);
  const updated=readFileSync(f.unitPath,"utf8");
  assert.equal(updated,unit(f.newRoot,f.home,endpoint));
  assert.equal(readFileSync(f.key,"utf8"),"identity stays");
  assert.equal(readFileSync(f.key+".device-id","utf8"),uuid+"\n");
  assert.equal(requireBackupAbsent(f.unitPath),true);
 }finally{f.cleanup();}
});
function requireBackupAbsent(file){
 try{readFileSync(file+".upgrade-backup");return false;}
 catch(e){if(e.code==="ENOENT")return true;throw e;}
}
linuxTest("active Agent gets same-identity quiescence consent before any restart",async()=>{
 const f=fixture();
 try{
  const calls=[];
  const result=await upgradeExistingSignedService({
   home:f.home,newRoot:f.newRoot,endpoint,
   systemctl:a=>{calls.push("system:"+a[0]);return a[0]==="show"?"ActiveState=active\nSubState=running\nMainPID=17":"";},
   freeze:async(key,action)=>{assert.equal(key,f.key);calls.push("freeze:"+action);return "ready";}
  });
  assert.equal(result.status,"active");
  assert.ok(calls.indexOf("freeze:freeze")<calls.indexOf("system:restart"));
  assert.equal(calls.at(-1),"freeze:release");
 }finally{f.cleanup();}
});
linuxTest("busy Agent must not update unit or release another in-flight freeze",async()=>{
 const f=fixture();
 try{
  const actions=[];
  await assert.rejects(upgradeExistingSignedService({
   home:f.home,newRoot:f.newRoot,endpoint,
   systemctl:a=>a[0]==="show"?"ActiveState=active\nSubState=running\nMainPID=12":"",
   freeze:async(_,a)=>{actions.push(a);return "busy";}
  }),/active or uncertain/);
  assert.deepEqual(actions,["freeze"]);
  assert.equal(readFileSync(f.unitPath,"utf8"),f.oldUnit);
  assert.equal(requireBackupAbsent(f.unitPath),true);
 }finally{f.cleanup();}
});
linuxTest("failed activation rolls back the exact unit and leaves key unchanged",async()=>{
 const f=fixture();
 try{
  let restarts=0;
  await assert.rejects(upgradeExistingSignedService({
   home:f.home,newRoot:f.newRoot,endpoint,
   systemctl:a=>{
    if(a[0]==="show")return "ActiveState=inactive\nSubState=dead\nMainPID=0";
    if(a[0]==="restart"&&++restarts===1)throw Error("new version failed");
    return "";
   },freeze:()=>{throw Error("unexpected freeze")}
  }),/new version failed/);
  assert.equal(restarts,2);
  assert.equal(readFileSync(f.unitPath,"utf8"),f.oldUnit);
  assert.equal(readFileSync(f.key,"utf8"),"identity stays");
  assert.equal(requireBackupAbsent(f.unitPath),true);
 }finally{f.cleanup();}
});
linuxTest("a foreign canonical unit, existing backup or drop-in blocks before changes",async()=>{
 for(const collision of ["canonical","backup","dropin"]){
  const f=fixture();
  try{
   const dir=path.dirname(f.unitPath);
   const targetPath=collision==="canonical"?path.join(dir,"remote-control-agent.service"):
    collision==="backup"?f.unitPath+".upgrade-backup":f.unitPath+".d";
   if(collision==="dropin")mkdirSync(targetPath,{mode:0o700});else writeFileSync(targetPath,"foreign",{mode:0o600});
   await assert.rejects(upgradeExistingSignedService({
    home:f.home,newRoot:f.newRoot,endpoint,
    systemctl:()=>{throw Error("should fail before systemd")},
   }),/Untrusted|Canonical|canonical|Interrupted|drop-in/);
   assert.equal(readFileSync(f.unitPath,"utf8"),f.oldUnit);
  }finally{f.cleanup();}
 }
});
