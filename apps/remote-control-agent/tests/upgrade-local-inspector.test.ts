import test from "node:test";
import assert from "node:assert/strict";
import {createHash} from "node:crypto";
import {mkdtempSync,mkdirSync,writeFileSync,rmSync,chmodSync,renameSync} from "node:fs";
import path from "node:path";
import {tmpdir} from "node:os";
import {inspectLinuxLocalUpgrade,parseUpgradeServiceState} from "../src/upgrade-local-inspector.ts";
import {assessUpgradeAfterReconnect} from "../src/upgrade-recovery.ts";
import {operationDigest,type OperationReceipt} from "../src/operations.ts";
import type {UpgradeRequest} from "../src/upgrade-authorization.ts";

const linuxTest=process.platform==="linux"&&process.getuid?.()!==0?test:test.skip;
const version="v0.1.23",target="linux-"+process.arch+"-glibc";
const uuid="af666663-b30c-4b3d-ad85-c8047dc3516b";
const privatePem="only a local test identity, no real key";
const fingerprint=createHash("sha256").update(privatePem).digest("hex");
const req:UpgradeRequest={
  operation_id:"remote-linux-upgrade",device_id:uuid,source_version:"v0.1.22",
  target_version:version,target_commit:"b".repeat(40),target_sha256:"c".repeat(64),
  target_platform:target,identity_sha256:fingerprint,authorized_until:1792845200000,
};
const fields=(file:string,pid:number)=>[
  "ActiveState=active","SubState=running","MainPID="+pid,
  "FragmentPath="+file,"DropInPaths=","",
].join("\n");
function fixture(){
  const home=mkdtempSync(path.join(tmpdir(),"rca-local-inspector-"));
  const root=path.join(home,".local/share/mcp-workers/remote-control/programs",version+"-"+target);
  const key=path.join(home,".local/share/mcp-workers/remote-control/v2-identity.pem");
  const receipt=path.join(home,".local/state/mcp-workers/remote-control-agent/operation-receipts.sqlite");
  const unit=path.join(home,".config/systemd/user/remote-control-v2-agent.service");
  const bin=path.join(root,"bin/node");
  const entry=path.join(root,"apps/remote-control-agent/src/v2-main.js");
  for(const file of [key,receipt,unit,bin,entry,path.join(root,"bundle.json")]){
    mkdirSync(path.dirname(file),{recursive:true,mode:0o700});
    writeFileSync(file,"",{mode:0o600});
  }
  for(const dir of [root,path.dirname(root)])chmodSync(dir,0o700);
  writeFileSync(key,privatePem,{mode:0o600});
  writeFileSync(key+".device-id",uuid+"\n",{mode:0o600});
  writeFileSync(path.join(root,"bundle.json"),JSON.stringify({
    name:"remote-control-agent",version,target,artifact_schema:1,device_protocol:2,
    receipt_schema:1,upgrade_profile:"paired-full-v1",
  }),{mode:0o600});
  writeFileSync(unit,[
    "# Managed by Remote Control Agent installer.",
    "[Unit]","Description=Remote Control Agent (signed outbound WSS)","StartLimitIntervalSec=0","",
    "[Service]","Type=simple","WorkingDirectory="+path.join(root,"apps/remote-control-agent"),
    "Environment=REMOTE_CONTROL_AGENT_ENDPOINT=https://rca.example.com/",
    "Environment=REMOTE_CONTROL_AGENT_KEY_PATH="+key,
    "UMask=0077",
    "ExecStartPre=/usr/bin/test -r "+key,
    "ExecStartPre=/usr/bin/test -r "+key+".device-id",
    "ExecStartPre=/usr/bin/test -x "+path.join(root,"apps/remote-control-agent/.build/session-supervisor"),
    "ExecStart="+bin+" "+entry,"Restart=on-failure","RestartSec=15s","TimeoutStopSec=15s","",
    "[Install]","WantedBy=default.target","",
  ].join("\n"),{mode:0o600});
  const header=Buffer.alloc(100);
  Buffer.from("SQLite format 3\0","ascii").copy(header);
  header.writeUInt32BE(1,60);
  writeFileSync(receipt,header,{mode:0o600});
  const context={
    home,keyPath:key,executable:bin,entrypoint:entry,pid:123456,
    expectedEndpoint:"https://rca.example.com/",
    serviceShow:()=>fields(unit,123456),
  };
  return {home,root,key,receipt,unit,bin,entry,context,
    cleanup:()=>rmSync(home,{recursive:true,force:true})};
}
linuxTest("owned running Linux service, exact binary, key and SQLite header are inspected read-only",async()=>{
 const f=fixture();
 try{
  const result=await inspectLinuxLocalUpgrade(req,f.context);
  assert.deepEqual(result,{
    deviceId:uuid,identitySha256:fingerprint,runningVersion:version,platform:target,
    serviceActive:true,servicePathsMatch:true,receiptHeaderCompatible:true,
  });
 }finally{f.cleanup();}
});
linuxTest("service PID mismatch and foreign drop-in cannot produce verified local service",async()=>{
 const f=fixture();
 try{
  for(const mutation of [
    {serviceShow:()=>fields(f.unit,123457)},
    {serviceShow:()=>fields(f.unit,123456).replace("DropInPaths=\n","DropInPaths=/tmp/override.conf\n")},
    {serviceShow:()=>fields(f.unit,123456).replace("ActiveState=active","ActiveState=inactive")},
  ]){
   const result=await inspectLinuxLocalUpgrade(req,{...f.context,...mutation});
   assert.equal(result.serviceActive,false);
   assert.equal(result.servicePathsMatch,false);
  }
 }finally{f.cleanup();}
});
linuxTest("altered identity, program, manifest and unit cannot satisfy native proof",async()=>{
 const f=fixture();
 try{
  assert.equal((await inspectLinuxLocalUpgrade({...req,device_id:"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"},f.context)).serviceActive,false);
  assert.equal((await inspectLinuxLocalUpgrade(req,{...f.context,entrypoint:"/tmp/user.js"})).serviceActive,false);
  writeFileSync(f.unit,"[Service]\nExecStart=/bin/bash",{mode:0o600});
  assert.equal((await inspectLinuxLocalUpgrade(req,f.context)).serviceActive,false);
 }finally{f.cleanup();}
});
linuxTest("an altered but syntactically valid systemd endpoint cannot self-authorize",async()=>{
 const f=fixture();
 try{
  const original=(await import("node:fs/promises")).readFile(f.unit,"utf8");
  const unit=await original;
  writeFileSync(f.unit,unit.replace("https://rca.example.com/","https://attacker.example/"),{mode:0o600});
  const rejected=await inspectLinuxLocalUpgrade(req,f.context);
  assert.equal(rejected.servicePathsMatch,false);
  assert.equal(rejected.serviceActive,false);
  const missing=await inspectLinuxLocalUpgrade(req,{...f.context,expectedEndpoint:""});
  assert.equal(missing.servicePathsMatch,false);
 }finally{f.cleanup();}
});
linuxTest("canonical systemd unit can prove the same exact owner-local runtime",async()=>{
 const f=fixture();
 try{
  const canonical=path.join(path.dirname(f.unit),"remote-control-agent.service");
  renameSync(f.unit,canonical);
  const result=await inspectLinuxLocalUpgrade(req,{...f.context,
    serviceShow:()=>fields(canonical,123456)});
  assert.equal(result.serviceActive,true);
  assert.equal(result.servicePathsMatch,true);
 }finally{f.cleanup();}
});
linuxTest("two configured service files are ambiguous, even with one active",async()=>{
 const f=fixture();
 try{
  const canonical=path.join(path.dirname(f.unit),"remote-control-agent.service");
  const unit=await (await import("node:fs/promises")).readFile(f.unit,"utf8");
  writeFileSync(canonical,unit,{mode:0o600});
  const result=await inspectLinuxLocalUpgrade(req,f.context);
  assert.equal(result.serviceActive,false);
  assert.equal(result.servicePathsMatch,false);
 }finally{f.cleanup();}
});
linuxTest("SQLite invalid schema is not reported as readable durable receipts",async()=>{
 const f=fixture();
 try{
  const data=Buffer.alloc(100);Buffer.from("SQLite format 3\0").copy(data);data.writeUInt32BE(99,60);
  writeFileSync(f.receipt,data,{mode:0o600});
  const result=await inspectLinuxLocalUpgrade(req,f.context);
  assert.equal(result.receiptHeaderCompatible,false);
 }finally{f.cleanup();}
});
linuxTest("local service proof alone MUST NOT attest immutable Release origin or authenticated WSS",async()=>{
 const f=fixture();
 try{
  const local=await inspectLinuxLocalUpgrade(req,f.context);
  const receipt:OperationReceipt={
    operation_id:req.operation_id,tool_name:"upgrade_agent",
    argument_digest:operationDigest("upgrade_agent",req),
    state:"unknown",created_at:"2026-10-24T00:00:00Z",updated_at:"2026-10-24T00:01:00Z",
  };
  // Those two missing proofs must be acquired independently at trusted
  // installer and authenticated connection boundaries, not inferred here.
  const verdict=assessUpgradeAfterReconnect(req,receipt,{
    ...local,immutableReleaseCommit:"",immutableReleaseAssetSha256:"",
    serviceExecutableVerified:false,durableReceiptsReadable:false,
    authenticatedSameDevice:false,
  });
  assert.deepEqual(verdict,{kind:"unresolved",operationId:req.operation_id,reason:"release"});
 }finally{f.cleanup();}
});
linuxTest("unreviewed ExecStartPre is not accepted as a signed service template",async()=>{
 const f=fixture();
 try {
   const original=await import("node:fs/promises").then(m=>m.readFile(f.unit,"utf8"));
   writeFileSync(f.unit,original.replace("Restart=on-failure",
     "ExecStartPre=/bin/sh -c untrusted\nRestart=on-failure"),{mode:0o600});
   const result=await inspectLinuxLocalUpgrade(req,f.context);
   assert.equal(result.servicePathsMatch,false);
 }finally{f.cleanup();}
});
test("systemctl key parser denies duplicate or missing fields",()=>{
 const valid="ActiveState=active\nSubState=running\nMainPID=123\nFragmentPath=/tmp/agent.service\nDropInPaths=\n";
 assert.equal(parseUpgradeServiceState(valid).MainPID,"123");
 for(const altered of [
  valid+"MainPID=123\n",valid.replace("MainPID=123\n",""),
  valid.replace("DropInPaths=\n","Other=invalid\n"),
  valid.replace("SubState=running","SubState=running\r"),
 ])assert.throws(()=>parseUpgradeServiceState(altered),/service/i);
});
