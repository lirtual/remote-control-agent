import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import path from "node:path";
import {spawnSync} from "node:child_process";
import test from "node:test";
import {
  remoteJobLabel,verifiedLaunchdJob,dispatchRemoteMacUpgrade,runRemoteMacUpgrade,
  forwardMacVersion,
} from "../scripts/macos-remote-upgrade.mjs";

const ID="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
const LABEL="org.mcp-workers.rca-upgrade-aaaaaaaabbbbccccddddeeeeeeeeeeee";
test("#657 remote macOS operation label is strict, unique and not a service alias",()=>{
  assert.equal(remoteJobLabel(ID),LABEL);
  for(const bad of ["", "../foreign","ABC","aaaa-bbbb","a".repeat(36)])
    assert.throws(()=>remoteJobLabel(bad),/Invalid one-shot/);
});
test("#657 detached Mac upgrade rejects same/older versions and other CPU",()=>{
  const base="v0.1.49-rc.4-darwin-arm64";
  for(const good of ["v0.1.49-darwin-arm64","v0.1.49-rc.5-darwin-arm64",
    "v0.1.50-darwin-arm64","v1.0.0-darwin-arm64"])
    assert.equal(forwardMacVersion(base,good),true,good);
  for(const bad of ["v0.1.49-rc.3-darwin-arm64",base,
    "v0.1.48-darwin-arm64","v0.1.49-rc.4-darwin-x64",
    "v0.1.49-darwin-x64","v0.1.49-rc.5-darwin-x64","untrusted"])
    assert.equal(forwardMacVersion(base,bad),false,bad);
  assert.equal(forwardMacVersion("v0.1.49-darwin-arm64",
    "v0.1.49-rc.5-darwin-arm64"),false);
});
test("#657 detached job cannot impersonate arbitrary service or shell PID",()=>{
  const stdout="gui/501/"+LABEL+" = {\n\tpid = 98765\n}";
  const invoke=(cmd,args)=>{
    assert.equal(cmd,"/bin/launchctl");
    assert.deepEqual(args,["print","gui/501/"+LABEL]);
    return {status:0,stdout};
  };
  assert.equal(verifiedLaunchdJob(ID,501,98765,invoke,1),true);
  for(const parent of [0,2,98431])
    assert.equal(verifiedLaunchdJob(ID,501,98765,invoke,parent),false);
  assert.equal(verifiedLaunchdJob(ID,0,98765,invoke,1),false);
  assert.equal(verifiedLaunchdJob(ID,501,98766,invoke,1),false);
  assert.equal(verifiedLaunchdJob(ID,501,98765,()=>({status:5,stderr:"unknown"}),1),false);
  assert.equal(verifiedLaunchdJob(ID,501,98765,()=>({
    status:0,stdout:"\tpid = 987650\n"}),1),false);
});
test("#657 unreviewed remote launch on non-Darwin cannot stage or switch",async()=>{
  if(process.platform==="darwin")return; // native CI tests cover real platform
  await assert.rejects(dispatchRemoteMacUpgrade({
    home:"/nonexistent",bundle:"/nonexistent",sourceSha:"a".repeat(40),
    endpoint:"https://rca.example.test/",
  }),/Native same-user macOS required/);
  await assert.rejects(runRemoteMacUpgrade(ID),/Not an authorized one-shot owner launchd job/);
});
test("#657 remote launcher references exactly one detached launchd job and durable receipt",()=>{
  const root=path.resolve(import.meta.dirname,"../scripts");
  const driver=readFileSync(path.join(root,"macos-remote-upgrade.mjs"),"utf8");
  const installer=readFileSync(path.join(root,"macos-local.sh"),"utf8");
  const publisher=readFileSync(path.join(root,"build-v2-release.mjs"),"utf8");
  assert.match(driver,/launchctl/);
  assert.match(driver,/"submit","-l",label/);
  assert.match(driver,/verifiedLaunchdJob/);
  assert.match(driver,/\bstate:"preparing"/);
  assert.match(driver,/owner_authorized_remote_upgrade/);
  assert.match(driver,/Unreconciled remote upgrade operation/);
  assert.match(driver,/localMacAction\("upgrade"/);
  assert.match(driver,/ask:async\(\)=>true/);
  assert.match(driver,/status:"connected_observed"/);
  assert.match(driver,/status:"needs_attention"/);
  assert.match(installer,/remote-upgrade/);
  assert.match(installer,/\[ -t 0 \] && \[ -t 1 \]/);
  assert.match(installer,/macos-remote-upgrade\.mjs/);
  assert.match(publisher,/scripts\/macos-remote-upgrade\.mjs/);
});
test("#657 remote-upgrade must never execute owner local upgrade on Linux",()=>{
  const sh=path.resolve(import.meta.dirname,"../scripts/macos-local.sh");
  const proc=spawnSync("sh",[sh,"remote-upgrade"],{encoding:"utf8",timeout:5000});
  if(process.platform!=="darwin")assert.match(proc.stderr,/Native macOS required/);
});

test("#657 native owner-on launchd dispatch preserves identity; no replay or silent pairing",{
  skip:process.platform!=="darwin"||!process.env.RCA_MACOS_BUNDLE_ROOT,
},async t=>{
  const {mkdtemp,mkdir,writeFile,readFile,cp,rm} = await import("node:fs/promises");
  const {tmpdir} = await import("node:os");
  const {localMacAction} = await import("../scripts/macos-local.mjs");
  const root=await mkdtemp(path.join(tmpdir(),"rca657-remote-test-"));
  t.after(()=>rm(root,{recursive:true,force:true,maxRetries:5,retryDelay:20}));
  const home=path.join(root,"home"),bundle=process.env.RCA_MACOS_BUNDLE_ROOT;
  await mkdir(home,{mode:0o700});
  const identity=path.join(home,".local/share/mcp-workers/remote-control");
  await mkdir(identity,{recursive:true,mode:0o700});
  const key=path.join(identity,"v2-identity.pem");
  await writeFile(key,"synthetic-key",{mode:0o600});
  await writeFile(key+".device-id",ID+"\n",{mode:0o600});
  const sourceSha=JSON.parse(await readFile(path.join(bundle,"bundle.json"),"utf8")).source_commit;
  const endpoint="https://rca.example.test/";
  const call=(cmd,args)=>{assert.equal(cmd,"/bin/launchctl");return {status:0,stdout:"ok"};};
  const installed=await localMacAction("install",{home,bundle,sourceSha,endpoint,
    invoke:call,ask:async()=>true,online:async()=>true});
  const receipts=path.join(home,".local/state/mcp-workers/remote-control-agent/operation-receipts.sqlite");
  await writeFile(receipts,"synthetic durable receipts",{mode:0o600});
  await writeFile(path.join(identity,"macos-connection.json"),JSON.stringify({
    generation:installed.generation,state:"connected",pid:process.pid,
    at:new Date(Date.now()-24*60*60*1000).toISOString(),
  }),{mode:0o600});
  const candidate=path.join(root,"new-candidate");
  await cp(bundle,candidate,{recursive:true});
  const metaPath=path.join(candidate,"bundle.json");
  const meta=JSON.parse(await readFile(metaPath,"utf8"));
  meta.version="v0.0.1-ci";
  await writeFile(metaPath,JSON.stringify(meta)+"\n",{mode:0o600});
  const seen=[];
  const invoke=(cmd,args)=>{
    assert.equal(cmd,"/bin/launchctl");
    seen.push(args[0]);
    if(args[0]==="print")return {status:0,stdout:"\tpid = "+process.pid+"\n"};
    return {status:0,stdout:""};
  };
  const launched=await dispatchRemoteMacUpgrade({home,bundle:candidate,sourceSha,endpoint,invoke});
  assert.equal(launched.status,"launched");
  assert.equal(launched.version,"v0.0.1-ci-darwin-"+process.arch);
  assert.equal(seen.filter(x=>x==="submit").length,1);
  await assert.rejects(dispatchRemoteMacUpgrade({home,bundle:candidate,sourceSha,endpoint,invoke}),
    /Unreconciled remote upgrade/);
  await assert.rejects(runRemoteMacUpgrade(launched.operation_id,{home,invoke,ppid:2}),
    /Not an authorized one-shot/);
  const receiptPath=path.join(identity,"macos/remote-upgrades",launched.operation_id,"result.json");
  await assert.rejects(readFile(receiptPath),{code:"ENOENT"});
  const out=await runRemoteMacUpgrade(launched.operation_id,{home,invoke,ppid:1,
    freezeAgent:async()=> "ready",online:async()=>true});
  assert.equal(out.status,"connected_observed");
  const receipt=JSON.parse(await readFile(receiptPath,"utf8"));
  assert.equal(receipt.version,launched.version);
  assert.equal(receipt.status,"connected_observed");
  assert.equal(await readFile(key+".device-id","utf8"),ID+"\n");
  assert.equal(await readFile(receipts,"utf8"),"synthetic durable receipts");
  await assert.rejects(runRemoteMacUpgrade(launched.operation_id,{home,invoke,ppid:1}),
    /already attempted/);
});
