import assert from "node:assert/strict";
import {test} from "node:test";
import {mkdtemp,mkdir,writeFile,chmod,rm} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import {stageAndLaunchApprovedLinuxUpgrade}
  from "../src/linux-upgrade-executor.ts";

const linux=process.platform==="linux"&&process.getuid?.()!==0?test:test.skip;
const OP="linux-executor-39";
const DEVICE="af666663-b30c-4b3d-ad85-c8047dc3516b";
const CURRENT="v0.1.22",TARGET="v0.1.33";
const PIN={tag:TARGET,commit:"a".repeat(40),linux_asset_sha256:"b".repeat(64),
  linux_arch:process.arch==="arm64"?"arm64" as const:"x64" as const};
const intent={operation_id:OP,device_id:DEVICE,fingerprint:"a".repeat(24),
  current_version:CURRENT,target:PIN,
  approved_at:1793100000000,expires_at:1793100240000};

async function fixture(){
  const home=await mkdtemp(path.join(os.tmpdir(),"rca-linux-exec-"));
  const programs=path.join(home,".local/share/mcp-workers/remote-control/programs");
  const installedRoot=path.join(programs,CURRENT+"-linux-"+process.arch+"-glibc");
  const script=path.join(installedRoot,"apps/remote-control-agent/scripts/bootstrap-v2.py");
  await mkdir(path.dirname(script),{recursive:true,mode:0o700});
  await writeFile(script,"# test-only", {mode:0o600});
  const calls:{type:string;args:unknown}[]=[];
  const run=async(changes:Record<string,unknown>={})=>
    stageAndLaunchApprovedLinuxUpgrade(intent,{
      installedRoot,home,endpoint:"https://rca.example.org/",
      readAdmission:async id=>{
        calls.push({type:"admission",args:id});return id===OP;
      },
      stage:async(exe,args)=>{
        calls.push({type:"stage",args:{exe,args}});
        assert.equal(exe,"/usr/bin/python3");
        assert.deepEqual(args,[script,"--stage-only","--tag",TARGET,
          "--commit",PIN.commit,"--endpoint","https://rca.example.org/",
          "--asset-sha256",PIN.linux_asset_sha256]);
      },
      launch:async options=>{
        calls.push({type:"launch",args:options.operationId});
        assert.equal(await options.assertAdmission({
          operationId:OP,deviceId:DEVICE,currentVersion:CURRENT,targetVersion:TARGET,
          targetRoot:"unused"}),true);
        assert.equal(await options.verifyPinnedTarget({
          operationId:OP,deviceId:DEVICE,currentVersion:CURRENT,targetVersion:TARGET,
          targetRoot:path.join(programs,TARGET+"-linux-"+process.arch+"-glibc")}),true);
        return {status:"launched",operationId:OP,unit:"fixture"};
      },
      ...changes,
    });
  return {home,script,installedRoot,calls,run,cleanup:()=>rm(home,{recursive:true,force:true})};
}

linux("signed Linux one-shot stages fixed Python pin and then launches same-owner watchdog",async()=>{
  const f=await fixture();
  try{
    assert.equal(await f.run(),"launched");
    assert.deepEqual(f.calls.map(x=>x.type),[
      "admission","stage","launch","admission"]);
  }finally{await f.cleanup();}
});

linux("Linux one-shot rejects untrusted owner context before any staged/native effects",async()=>{
  for(const change of [
    {installedRoot:"/tmp/foreign"},
    {endpoint:"http://rca.example.org/"},
    {endpoint:"https://rca.example.org/evil"},
    {endpoint:"https://rca.example.org:8443/"},
    {readAdmission:async()=>false},
  ]){
    const f=await fixture();
    try{
      await assert.rejects(f.run(change));
      assert.equal(f.calls.some(x=>x.type==="stage"||x.type==="launch"),
        false,JSON.stringify(change));
    }finally{await f.cleanup();}
  }
});

linux("unsafe Linux source bootstrap aborts before immutable asset staging",async()=>{
  const f=await fixture();
  try{
    await chmod(f.script,0o644);
    await assert.rejects(f.run(),/Untrusted immutable Linux bootstrap/);
    assert.deepEqual(f.calls,[]);
  }finally{await f.cleanup();}
});

linux("staging failure must never launch detached Linux service",async()=>{
  const f=await fixture();
  try{
    await assert.rejects(f.run({stage:async()=>{
      f.calls.push({type:"failed-stage",args:null});
      throw Error("SHA mismatch");
    }}),/SHA mismatch/);
    assert.deepEqual(f.calls.map(x=>x.type),["admission","failed-stage"]);
  }finally{await f.cleanup();}
});
