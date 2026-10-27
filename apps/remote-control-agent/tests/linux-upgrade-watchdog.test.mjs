import assert from "node:assert/strict";
import {test} from "node:test";
import {mkdtempSync,mkdirSync,writeFileSync,readFileSync,readdirSync,rmSync,
  chmodSync} from "node:fs";
import os from "node:os";
import path from "node:path";
import {hashOperation,matchingLinuxProof,waitForLinuxSignedProof,
  runLinuxOneShotWatchdog} from "../scripts/linux-upgrade-watchdog.mjs";
import {HISTORICAL_UNIT} from "../scripts/upgrade-existing-service.mjs";

const linux=process.platform==="linux"&&process.getuid?.()!==0?test:test.skip;
const OP="proof-one-shot-39",DEVICE="af666663-b30c-4b3d-ad85-c8047dc3516b";
const SOURCE="v0.1.22",TARGET="v0.1.23";
const expected={operationId:OP,deviceId:DEVICE,version:TARGET,service:HISTORICAL_UNIT};
function fixture(){
  const home=mkdtempSync(path.join(os.tmpdir(),"rca-linux-watchdog-"));
  const state=path.join(home,"state");
  mkdirSync(state,{mode:0o700});
  const hash=hashOperation(OP);
  const proof=path.join(state,"upgrade-auth-"+hash+".json");
  const outcome=path.join(state,"upgrade-outcome-"+hash+".json");
  const attempt={home,state,hash,operation_id:OP,device_id:DEVICE,
    current_version:SOURCE,target_version:TARGET,endpoint:"https://rc.example.net/"};
  const writeProof=(changes={})=>writeFileSync(proof,JSON.stringify({
    operation_id:OP,device_id:DEVICE,target_version:TARGET,
    status:"authenticated_wss",...changes,
  }),{mode:0o600});
  const opts={home,operationId:OP,readAttempt:async()=>attempt};
  return {home,state,proof,outcome,attempt,opts,writeProof,
    cleanup:()=>rmSync(home,{recursive:true,force:true})};
}
linux("fresh exact same-device and same-operation proof is required; malformed and foreign proofs fail closed",async()=>{
 const f=fixture();
 try{
  assert.equal(await matchingLinuxProof(f.proof,expected),false);
  for(const change of [
   {operation_id:"other-approval"},{device_id:"11111111-1111-4111-8111-111111111111"},
   {target_version:SOURCE},{status:"connected"},{untrusted:true},
  ]){
    f.writeProof(change);
    assert.equal(await matchingLinuxProof(f.proof,expected),false);
  }
  f.writeProof();
  assert.equal(await matchingLinuxProof(f.proof,expected),true);
  chmodSync(f.proof,0o644);
  assert.equal(await matchingLinuxProof(f.proof,expected),false,
    "unprotected success evidence is never trusted");
 }finally{f.cleanup();}
});
linux("bounded signed proof waits without turning missing proof into success",async()=>{
 const f=fixture();
 try{
  let clock=1000,checks=0;
  assert.equal(await waitForLinuxSignedProof(f.proof,expected,{
    now:()=>clock,maxMs:100,
    wait:async ms=>{clock+=ms;checks++;}
  }),false);
  assert.ok(checks>=1);
  clock=1000;checks=0;
  assert.equal(await waitForLinuxSignedProof(f.proof,expected,{
    now:()=>clock,maxMs:100,
    wait:async ms=>{clock+=ms;checks++;if(checks===1)f.writeProof();}
  }),true);
  await assert.rejects(waitForLinuxSignedProof(f.proof,expected,{maxMs:90_001}),
    /Unbounded/);
 }finally{f.cleanup();}
});
linux("watchdog validates exact proof and commits completion only after native cutover returns",async()=>{
 const f=fixture();
 try{
  let cutovers=0;
  const result=await runLinuxOneShotWatchdog({...f.opts,upgrade:async props=>{
    cutovers++;
    assert.equal(props.home,f.home);
    assert.equal(props.endpoint,f.attempt.endpoint);
    assert.equal(props.upgradeOperationId,OP);
    assert.ok(props.newRoot.endsWith(TARGET+"-linux-"+process.arch+"-glibc"));
    const claim=path.join(f.state,"upgrade-exec-"+hashOperation(OP)+".json");
    assert.deepEqual(JSON.parse(readFileSync(claim,"utf8")),{
      operation_id:OP,device_id:DEVICE,target_version:TARGET,
    },"durable execution guard must precede native systemd change");
    assert.equal(readdirSync(f.state).some(x=>x.startsWith("upgrade-outcome-")),false,
      "success cannot be prewritten before native cutover completes");
    const verified=await props.verifySignedReconnect(expected);
    assert.equal(verified,true);
    return {status:"active",deviceId:DEVICE,version:TARGET,
      service:HISTORICAL_UNIT,identityPreserved:true};
  },waitForProof:async(file,binding)=>{
    assert.equal(file,f.proof);
    assert.deepEqual(binding,expected);
    f.writeProof();return true;
  }});
  assert.deepEqual(result,{status:"completed"});
  assert.equal(cutovers,1);
  assert.deepEqual(JSON.parse(readFileSync(f.outcome,"utf8")),{
    operation_id:OP,device_id:DEVICE,
    original_version:SOURCE,target_version:TARGET,status:"completed",
  });
  await assert.rejects(runLinuxOneShotWatchdog({...f.opts,
    upgrade:async()=>{throw Error("must not switch twice");}
  }),/Existing proof or outcome/);
 }finally{f.cleanup();}
});
linux("missing proof, callback error, or failed rollback emits guarded attention rather than success",async()=>{
 for(const mode of ["missing","error","rollback"]){
  const f=fixture();
  try{
   let invocations=0;
   assert.deepEqual(await runLinuxOneShotWatchdog({...f.opts,
     upgrade:async params=>{
       invocations++;
       if(mode==="rollback")throw Error("rollback uncertain");
       const valid=await params.verifySignedReconnect(
         mode==="missing"?{...expected,operationId:"replay"}:expected);
       if(mode==="missing"){assert.equal(valid,false);throw Error("new socket absent");}
       assert.equal(valid,false);
       throw Error("new socket validation refused");
     },
     waitForProof:mode==="error"?async()=>{throw Error("read error")}:async()=>true,
   }),{status:"needs_attention"});
   assert.equal(invocations,1);
   const entry=JSON.parse(readFileSync(f.outcome,"utf8"));
   assert.equal(entry.status,"needs_attention");
  }finally{f.cleanup();}
 }
});
linux("stale WSS proof or result before switching refuses without invoking installer",async()=>{
 for(const prior of ["proof","outcome"]){
  const f=fixture();
  try{
    writeFileSync(prior==="proof"?f.proof:f.outcome,"{}",{mode:0o600});
    let calls=0;
    await assert.rejects(runLinuxOneShotWatchdog({...f.opts,
      upgrade:async()=>{calls++;}
    }),/Existing proof or outcome/);
    assert.equal(calls,0);
  }finally{f.cleanup();}
 }
});

linux("watchdog crash before outcome cannot reexecute same operation",async()=>{
 const f=fixture();
 try{
  let invocations=0;
  await runLinuxOneShotWatchdog({...f.opts,upgrade:async()=>{
    invocations++;throw Error("simulated process crash");
  }});
  // A real crash might happen before any outcome was written. Its durable
  // execution guard survives and must reject the next one-shot invocation.
  const {unlinkSync}=await import("node:fs");
  unlinkSync(f.outcome);
  await assert.rejects(runLinuxOneShotWatchdog({...f.opts,
    upgrade:async()=>{invocations++;}}),/EEXIST|already exists/i);
  assert.equal(invocations,1);
 }finally{f.cleanup();}
});
linux("watched success cannot be inferred from signed proof alone or foreign result",async()=>{
 for(const variant of ["no-hook","foreign-device","foreign-version","no-identity"]){
  const f=fixture();
  try{
   const outcome=await runLinuxOneShotWatchdog({...f.opts,
     upgrade:async props=>{
       if(variant!=="no-hook")
         assert.equal(await props.verifySignedReconnect(expected),true);
       return {status:"active",
         deviceId:variant==="foreign-device"?"11111111-1111-4111-8111-111111111111":DEVICE,
         version:variant==="foreign-version"?SOURCE:TARGET,
         service:HISTORICAL_UNIT,
         identityPreserved:variant!=="no-identity"};
     },
     waitForProof:async()=>true,
   });
   assert.equal(outcome.status,"needs_attention",variant);
   assert.equal(JSON.parse(readFileSync(f.outcome,"utf8")).status,"needs_attention");
  }finally{f.cleanup();}
 }
});
