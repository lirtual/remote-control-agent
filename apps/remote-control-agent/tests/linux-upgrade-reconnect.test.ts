import assert from "node:assert/strict";
import {test} from "node:test";
import {createHash} from "node:crypto";
import {mkdtemp,mkdir,writeFile,readFile,chmod,lstat,rm} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import {acknowledgeAuthenticatedLinuxUpgrade,readLinuxUpgradeOutcome}
  from "../src/linux-upgrade-reconnect.ts";

const linux=process.platform==="linux"&&process.getuid?.()!==0?test:test.skip;
const OP="signed-linux-watchdog-39";
const DEVICE="af666663-b30c-4b3d-ad85-c8047dc3516b";
const TARGET="v0.1.23",CURRENT="v0.1.22";
async function fixture() {
  const home=await mkdtemp(path.join(os.tmpdir(),"rca-linux-proof-"));
  const dir=path.join(home,"private-receipts");
  await mkdir(dir,{mode:0o700});
  const manifest=path.join(home,"bundle.json");
  const bytes=JSON.stringify({name:"remote-control-agent",version:TARGET,
    target:"linux-"+process.arch+"-glibc",upgrade_profile:"paired-full-v1",
    upgrade_protocol:"owner-one-shot-v1",device_protocol:2,receipt_schema:1});
  await writeFile(manifest,bytes,{mode:0o600});
  const key=createHash("sha256").update(OP).digest("hex");
  const pending=path.join(dir,"upgrade-run-"+key+".json");
  const proof=path.join(dir,"upgrade-auth-"+key+".json");
  const record={operation_id:OP,device_id:DEVICE,
    current_version:CURRENT,target_version:TARGET,
    current_manifest_sha256:"0".repeat(64),
    target_manifest_sha256:createHash("sha256").update(bytes).digest("hex")};
  await writeFile(pending,JSON.stringify(record),{mode:0o600});
  const run=(changes:Record<string,unknown>={},
    canAdmit=async (_:string)=>true)=>
    acknowledgeAuthenticatedLinuxUpgrade({stateDirectory:dir,
      deviceId:DEVICE,runningVersion:TARGET,manifestPath:manifest,
      isAdmitted:canAdmit,...changes});
  return {home,dir,manifest,pending,proof,record,run,
    cleanup:()=>rm(home,{recursive:true,force:true})};
}
linux("new exact signed WSS handshake produces one fsynced owner-only Linux proof",async()=>{
  const f=await fixture();
  try {
    let admitted=0;
    assert.equal(await f.run({},async op=>{
      admitted++;assert.equal(op,OP);return true;
    }),1);
    assert.equal(admitted,1);
    assert.deepEqual(JSON.parse(await readFile(f.proof,"utf8")),{
      operation_id:OP,device_id:DEVICE,target_version:TARGET,
      status:"authenticated_wss",
    });
    assert.equal((await lstat(f.proof)).mode&0o777,0o600);
    assert.equal(await f.run(),0,
      "exactly the same signed session cannot replace an existing proof");
  }finally {await f.cleanup();}
});
linux("wrong device, target, approval, protocol, pin or unsafe state cannot sign",async()=>{
  for(const variant of [
    "wrong-device","wrong-version","receipt-refused","altered-manifest",
    "foreign-pin","unreviewed-protocol","unsafe-state","unsafe-attempt",
    "same-version","extra-field",
  ]){
    const f=await fixture();
    try{
      let opts:Record<string,unknown>={};
      let admission=async (_:string)=>true;
      if(variant==="wrong-device")opts={deviceId:"11111111-1111-4111-8111-111111111111"};
      if(variant==="wrong-version")opts={runningVersion:CURRENT};
      if(variant==="receipt-refused")admission=async()=>false;
      if(variant==="altered-manifest")
        await writeFile(f.manifest,JSON.stringify({unreviewed:true}));
      if(variant==="foreign-pin")
        await writeFile(f.pending,JSON.stringify({...f.record,
          target_manifest_sha256:"f".repeat(64)}));
      if(variant==="same-version")
        await writeFile(f.pending,JSON.stringify({...f.record,
          current_version:TARGET}));
      if(variant==="extra-field")
        await writeFile(f.pending,JSON.stringify({...f.record,
          unreviewed:true}));
      if(variant==="unreviewed-protocol"){
        const manifest=JSON.parse(await readFile(f.manifest,"utf8"));
        delete manifest.upgrade_protocol;
        await writeFile(f.manifest,JSON.stringify(manifest));
      }
      if(variant==="unsafe-state")await chmod(f.dir,0o755);
      if(variant==="unsafe-attempt")await chmod(f.pending,0o644);
      assert.equal(await f.run(opts,admission),0,variant);
      await assert.rejects(lstat(f.proof),{code:"ENOENT"});
    }finally{await f.cleanup();}
  }
});
linux("absent or malformed marker never authorizes signing based on version alone",async()=>{
  const f=await fixture();
  try{
    await writeFile(f.pending,"{}",{mode:0o600});
    assert.equal(await f.run(),0);
    await assert.rejects(lstat(f.proof),{code:"ENOENT"});
  }finally{await f.cleanup();}
});


linux("Linux completion requires private claim, exact watchdog result and signed WSS proof",async()=>{
  const f=await fixture();
  try{
    const key=createHash("sha256").update(OP).digest("hex");
    const claim=path.join(f.dir,"upgrade-exec-"+key+".json");
    const outcome=path.join(f.dir,"upgrade-outcome-"+key+".json");
    const write=async(file:string,row:object)=>
      writeFile(file,JSON.stringify(row),{mode:0o600});
    const executed={operation_id:OP,device_id:DEVICE,target_version:TARGET};
    const finished={operation_id:OP,device_id:DEVICE,
      original_version:CURRENT,target_version:TARGET,status:"completed"};
    assert.equal(await readLinuxUpgradeOutcome(f.dir,OP,TARGET,DEVICE),null);
    await write(claim,executed);
    await write(outcome,finished);
    assert.equal(await readLinuxUpgradeOutcome(f.dir,OP,TARGET,DEVICE),null,
      "the watchdog result cannot replace authenticated WSS");
    assert.equal(await f.run(),1);
    assert.equal(await readLinuxUpgradeOutcome(f.dir,OP,TARGET,DEVICE),"completed");
    assert.equal(await readLinuxUpgradeOutcome(f.dir,OP,CURRENT,DEVICE),null);
    assert.equal(await readLinuxUpgradeOutcome(f.dir,OP,TARGET,
      "11111111-1111-4111-8111-111111111111"),null);
    await chmod(claim,0o644);
    assert.equal(await readLinuxUpgradeOutcome(f.dir,OP,TARGET,DEVICE),null,
      "world-readable execution claim must be rejected");
  }finally{await f.cleanup();}
});

linux("confirmed original-service rollback needs exact durable claim and matching old runtime",async()=>{
  const f=await fixture();
  try{
    const key=createHash("sha256").update(OP).digest("hex");
    const claim=path.join(f.dir,"upgrade-exec-"+key+".json");
    const outcome=path.join(f.dir,"upgrade-outcome-"+key+".json");
    const executed={operation_id:OP,device_id:DEVICE,target_version:TARGET};
    const restored={operation_id:OP,device_id:DEVICE,
      original_version:CURRENT,target_version:TARGET,status:"rolled_back"};
    assert.equal(await readLinuxUpgradeOutcome(f.dir,OP,CURRENT,DEVICE),null);
    await writeFile(claim,JSON.stringify(executed),{mode:0o600});
    await writeFile(outcome,JSON.stringify(restored),{mode:0o600});
    assert.equal(await readLinuxUpgradeOutcome(f.dir,OP,CURRENT,DEVICE),"rolled_back");
    assert.equal(await readLinuxUpgradeOutcome(f.dir,OP,TARGET,DEVICE),null,
      "the new runtime cannot claim restoration of the previous version");
    await writeFile(outcome,JSON.stringify({...restored,status:"needs_attention"}));
    assert.equal(await readLinuxUpgradeOutcome(f.dir,OP,CURRENT,DEVICE),null);
    await writeFile(outcome,JSON.stringify(restored));
    await chmod(claim,0o644);
    assert.equal(await readLinuxUpgradeOutcome(f.dir,OP,CURRENT,DEVICE),null,
      "tampered one-shot claim cannot confirm rollback");
  }finally{await f.cleanup();}
});

linux("malformed, foreign or guarded Linux outcomes never complete the receipt",async()=>{
  for(const variant of ["attention","foreign-device","wrong-target",
      "wrong-operation","foreign-original","claim-foreign",
      "proof-foreign","extra-outcome","unsafe-outcome","missing-claim"]){
    const f=await fixture();
    try{
      const key=createHash("sha256").update(OP).digest("hex");
      const claim=path.join(f.dir,"upgrade-exec-"+key+".json");
      const outcome=path.join(f.dir,"upgrade-outcome-"+key+".json");
      const executed={operation_id:OP,device_id:DEVICE,target_version:TARGET};
      const finished={operation_id:OP,device_id:DEVICE,
        original_version:CURRENT,target_version:TARGET,status:"completed"};
      await f.run();
      if(variant==="proof-foreign")
        await writeFile(f.proof,JSON.stringify({
          operation_id:OP,device_id:DEVICE,target_version:CURRENT,
          status:"authenticated_wss"}));
      if(variant!=="missing-claim")
        await writeFile(claim,JSON.stringify(variant==="claim-foreign"
          ?{...executed,device_id:"11111111-1111-4111-8111-111111111111"}
          :executed),{mode:0o600});
      const changes:Record<string,unknown> =
        variant==="attention"?{status:"needs_attention"}:
        variant==="foreign-device"?{device_id:"11111111-1111-4111-8111-111111111111"}:
        variant==="wrong-target"?{target_version:CURRENT}:
        variant==="wrong-operation"?{operation_id:"other-op"}:
        variant==="foreign-original"?{original_version:TARGET}:
        variant==="extra-outcome"?{unreviewed:true}:{};
      await writeFile(outcome,JSON.stringify({...finished,...changes}),{mode:0o600});
      if(variant==="unsafe-outcome")await chmod(outcome,0o644);
      assert.equal(await readLinuxUpgradeOutcome(f.dir,OP,TARGET,DEVICE),
        null,variant);
    }finally{await f.cleanup();}
  }
});
