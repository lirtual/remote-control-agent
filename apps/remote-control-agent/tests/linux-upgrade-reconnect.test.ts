import assert from "node:assert/strict";
import {test} from "node:test";
import {createHash} from "node:crypto";
import {mkdtemp,mkdir,writeFile,readFile,chmod,lstat,rm} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import {acknowledgeAuthenticatedLinuxUpgrade}
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
