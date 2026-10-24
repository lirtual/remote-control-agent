import test from "node:test";
import assert from "node:assert/strict";
import {operationDigest, ReceiptStore, type OperationReceipt} from "../src/operations.ts";
import {assessUpgradeAfterReconnect, finalizeUpgradeAfterReconnect, type TrustedUpgradeEvidence} from "../src/upgrade-recovery.ts";
import type {UpgradeRequest} from "../src/upgrade-authorization.ts";
import {admitOwnerApprovedUpgrade} from "../src/upgrade-admission.ts";
import {mkdtemp,rm} from "node:fs/promises";
import {tmpdir} from "node:os";
import path from "node:path";

const request:UpgradeRequest = {
  operation_id:"remote-upgrade-2026-1",
  device_id:"2a83dae6-600c-49cc-b643-ab0d5ec7e0c8",
  source_version:"v0.1.22",target_version:"v0.1.23",
  target_commit:"b".repeat(40),target_sha256:"c".repeat(64),
  target_platform:"windows-x64",identity_sha256:"a".repeat(64),
  authorized_until:1792845120000,
};
const receipt:OperationReceipt={
  operation_id:request.operation_id,tool_name:"upgrade_agent",
  argument_digest:operationDigest("upgrade_agent",request),
  state:"unknown",created_at:"2026-10-24T00:00:00.000Z",
  updated_at:"2026-10-24T00:01:00.000Z",
};
const evidence:TrustedUpgradeEvidence={
  deviceId:request.device_id,identitySha256:request.identity_sha256,
  runningVersion:request.target_version,platform:request.target_platform,
  immutableReleaseCommit:request.target_commit,
  immutableReleaseAssetSha256:request.target_sha256,
  serviceActive:true,serviceExecutableVerified:true,
  durableReceiptsReadable:true,authenticatedSameDevice:true,
};
const assess=(r:OperationReceipt|null=receipt,e:TrustedUpgradeEvidence=evidence,q:UpgradeRequest=request)=>
  assessUpgradeAfterReconnect(q,r,e);
test("restarted unknown receipt becomes verifiable only with complete local evidence",()=>{
  assert.deepEqual(assess(),{kind:"verified",operationId:request.operation_id});
});
test("missing, forged, failed or cross-tool receipts cannot establish a verified upgrade",()=>{
  assert.equal(assess(null).kind,"unresolved");
  for (const altered of [
    {...receipt,operation_id:"different"},
    {...receipt,tool_name:"start_process" as const},
    {...receipt,argument_digest:"f".repeat(64)},
    {...receipt,state:"failed" as const},
    {...receipt,state:"admitted" as const},
  ]) assert.deepEqual(assess(altered),{kind:"unresolved",operationId:request.operation_id,reason:"receipt"});
});
test("prior upgrade authorization is cryptographically bound to the same exact request",()=>{
  for(const mutated of [
    {...request,target_sha256:"d".repeat(64)},
    {...request,authorized_until:request.authorized_until+1000},
    {...request,device_id:"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"},
  ])assert.equal(assess(receipt,evidence,mutated).kind,"unresolved");
});
test("running newer executable or same version alone cannot prove full upgrade",()=>{
  for (const mutation of [
    {runningVersion:"v0.1.22"},
    {immutableReleaseCommit:"d".repeat(40)},
    {immutableReleaseAssetSha256:"e".repeat(64)},
    {platform:"linux-x64-glibc"},
  ])assert.deepEqual(assess(receipt,{...evidence,...mutation}),{
    kind:"unresolved",operationId:request.operation_id,reason:"release",
  });
});
test("device identity mismatch cannot be masked by valid release or signed WSS",()=>{
  for (const mutation of [
    {identitySha256:"d".repeat(64)},
    {deviceId:"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"},
  ]) assert.deepEqual(assess(receipt,{...evidence,...mutation}),{
    kind:"unresolved",operationId:request.operation_id,reason:"identity",
  });
});
test("inactive or unverifiable OS task/service and inaccessible durable receipts stay unknown",()=>{
  for(const mutation of [
    {serviceActive:false},
    {serviceExecutableVerified:false},
    {durableReceiptsReadable:false},
  ])assert.deepEqual(assess(receipt,{...evidence,...mutation}),{
    kind:"unresolved",operationId:request.operation_id,reason:"service",
  });
});
test("same-device authenticated reconnection is mandatory before completion",()=>{
  assert.deepEqual(assess(receipt,{...evidence,authenticatedSameDevice:false}),{
    kind:"unresolved",operationId:request.operation_id,reason:"connection",
  });
});


async function liveReceiptFixture(fn:(store:ReceiptStore,dir:string)=>Promise<void>) {
  const directory=await mkdtemp(path.join(tmpdir(),"rca-reconnect-finalize-"));
  const store=new ReceiptStore(directory);
  try {
    await store.open();
    const context={
      deviceId:request.device_id,installedVersion:request.source_version,
      identityDigest:request.identity_sha256,platform:request.target_platform,
      now:request.authorized_until-1000,
      approvedRelease:{
        version:request.target_version,commit:request.target_commit,
        sha256:request.target_sha256,platform:request.target_platform,
      },
    };
    assert.equal((await admitOwnerApprovedUpgrade(store,request,context,async()=>true)).kind,"new");
    await fn(store,directory);
  } finally {await store.close();await rm(directory,{recursive:true,force:true});}
}
test("restarted unknown upgrade becomes completed only after trusted verification and keeps durable original ID",async()=>{
  await liveReceiptFixture(async(store,dir)=>{
    await store.update(request.operation_id,"running","Verified handoff to owner-local installer");
    await store.close();
    const reopened=new ReceiptStore(dir);
    try{
      await reopened.open();
      assert.equal((await reopened.get(request.operation_id))?.state,"unknown");
      const first=await finalizeUpgradeAfterReconnect(reopened,request.operation_id,async(original)=>{
        assert.deepEqual(original,request);return evidence;
      });
      assert.deepEqual(first,{kind:"verified",operationId:request.operation_id});
      const after=await reopened.get(request.operation_id);
      assert.equal(after?.state,"completed");
      assert.match(after?.safe_result_summary??"",/verified after reconnect/);
      const repeat=await finalizeUpgradeAfterReconnect(reopened,request.operation_id,async()=>evidence);
      assert.equal(repeat.kind,"verified");
      assert.equal((await reopened.get(request.operation_id))?.updated_at,after?.updated_at);
      assert.deepEqual(await reopened.getUpgradeIntent(request.operation_id),request);
    } finally{await reopened.close();}
  });
});
test("no upgrade completion through generic mutation receipts API",async()=>{
  await liveReceiptFixture(async(store)=>{
    await store.update(request.operation_id,"running","Handoff started");
    await assert.rejects(
      store.update(request.operation_id,"completed","Optimistic caller result"),
      /verified recovery/,
    );
    assert.equal((await store.get(request.operation_id))?.state,"running");
  });
});
test("admitted but not started operation can never be finalized, even with an apparently healthy new binary",async()=>{
  await liveReceiptFixture(async(store)=>{
    const verdict=await finalizeUpgradeAfterReconnect(store,request.operation_id,async()=>evidence);
    assert.deepEqual(verdict,{kind:"unresolved",operationId:request.operation_id,reason:"receipt"});
    assert.equal((await store.get(request.operation_id))?.state,"admitted");
  });
});
test("identity, immutable release, service and connection discrepancies all preserve unknown receipt",async()=>{
  await liveReceiptFixture(async(store)=>{
    await store.update(request.operation_id,"unknown","Offline upgrade outcome uncertain");
    for(const [change,reason] of [
      [{deviceId:"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"},"identity"],
      [{immutableReleaseAssetSha256:"e".repeat(64)},"release"],
      [{serviceActive:false},"service"],
      [{authenticatedSameDevice:false},"connection"],
    ] as const){
      assert.deepEqual(
        await finalizeUpgradeAfterReconnect(store,request.operation_id,async()=>({...evidence,...change})),
        {kind:"unresolved",operationId:request.operation_id,reason},
      );
      assert.equal((await store.get(request.operation_id))?.state,"unknown");
    }
    assert.equal(
      (await finalizeUpgradeAfterReconnect(store,request.operation_id,async()=>{throw Error("Inspection unavailable");})).kind,
      "unresolved",
    );
    assert.equal((await store.get(request.operation_id))?.state,"unknown");
  });
});
test("stale external inspection cannot close a receipt concurrently marked failed",async()=>{
  await liveReceiptFixture(async(store)=>{
    await store.update(request.operation_id,"running","Handoff started");
    const verdict=await finalizeUpgradeAfterReconnect(store,request.operation_id,async()=>{
      await store.update(request.operation_id,"failed","Effect remains uncertain");
      return evidence;
    });
    assert.deepEqual(verdict,{kind:"unresolved",operationId:request.operation_id,reason:"receipt"});
    assert.equal((await store.get(request.operation_id))?.state,"failed");
  });
});
test("post-verification SQLite COMMIT failure leaves upgraded operation guarded and unconfirmed",async()=>{
  const directory=await mkdtemp(path.join(tmpdir(),"rca-reconnect-commit-"));
  let failCommit=false;
  const store=new ReceiptStore(directory,stage=>failCommit&&stage==="commit");
  try{
    await store.open();
    await store.admit(request.operation_id,"upgrade_agent",operationDigest("upgrade_agent",request),JSON.stringify(request));
    await store.update(request.operation_id,"unknown","Awaiting reconnect verification");
    const verdict=await finalizeUpgradeAfterReconnect(store,request.operation_id,async()=>{
      failCommit=true;return evidence;
    });
    failCommit=false;
    assert.deepEqual(verdict,{kind:"unresolved",operationId:request.operation_id,reason:"receipt"});
    assert.equal((await store.get(request.operation_id))?.state,"unknown");
    assert.equal((await finalizeUpgradeAfterReconnect(store,request.operation_id,async()=>evidence)).kind,"verified");
  }finally{failCommit=false;await store.close();await rm(directory,{recursive:true,force:true});}
});
test("missing or altered approved intent never allows completion",async()=>{
  await liveReceiptFixture(async(store,dir)=>{
    await store.update(request.operation_id,"running","Handoff started");
    await store.close();
    const {DatabaseSync}=await import("node:sqlite");
    const db=new DatabaseSync(path.join(dir,"operation-receipts.sqlite"));
    try{
      db.prepare("UPDATE upgrade_intents SET request_json=? WHERE operation_id=?")
        .run(JSON.stringify({...request,target_sha256:"f".repeat(64)}),request.operation_id);
    }finally{db.close();}
    await store.open();
    assert.deepEqual(await finalizeUpgradeAfterReconnect(store,request.operation_id,async()=>evidence),
      {kind:"unresolved",operationId:request.operation_id,reason:"receipt"});
    assert.equal((await store.get(request.operation_id))?.state,"unknown");
  });
});


test("verified completed upgrade cannot regress to running or failed",async()=>{
  await liveReceiptFixture(async(store)=>{
    await store.update(request.operation_id,"running","Handoff started");
    assert.equal((await finalizeUpgradeAfterReconnect(store,request.operation_id,async()=>evidence)).kind,"verified");
    for (const next of ["running","failed","unknown","completed"] as const) {
      await assert.rejects(store.update(request.operation_id,next,"Late old-agent status"),/Upgrade/);
    }
    assert.equal((await store.get(request.operation_id))?.state,"completed");
  });
});
test("unknown and failed upgrade cannot be restarted by a stale executor",async()=>{
  await liveReceiptFixture(async(store)=>{
    await store.update(request.operation_id,"unknown","Previous process disconnected");
    await assert.rejects(store.update(request.operation_id,"running","Replay"),/cannot be restarted/);
    await store.update(request.operation_id,"failed","Uncertain effect");
    await assert.rejects(store.update(request.operation_id,"running","Replay after failure"),/cannot be restarted/);
    assert.equal((await store.get(request.operation_id))?.state,"failed");
  });
});
