import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { ReceiptStore, operationDigest } from "../src/operations.ts";
import { admitOwnerApprovedUpgrade } from "../src/upgrade-admission.ts";

const device="2a83dae6-600c-49cc-b643-ab0d5ec7e0c8";
const idHash="a".repeat(64), commit="b".repeat(40), sha="c".repeat(64);
const now=1792845000000;
const req={
  operation_id:"approved-upgrade-1",device_id:device,source_version:"v0.1.22",
  target_version:"v0.1.23",target_commit:commit,target_sha256:sha,
  target_platform:"windows-x64",identity_sha256:idHash,authorized_until:now+120000,
};
const ctx={
  deviceId:device,installedVersion:"v0.1.22",identityDigest:idHash,
  platform:"windows-x64",now,
  approvedRelease:{version:"v0.1.23",commit,sha256:sha,platform:"windows-x64"},
};
async function fixture(fn: (store: ReceiptStore, directory: string) => Promise<void>) {
  const directory=await mkdtemp(path.join(tmpdir(),"rca-upgrade-approval-"));
  const store=new ReceiptStore(directory);
  try {await store.open();await fn(store,directory);}
  finally {await store.close();await rm(directory,{recursive:true,force:true});}
}
test("persist one owner-approved upgrade using existing durable SQLite receipts",async()=>{
  await fixture(async(store)=>{
    let verified=0;
    const check=async()=>{verified++;return true;};
    const first=await admitOwnerApprovedUpgrade(store,req,ctx,check);
    assert.equal(first.kind,"new");
    assert.equal(first.receipt.state,"admitted");
    assert.equal(first.receipt.tool_name,"upgrade_agent");
    assert.equal(first.receipt.argument_digest,operationDigest("upgrade_agent",req));
    const again=await admitOwnerApprovedUpgrade(store,req,ctx,check);
    assert.equal(again.kind,"existing");
    assert.equal(again.receipt.created_at,first.receipt.created_at);
    assert.equal(verified,2);
  });
});
test("reject missing approval without storing an operation",async()=>{
  await fixture(async(store)=>{
    await assert.rejects(()=>admitOwnerApprovedUpgrade(store,req,ctx,async()=>false),/approval missing/);
    assert.equal(await store.get(req.operation_id),null);
    await assert.rejects(()=>admitOwnerApprovedUpgrade(store,req,ctx,async()=>{throw Error("provider unavailable")}),/provider unavailable/);
    assert.equal(await store.get(req.operation_id),null);
  });
});
test("same operation with different arguments is a durable conflict",async()=>{
  await fixture(async(store)=>{
    assert.equal((await admitOwnerApprovedUpgrade(store,req,ctx,async()=>true)).kind,"new");
    const different={...req,authorized_until:now+60000};
    const conflict=await admitOwnerApprovedUpgrade(store,different,ctx,async()=>true);
    assert.equal(conflict.kind,"conflict");
    assert.equal(conflict.receipt.argument_digest,operationDigest("upgrade_agent",req));
  });
});
test("operation ID collision with file/Shell tool cannot be repurposed as upgrade",async()=>{
  await fixture(async(store)=>{
    await store.admit(req.operation_id,"start_process","d".repeat(64));
    const conflict=await admitOwnerApprovedUpgrade(store,req,ctx,async()=>true);
    assert.equal(conflict.kind,"conflict");
    assert.equal(conflict.receipt.tool_name,"start_process");
  });
});
test("restart preserves prior upgrade as unknown, never safely replayable",async()=>{
  await fixture(async(store,dir)=>{
    const first=await admitOwnerApprovedUpgrade(store,req,ctx,async()=>true);
    assert.equal(first.kind,"new");
    await store.update(req.operation_id,"running","Approved upgrade handoff started");
    await store.close();
    const restarted=new ReceiptStore(dir);
    try{
      await restarted.open();
      const prev=await restarted.get(req.operation_id);
      assert.equal(prev?.state,"unknown");
      assert.match(prev?.safe_result_summary??"",/cannot be established/);
      const same=await admitOwnerApprovedUpgrade(restarted,req,ctx,async()=>true);
      assert.equal(same.kind,"existing");
      assert.equal(same.receipt.state,"unknown");
    }finally{await restarted.close();}
  });
});
test("expired approvals and unapproved release drift fail before any receipt",async()=>{
  await fixture(async(store)=>{
    await assert.rejects(
      ()=>admitOwnerApprovedUpgrade(store,req,{...ctx,now:now+180000},async()=>true),
      /expired/,
    );
    await assert.rejects(
      ()=>admitOwnerApprovedUpgrade(store,req,{...ctx,approvedRelease:null},async()=>true),
      /not approved/,
    );
    assert.equal(await store.get(req.operation_id),null);
  });
});
test("old receipts remain intact and queryable alongside upgrade receipt",async()=>{
  await fixture(async(store)=>{
    await store.admit("preexisting-file-write","write_file","f".repeat(64));
    await store.update("preexisting-file-write","completed","Done");
    await admitOwnerApprovedUpgrade(store,req,ctx,async()=>true);
    const old=await store.get("preexisting-file-write");
    assert.equal(old?.state,"completed");
    assert.equal(old?.tool_name,"write_file");
  });
});

test("concurrent same-ID requests have exactly one new admission",async()=>{
  await fixture(async(store)=>{
    const attempts=await Promise.all(Array.from({length:8},()=>admitOwnerApprovedUpgrade(
      store,req,ctx,async()=>true,
    )));
    assert.equal(attempts.filter(a=>a.kind==="new").length,1);
    assert.equal(attempts.filter(a=>a.kind==="existing").length,7);
    assert.ok(attempts.every(a=>a.kind!=="busy"&&
      a.receipt.argument_digest===operationDigest("upgrade_agent",req)));
  });
});
test("concurrent conflicting targets cannot share one authorization operation",async()=>{
  await fixture(async(store)=>{
    const revised={...req,authorized_until:now+60000};
    const attempts=await Promise.all([
      admitOwnerApprovedUpgrade(store,req,ctx,async()=>true),
      admitOwnerApprovedUpgrade(store,revised,ctx,async()=>true),
    ]);
    assert.deepEqual(attempts.map(a=>a.kind).sort(),["conflict","new"]);
    const stored=await store.get(req.operation_id);
    assert.ok(stored?.argument_digest===operationDigest("upgrade_agent",req)||
      stored?.argument_digest===operationDigest("upgrade_agent",revised));
  });
});
test("SQLite commit failure fails closed without accepting or replaying upgrade",async()=>{
  const directory=await mkdtemp(path.join(tmpdir(),"rca-upgrade-persist-"));
  let rejectCommit=false;
  const store=new ReceiptStore(directory,phase=>rejectCommit&&phase==="commit");
  try {
    await store.open();
    rejectCommit=true;
    await assert.rejects(admitOwnerApprovedUpgrade(store,req,ctx,async()=>true),/commit is unavailable/);
    rejectCommit=false;
    assert.equal(await store.get(req.operation_id),null);
    const admitted=await admitOwnerApprovedUpgrade(store,req,ctx,async()=>true);
    assert.equal(admitted.kind,"new");
  } finally {
    rejectCommit=false;
    await store.close();
    await rm(directory,{recursive:true,force:true});
  }
});


test("active upgrade blocks any second operation ID until verified completion",async()=>{
  await fixture(async(store)=>{
    const other={...req,operation_id:"approved-upgrade-2"};
    assert.equal((await admitOwnerApprovedUpgrade(store,req,ctx,async()=>true)).kind,"new");
    assert.equal((await admitOwnerApprovedUpgrade(store,other,ctx,async()=>true)).kind,"busy");
    assert.equal(await store.get(other.operation_id),null);
    await assert.rejects(store.update(req.operation_id,"completed","Caller guessed success"),/verified recovery/);
    await store.update(req.operation_id,"running","Verified handoff began");
    await store.completeVerifiedUpgrade(req.operation_id,operationDigest("upgrade_agent",req));
    assert.equal((await admitOwnerApprovedUpgrade(store,other,ctx,async()=>true)).kind,"new");
  });
});
test("uncertain and guarded failures keep global upgrade admission closed",async()=>{
  await fixture(async(store)=>{
    const other={...req,operation_id:"approved-upgrade-3"};
    await admitOwnerApprovedUpgrade(store,req,ctx,async()=>true);
    await store.update(req.operation_id,"unknown","Upgrade outcome uncertain");
    assert.equal((await admitOwnerApprovedUpgrade(store,other,ctx,async()=>true)).kind,"busy");
    await store.update(req.operation_id,"failed","Cannot establish old service state");
    assert.equal((await admitOwnerApprovedUpgrade(store,other,ctx,async()=>true)).kind,"busy");
    await store.update(req.operation_id,"failed","No side effects established",undefined,true);
    assert.equal((await admitOwnerApprovedUpgrade(store,other,ctx,async()=>true)).kind,"new");
  });
});
test("concurrent distinct IDs cannot both reserve a device-wide upgrade slot",async()=>{
  await fixture(async(store)=>{
    const other={...req,operation_id:"approved-upgrade-4"};
    const results=await Promise.all([
      admitOwnerApprovedUpgrade(store,req,ctx,async()=>true),
      admitOwnerApprovedUpgrade(store,other,ctx,async()=>true),
    ]);
    assert.deepEqual(results.map(r=>r.kind).sort(),["busy","new"]);
  });
});
test("atomic approved request metadata survives restart in the original receipt SQLite file",async()=>{
  await fixture(async(store,dir)=>{
    const first=await admitOwnerApprovedUpgrade(store,req,ctx,async()=>true);
    assert.equal(first.kind,"new");
    assert.deepEqual(await store.getUpgradeIntent(req.operation_id),req);
    await store.update(req.operation_id,"running","Upgrade handoff started");
    await store.close();
    const restarted=new ReceiptStore(dir);
    try{
      await restarted.open();
      assert.equal((await restarted.get(req.operation_id))?.state,"unknown");
      assert.deepEqual(await restarted.getUpgradeIntent(req.operation_id),req);
      assert.equal((await admitOwnerApprovedUpgrade(restarted,req,ctx,async()=>true)).kind,"existing");
    }finally{await restarted.close();}
  });
});
test("SQLite metadata and receipt rollback together on forced COMMIT failure",async()=>{
  const directory=await mkdtemp(path.join(tmpdir(),"rca-upgrade-atomic-"));
  let fail=false;
  const store=new ReceiptStore(directory,phase=>fail&&phase==="commit");
  try{
    await store.open();fail=true;
    await assert.rejects(admitOwnerApprovedUpgrade(store,req,ctx,async()=>true),/commit is unavailable/);
    fail=false;
    assert.equal(await store.get(req.operation_id),null);
    assert.equal(await store.getUpgradeIntent(req.operation_id),null);
    assert.equal((await admitOwnerApprovedUpgrade(store,req,ctx,async()=>true)).kind,"new");
    assert.deepEqual(await store.getUpgradeIntent(req.operation_id),req);
  }finally{fail=false;await store.close();await rm(directory,{recursive:true,force:true});}
});
test("tampered persisted upgrade metadata cannot be recovered or reused",async()=>{
  await fixture(async(store,dir)=>{
    await admitOwnerApprovedUpgrade(store,req,ctx,async()=>true);
    await store.close();
    const {DatabaseSync}=await import("node:sqlite");
    const db=new DatabaseSync(path.join(dir,"operation-receipts.sqlite"));
    try{
      db.prepare("UPDATE upgrade_intents SET request_json = ? WHERE operation_id = ?")
        .run(JSON.stringify({...req,target_sha256:"d".repeat(64)}),req.operation_id);
    }finally{db.close();}
    await store.open();
    await assert.rejects(store.getUpgradeIntent(req.operation_id),/digest mismatch/);
    assert.equal((await admitOwnerApprovedUpgrade(store,req,ctx,async()=>true)).kind,"conflict");
  });
});
test("non-upgrade receipt writes never require or create upgrade metadata",async()=>{
  await fixture(async(store)=>{
    await store.admit("another-write","write_file","e".repeat(64));
    assert.equal(await store.getUpgradeIntent("another-write"),null);
    await assert.rejects(store.admit("invalid-direct","upgrade_agent","e".repeat(64)),/metadata required/);
    assert.equal(await store.get("invalid-direct"),null);
  });
});
