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
