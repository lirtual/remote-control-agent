import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { createAgentExecutionEngine } from "../src/execution.ts";
import { startUpgradeControl, upgradeSocketPath } from "../src/upgrade-control.ts";
import { requestUpgradeConsent } from "../scripts/install-v2.mjs";

test("owner-local upgrade socket freezes operation admission atomically and releases on installer failure",async()=>{
  const dir=await mkdtemp(path.join(os.tmpdir(),"rc-upgrade-freeze-"));
  const execution=createAgentExecutionEngine({receiptDirectory:path.join(dir,"receipts")});
  const keyPath=path.join(dir,"identity.pem");
  const signal=new AbortController().signal;
  let control;
  try {
    control=await startUpgradeControl(execution,keyPath);
    const stat=await import("node:fs/promises").then(fs=>fs.lstat(upgradeSocketPath(keyPath)));
    assert.equal(stat.mode & 0o777,0o600);
    assert.equal(await requestUpgradeConsent(keyPath,"freeze"),"ready");
    assert.equal(await requestUpgradeConsent(keyPath,"freeze"),"busy");
    const operation_id="upgrade-locked-"+randomUUID();
    const denied=await execution.executeTool({
      tool:"write_file",arguments:{path:path.join(dir,"effect.txt"),content:"ok",mode:"rewrite"},operation_id,
    },signal);
    assert.equal(denied?.status,503);
    assert.equal(await execution.getReceipt(operation_id),null);
    assert.equal(await requestUpgradeConsent(keyPath,"release"),"released");
    const allowed=await execution.executeTool({
      tool:"write_file",arguments:{path:path.join(dir,"effect.txt"),content:"ok",mode:"rewrite"},operation_id,
    },signal);
    assert.equal(allowed?.status,200);
    assert.equal(await readFile(path.join(dir,"effect.txt"),"utf8"),"ok");
  } finally {
    await control?.close();
    await execution.close();
    await rm(dir,{recursive:true,force:true});
  }
});
test("busy full-tools Shell session refuses upgrade until completed",async()=>{
  const dir=await mkdtemp(path.join(os.tmpdir(),"rc-upgrade-busy-"));
  const execution=createAgentExecutionEngine({receiptDirectory:path.join(dir,"receipts")});
  const keyPath=path.join(dir,"identity.pem");
  let control;
  try {
    control=await startUpgradeControl(execution,keyPath);
    const started=await execution.executeTool({
      tool:"start_process",arguments:{command:"sleep 2",timeout_ms:0},
      operation_id:"busy-shell-"+randomUUID(),
    },new AbortController().signal);
    assert.equal(started?.status,200);
    assert.equal(await requestUpgradeConsent(keyPath,"freeze"),"busy");
    // The denial must never leave new operations frozen.
    const cleared=await execution.executeTool({
      tool:"get_file_info",arguments:{path:dir},
    },new AbortController().signal);
    assert.equal(cleared?.status,200);
  } finally {
    await control?.close();
    await execution.close();
    await rm(dir,{recursive:true,force:true});
  }
});
test("missing upgrade socket fails closed without creating receipts",async()=>{
  const dir=await mkdtemp(path.join(os.tmpdir(),"rc-upgrade-absent-"));
  try {
    await assert.rejects(requestUpgradeConsent(path.join(dir,"identity.pem"),"freeze"),{code:"ENOENT"});
  } finally {
    await rm(dir,{recursive:true,force:true});
  }
});


test("freeze refuses an operation still awaiting async receipt admission",async()=>{
  const dir=await mkdtemp(path.join(os.tmpdir(),"rc-upgrade-admitting-"));
  const execution=createAgentExecutionEngine({receiptDirectory:path.join(dir,"receipts")});
  try {
    const inProgress=execution.executeTool({
      tool:"write_file",arguments:{path:path.join(dir,"committed.txt"),content:"once",mode:"rewrite"},
      operation_id:"pending-admission-"+randomUUID(),
    },new AbortController().signal);
    assert.equal(execution.freezeForUpgrade(),false);
    assert.equal((await inProgress)?.status,200);
    assert.equal(execution.freezeForUpgrade(),true);
    execution.releaseUpgradeFreeze();
  } finally {
    await execution.close();
    await rm(dir,{recursive:true,force:true});
  }
});
test("P16 merged browser effects respect owner-local upgrade freeze and an active Profile prevents promotion", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "rc-p16-browser-freeze-"));
  const sid = randomUUID();
  let active = null;
  let starts = 0;
  const browser = {
    status: () => active,
    start: async () => { starts++; active = { session_id:sid, tab_id:"tab-1", backend:"playwright", uncertain:false, snapshot_version:0 }; return active; },
    navigate: async () => {},
    snapshot: async () => ({ text:"", truncated:false, snapshot_version:0 }),
    close: async () => { active=null; },
  };
  const execution = createAgentExecutionEngine({browser, receiptDirectory:path.join(dir,"receipts")});
  const signal = new AbortController().signal;
  try {
    const startId="p16-start-"+randomUUID();
    await execution.executeTool({tool:"browser_start",arguments:{},operation_id:startId},signal);
    assert.equal(starts,1);
    assert.equal(execution.freezeForUpgrade(),false,"active owned browser must block upgrade");
    const closeId="p16-close-"+randomUUID();
    await execution.executeTool({tool:"browser_close",arguments:{session_id:sid},operation_id:closeId},signal);
    assert.equal(active,null);
    assert.equal(execution.freezeForUpgrade(),true);
    const refusedId="p16-refused-"+randomUUID();
    const refused=await execution.executeTool({tool:"browser_start",arguments:{},operation_id:refusedId},signal);
    assert.equal(refused?.status,503);
    assert.equal(await execution.getReceipt(refusedId),null);
    assert.equal(starts,1,"frozen browser launch must not execute or create a receipt");
    execution.releaseUpgradeFreeze();
    await execution.executeTool({tool:"browser_start",arguments:{},operation_id:refusedId},signal);
    assert.equal(starts,2);
  } finally {
    await execution.close();
    await rm(dir,{recursive:true,force:true});
  }
});

test("P16 upgrade freeze rejects every browser effect without issuing a receipt or side effect", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "p16-frozen-browser-all-effects-"));
  const sid = randomUUID();
  const calls = { start:0, navigate:0, close:0 };
  const backend = {
    status: () => null,
    start: async () => { calls.start++; return {session_id:sid,tab_id:"tab-1",backend:"playwright",uncertain:false,snapshot_version:0}; },
    navigate: async () => { calls.navigate++; },
    close: async () => { calls.close++; },
    snapshot: async () => ({text:"",truncated:false,snapshot_version:0}),
  };
  const engine = createAgentExecutionEngine({browser:backend,receiptDirectory:path.join(dir,"receipts")});
  try {
    assert.equal(engine.freezeForUpgrade(),true);
    for (const [tool,args] of [
      ["browser_start", {}],
      ["browser_navigate", {session_id:sid,url:"https://example.com/"}],
      ["browser_close", {session_id:sid}],
    ]) {
      const operation_id="p16-freeze-"+randomUUID();
      const outcome=await engine.executeTool({tool,arguments:args,operation_id},new AbortController().signal);
      assert.equal(outcome?.status,503,tool+" must fail closed during an upgrade");
      assert.equal(await engine.getReceipt(operation_id),null,tool+" must not create a receipt");
    }
    assert.deepEqual(calls,{start:0,navigate:0,close:0});
  } finally {
    engine.releaseUpgradeFreeze();
    await engine.close();
    await rm(dir,{recursive:true,force:true});
  }
});

test("P16 pending browser startup blocks freeze even before Chrome exposes a session", async () => {
  const dir=await mkdtemp(path.join(os.tmpdir(),"p16-browser-pending-upgrade-"));
  let releaseStart=() => {};
  const gate=new Promise(resolve => { releaseStart=resolve; });
  const sid=randomUUID();
  let active=null;
  const backend={
    status:()=>active,
    start:async()=>{await gate;active={session_id:sid,tab_id:"tab-1",backend:"playwright",uncertain:false,snapshot_version:0};return active;},
    navigate:async()=>{},
    snapshot:async()=>({text:"",truncated:false,snapshot_version:0}),
    close:async()=>{active=null;},
  };
  const engine=createAgentExecutionEngine({browser:backend,receiptDirectory:path.join(dir,"receipts")});
  const id="p16-pending-"+randomUUID();
  try{
    const startup=engine.executeTool({tool:"browser_start",arguments:{},operation_id:id},new AbortController().signal);
    await new Promise(resolve=>setTimeout(resolve,210));
    assert.equal(engine.freezeForUpgrade(),false,"pending startup must deny upgrade while backend status is null");
    const initial=await startup;
    assert.equal(initial?.status,200);
    releaseStart();
    let receipt=null;
    for(let i=0;i<30;i++){
      receipt=await engine.getReceipt(id);
      if(receipt?.state==="completed")break;
      await new Promise(resolve=>setTimeout(resolve,20));
    }
    assert.equal(receipt?.state,"completed");
    assert.equal(engine.freezeForUpgrade(),false,"active browser session must deny upgrade");
    await engine.executeTool({tool:"browser_close",arguments:{session_id:sid},operation_id:"p16-close-"+randomUUID()},new AbortController().signal);
    assert.equal(engine.freezeForUpgrade(),true,"after browser close upgrade may be admitted");
  }finally{
    releaseStart();
    engine.releaseUpgradeFreeze();
    await engine.close();
    await rm(dir,{recursive:true,force:true});
  }
});
