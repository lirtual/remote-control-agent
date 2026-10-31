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
