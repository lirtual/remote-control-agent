import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { createAgentExecutionEngine } from "../src/execution.ts";
import { parseBrowserArguments } from "../src/browser-operations.ts";
import type { BrowserBackend, BrowserStatus } from "../src/browser-backend.ts";

test("browser gateway reuses durable Agent receipts and honors 5s Worker deadline", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "browser-receipt-mcp-"));
  const sid = randomUUID();
  let release!: () => void;
  const ready = new Promise<void>(done => { release = done; });
  let starts = 0;
  let navigations = 0;
  let closes = 0;
  let active: BrowserStatus | null = null;
  const browser = {
    status: () => active,
    start: async () => {
      starts++;
      await ready; // intentionally longer than the initial 150ms fast response
      active = { session_id: sid, tab_id: "tab-1" as const, backend: "playwright" as const, uncertain: false, snapshot_version: 0 };
      return active;
    },
    navigate: async (_id: string, _url: string) => { navigations++; throw Error("lost navigation reply"); },
    snapshot: async (_id: string) => ({ text: '- textbox "Test" [ref=e1]', truncated: false }),
    close: async () => { closes++; active = null; },
  } as unknown as BrowserBackend;
  const engine = createAgentExecutionEngine({ browser, receiptDirectory: root });
  const signal = new AbortController().signal;
  try {
    const firstId = "browser-start-" + randomUUID();
    const first = await engine.executeTool({ tool: "browser_start", arguments: {}, operation_id: firstId }, signal);
    assert.equal((first?.body as any).status, "running");
    assert.equal(starts, 1);
    assert.equal((await engine.getReceipt(firstId))?.state, "running");
    const dup = await engine.executeTool({ tool: "browser_start", arguments: {}, operation_id: firstId }, signal);
    assert.equal((dup?.body as any).status, "running");
    assert.equal(starts, 1, "same operation ID never launches another browser");
    release();
    for (let attempt = 0; attempt < 60; attempt++) {
      if ((await engine.getReceipt(firstId))?.state === "completed") break;
      await new Promise(done => setTimeout(done, 10));
    }
    const receipt = await engine.getReceipt(firstId);
    assert.equal(receipt?.state, "completed");
    assert.equal(receipt?.session_id, sid);
    assert.equal((await engine.executeTool({ tool: "browser_status", arguments: {} }, signal))?.status, 200);
    const snap = await engine.executeTool({ tool: "browser_snapshot", arguments: { session_id: sid } }, signal);
    assert.match(JSON.stringify(snap?.body), /Test/);

    const navId = "browser-nav-" + randomUUID();
    const nav = await engine.executeTool({tool:"browser_navigate",arguments:{session_id:sid,url:"https://example.com/"},operation_id:navId},signal);
    assert.equal((nav?.body as any).status, "unknown");
    const repeat = await engine.executeTool({tool:"browser_navigate",arguments:{session_id:sid,url:"https://example.com/"},operation_id:navId},signal);
    assert.equal((repeat?.body as any).status, "unknown");
    assert.equal(navigations, 1);
    const conflict = await engine.executeTool({tool:"browser_close",arguments:{session_id:sid},operation_id:navId},signal);
    assert.equal(conflict?.status, 409);
    assert.equal(closes, 0);

    const bad = await engine.executeTool({tool:"browser_start",arguments:{command:"whoami"},operation_id:"browser-bad-"+randomUUID()},signal);
    assert.equal(bad?.status, 400);
    const closeId = "browser-close-" + randomUUID();
    const close = await engine.executeTool({tool:"browser_close",arguments:{session_id:sid},operation_id:closeId},signal);
    assert.equal((close?.body as any).status, "completed");
    assert.equal(closes, 1);
  } finally {
    release();
    await engine.close();
    await rm(root, {recursive:true,force:true});
  }
});

test("browser parser rejects undocumented arguments and arbitrary executable/path overrides", () => {
  const id = randomUUID();
  assert.deepEqual(parseBrowserArguments("browser_start", {}), {});
  assert.deepEqual(parseBrowserArguments("browser_snapshot", { session_id:id }), {session_id:id});
  for (const input of [
    { profile: "/tmp/personal" }, { executable: "node" }, { command: "ls" },
    { session_id: id, arbitrary: true }, null, [],
  ]) assert.equal(parseBrowserArguments("browser_start", input), null);
  assert.equal(parseBrowserArguments("browser_navigate", {session_id:id,url:"https://example.com/",script:"alert(1)"}), null);
  assert.equal(parseBrowserArguments("browser_close", {session_id:"bad"}), null);
});

test("device revocation attempts owned browser shutdown and reports uncertainty", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(),"browser-revoke-test-"));
  const sid = randomUUID();
  let active=true, closures=0, refuse=false;
  const browser={
    status:()=>active?{session_id:sid,tab_id:"tab-1",backend:"playwright",uncertain:false,snapshot_version:0}:null,
    close:async()=>{closures++;if(refuse)throw Error("busy");active=false;},
  } as unknown as BrowserBackend;
  const engine=createAgentExecutionEngine({browser,receiptDirectory:dir});
  try {
    assert.equal(await engine.stopOwnedForRevocation(),"confirmed");
    assert.equal(closures,1);
    active=true;refuse=true;
    assert.equal(await engine.stopOwnedForRevocation(),"uncertain");
    assert.equal(closures,2);
  } finally { active=false;await engine.close();await rm(dir,{recursive:true,force:true}); }
});


test("P3 Agent shutdown interrupts its owned busy browser instead of abandoning it",async()=>{
  const dir=await mkdtemp(path.join(os.tmpdir(),"rca-p3-exit-browser-"));
  const sid=randomUUID();
  let active=true, forceCalls=0, ordinaryCalls=0;
  const browser={
    status:()=>active?{session_id:sid,tab_id:"tab-1",backend:"playwright",uncertain:false,snapshot_version:0}:null,
    close:async()=>{ordinaryCalls++;throw Error("Navigation busy");},
    stopOwnedForRevocation:async()=>{
      forceCalls++;
      active=false;
      return "confirmed" as const;
    },
  } as unknown as BrowserBackend;
  const engine=createAgentExecutionEngine({browser,receiptDirectory:dir});
  try{
    await engine.close();
    assert.equal(active,false,"The owned browser must be reclaimed on exit");
    assert.equal(forceCalls,1,"Reuses existing cancel/owned-context close");
    assert.equal(ordinaryCalls,0,"Does not attempt a busy normal close");
  }finally{await rm(dir,{recursive:true,force:true});}
});
