import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { monitorDeviceSocket, executeV2FileOperation, executeV2SessionRead } from "../src/v2-connection-lifecycle.ts";
import { createAgentExecutionEngine } from "../src/execution.ts";
import type { BrowserCliAdapter, BrowserCliStatus } from "../src/browser-cli.ts";

class FakeSocket extends EventTarget {
  readyState = WebSocket.OPEN;
  private readonly outstanding = new Map<string, (message: any) => void>();
  send(text: string): void {
    if (text.startsWith("{")) {
      const message = JSON.parse(text);
      const next = this.outstanding.get(message.request_id);
      if (next) { this.outstanding.delete(message.request_id); next(message); }
    }
  }
  close(): void { this.readyState = WebSocket.CLOSED; }
  call(frame: Record<string, unknown>): Promise<any> {
    const request_id = randomUUID();
    return new Promise(resolve => {
      this.outstanding.set(request_id, resolve);
      this.dispatchEvent(new MessageEvent("message", { data: JSON.stringify({ ...frame, request_id }) }));
    });
  }
}

test("authenticated socket dispatches bounded browser commands through existing receipts", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "rca-browser-wss-"));
  const sid = randomUUID();
  let started = 0;
  let closed = 0;
  let active: BrowserCliStatus | null = null;
  const fakeBrowser = {
    start: async () => {
      started++;
      active = { session_id:sid, tab_id:"tab-1" as const, backend:"agent-browser" as const, uncertain:false };
      return active;
    },
    status: () => active,
    navigate: async () => {},
    snapshot: async () => ({text:'- textbox "Demo" [ref=e1]', truncated:false}),
    close: async () => { closed++; active = null; },
  } as unknown as BrowserCliAdapter;
  const execution = createAgentExecutionEngine({receiptDirectory:root,browser:fakeBrowser});
  const socket = new FakeSocket();
  const controller = new AbortController();
  const monitored = monitorDeviceSocket(socket as unknown as WebSocket,controller.signal,
    {intervalMs:1000,timeoutMs:100,authIntervalMs:2000},
    (tool,args,signal) => executeV2SessionRead(execution,tool,args,signal),
    (tool,args,id,signal) => executeV2FileOperation(execution,tool,args,id,signal),
    true);
  try {
    const opid = "browser-start-" + randomUUID();
    const first = await socket.call({kind:"operation",tool:"browser_start",arguments:{},operation_id:opid});
    assert.equal(first.kind,"operation_result");
    assert.equal(first.result.operation_id,opid);
    assert.ok(["running","completed"].includes(first.result.status));
    for(let n=0;n<50;n++){if((await execution.getReceipt(opid))?.state==="completed")break;await new Promise(done=>setTimeout(done,10));}
    const receipt = await execution.getReceipt(opid);
    assert.equal(receipt?.state,"completed");
    assert.equal(receipt?.session_id,sid);
    const duplicate = await socket.call({kind:"operation",tool:"browser_start",arguments:{},operation_id:opid});
    assert.equal(duplicate.result.status,"completed");
    assert.equal(started,1);

    const page = await socket.call({kind:"read",tool:"browser_snapshot",arguments:{session_id:sid}});
    assert.equal(page.kind,"read_result");
    assert.equal(page.status,"completed");
    assert.match(page.text,/textbox/);

    const status = await socket.call({kind:"read",tool:"browser_status",arguments:{}});
    assert.equal(status.status,"completed");
    assert.match(status.text,/session_id/);

    const closeId = "browser-close-"+randomUUID();
    const close = await socket.call({kind:"operation",tool:"browser_close",arguments:{session_id:sid},operation_id:closeId});
    assert.ok(["running","completed"].includes(close.result.status));
    for(let n=0;n<50;n++){if((await execution.getReceipt(closeId))?.state==="completed")break;await new Promise(done=>setTimeout(done,10));}
    assert.equal((await execution.getReceipt(closeId))?.state,"completed");
    assert.equal(closed,1);
  } finally {
    controller.abort();
    await monitored;
    await execution.close();
    await rm(root,{recursive:true,force:true});
  }
});
