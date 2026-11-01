import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { createAgentExecutionEngine, defaultAgentShellPath } from "../src/execution.ts";
import { executeV2FileOperation, executeV2SessionRead, monitorDeviceSocket } from "../src/v2-connection-lifecycle.ts";

test("#658 signed Agent tool adapter: write/read/search/edit receipts survive restart without replay", async () => {
  const root=await mkdtemp(path.join(os.tmpdir(),"rca-mac-file-seam-"));
  const filename=path.join(root,"visible.txt");
  const receiptDirectory=path.join(root,"receipts");
  const signal=new AbortController().signal;
  const id=randomUUID();
  const call={path:filename,content:"needle-one\n",mode:"rewrite"};
  let engine=createAgentExecutionEngine({receiptDirectory});
  try {
    await writeFile(filename,"original\n");
    const first=await executeV2FileOperation(engine,"write_file",call,id,signal);
    assert.equal(first.status,"completed");
    assert.equal(await readFile(filename,"utf8"),"needle-one\n");
    assert.equal((await executeV2FileOperation(engine,"get_operation_status",{},id,signal)).status,"completed");
    assert.equal((await executeV2FileOperation(engine,"write_file",call,id,signal)).status,"completed");
    assert.equal((await executeV2FileOperation(engine,"write_file",{...call,content:"evil"},id,signal)).status,"conflict");
    assert.equal(await readFile(filename,"utf8"),"needle-one\n");
    const read=await executeV2SessionRead(engine,"read_file",{path:filename},signal);
    assert.match(read??"",/needle-one/);
    const search=await executeV2SessionRead(engine,"start_search",{
      path:root,pattern:"visible.txt",search_type:"filename",
    },signal);
    assert.match(search??"",/visible.txt/);
    const editId=randomUUID();
    const edit=await executeV2FileOperation(engine,"edit_block",{
      file_path:filename,old_string:"needle-one",new_string:"needle-two",expected_replacements:1,
    },editId,signal);
    assert.equal(edit.status,"completed");
    assert.equal(await readFile(filename,"utf8"),"needle-two\n");
    await engine.close();
    engine=createAgentExecutionEngine({receiptDirectory});
    assert.equal((await executeV2FileOperation(engine,"get_operation_status",{},editId,signal)).status,"completed");
    assert.equal((await executeV2FileOperation(engine,"write_file",call,id,signal)).status,"completed");
    assert.equal(await readFile(filename,"utf8"),"needle-two\n",
      "old operation ID must not revert later edits");
  } finally {await engine.close();await rm(root,{recursive:true,force:true});}
});

test("#658 Darwin shell default never inherits an ambient interactive SHELL", () => {
  assert.equal(defaultAgentShellPath("darwin"),"/bin/sh");
});

test("#658 failed post-effect SQLite commit is unknown and cannot append again after restart", async () => {
  const root=await mkdtemp(path.join(os.tmpdir(),"rca-mac-unknown-"));
  const filename=path.join(root,"effect.txt");
  const receipts=path.join(root,"receipts");
  const id=randomUUID();
  const signal=new AbortController().signal;
  const call={path:filename,content:"once\n",mode:"append"};
  let block=true;
  let engine=createAgentExecutionEngine({
    receiptDirectory:receipts,
    receiptFaultForTests: phase=>phase==="commit" && block && existsSync(filename),
  });
  try {
    const initial=await executeV2FileOperation(engine,"write_file",call,id,signal);
    assert.equal(initial.status,"unknown");
    assert.equal(await readFile(filename,"utf8"),"once\n");
    block=false;
    assert.equal((await executeV2FileOperation(engine,"write_file",call,id,signal)).status,"unknown");
    assert.equal(await readFile(filename,"utf8"),"once\n");
    await engine.close();
    engine=createAgentExecutionEngine({receiptDirectory:receipts});
    assert.equal((await executeV2FileOperation(engine,"get_operation_status",{},id,signal)).status,"unknown");
    assert.equal((await executeV2FileOperation(engine,"write_file",call,id,signal)).status,"unknown");
    assert.equal(await readFile(filename,"utf8"),"once\n");
  } finally {block=false;await engine.close();await rm(root,{recursive:true,force:true});}
});

test("#658 authenticated WSS frame adapter writes and reads a real native file without Shell", async () => {
  const root=await mkdtemp(path.join(os.tmpdir(),"rca-mac-wss-"));
  const filename=path.join(root,"wss.txt");
  const controller=new AbortController();
  const socket=new class extends EventTarget {
    readyState=WebSocket.OPEN;
    protocol="rc-v2";
    sent: string[]=[];
    send(msg: string) {this.sent.push(msg);}
    close() {this.readyState=WebSocket.CLOSED;}
    frame(value: object) {
      const message=new Event("message");
      Object.defineProperty(message,"data",{value:JSON.stringify(value)});
      this.dispatchEvent(message);
    }
  }();
  const engine=createAgentExecutionEngine({receiptDirectory:path.join(root,"receipts")});
  const status=monitorDeviceSocket(socket as unknown as WebSocket,controller.signal,
    {intervalMs:60_000,timeoutMs:10_000},
    (tool,args,signal)=>executeV2SessionRead(engine,tool,args,signal),
    (tool,args,id,signal)=>executeV2FileOperation(engine,tool,args,id,signal),false);
  try {
    const id=randomUUID(), requestId=randomUUID();
    socket.frame({kind:"operation",request_id:requestId,operation_id:id,
      tool:"write_file",arguments:{path:filename,content:"signed-message\n",mode:"rewrite"}});
    await new Promise(resolve=>setTimeout(resolve,30));
    const write=socket.sent.map(x=>JSON.parse(x) as Record<string,any>)
      .find(x=>x.kind==="operation_result" && x.request_id===requestId);
    assert.equal(write?.result?.status,"completed");
    assert.equal(await readFile(filename,"utf8"),"signed-message\n");
    const readId=randomUUID();
    socket.frame({kind:"read",request_id:readId,tool:"read_file",arguments:{path:filename}});
    await new Promise(resolve=>setTimeout(resolve,30));
    const read=socket.sent.map(x=>JSON.parse(x) as Record<string,any>)
      .find(x=>x.kind==="read_result" && x.request_id===readId);
    assert.equal(read?.status,"completed");
    assert.match(read?.text??"",/signed-message/);
    const shellId=randomUUID();
    socket.frame({kind:"operation",request_id:randomUUID(),operation_id:shellId,
      tool:"start_process",arguments:{command:"printf not-supported"}});
    await new Promise(resolve=>setTimeout(resolve,15));
    assert.equal((await engine.getReceipt(shellId)),null,
      "file-only macOS must never admit a Shell effect");
  } finally {
    controller.abort();
    assert.equal(await status,"aborted");
    await engine.close();
    await rm(root,{recursive:true,force:true});
  }
});
