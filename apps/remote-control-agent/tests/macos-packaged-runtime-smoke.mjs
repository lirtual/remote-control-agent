/** Execute the actual unpacked Node/Mach-O candidate, never source adapters. */
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import test from "node:test";

const bundle = process.env.RCA_MACOS_BUNDLE_ROOT;
if (!bundle || process.platform !== "darwin" || !["arm64","x64"].includes(process.arch))
  throw Error("This smoke requires an unpacked bundle on a native ARM64 or Intel Mac.");
const moduleUrl = name => pathToFileURL(path.join(bundle,
  "apps/remote-control-agent/src",name)).href;
const { createAgentExecutionEngine } = await import(moduleUrl("execution.js"));
const { executeV2FileOperation, executeV2SessionRead, monitorDeviceSocket } =
  await import(moduleUrl("v2-connection-lifecycle.js"));

class LocalAuthorizedSocket extends EventTarget {
  readyState = WebSocket.OPEN;
  protocol = "rc-v2";
  replies = [];
  waiters = new Map();
  send(raw) {
    const reply = JSON.parse(raw);
    this.replies.push(reply);
    const key = reply.kind + ":" + reply.request_id;
    const waiter = this.waiters.get(key);
    if (waiter) { this.waiters.delete(key); waiter(reply); }
  }
  close() { this.readyState = WebSocket.CLOSED; }
  frame(message) {
    const event = new Event("message");
    Object.defineProperty(event,"data",{value:JSON.stringify(message)});
    this.dispatchEvent(event);
  }
  result(kind,requestId) {
    const key = kind + ":" + requestId;
    const previous = this.replies.find(r=>r.kind===kind && r.request_id===requestId);
    if (previous) return Promise.resolve(previous);
    return new Promise((resolve,reject)=>{
      const timer = setTimeout(()=>{this.waiters.delete(key);reject(Error("Missing native WSS reply"));},3000);
      this.waiters.set(key,reply=>{clearTimeout(timer);resolve(reply);});
    });
  }
}

test("#658 unpacked Mach-O Node runs real native file/WSS/SQLite receipt and Unknown paths", async()=>{
  const root = await mkdtemp(path.join(os.tmpdir(),"rca658-packaged-"));
  const filename=path.join(root,"macos.txt");
  const receipts=path.join(root,"receipts");
  const controller=new AbortController();
  let engine=createAgentExecutionEngine({receiptDirectory:receipts});
  const socket=new LocalAuthorizedSocket();
  const monitor=monitorDeviceSocket(socket,controller.signal,
    {intervalMs:60000,timeoutMs:10000},
    (tool,args,signal)=>executeV2SessionRead(engine,tool,args,signal),
    (tool,args,id,signal)=>executeV2FileOperation(engine,tool,args,id,signal),true);
  const sendOperation=async(tool,args,id=randomUUID())=>{
    const request_id=randomUUID();
    socket.frame({kind:"operation",request_id,operation_id:id,tool,arguments:args});
    return (await socket.result("operation_result",request_id)).result;
  };
  const sendRead=async(tool,args)=>{
    const request_id=randomUUID();
    socket.frame({kind:"read",request_id,tool,arguments:args});
    return await socket.result("read_result",request_id);
  };
  try {
    const id=randomUUID(), append={path:filename,content:"once\n",mode:"append"};
    assert.equal((await sendOperation("write_file",append,id)).status,"completed");
    assert.equal((await readFile(filename,"utf8")),"once\n");
    assert.equal((await sendRead("read_file",{path:filename})).status,"completed");
    const search=await sendRead("start_search",{path:root,pattern:"macos.txt",search_type:"filename"});
    assert.match(search.text,/macos.txt/);
    const edit=await sendOperation("edit_block",{
      file_path:filename,old_string:"once",new_string:"updated",expected_replacements:1,
    });
    assert.equal(edit.status,"completed");
    assert.equal((await sendOperation("get_operation_status",{operation_id:edit.operation_id},
      edit.operation_id)).status,"completed");
    await engine.close();
    engine=createAgentExecutionEngine({receiptDirectory:receipts});
    assert.equal((await sendOperation("write_file",append,id)).status,"completed");
    assert.equal((await readFile(filename,"utf8")),"updated\n",
      "same operation ID must not append or undo newer changes");
    const conflict=await sendOperation("write_file",{...append,content:"evil\n"},id);
    assert.equal(conflict.status,"conflict");
    await chmod(filename,0o000);
    assert.equal((await sendRead("read_file",{path:filename})).status,"failed");
    await chmod(filename,0o600);
    const shellId=randomUUID();
    const shell=await sendOperation("start_process",{command:"printf bundled-shell-ok",timeout_ms:2000},shellId);
    assert.ok(["completed","running"].includes(shell.status),"bundled Mach-O helper must admit Shell");
    const sessionRead=await sendRead("list_sessions",{});
    assert.equal(sessionRead.status,"completed");
    assert.match(sessionRead.text,/bundled-shell-ok|session_id/);
    assert.notEqual((await sendOperation("get_operation_status",{operation_id:shellId},shellId)).status,"not_found");
    // Fault-inject a commit after a real file effect; a new engine must not replay it.
    await engine.close();
    engine=createAgentExecutionEngine({receiptDirectory:receipts,
      // A first receipt admission must commit; inject failure ONLY after the
      // append has made its real filesystem effect (not before admission).
      receiptFaultForTests:phase=>phase==="commit" &&
        readFileSync(filename,"utf8").endsWith("last\n")});
    const unknownId=randomUUID(), unknown={path:filename,content:"last\n",mode:"append"};
    assert.equal((await sendOperation("write_file",unknown,unknownId)).status,"unknown");
    assert.equal((await readFile(filename,"utf8")),"updated\nlast\n");
    await engine.close();
    engine=createAgentExecutionEngine({receiptDirectory:receipts});
    assert.equal((await sendOperation("write_file",unknown,unknownId)).status,"unknown");
    assert.equal((await readFile(filename,"utf8")),"updated\nlast\n");
  } finally {
    controller.abort();
    await monitor;
    await engine.close();
    await chmod(filename,0o600).catch(()=>{});
    await rm(root,{recursive:true,force:true,maxRetries:5,retryDelay:20});
  }
});
