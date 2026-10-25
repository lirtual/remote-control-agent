/** Cross-repository local contract smoke. No network, pairing, device or deployment.
 * node --experimental-strip-types tests/browser-handoff-worker-smoke.mjs /absolute/mcp-workers
 * The fixture represents an ALREADY authenticated signed socket; the existing
 * nonce/signature suites verify authentication independently.
 */
import assert from "node:assert/strict";
import {randomUUID} from "node:crypto";
import {mkdtemp,rm} from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import {pathToFileURL} from "node:url";
import {createAgentExecutionEngine} from "../src/execution.ts";
import {monitorDeviceSocket,executeV2SessionRead,executeV2FileOperation} from "../src/v2-connection-lifecycle.ts";
const workerRoot=process.argv[2];
if(!workerRoot || !path.isAbsolute(workerRoot))throw Error("Absolute Worker source repository required.");
const {default:worker,V2OwnerCoordinator}=await import(pathToFileURL(path.join(workerRoot,"apps/remote-control-mcp-worker/src/worker.ts")).href);
const root=await mkdtemp(path.join(os.tmpdir(),"handoff-cross-repo-"));
const device=randomUUID(),session=randomUUID(),epoch="authenticated-fixture";
let invalidated=0;
const browser={status:()=>({session_id:session,tab_id:"tab-1",uncertain:false}),
  invalidateHandoffReferences:async()=>{invalidated++;},close:async()=>{}};
const engine=createAgentExecutionEngine({receiptDirectory:root,browser});
let owner;
class AgentSocket extends EventTarget {
  readyState=WebSocket.OPEN;
  send(wire){if(wire.startsWith("{"))queueMicrotask(()=>void owner.webSocketMessage(serverSocket,wire));}
  close(){this.readyState=WebSocket.CLOSED;}
}
const agentSocket=new AgentSocket();
const serverSocket={readyState:WebSocket.OPEN,deserializeAttachment:()=>({device_id:device,epoch}),close(){},
  send(wire){queueMicrotask(()=>agentSocket.dispatchEvent(new MessageEvent("message",{data:wire})));}};
owner=new V2OwnerCoordinator({storage:{get:async(key)=>key==="device:"+device?{device_id:device,revoked:false}:key==="session:epoch:"+device?epoch:undefined},getWebSockets:()=>[serverSocket]});
const env={MCP_ACCESS_TOKEN:"local-contract-fixture",DEVICE_COORDINATOR:{idFromName:()=>({}),get:()=>({fetch:(url,init)=>owner.fetch(new Request(url,init))})}};
const abort=new AbortController();
const monitored=monitorDeviceSocket(agentSocket,abort.signal,{intervalMs:5000,timeoutMs:1000,authIntervalMs:10000},
  (tool,args,signal)=>executeV2SessionRead(engine,tool,args,signal),
  (tool,args,id,signal)=>executeV2FileOperation(engine,tool,args,id,signal),true,()=>engine.stopOwnedForRevocation(),engine);
async function call(name,args){
  const response=await worker.fetch(new Request("https://mcp.example.test/mcp",{method:"POST",headers:{authorization:"Bearer local-contract-fixture","content-type":"application/json"},body:JSON.stringify({jsonrpc:"2.0",id:1,method:"tools/call",params:{name,arguments:{device_id:device,...args}}})}),env);
  assert.equal(response.status,200);return (await response.json()).result;
}
try{
  const file=path.join(root,"data.txt"),operation_id="cross-repo-original-intent";
  assert.equal((await call("write_file",{path:file,content:"PRIVATE FIXTURE",mode:"rewrite",operation_id})).isError,false);
  assert.match((await call("read_file",{path:file})).content[0].text,/PRIVATE FIXTURE/);
  const requested=await call("browser_handoff_request",{session_id:session});
  assert.equal(JSON.parse(requested.content[0].text).state,"pending_return");
  assert.equal((await call("read_file",{path:file})).isError,true);
  const receipt=await call("get_operation_status",{operation_id});
  assert.equal(receipt.isError,false);
  const receiptText=receipt.content[0].text;
  assert.match(receiptText,/completed/);assert.ok(!/PRIVATE|argument_digest|safe_result_summary|session_id/.test(receiptText));
  assert.equal((await call("browser_handoff_status",{})).isError,false);
  const returned=await call("browser_handoff_return",{});
  assert.equal(JSON.parse(returned.content[0].text).state,"ai");assert.equal(invalidated,1);
  assert.equal((await call("read_file",{path:file})).isError,false);
  console.log("PASS: authenticated MCP -> existing DO -> WSS monitor -> Agent execution/receipts; block and explicit return");
}finally{abort.abort();await monitored;await engine.close();await rm(root,{recursive:true,force:true});}
