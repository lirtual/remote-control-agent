import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { createAgentExecutionEngine } from "../src/execution.ts";
import { BrowserHandoff } from "../src/browser-handoff.ts";
import { ReceiptStore, operationDigest } from "../src/operations.ts";
import { supportsProtectedQuickTunnel } from "../src/protected-tunnel.ts";
import { executeV2FileOperation, executeV2SessionRead, monitorDeviceSocket } from "../src/v2-connection-lifecycle.ts";
import type { BrowserBackend, BrowserStatus } from "../src/browser-backend.ts";

const signal = () => new AbortController().signal;
async function waitFor(check: () => Promise<boolean> | boolean): Promise<void> {
  for (let i=0;i<100;i++) {
    if (await check()) return;
    await new Promise(resolve=>setTimeout(resolve,10));
  }
  assert.fail("bounded state transition did not complete");
}
function browserFixture() {
  const id = randomUUID();
  let invalidated = 0;
  const state: BrowserStatus = {session_id:id,tab_id:"tab-1",browser_family:"msedge",backend:"playwright",uncertain:false,snapshot_version:2};
  return {id,state,invalidated:()=>invalidated, browser:{
    status:()=>state,
    snapshot:async()=>({text:"PRIVATE PAGE",truncated:false,snapshot_version:3}),
    invalidateHandoffReferences:async()=>{invalidated++;state.snapshot_version++;state.tab_id=null;state.uncertain=false;},
    close:async()=>{},
  } as unknown as BrowserBackend};
}

test("whole-device barrier survives restart; receipts retain ID/state without sensitive payload",async()=>{
  const root=await mkdtemp(path.join(os.tmpdir(),"handoff-engine-"));
  const f=browserFixture();
  let engine=createAgentExecutionEngine({receiptDirectory:root,browser:f.browser});
  const call=(tool:string,args:unknown={},operation_id?:string)=>engine.executeTool({tool,arguments:args,operation_id},signal());
  try {
    const file=path.join(root,"sample.txt");
    await call("write_file",{path:file,mode:"rewrite",content:"PRIVATE FILE"},"original-intent");
    assert.equal((await engine.getReceipt("original-intent"))?.state,"completed");
    const requested=await call("browser_handoff_request",{session_id:f.id});
    assert.equal((requested?.body as {state:string}).state,"preparing");
    // Preparation now runs detached from the one-shot MCP response.
    await waitFor(async()=>((await call("browser_handoff_status"))?.body as {state:string}).state==="pending_return");
    const firstEpoch=engine.handoffGeneration();
    const marker=await readFile(path.join(root,"browser-handoff-pending.json"),"utf8");
    assert.ok(!/PRIVATE|token|cookie|email/.test(marker));
    // Include unknown/future tools: the gate is default-deny, not a tool list.
    for (const tool of ["read_file","read_multiple_files","read_process_output","list_sessions","start_process","interact_with_process","force_terminate","browser_status","browser_snapshot","browser_tabs","browser_close","delete_file","future_tool"])
      assert.equal((await call(tool,{}))?.status,423,tool);
    const receipt=await engine.getReceipt("original-intent");
    assert.deepEqual(receipt,{operation_id:"original-intent",state:"completed"});
    await call("browser_handoff_request",{session_id:f.id});
    assert.equal(engine.handoffGeneration(),firstEpoch,"repeat cannot create another handoff");
    assert.equal(await readFile(path.join(root,"browser-handoff-pending.json"),"utf8"),marker);
    await engine.close();
    // No browser is restored after a restart.
    engine=createAgentExecutionEngine({receiptDirectory:root});
    assert.equal((await call("read_file",{path:file}))?.status,423);
    const status=await call("browser_handoff_status");
    assert.match(JSON.stringify(status?.body),/agent_restarted_browser_session_not_restored/);
    await call("browser_handoff_return");
    assert.equal(engine.handoffBlocked(),false);
    assert.equal((await call("read_file",{path:file}))?.status,200);
    await call("browser_handoff_return");
    assert.equal(engine.handoffBlocked(),false,"return is idempotent");
  } finally {await engine.close();await rm(root,{recursive:true,force:true});}
});

test("in-flight browser observation drains but its result is discarded; return invalidates references",async()=>{
  const root=await mkdtemp(path.join(os.tmpdir(),"handoff-drain-"));
  const f=browserFixture();
  let release!:()=>void;
  const wait=new Promise<void>(resolve=>{release=resolve;});
  let entered!:()=>void;
  const started=new Promise<void>(resolve=>{entered=resolve;});
  f.browser.snapshot=async()=>{entered();await wait;return {text:"SENSITIVE DELAYED RESULT",truncated:false,snapshot_version:3};};
  const engine=createAgentExecutionEngine({receiptDirectory:root,browser:f.browser});
  try {
    const delayed=engine.executeTool({tool:"browser_snapshot",arguments:{session_id:f.id}},signal());
    await started;
    const request=engine.executeTool({tool:"browser_handoff_request",arguments:{session_id:f.id}},signal());
    assert.equal(engine.handoffBlocked(),true,"blocks synchronously before draining");
    const early=await engine.executeTool({tool:"browser_handoff_return",arguments:{}},signal());
    assert.notEqual((early?.body as {state:string}).state,"ai","cannot return during preparation");
    release();
    assert.equal((await delayed)?.status,423);
    await request;
    await waitFor(async()=>((await engine.executeTool({tool:"browser_handoff_status",arguments:{}},signal()))?.body as {state:string}).state==="pending_return");
    const returned=await engine.executeTool({tool:"browser_handoff_return",arguments:{}},signal());
    assert.equal((returned?.body as {state:string}).state,"ai");
    assert.equal(f.invalidated(),1);
    assert.equal(f.state.tab_id,null);
  } finally {release();await engine.close();await rm(root,{recursive:true,force:true});}
});

test("explicit owner return reconciles a settled unknown human input without replay",async()=>{
  const root=await mkdtemp(path.join(os.tmpdir(),"handoff-human-unknown-"));
  const f=browserFixture();
  const engine=createAgentExecutionEngine({receiptDirectory:root,browser:f.browser});
  const call=(tool:string,args:unknown={})=>engine.executeTool({tool,arguments:args},signal());
  try {
    const requested=await call("browser_handoff_request",{session_id:f.id});
    assert.notEqual((requested?.body as {state:string}).state,"ai");
    assert.equal(engine.handoffBlocked(),true);
    // A Playwright human input already settled with an unknown external effect.
    // Owner return MUST NOT issue a second browser input.
    f.state.uncertain=true;
    await waitFor(async()=>((await call("browser_handoff_status"))?.body as {state:string}).state==="pending_return");
    const result=await call("browser_handoff_return");
    assert.equal((result?.body as {state:string}).state,"ai");
    assert.equal(f.invalidated(),1);
    assert.equal(f.state.uncertain,false);
    assert.equal(f.state.tab_id,null);
    assert.equal(engine.handoffBlocked(),false);
  } finally {await engine.close();await rm(root,{recursive:true,force:true});}
});

test("expiry, reconnect and unknown cleanup never implicitly return AI admission",async()=>{
  const root=await mkdtemp(path.join(os.tmpdir(),"handoff-expiry-"));
  try {
    const handoff=new BrowserHandoff(root);
    assert.equal(handoff.begin(randomUUID()),true);
    let closes=0;
    handoff.ready({close:async()=>{closes++;return "uncertain";}},Date.now()-1);
    assert.equal(handoff.status().state,"expired");
    assert.equal(handoff.isBlocked(),true);
    assert.equal(closes,1);
    const result=await handoff.explicitReturn(async()=>{});
    assert.equal(result.reason,"cleanup_unknown");
    assert.equal(handoff.isBlocked(),true);
    const restarted=new BrowserHandoff(root);
    assert.equal(restarted.isBlocked(),true);
  } finally {await rm(root,{recursive:true,force:true});}
});

test("malformed marker and private store errors default to blocked",async()=>{
  const root=await mkdtemp(path.join(os.tmpdir(),"handoff-marker-"));
  try {
    await writeFile(path.join(root,"browser-handoff-pending.json"),"corrupted");
    assert.equal(new BrowserHandoff(root).isBlocked(),true);
    const file=path.join(root,"not-a-directory");await writeFile(file,"");
    assert.equal(new BrowserHandoff(file).isBlocked(),true);
  } finally {await rm(root,{recursive:true,force:true});}
});

class Socket extends EventTarget {
  readyState=WebSocket.OPEN;
  private replies=new Map<string,(v:Record<string,any>)=>void>();
  send(text:string):void {if(!text.startsWith("{"))return;const message=JSON.parse(text);this.replies.get(message.request_id)?.(message);this.replies.delete(message.request_id);}
  close():void {this.readyState=WebSocket.CLOSED;}
  call(frame:Record<string,unknown>):Promise<Record<string,any>> {
    const request_id=randomUUID();
    return new Promise(resolve=>{this.replies.set(request_id,resolve);this.dispatchEvent(new MessageEvent("message",{data:JSON.stringify({...frame,request_id})}));});
  }
}

test("signed WSS public seam blocks files/processes and redacts delayed replies and old receipts",async()=>{
  const root=await mkdtemp(path.join(os.tmpdir(),"handoff-wss-"));
  const f=browserFixture(),engine=createAgentExecutionEngine({receiptDirectory:root,browser:f.browser});
  const socket=new Socket(),abort=new AbortController();
  let release!:()=>void;const wait=new Promise<void>(resolve=>{release=resolve;});
  let readStarted!:()=>void;const entered=new Promise<void>(resolve=>{readStarted=resolve;});
  const monitored=monitorDeviceSocket(socket as unknown as WebSocket,abort.signal,{intervalMs:5000,timeoutMs:1000,authIntervalMs:10000},
    async(tool,args,signal)=>{
      // Model an adapter whose result was already computed, delayed before send.
      if(tool==="browser_snapshot"){readStarted();await wait;return "PRIVATE WSS RESULT";}
      return executeV2SessionRead(engine,tool,args,signal);
    },(tool,args,id,signal)=>executeV2FileOperation(engine,tool,args,id,signal),true,
    ()=>engine.stopOwnedForRevocation(),engine);
  try {
    const delayed=socket.call({kind:"read",tool:"browser_snapshot",arguments:{session_id:f.id}});
    await entered;
    const requested=await socket.call({kind:"read",tool:"browser_handoff_request",arguments:{session_id:f.id}});
    assert.equal(requested.status,"completed");
    release();
    assert.deepEqual(Object.keys(await delayed).sort(),["kind","request_id","status"]);
    const file=await socket.call({kind:"read",tool:"read_file",arguments:{path:path.join(root,"missing")}});
    assert.equal(file.status,"failed");
    const mutation=await socket.call({kind:"operation",tool:"start_process",arguments:{command:"echo denied"},operation_id:"handoff-denied-command"});
    assert.equal(mutation.result.status,"unavailable");
    assert.equal(await engine.getReceipt("handoff-denied-command"),null);
    assert.equal((await socket.call({kind:"read",tool:"browser_handoff_status",arguments:{}})).status,"completed");
    await waitFor(async()=>((await engine.executeTool({tool:"browser_handoff_status",arguments:{}},signal()))?.body as {state:string}).state==="pending_return");
    assert.equal((await socket.call({kind:"read",tool:"browser_handoff_return",arguments:{}})).status,"completed");
    assert.equal(engine.handoffBlocked(),false);
  } finally {release();abort.abort();await monitored;await engine.close();await rm(root,{recursive:true,force:true});}
});

test("protected tunnel requires >=2026.9.3 AND the actual protected flag",()=>{
  assert.equal(supportsProtectedQuickTunnel("cloudflared version 2026.9.3 (built today)","  --allowed-mail value"),true);
  for(const [version,help] of [["2026.9.2","--allowed-mail value"],["2026.8.99","--allowed-mail value"],["2026.9.3","--allowed-mailbox value"],["2026.9.3","unprotected"]])
    assert.equal(supportsProtectedQuickTunnel("cloudflared version "+version,help!),false);
});

test("a browser effect outliving its running reply drains before handoff; unknown receipt refuses human input",async()=>{
  const root=await mkdtemp(path.join(os.tmpdir(),"handoff-effect-"));
  const f=browserFixture();let release!:()=>void;
  const wait=new Promise<void>(resolve=>{release=resolve;});
  f.browser.navigate=async()=>{await wait;throw Error("Unknown external effect");};
  let checked=0;
  const engine=createAgentExecutionEngine({receiptDirectory:root,browser:f.browser,verifyHandoffPrerequisites:()=>{checked++;}});
  try {
    const operation=await engine.executeTool({tool:"browser_navigate",operation_id:"uncertain-browser-intent",arguments:{session_id:f.id,tab_id:"tab-1",snapshot_version:2,url:"https://example.com/"}},signal());
    assert.equal((operation?.body as {status:string}).status,"running");
    const handoff=engine.executeTool({tool:"browser_handoff_request",arguments:{session_id:f.id}},signal());
    assert.equal(engine.handoffBlocked(),true);
    release();
    const result=await handoff;
    assert.equal((result?.body as {state:string}).state,"preparing");
    await waitFor(async()=>((await engine.executeTool({tool:"browser_handoff_status",arguments:{}},signal()))?.body as {reason?:string}).reason==="browser_receipt_unknown");
    assert.equal(checked,0,"never start external access while a receipt is unresolved");
    assert.deepEqual(await engine.getReceipt("uncertain-browser-intent"),{operation_id:"uncertain-browser-intent",state:"unknown"});
  } finally {release();await engine.close();await rm(root,{recursive:true,force:true});}
});

test("fresh browser session may hand off despite historical unknown receipts without replay or rewriting them",async()=>{
  const root=await mkdtemp(path.join(os.tmpdir(),"handoff-receipt-scope-"));
  const store=new ReceiptStore(root);
  const first=browserFixture().id,second=browserFixture().id;
  const put=async(id:string,tool:"browser_start"|"browser_click"|"browser_navigate",state:"completed"|"unknown",session?:string)=>{
    assert.equal((await store.admit(id,tool,operationDigest(tool,{operation_id:id}))).kind,"new");
    return store.update(id,state,"Browser action outcome is uncertain.",session);
  };
  try {
    await store.open();
    await put("historic-unknown-click","browser_click","unknown");
    assert.equal(store.hasUnresolvedBrowserOperations(first),true,"no proven session start must fail closed");
    await put("fresh-proven-start","browser_start","completed",first);
    assert.equal(store.hasUnresolvedBrowserOperations(first),false,"old session effects cannot be in flight in new context");
    assert.equal((await store.get("historic-unknown-click"))?.state,"unknown","old receipt and replay guard retained");
    await put("current-unknown-navigate","browser_navigate","unknown");
    assert.equal(store.hasUnresolvedBrowserOperations(first),true,"unknown effect in current context must block");
    await put("second-proven-start","browser_start","completed",second);
    assert.equal(store.hasUnresolvedBrowserOperations(second),false,"a genuinely new context can proceed");
    assert.equal((await store.get("current-unknown-navigate"))?.state,"unknown","unresolved result never overwritten");
    await store.close();
    await store.open();
    assert.equal(store.hasUnresolvedBrowserOperations(first),true,"restart must not silently reconcile original session");
    assert.equal(store.hasUnresolvedBrowserOperations(second),false,"historical effects must not permanently deny fresh session");
  } finally {await store.close();await rm(root,{recursive:true,force:true});}
});

test("one device's handoff never blocks a separate device engine",async()=>{
  const root=await mkdtemp(path.join(os.tmpdir(),"handoff-devices-"));
  const f=browserFixture();
  const one=createAgentExecutionEngine({receiptDirectory:path.join(root,"one"),browser:f.browser});
  const two=createAgentExecutionEngine({receiptDirectory:path.join(root,"two")});
  try {
    await one.executeTool({tool:"browser_handoff_request",arguments:{session_id:f.id}},signal());
    assert.equal((await one.executeTool({tool:"list_sessions",arguments:{}},signal()))?.status,423);
    assert.equal((await two.executeTool({tool:"list_sessions",arguments:{}},signal()))?.status,200);
  } finally {await one.close();await two.close();await rm(root,{recursive:true,force:true});}
});

test("two-phase handoff returns immediately; correct session claims URL once, never via status or receipts",async()=>{
  const root=await mkdtemp(path.join(os.tmpdir(),"handoff-two-phase-"));
  const f=browserFixture();
  const token="OTP_ONE_SHOT_TEST_SECRET";
  const link="https://test-quick-tunnel.trycloudflare.com/?handoff_token="+token;
  let resolveReady!: (value:{url:string;expiresAt:number})=>void;
  let started!:()=>void;
  const startedPromise=new Promise<void>(r=>{started=r;});
  const readiness=new Promise<{url:string;expiresAt:number}>(r=>{resolveReady=r;});
  let closes=0;
  const engine=createAgentExecutionEngine({
    receiptDirectory:root,browser:f.browser,
    verifyHandoffPrerequisites:()=>({}) as never,
    handoffDeviceId:()=>randomUUID(),
    // Only local test injection; real production always uses pinned cloudflared.
    handoffFactory:(()=>({
      start:()=>{started();return readiness;},
      close:async()=>{closes++;return "confirmed" as const;},
    })) as never,
  });
  const call=(tool:string,args:unknown={})=>engine.executeTool({tool,arguments:args},signal());
  try {
    const first=await call("browser_handoff_request",{session_id:f.id});
    assert.equal((first?.body as {state:string}).state,"preparing");
    assert.equal(JSON.stringify(first).includes(token),false);
    assert.equal(engine.handoffBlocked(),true);
    assert.equal((await call("browser_snapshot",{session_id:f.id}))?.status,423);
    await startedPromise;
    assert.equal((await call("browser_handoff_request",{session_id:f.id}))?.body != null,true);
    assert.equal(JSON.stringify((await call("browser_handoff_status"))?.body).includes(token),false);
    const deadline=Date.now()+120_000;
    resolveReady({url:link,expiresAt:deadline});
    await waitFor(async()=>((await call("browser_handoff_status"))?.body as {state:string}).state==="link_ready");
    const wrong=await call("browser_handoff_request",{session_id:randomUUID()});
    assert.equal(JSON.stringify(wrong).includes(token),false,"other browser session cannot steal a link");
    const status=await call("browser_handoff_status");
    assert.equal(JSON.stringify(status).includes(token),false);
    const [claimed,replay]=await Promise.all([
      call("browser_handoff_request",{session_id:f.id}),
      call("browser_handoff_request",{session_id:f.id}),
    ]);
    assert.equal((claimed?.body as {url?:string}).url,link);
    assert.equal((claimed?.body as {expires_at?:number}).expires_at,deadline);
    assert.equal((replay?.body as {url?:string}).url,undefined,"concurrent claim cannot replay the one-shot link");
    assert.equal(JSON.stringify(await call("browser_handoff_status")).includes(token),false);
    const returned=await call("browser_handoff_return");
    assert.equal((returned?.body as {state:string}).state,"ai");
    assert.equal(closes,1);
    assert.equal(((await call("browser_handoff_status"))?.body as {state:string}).state,"ai");
    assert.equal(JSON.stringify(await call("browser_handoff_status")).includes(token),false);
  } finally {await engine.close();await rm(root,{recursive:true,force:true});}
});

test("unclaimed link never survives expiry, cleanup or process restart",async()=>{
  const root=await mkdtemp(path.join(os.tmpdir(),"handoff-claim-lifetime-"));
  const id=randomUUID();
  try {
    const session=new BrowserHandoff(root);
    assert.equal(session.begin(id),true);
    const access={close:async()=>"confirmed" as const};
    const expiry=Date.now()+15_000;
    session.ready(access,expiry,{sessionId:id,url:"https://safe.trycloudflare.com/?handoff_token=SECRET"});
    assert.equal(session.claim(randomUUID()),undefined);
    assert.equal(session.claim(id)?.url?.includes("SECRET"),true);
    assert.equal(session.claim(id),undefined);
    session.stopAccess();
    assert.equal(session.claim(id),undefined,"revocation destroys unclaimed/claimed links");
    const cleared=await session.explicitReturn(async()=>{});
    assert.equal(cleared.state,"ai");
    assert.equal(session.claim(id),undefined);
    assert.equal(session.begin(id),true);
    session.ready(access,Date.now()-1);
    assert.equal(session.claim(id),undefined,"expired link must never be delivered");
    const restored=new BrowserHandoff(root);
    assert.equal(restored.isBlocked(),true,"a restarted Agent must not restore the link");
    assert.equal(restored.claim(id),undefined);
  } finally {await rm(root,{recursive:true,force:true});}
});

test("shutdown during detached setup joins all background work before deleting the receipt store",async()=>{
  const root=await mkdtemp(path.join(os.tmpdir(),"handoff-prepare-shutdown-"));
  const f=browserFixture();
  let factoryCalled=0;
  const engine=createAgentExecutionEngine({
    receiptDirectory:root,browser:f.browser,
    verifyHandoffPrerequisites:()=>({}) as never,
    handoffDeviceId:()=>randomUUID(),
    handoffFactory:(()=>{factoryCalled++;throw Error("start after shutdown");}) as never,
  });
  try {
    const initial=await engine.executeTool({tool:"browser_handoff_request",arguments:{session_id:f.id}},signal());
    assert.equal((initial?.body as {state:string}).state,"preparing");
    await engine.close();
    assert.equal(factoryCalled,0,"shutdown must stop async preparation before it spawns a Tunnel");
    const restarted=new BrowserHandoff(root);
    assert.equal(restarted.isBlocked(),true,"restarted Agent still requires explicit cleanup");
  } finally {await engine.close();await rm(root,{recursive:true,force:true});}
});
