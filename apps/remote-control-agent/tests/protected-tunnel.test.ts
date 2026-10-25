import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import type { ChildProcess, SpawnOptions } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { CHILD_MARKER, createManagedHandoff, isProtectedChallenge, tunnelOriginFromLog, windowsTunnelLauncher } from "../src/protected-tunnel.ts";
import { BrowserHandoff } from "../src/browser-handoff.ts";
import type { BrowserBackend } from "../src/browser-backend.ts";
import type { startHandoffController } from "../src/handoff-controller.ts";

const origin="https://some-owned-tunnel.trycloudflare.com";
function challenge(probePath:string):Response {
  const state="a".repeat(43);
  const payload=Buffer.from(JSON.stringify({state,hostname:new URL(origin).hostname,return_path:probePath,exp:Math.floor(Date.now()/1000)+600})).toString("base64url");
  return new Response(null,{status:302,headers:{location:`https://login.trycloudflare.com/authorize?hostname=${new URL(origin).hostname}&state=${state}`,
    "cache-control":"private, no-store","referrer-policy":"no-referrer",
    "set-cookie":`__Secure-cloudflared-qt-auth-state-${state}=${payload}.${"b".repeat(43)}; Path=/.cloudflared/qt-auth/callback; Max-Age=600; Secure; HttpOnly; SameSite=None`}});
}
test("URL extraction accepts only bounded structured tunnel origins, never arbitrary log URLs",()=>{
  assert.equal(tunnelOriginFromLog(JSON.stringify({level:"info",message:`|  ${origin}   |`})),origin);
  for(const message of [origin+"/path",origin+".evil.test","https://login.trycloudflare.com","http://abc.trycloudflare.com","https://-bad.trycloudflare.com","prefix "+origin,"x".repeat(9000)])
    assert.equal(tunnelOriginFromLog(JSON.stringify({level:"info",message})),undefined);
  assert.equal(tunnelOriginFromLog(origin),undefined);
  assert.equal(tunnelOriginFromLog(JSON.stringify({level:"error",message:origin})),undefined);
});
test("OTP proof requires the exact trusted broker and matching browser-state cookie/path",()=>{
  const probe="/__handoff_probe/random";
  assert.equal(isProtectedChallenge(challenge(probe),origin,probe),true);
  assert.equal(isProtectedChallenge(challenge(probe),origin,probe+"different"),false);
  for(const location of ["https://evil.test/authorize","https://login.trycloudflare.com.evil.test/authorize","https://login.trycloudflare.com/authorize","/login"]) {
    const response=challenge(probe);response.headers.set("location",location);
    assert.equal(isProtectedChallenge(response,origin,probe),false);
  }
  for(const header of ["set-cookie","cache-control","referrer-policy"]) {
    const response=challenge(probe);response.headers.delete(header);
    assert.equal(isProtectedChallenge(response,origin,probe),false);
  }
  const response=challenge(probe);response.headers.set("set-cookie",response.headers.get("set-cookie")+"; Domain=trycloudflare.com");
  assert.equal(isProtectedChallenge(response,origin,probe),false);
});

async function fixture(controllerGate?: Promise<void>) {
  const directory=await mkdtemp(path.join(os.tmpdir(),"managed-handoff-"));
  const sessionId=randomUUID(),deviceId=randomUUID();
  let controllerOptions!:Parameters<typeof startHandoffController>[0];
  let localClosed=false,kills=0,allowExit=true,publicProof=true,confirmed=true;
  const child=Object.assign(new EventEmitter(),{pid:1234,exitCode:null as number|null,signalCode:null as string|null,
    stdout:new PassThrough(),stderr:new PassThrough(),kill:()=>{
      kills++;
      assert.equal(controllerOptions.active(),false,"credentials revoke before child termination");
      if(allowExit) {child.exitCode=0;child.emit("exit",0,null);} return true;
    }});
  let args:string[]=[];
  const config={configurationDirectory:directory,email:"owner@example.com",cloudflared_path:"C:\\trusted\\cloudflared.exe",cloudflared_sha256:"a".repeat(64)};
  const access=createManagedHandoff({directory,config,deviceId,sessionId,browser:{status:()=>({session_id:sessionId})} as BrowserBackend,
    connected:()=>{},explicitReturn:async()=>{}},{platform:"win32",
    controller:async options=>{controllerOptions=options;assert.equal(options.active(),false);await controllerGate;return {port:3456,token:"secret",close:async()=>{localClosed=true;return "confirmed";}};},
    launch:(_exe:string,argv:string[],_options:SpawnOptions)=>{args=argv;queueMicrotask(()=>child.stdout.write(JSON.stringify({level:"info",message:`| ${origin} |`})+"\n"));return child as unknown as ChildProcess;},
    confirm:()=>confirmed ? "confirmed" : "uncertain",
    send:(async(url,init)=>{
      assert.equal(controllerOptions.active(),false,"access disabled throughout readiness proof");
      assert.equal(init?.redirect,"manual");
      const parsed=new URL(String(url));
      if(parsed.protocol==="http:")return Response.json({probe:controllerOptions.readinessProbe,device_id:deviceId,session_id:sessionId});
      assert.equal(init?.credentials,"omit");
      if(!publicProof)return new Response(null,{status:302,headers:{location:"https://evil.test/login"}});
      return init?.method==="POST" ? new Response(null,{status:401}) : challenge(parsed.pathname);
    }) as typeof fetch,
  });
  return {directory,access,child,args:()=>args,controller:()=>controllerOptions,kills:()=>kills,localClosed:()=>localClosed,
    unknown:()=>{confirmed=false;},noExit:()=>{allowExit=false;},badProof:()=>{publicProof=false;}};
}
test("managed tunnel proves local and public protection before enabling; secrets never persist",async()=>{
  const f=await fixture();
  try {
    const before=Date.now();const result=await f.access.start();
    assert.equal(result.url,origin+"/?handoff_token=secret");assert.ok(result.expiresAt>=before+900_000 && result.expiresAt<=Date.now()+900_000);
    assert.equal(f.controller().active(),true);
    assert.equal(f.args().filter(x=>x==="--allowed-mail").length,1);assert.ok(f.args().includes("owner@example.com"));
    assert.ok(f.args().includes("http://127.0.0.1:3456"));assert.ok(f.args().includes("json"));
    const marker=await readFile(path.join(f.directory,CHILD_MARKER),"utf8");assert.doesNotMatch(marker,/secret|owner@|trycloudflare/);
    await assert.rejects(f.access.start(),/already_requested/,"never replay a cached URL");
    const closed=f.access.close();assert.equal(f.controller().active(),false);assert.equal(f.localClosed(),true);
    assert.equal(await closed,"confirmed");assert.equal(f.kills(),1);assert.equal(await f.access.close(),"confirmed");
    await assert.rejects(readFile(path.join(f.directory,CHILD_MARKER)));
  } finally {await f.access.close();await rm(f.directory,{recursive:true,force:true});}
});
test("untrusted public redirects never enable the controller and cleanup confirms child exit",async()=>{
  const f=await fixture();f.badProof();
  try {await assert.rejects(f.access.start(),/challenge_unverified/);assert.equal(f.controller().active(),false);assert.equal(await f.access.close(),"confirmed");assert.equal(f.kills(),1);}
  finally {await f.access.close();await rm(f.directory,{recursive:true,force:true});}
});
test("crash spawn-intent evidence survives explicit return and never re-enables AI",async()=>{
  const directory=await mkdtemp(path.join(os.tmpdir(),"orphan-handoff-"));
  try {
    await writeFile(path.join(directory,CHILD_MARKER),JSON.stringify({spawn_pending:true}));
    const handoff=new BrowserHandoff(directory);assert.equal(handoff.isBlocked(),true);
    assert.equal((await handoff.explicitReturn(async()=>{})).reason,"cleanup_unknown");assert.equal(handoff.isBlocked(),true);
    assert.ok(await readFile(path.join(directory,CHILD_MARKER),"utf8"));
  } finally {await rm(directory,{recursive:true,force:true});}
});
test("a kill request without observed exit remains uncertain and preserves recovery identity",async t=>{
  const f=await fixture();f.noExit();
  try {
    await f.access.start();t.mock.timers.enable({apis:["setTimeout"]});
    const closing=f.access.close();await Promise.resolve();await Promise.resolve();t.mock.timers.tick(6001);
    assert.equal(await closing,"uncertain");assert.equal(f.controller().active(),false);
    assert.ok(await readFile(path.join(f.directory,CHILD_MARKER),"utf8"));
  } finally {t.mock.timers.reset();f.child.exitCode=0;await rm(f.directory,{recursive:true,force:true});}
});


test("shutdown during loopback startup never launches a tunnel or enables input",async()=>{
  let release!:()=>void;const gate=new Promise<void>(resolve=>{release=resolve;});
  const f=await fixture(gate);
  try {
    const starting=f.access.start();const cleanup=f.access.close();
    assert.equal(f.controller().active(),false);release();
    await assert.rejects(starting,/handoff_closed/);assert.equal(await cleanup,"confirmed");
    assert.equal(f.kills(),0);assert.equal(f.localClosed(),true);assert.deepEqual(f.args(),[]);
  } finally {release();await f.access.close();await rm(f.directory,{recursive:true,force:true});}
});
test("absolute deadline revokes locally and terminates the owned tunnel without a status poll",async t=>{
  const f=await fixture();
  try {
    t.mock.timers.enable({apis:["setTimeout"]});await f.access.start();
    t.mock.timers.tick(900_001);
    assert.equal(f.controller().active(),false);assert.equal(f.localClosed(),true);
    assert.equal(await f.access.close(),"confirmed");assert.equal(f.kills(),1);
  } finally {t.mock.timers.reset();await f.access.close();await rm(f.directory,{recursive:true,force:true});}
});

test("unknown native job cleanup blocks return even after supervisor exits",async()=>{
  const f=await fixture();f.unknown();
  try {
    await f.access.start();
    assert.equal(await f.access.close(),"uncertain");
    assert.equal(f.localClosed(),true);
    assert.ok(await readFile(path.join(f.directory,CHILD_MARKER),"utf8"));
  } finally {await rm(f.directory,{recursive:true,force:true});}
});
test("launcher selects only the fixed pinned Windows supervisor, never cloudflared directly",()=>{
  assert.throws(()=>windowsTunnelLauncher("linux"),/native_windows_required/);
  const systemRoot=process.env.SystemRoot;
  try {
    process.env.SystemRoot ??= "C:\\Windows";
    const launcher=windowsTunnelLauncher("win32");
    assert.match(launcher.executable,/WindowsPowerShell.*powershell.exe$/);
    assert.equal(launcher.args[0],"-NoProfile");
    assert.match(launcher.args.at(-1)!,/scripts[\\/]windows-handoff-tunnel.ps1$/);
    assert.equal(launcher.args.includes("-Command"),false);
  } finally {if(systemRoot===undefined)delete process.env.SystemRoot;else process.env.SystemRoot=systemRoot;}
});
