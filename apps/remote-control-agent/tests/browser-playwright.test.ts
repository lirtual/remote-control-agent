import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { connect } from "node:net";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import type { BrowserType } from "playwright-core";
import { PlaywrightBrowserManager } from "../candidates/browser-playwright.ts";

function fakeBrowser(options: { navigationFails?: boolean; restoredUrl?: string; snapshot?: string; navigationWait?: Promise<void>; launchWait?: Promise<void> } = {}) {
  const calls: string[] = [];
  let proxyEndpoint: string | undefined;
  const contextCloseListeners: Array<() => void> = [];
  let requestFilter: ((route: {
    request(): {url(): string};
    continue(): Promise<void>;
    abort(reason: string): Promise<void>;
  }) => Promise<void>) | undefined;
  const page = {
    setDefaultTimeout: (ms: number) => { calls.push("timeout:"+ms); },
    isClosed: () => false,
    goto: async (url: string) => {
      calls.push("goto:"+url);
      if (options.navigationWait) await options.navigationWait;
      if (options.navigationFails) throw Error("Navigation outcome uncertain.");
    },
    ariaSnapshot: async (args: {mode: string}) => {
      assert.equal(args.mode,"ai");
      return options.snapshot ?? '- button "Demo" [ref=e2]';
    },
  };
  const context = {
    on: (event: string, handler: () => void) => {
      if (event === "close") contextCloseListeners.push(handler);
    },
    pages: () => options.restoredUrl ? [{url:()=>options.restoredUrl,close:async()=>{}}] : [],
    newPage: async () => {
      assert.ok(requestFilter, "Request filtering must precede page creation.");
      return page;
    },
    route: async (pattern: string, filter: typeof requestFilter) => {
      assert.equal(pattern, "**/*");
      requestFilter=filter;
      calls.push("context-route");
    },
    close: async () => {calls.push("context-close");},
  };
  const driver = {
    launchPersistentContext: async (profile:string,settings: Record<string,unknown>) => {
      calls.push("launch:"+profile);
      assert.equal(settings.headless,false);
      assert.equal(settings.acceptDownloads,false);
      assert.equal(settings.serviceWorkers,"block");
      const proxy=settings.proxy as {server:string;bypass:string};
      assert.match(proxy.server,/^http:\/\/127\.0\.0\.1:[0-9]+$/);
      assert.equal(proxy.bypass,"<-loopback>");
      proxyEndpoint=proxy.server;
      assert.deepEqual(settings.args,[
        "--proxy-bypass-list=<-loopback>",
        "--disable-quic",
        "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1",
        "--webrtc-ip-handling-policy=disable_non_proxied_udp",
      ]);
      calls.push("channel:"+String(settings.channel));
      calls.push("executable:"+String(settings.executablePath));
      if (options.launchWait) await options.launchWait;
      return context;
    },
  } as unknown as BrowserType<{}>;
  return {driver,calls,proxyEndpoint:()=>proxyEndpoint,
    simulateContextExit: () => contextCloseListeners.forEach(handler => handler()),
    request:async (url:string) => {
      assert.ok(requestFilter);
      let outcome="";
      await requestFilter!({
        request:()=>({url:()=>url}),
        continue:async()=>{ outcome="continue"; },
        abort:async(reason:string)=>{assert.equal(reason,"blockedbyclient");outcome="blocked";},
      });
      return outcome;
    },
  };
}

test("one Playwright-only session reuses Agent Profile, provides AI snapshot, and closes owned context",async()=>{
  const tmp=await mkdtemp(path.join(os.tmpdir(),"rca-native-pw-test-"));
  const fake=fakeBrowser();
  const browser=new PlaywrightBrowserManager({agentStore:tmp,chromiumForTests:fake.driver});
  try{
    const status=await browser.start();
    assert.equal(status.backend,"playwright");
    assert.equal(status.tab_id,"tab-1");
    assert.equal(status.snapshot_version,0);
    assert.match(fake.calls[0] ?? "",/browser-automation-profile-chrome$/);
    assert.equal((await browser.start()).session_id,status.session_id);
    await assert.rejects(browser.navigate(status.session_id,"http://localhost/",browser.status()!.tab_id!,browser.status()!.snapshot_version),/outside first-phase/);
    for (const url of ["http://localhost./","http://localhost../",
      "https://printer.local./","https://db.internal..","http://127.0.0.1../"]) {
      await assert.rejects(browser.navigate(status.session_id,url,browser.status()!.tab_id!,browser.status()!.snapshot_version),/outside first-phase/,url);
    }
    await browser.navigate(status.session_id,"https://example.com./",browser.status()!.tab_id!,browser.status()!.snapshot_version);
    assert.ok(fake.calls.includes("goto:https://example.com./"));
    await browser.navigate(status.session_id,"https://example.com/page",browser.status()!.tab_id!,browser.status()!.snapshot_version);
    assert.ok(fake.calls.includes("goto:https://example.com/page"));
    const snap=await browser.snapshot(status.session_id);
    assert.match(snap.text,/\[ref=e2\]/);
    assert.ok(snap.snapshot_version>0);
    assert.equal(browser.status()?.backend,"playwright");
    await browser.close(status.session_id);
    assert.equal(browser.status(),null);
    const proxyUrl=new URL(fake.proxyEndpoint()!);
    await assert.rejects(new Promise<void>((resolve,reject)=>{
      const socket=connect(Number(proxyUrl.port),"127.0.0.1",()=>{
        socket.destroy();
        resolve();
      });
      socket.once("error",reject);
    }), /ECONNREFUSED/, "A closed Agent browser must not leave a listening egress proxy.");
    assert.equal(fake.calls.filter(x=>x==="context-close").length,1);
    await assert.rejects(browser.snapshot(status.session_id),/Unknown or closed/);
  } finally { await rm(tmp,{recursive:true,force:true}); }
});

test("installed Chrome uses Playwright's built-in cross-platform channel, not a custom path finder",async()=>{
  const tmp=await mkdtemp(path.join(os.tmpdir(),"rca-p3-native-channel-"));
  const fake=fakeBrowser();
  const browser=new PlaywrightBrowserManager({agentStore:tmp,chromiumForTests:fake.driver});
  try{
    const {session_id}=await browser.start();
    assert.ok(fake.calls.includes("channel:chrome"));
    assert.ok(fake.calls.includes("executable:undefined"));
    await browser.close(session_id);
  }finally{await rm(tmp,{recursive:true,force:true});}
});

test("trusted installer-owned Chromium absolute path takes precedence over Chrome channel",async()=>{
  const tmp=await mkdtemp(path.join(os.tmpdir(),"rca-p3-matching-binary-"));
  const fake=fakeBrowser();
  const executable=path.join(tmp,"trusted-browser","chrome-headless-shell");
  const browser=new PlaywrightBrowserManager({agentStore:tmp,browserExecutable:executable,chromiumForTests:fake.driver});
  try{
    const {session_id}=await browser.start();
    assert.ok(fake.calls.includes("channel:undefined"));
    assert.ok(fake.calls.includes("executable:"+executable));
    await browser.close(session_id);
  }finally{await rm(tmp,{recursive:true,force:true});}
});

test("uncertain navigation cannot be replayed, but can be inspected then closed",async()=>{
  const tmp=await mkdtemp(path.join(os.tmpdir(),"rca-native-pw-unknown-"));
  const fake=fakeBrowser({navigationFails:true});
  const browser=new PlaywrightBrowserManager({agentStore:tmp,chromiumForTests:fake.driver});
  try{
    const {session_id}=await browser.start();
    await assert.rejects(browser.navigate(session_id,"https://example.com",browser.status()!.tab_id!,browser.status()!.snapshot_version),/outcome uncertain/);
    assert.equal(browser.status()?.uncertain,true);
    await assert.rejects(browser.navigate(session_id,"https://example.com",browser.status()!.tab_id!,browser.status()!.snapshot_version),/Uncertain browser navigation/);
    assert.equal(fake.calls.filter(x=>x.startsWith("goto:")).length,1);
    assert.equal((await browser.snapshot(session_id)).truncated,false);
    await browser.close(session_id);
  } finally { await rm(tmp,{recursive:true,force:true}); }
});

test("reject restored pages before using a persistent automation Profile",async()=>{
  const tmp=await mkdtemp(path.join(os.tmpdir(),"rca-native-pw-restored-"));
  const fake=fakeBrowser({restoredUrl:"https://example.com"});
  const browser=new PlaywrightBrowserManager({agentStore:tmp,chromiumForTests:fake.driver});
  try{
    await assert.rejects(browser.start(),/restored an unexpected page/);
    assert.equal(browser.status(),null);
    assert.ok(fake.calls.includes("context-close"));
  } finally { await rm(tmp,{recursive:true,force:true}); }
});

test("source browser manager applies 8000 character output limit",async()=>{
  const tmp=await mkdtemp(path.join(os.tmpdir(),"rca-native-pw-bounds-"));
  const fake=fakeBrowser({snapshot:"a".repeat(20000)});
  const browser=new PlaywrightBrowserManager({agentStore:tmp,chromiumForTests:fake.driver});
  try{
    const {session_id}=await browser.start();
    const result=await browser.snapshot(session_id);
    assert.equal(result.text.length,8000);
    assert.equal(result.truncated,true);
    assert.equal(result.next_offset,8000);
    const second=await browser.snapshot(session_id,result.next_offset);
    assert.equal(second.text.length,8000);
    assert.equal(second.next_offset,16000);
    const last=await browser.snapshot(session_id,second.next_offset);
    assert.equal(last.text.length,4000);
    assert.equal(last.truncated,false);
    await browser.close(session_id);
  } finally {await rm(tmp,{recursive:true,force:true});}
});

test("revocation interrupts active navigation and denies any later reuse",async()=>{
  const tmp=await mkdtemp(path.join(os.tmpdir(),"rca-pw-revoke-busy-"));
  let release!:()=>void;
  const gate=new Promise<void>(done=>{release=done;});
  const fake=fakeBrowser({navigationWait:gate});
  const browser=new PlaywrightBrowserManager({agentStore:tmp,chromiumForTests:fake.driver});
  try{
    const {session_id}=await browser.start();
    const navigation=browser.navigate(session_id,"https://example.com/",browser.status()!.tab_id!,browser.status()!.snapshot_version);
    assert.ok(fake.calls.includes("goto:https://example.com/"));
    assert.equal(await browser.stopOwnedForRevocation(),"confirmed");
    assert.equal(browser.status(),null,"revoked session must be forgotten immediately");
    release();
    await assert.rejects(navigation,/revoked during navigation/);
    await assert.rejects(browser.start(),/revoked/);
    assert.equal(fake.calls.filter(x=>x==="context-close").length,1);
  }finally{release();await rm(tmp,{recursive:true,force:true});}
});

test("revocation during slow Chromium startup prevents publishing a session",async()=>{
  const tmp=await mkdtemp(path.join(os.tmpdir(),"rca-pw-revoke-start-"));
  let release!:()=>void;
  const gate=new Promise<void>(done=>{release=done;});
  const fake=fakeBrowser({launchWait:gate});
  const browser=new PlaywrightBrowserManager({agentStore:tmp,chromiumForTests:fake.driver});
  try{
    const starting=browser.start();
    for(let i=0;i<40&&!fake.calls.some(x=>x.startsWith("launch:"));i++)
      await new Promise(done=>setTimeout(done,5));
    assert.ok(fake.calls.some(x=>x.startsWith("launch:")));
    assert.equal(await browser.stopOwnedForRevocation(),"confirmed");
    release();
    await assert.rejects(starting,/revoked during startup/);
    assert.equal(browser.status(),null);
    assert.equal(fake.calls.filter(x=>x==="context-close").length,1);
  }finally{release();await rm(tmp,{recursive:true,force:true});}
});

test("context filters intercepted direct local requests; real browser redirect follow-up is a separate unpassed gate",async()=>{
  const tmp=await mkdtemp(path.join(os.tmpdir(),"rca-p5-request-guard-"));
  const fake=fakeBrowser();
  const manager=new PlaywrightBrowserManager({agentStore:tmp,chromiumForTests:fake.driver});
  try {
    const session=await manager.start();
    assert.equal(fake.calls.filter(x=>x==="context-route").length,1);
    assert.ok(fake.calls.indexOf("context-route")<fake.calls.indexOf("timeout:5000"));
    // These are simulated requests delivered to the route callback.
    // They do not prove the callback is re-invoked on a browser-followed 302.
    for (const url of [
      "http://127.0.0.1:18781/p4/private",
      "http://10.1.2.3/",
      "http://192.168.5.10/image.png",
      "http://169.254.169.254/metadata",
      "http://[::1]/",
      "http://2130706433/admin",
      "http://localhost:18781/",
      "https://printer.local/file",
      "https://printer.local./file",
      "https://db.internal../query",
      "http://localhost./",
      "https://db.internal/query",
      "https://intranet/",
      "file:///C:/Users/owner/secrets",
    ]) assert.equal(await fake.request(url),"blocked",url);
    for(const url of [
      "https://example.com/",
      "https://cdn.example.net/image.png",
      "https://example.org/very-long-asset?"+"q".repeat(2400),
    ]) assert.equal(await fake.request(url),"continue",url);
    // Context request interception cannot pin DNS resolutions or necessarily
    // capture WebSocket traffic; these tests do NOT certify an SSRF sandbox.
    await manager.close(session.session_id);
  }finally{await rm(tmp,{recursive:true,force:true});}
});

test("unexpected browser exit forgets the session and removes its owned proxy", async () => {
  const tmp = await mkdtemp(path.join(os.tmpdir(), "rca-pw-context-exit-"));
  const fake = fakeBrowser();
  const browser = new PlaywrightBrowserManager({agentStore: tmp, chromiumForTests: fake.driver});
  try {
    const session = await browser.start();
    const endpoint = new URL(fake.proxyEndpoint()!);
    fake.simulateContextExit();
    assert.equal(browser.status(), null, "An exited browser must not retain an MCP session.");
    await assert.rejects(browser.snapshot(session.session_id), /Unknown or closed/);
    // The close callback initiates asynchronous shutdown; poll for the real
    // listening socket to vanish, not a fixed CI-dependent delay.
    let refused = false;
    for (let attempt = 0; attempt < 40 && !refused; attempt++) {
      refused = await new Promise<boolean>(resolve => {
        const socket = connect(Number(endpoint.port), "127.0.0.1");
        socket.once("connect", () => {socket.destroy(); resolve(false);});
        socket.once("error", (error: NodeJS.ErrnoException) =>
          resolve(error.code === "ECONNREFUSED"));
      });
      if (!refused) await new Promise(resolve => setTimeout(resolve, 25));
    }
    assert.equal(refused, true, "Unexpected browser exit left the proxy listening.");
  } finally {
    await rm(tmp, {recursive:true,force:true});
  }
});
