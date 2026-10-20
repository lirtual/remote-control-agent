import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import type { BrowserType } from "playwright-core";
import { PlaywrightBrowserManager } from "../candidates/browser-playwright.ts";

function fakeBrowser(options: { navigationFails?: boolean; restoredUrl?: string; snapshot?: string; navigationWait?: Promise<void>; launchWait?: Promise<void> } = {}) {
  const calls: string[] = [];
  const page = {
    setDefaultTimeout: (ms: number) => { calls.push("timeout:"+ms); },
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
    pages: () => options.restoredUrl ? [{url:()=>options.restoredUrl,close:async()=>{}}] : [],
    newPage: async () => page,
    close: async () => {calls.push("context-close");},
  };
  const driver = {
    launchPersistentContext: async (profile:string,settings: Record<string,unknown>) => {
      calls.push("launch:"+profile);
      assert.equal(settings.headless,true);
      assert.equal(settings.acceptDownloads,false);
      assert.equal(settings.serviceWorkers,"block");
      if (options.launchWait) await options.launchWait;
      return context;
    },
  } as unknown as BrowserType<{}>;
  return {driver,calls};
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
    assert.match(fake.calls[0] ?? "",/browser-automation-profile$/);
    await assert.rejects(browser.start(),/already in use/);
    await assert.rejects(browser.navigate(status.session_id,"http://localhost/"),/outside first-phase/);
    await browser.navigate(status.session_id,"https://example.com/page");
    assert.ok(fake.calls.includes("goto:https://example.com/page"));
    const snap=await browser.snapshot(status.session_id);
    assert.match(snap.text,/\[ref=e2\]/);
    assert.ok(snap.snapshot_version>0);
    assert.equal(browser.status()?.backend,"playwright");
    await browser.close(status.session_id);
    assert.equal(browser.status(),null);
    assert.equal(fake.calls.filter(x=>x==="context-close").length,1);
    await assert.rejects(browser.snapshot(status.session_id),/Unknown or closed/);
  } finally { await rm(tmp,{recursive:true,force:true}); }
});

test("uncertain navigation cannot be replayed, but can be inspected then closed",async()=>{
  const tmp=await mkdtemp(path.join(os.tmpdir(),"rca-native-pw-unknown-"));
  const fake=fakeBrowser({navigationFails:true});
  const browser=new PlaywrightBrowserManager({agentStore:tmp,chromiumForTests:fake.driver});
  try{
    const {session_id}=await browser.start();
    await assert.rejects(browser.navigate(session_id,"https://example.com"),/outcome uncertain/);
    assert.equal(browser.status()?.uncertain,true);
    await assert.rejects(browser.navigate(session_id,"https://example.com"),/Uncertain browser navigation/);
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
    const navigation=browser.navigate(session_id,"https://example.com/");
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
