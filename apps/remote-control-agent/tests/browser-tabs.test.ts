import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import type { BrowserType } from "playwright-core";
import { PlaywrightBrowserManager } from "../candidates/browser-playwright.ts";

function fakeContext() {
  const calls: string[] = [];
  let pageHandler: ((page: unknown) => void) | undefined;
  let contextHandler: ((x: any) => void) | undefined;
  const pages: Array<ReturnType<typeof makePage>> = [];
  let count = 1;
  function makePage() {
    let closed = false;
    let href = "about:blank";
    let closeHandler: (() => void) | undefined;
    return {
      on: (event: string, handler: () => void) => {if(event==="close")closeHandler=handler;},
      isClosed: () => closed,
      url: () => href,
      title: async () => "Sample tab",
      setDefaultTimeout: () => {},
      bringToFront: async () => {calls.push("front:"+href);},
      close: async () => {closed=true;closeHandler?.();calls.push("tab-closed");},
      goto: async (url: string) => {href=url;calls.push("goto:"+url);},
      ariaSnapshot: async () => '- textbox "Search"\n- button "Search"\n- combobox "Size"',
      getByRole: (role:string, options:{name:string}) => {
        calls.push("lookup:"+role+":"+options.name);
        return {
          count:async()=>count,
          click:async()=>{calls.push("clicked");},
          fill:async(text:string)=>{calls.push("filled:"+text);},
          selectOption:async(value:string)=>{calls.push("selected:"+value);return [];},
        };
      },
      keyboard:{press:async(key:string)=>{calls.push("key:"+key);}},
    };
  }
  const context = {
    pages:()=>pages.filter(p=>!p.isClosed()),
    newPage:async()=>{
      const page=makePage();
      pages.push(page);
      pageHandler?.(page);
      return page;
    },
    on:(event:string,handler:(x:any)=>void)=>{
      if(event==="page")pageHandler=handler;
      if(event==="close")contextHandler=handler;
    },
    route:async()=>{},
    close:async()=>{
      for(const page of pages.filter(p=>!p.isClosed()))await page.close();
      contextHandler?.(undefined);
    },
  };
  const driver={
    launchPersistentContext:async(profile:string,settings:{headless:boolean;channel:string})=>{
      calls.push("profile:"+path.basename(profile));
      calls.push("headless:"+settings.headless);
      calls.push("channel:"+settings.channel);
      return context;
    },
  } as unknown as BrowserType<{}>;
  return {driver,calls,manualOpen:async(url:string)=>{
    const page=await context.newPage();
    await page.goto(url);
    return page;
  },setCount:(value:number)=>{count=value;},closeContext:()=>context.close()};
}

test("headed BrowserContext reuses session and exposes manually opened tabs without guessing selection",async()=>{
  const dir=await mkdtemp(path.join(os.tmpdir(),"spec152-tabs-"));
  const fake=fakeContext();
  const manager=new PlaywrightBrowserManager({agentStore:dir,chromiumForTests:fake.driver,browserChannelForTests:"msedge"});
  try{
    const start=await manager.start();
    assert.equal(start.tab_id,"tab-1");
    assert.equal(start.browser_family,"msedge");
    assert.equal((await manager.start()).session_id,start.session_id);
    assert.equal(fake.calls.filter(x=>x.startsWith("profile:")).length,1);
    assert.ok(fake.calls.includes("headless:false"));
    assert.ok(fake.calls.includes("profile:browser-automation-profile-msedge"));
    await fake.manualOpen("https://example.org/manual");
    let list=await manager.tabs(start.session_id,"list");
    assert.deepEqual(list.tabs.map(x=>x.tab_id),["tab-1","tab-2"]);
    assert.equal(list.selected_tab_id,"tab-1","manual new tab must not silently switch the target");
    await manager.tabs(start.session_id,"select","tab-2");
    await manager.navigate(start.session_id,"https://example.com/new");
    assert.ok(fake.calls.includes("goto:https://example.com/new"));
    await manager.tabs(start.session_id,"close","tab-2");
    assert.equal(manager.status()?.tab_id,null,"closing selected tab must never select another tab");
    await assert.rejects(manager.snapshot(start.session_id),/No selected live tab/);
    list=await manager.tabs(start.session_id,"list");
    assert.deepEqual(list.tabs.map(x=>x.tab_id),["tab-1"]);
    await manager.tabs(start.session_id,"select","tab-1");
    await manager.close(start.session_id);
    assert.equal(manager.status(),null);
    assert.equal((await manager.start()).browser_family,"msedge");
    assert.equal(fake.calls.filter(x=>x.startsWith("profile:")).length,2);
  }finally{
    await manager.stopOwnedForRevocation();
    await rm(dir,{recursive:true,force:true});
  }
});

test("fresh unique semantic locator is required for click, fill, select and bounded key",async()=>{
  const dir=await mkdtemp(path.join(os.tmpdir(),"spec152-target-"));
  const fake=fakeContext();
  const manager=new PlaywrightBrowserManager({agentStore:dir,chromiumForTests:fake.driver});
  try{
    const {session_id}=await manager.start();
    const snap=await manager.snapshot(session_id);
    await manager.fill(session_id,{role:"textbox",name:"Search",snapshot_version:snap.snapshot_version},"PRIVATE-TEST-INPUT");
    assert.ok(fake.calls.includes("filled:PRIVATE-TEST-INPUT"));
    await assert.rejects(manager.click(session_id,{role:"button",name:"Search",snapshot_version:snap.snapshot_version}),/Stale snapshot/);
    const fresh=await manager.snapshot(session_id);
    await manager.click(session_id,{role:"button",name:"Search",snapshot_version:fresh.snapshot_version});
    const third=await manager.snapshot(session_id);
    await manager.selectOption(session_id,{role:"combobox",name:"Size",snapshot_version:third.snapshot_version},"M");
    assert.ok(fake.calls.includes("selected:M"));
    const last=await manager.snapshot(session_id);
    await assert.rejects(manager.pressKey(session_id,"Alt+F4",last.snapshot_version),/outside the allowed set/);
    await manager.pressKey(session_id,"Enter",last.snapshot_version);
    assert.ok(fake.calls.includes("key:Enter"));
    const fifth=await manager.snapshot(session_id);
    fake.setCount(2);
    await assert.rejects(manager.click(session_id,{role:"button",name:"Search",snapshot_version:fifth.snapshot_version}),/not unique/);
  }finally{
    await manager.stopOwnedForRevocation();
    await rm(dir,{recursive:true,force:true});
  }
});
