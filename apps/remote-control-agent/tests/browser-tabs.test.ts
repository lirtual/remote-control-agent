import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import type { BrowserType } from "playwright-core";
import { PlaywrightBrowserManager } from "../candidates/browser-playwright.ts";

function fakeContext(options: {closeFails?: boolean} = {}) {
  const calls: string[] = [];
  let pageHandler: ((page: unknown) => void) | undefined;
  let contextHandler: ((x: any) => void) | undefined;
  const pages: Array<ReturnType<typeof makePage>> = [];
  let count = 1;
  let duringCount: (() => Promise<void>) | undefined;
  function makePage() {
    let closed = false;
    let href = "about:blank";
    let closeHandler: (() => void) | undefined;
    const primaryFrame = {};
    let navigated: ((frame: typeof primaryFrame) => void) | undefined;
    return {
      on: (event: string, handler: (frame: typeof primaryFrame) => void) => {
        if (event==="close")closeHandler=()=>handler(primaryFrame);
        if (event==="framenavigated")navigated=handler;
      },
      mainFrame: () => primaryFrame,
      isClosed: () => closed,
      url: () => href,
      title: async () => "Sample tab",
      setDefaultTimeout: () => {},
      bringToFront: async () => {calls.push("front:"+href);},
      close: async () => {closed=true;closeHandler?.();calls.push("tab-closed");},
      goto: async (url: string) => {href=url;navigated?.(primaryFrame);calls.push("goto:"+url);},
      ariaSnapshot: async () => '- textbox "Search"\n- button "Search"\n- combobox "Size"',
      getByRole: (role:string, options:{name:string}) => {
        calls.push("lookup:"+role+":"+options.name);
        return {
          count:async()=>{if(duringCount)await duringCount();return count;},
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
      if(options.closeFails)throw Error("Managed context close failed.");
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
  },manualCloseAll:async()=>{
    for(const page of context.pages()) await page.close();
  },setCount:(value:number)=>{count=value;},
    onCount:(fn:()=>Promise<void>)=>{duringCount=fn;},
    closeContext:()=>context.close()};
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
    const versionBefore=manager.status()!.snapshot_version;
    await assert.rejects(manager.navigate(start.session_id,"https://example.com/should-not-navigate",
      "tab-1",versionBefore),/Stale selected tab/);
    await assert.rejects(manager.navigate(start.session_id,"https://example.com/should-not-navigate",
      "tab-2",versionBefore-1),/Stale snapshot/);
    assert.ok(!fake.calls.includes("goto:https://example.com/should-not-navigate"),
      "No side effect may precede exact tab and snapshot check");
    await manager.navigate(start.session_id,"https://example.com/new","tab-2",versionBefore);
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

test("closing the final window ends the session without racing Profile reuse",async()=>{
  const dir=await mkdtemp(path.join(os.tmpdir(),"spec152-owner-close-"));
  const fake=fakeContext();
  const manager=new PlaywrightBrowserManager({agentStore:dir,chromiumForTests:fake.driver});
  try{
    const first=await manager.start();
    await fake.manualOpen("https://example.org/manual");
    await fake.manualCloseAll();
    assert.equal(manager.status(),null,"last manually closed tab ends the session");
    await assert.rejects(manager.snapshot(first.session_id),/Unknown or closed/);
    // Immediate restart must await the previous Context close, retaining its
    // Profile without attaching to an orphaned or closed browser window.
    const next=await manager.start();
    assert.notEqual(next.session_id,first.session_id);
    assert.equal(next.tab_id,"tab-1");
    assert.equal(fake.calls.filter(x=>x.startsWith("profile:")).length,2);
    assert.equal((await manager.tabs(next.session_id,"list")).tabs.length,1);
    await manager.close(next.session_id);
    assert.equal(manager.status(),null);
  }finally{
    await manager.stopOwnedForRevocation();
    await rm(dir,{recursive:true,force:true});
  }
});

test("failed final-window shutdown denies Profile reuse and reports uncertain cleanup",async()=>{
  const dir=await mkdtemp(path.join(os.tmpdir(),"spec152-close-failed-"));
  const fake=fakeContext({closeFails:true});
  const manager=new PlaywrightBrowserManager({agentStore:dir,chromiumForTests:fake.driver});
  try{
    await manager.start();
    await fake.manualCloseAll();
    assert.equal(manager.status(),null);
    await assert.rejects(manager.start(),/Managed context close failed/);
    assert.equal(await manager.stopOwnedForRevocation(),"uncertain");
    assert.equal(fake.calls.filter(x=>x.startsWith("profile:")).length,1);
  }finally{
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

test("human navigation invalidates semantic snapshot before a potentially consequential action",async()=>{
  const dir=await mkdtemp(path.join(os.tmpdir(),"spec152-handoff-stale-"));
  const fake=fakeContext();
  const manager=new PlaywrightBrowserManager({agentStore:dir,chromiumForTests:fake.driver});
  try{
    const {session_id}=await manager.start();
    const externalPage=await fake.manualOpen("https://example.org/initial");
    await manager.tabs(session_id,"select","tab-2");
    const observed=await manager.snapshot(session_id);
    // User follows a link or navigates the address bar outside the MCP gateway.
    await externalPage.goto("https://example.org/other-form");
    await assert.rejects(
      manager.click(session_id,{role:"button",name:"Search",snapshot_version:observed.snapshot_version}),
      /Stale snapshot/,
    );
    assert.equal(fake.calls.includes("clicked"),false);
    const fresh=await manager.snapshot(session_id);
    await manager.click(session_id,{role:"button",name:"Search",snapshot_version:fresh.snapshot_version});
    assert.equal(fake.calls.includes("clicked"),true);
  }finally{
    await manager.stopOwnedForRevocation();
    await rm(dir,{recursive:true,force:true});
  }
});

test("human navigation during locator resolution must reject the stale action",async()=>{
  const dir=await mkdtemp(path.join(os.tmpdir(),"spec152-navigation-race-"));
  const fake=fakeContext();
  const manager=new PlaywrightBrowserManager({agentStore:dir,chromiumForTests:fake.driver});
  try{
    const {session_id}=await manager.start();
    const page=await fake.manualOpen("https://example.org/one");
    await manager.tabs(session_id,"select","tab-2");
    const observed=await manager.snapshot(session_id);
    // Navigation occurs after the first version check, while locator.count awaits.
    fake.onCount(async()=>{await page.goto("https://example.org/two");});
    await assert.rejects(
      manager.click(session_id,{role:"button",name:"Search",snapshot_version:observed.snapshot_version}),
      /Stale snapshot/,
    );
    assert.equal(fake.calls.includes("clicked"),false);
  }finally{
    await manager.stopOwnedForRevocation();
    await rm(dir,{recursive:true,force:true});
  }
});
