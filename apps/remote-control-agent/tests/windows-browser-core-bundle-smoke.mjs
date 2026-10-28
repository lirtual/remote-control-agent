import assert from "node:assert/strict";
import {createServer} from "node:http";
import {createHash} from "node:crypto";
import {mkdtemp,readFile,writeFile,rm} from "node:fs/promises";
import {spawnSync} from "node:child_process";
import {pathToFileURL,fileURLToPath} from "node:url";
import os from "node:os";
import path from "node:path";
import {inspectWindowsPreview} from "../scripts/verify-windows-preview.mjs";

// Invoked only by the isolated windows-2025 CI runner, not by a paired Agent.
const stage=process.argv[2];
if(process.platform!=="win32" || !stage || !path.isAbsolute(stage))
  throw Error("Native Windows absolute staging directory required");
const results=inspectWindowsPreview(stage);
assert.equal(results.version,process.env.RCA_EXPECTED_BUNDLE_VERSION ?? "v0.0.1-ci");
// The StageOnly installer is packaged from the reviewed root source as a pinned file.
assert.equal(results.files,42,"Unexpected reviewed Windows Playwright file inventory");
assert.deepEqual(
  await readFile(path.join(stage,"apps/remote-control-agent/scripts/windows-stage-install.ps1")),
  await readFile(fileURLToPath(new URL("../../../install.ps1",import.meta.url))),
  "The staged immutable Release verifier must be byte-identical to the reviewed interactive installer"
);
const nativeStageInstaller=path.join(stage,"apps/remote-control-agent/scripts/windows-stage-install.ps1");
const verifiedStageInstaller=await readFile(nativeStageInstaller);
try{
  await writeFile(nativeStageInstaller,Buffer.concat([verifiedStageInstaller,Buffer.from("\n# tampered")]));
  assert.throws(()=>inspectWindowsPreview(stage),/checksum mismatch/,
    "Modifying the locally installed stage-only PowerShell must invalidate the release bundle");
}finally{
  await writeFile(nativeStageInstaller,verifiedStageInstaller);
}
assert.equal(inspectWindowsPreview(stage).files,42);

const manifestFile=path.join(stage,"bundle.json");
const manifest=JSON.parse(await readFile(manifestFile,"utf8"));
assert.equal(Object.hasOwn(manifest.hashes ?? {}, "apps/remote-control-agent/src/linux-upgrade-reconnect.js"),false,
  "Retired remote-upgrade proof must not be required in the Windows runtime");
const infoModule=path.join(stage,"apps/remote-control-agent/src/device-info.js");
const {collectDeviceInfo}=await import(pathToFileURL(infoModule).href);
const signedInfo=collectDeviceInfo();
assert.equal(signedInfo.agent_version,results.version);
assert.equal(signedInfo.upgrade_protocol,undefined,
  "The signed Agent must no longer advertise MCP remote-upgrade readiness");

const pinned=manifest.browser_runtime;
assert.equal(pinned?.name,"playwright-core");
assert.equal(pinned.version,"1.64.1");
assert.equal(pinned.files.length,9);
const pkg=path.join(stage,"apps/remote-control-agent/node_modules/playwright-core");
const managerPath=path.join(stage,"apps/remote-control-agent/candidates/browser-playwright.js");
const compiledAgent=path.join(stage,"apps/remote-control-agent/src/windows-v2.js");
const {createPackagedBrowserForWindows}=await import(pathToFileURL(compiledAgent).href);
const defaultStage=process.argv[3];
if(defaultStage){
  const {createPackagedBrowserForWindows:plainLoader}=await import(
    pathToFileURL(path.join(defaultStage,"apps/remote-control-agent/src/windows-v2.js")).href);
  assert.equal(await plainLoader(path.join(defaultStage,"unrelated-private-store")),undefined,
    "The default Agent must remain browser-free");
}
const originalManifest=await readFile(manifestFile);
const original=await readFile(path.join(pkg,"lib/coreBundle.js"));
let ctx;
const profile=await mkdtemp(path.join(os.tmpdir(),"rca-ci-p3-playwright-"));
try{
  const {chromium}=await import(pathToFileURL(path.join(pkg,"index.mjs")).href);
  ctx=await chromium.launchPersistentContext(path.join(profile,"private-profile"),{
    channel:"chrome",headless:true,acceptDownloads:false,serviceWorkers:"block",timeout:20000
  });
  const page=ctx.pages()[0]??await ctx.newPage();
  await page.setContent('<input placeholder="What needs to be done?"><iframe title="Demo" srcdoc="<button>Child</button>"></iframe>');
  const snap=await page.ariaSnapshot({mode:"ai"});
  const ref=snap.match(/- textbox "What needs to be done\?" \[ref=([^\]]+)\]/)?.[1];
  assert.ok(ref,"Expected real semantic input ref");
  await page.getByRef(ref).fill("Windows packaged core test");
  assert.equal(await page.getByRef(ref).inputValue(),"Windows packaged core test");
  assert.match(await page.ariaSnapshot({mode:"ai"}),/Child/);
  console.log("P3_WINDOWS_PACKAGED_PINNED_PLAYWRIGHT_CHROME=PASS");
}finally{
  await ctx?.close();
  await rm(profile,{recursive:true,force:true});
}
// Test the exact Windows Agent startup helper and the real compiled
// BrowserManager, not merely Playwright's generic public API.
const ownStore=await mkdtemp(path.join(os.tmpdir(),"rca-ci-p3-manager-"));
let ownedBrowser;
try{
  ownedBrowser=await createPackagedBrowserForWindows(ownStore,
    pathToFileURL(compiledAgent).href);
  assert.ok(ownedBrowser,"An explicitly packaged, verified candidate can be injected locally");
  assert.equal(ownedBrowser.status(),null,"Creating the manager does not launch Chrome");
  const session=await ownedBrowser.start();
  assert.equal(session.backend,"playwright");
  const snapshot=await ownedBrowser.snapshot(session.session_id);
  assert.ok(snapshot.snapshot_version>0 && typeof snapshot.text==="string");
  // Verify the ACTUAL packaged BrowserManager context, not just a stub. The
  // server binds loopback and never communicates with any other internal site.
  let localHits=0;
  const localServer=createServer((_request,response)=>{
    localHits++;
    response.writeHead(200,{"content-type":"text/plain"});
    response.end("PRIVATE_ENDPOINT_REACHED");
  });
  await new Promise((resolve,reject)=>{
    localServer.once("error",reject);
    localServer.listen(0,"127.0.0.1",resolve);
  });
  try {
    const address=localServer.address();
    assert.ok(address && typeof address!=="string");
    const privateUrl="http://127.0.0.1:"+address.port+"/private";
    const context=ownedBrowser.context;
    assert.ok(context,"Expected the test-owned Chromium Context");
    const ownedPage=context.pages()[0];
    assert.ok(ownedPage);
    await ownedPage.setContent('<img src="'+privateUrl+'/asset">');
    await ownedPage.waitForTimeout(250);
    assert.equal(localHits,0,"A local-image subresource must be blocked");
    // A real public->loopback 302 previously ESCAPED Context route checks
    // on this exact Chrome/Playwright version (CI #39520350950 hit local
    // server once). Playwright documents redirects as one routed unit.
    // Never assert a redirect safety claim here; browser MCP stays disabled.
    console.log("P5_WINDOWS_PACKAGED_CHROME_DIRECT_LOCAL_SUBRESOURCE_DENIED=PASS");
    console.log("P5_REDIRECT_EGRESS_ISOLATION=NOT_ACCEPTED");
  } finally {
    await new Promise(resolve=>localServer.close(resolve));
  }
  // Exercise the packaged BrowserManager against actual Windows Chrome.
  // These are rejection-only checks: no public navigation, paired device,
  // or owner credentials are needed, and a rejected call must not touch the page.
  const originalStatus=ownedBrowser.status();
  assert.ok(originalStatus?.tab_id);
  const originalPage=ownedBrowser.context.pages()[0];
  const originalUrl=originalPage.url();
  const attemptedUrl="https://example.com/never-opened-by-this-test";
  await assert.rejects(ownedBrowser.navigate(
    session.session_id,attemptedUrl,"tab-999",originalStatus.snapshot_version
  ),/Stale selected tab/);
  await assert.rejects(ownedBrowser.navigate(
    session.session_id,attemptedUrl,originalStatus.tab_id,originalStatus.snapshot_version-1
  ),/Stale snapshot/);
  assert.equal(originalPage.url(),originalUrl);
  assert.equal(ownedBrowser.status()?.snapshot_version,originalStatus.snapshot_version);

  await ownedBrowser.tabs(session.session_id,"new");
  const switchedStatus=ownedBrowser.status();
  assert.ok(switchedStatus?.tab_id && switchedStatus.tab_id!==originalStatus.tab_id);
  await assert.rejects(ownedBrowser.navigate(
    session.session_id,attemptedUrl,originalStatus.tab_id,switchedStatus.snapshot_version
  ),/Stale selected tab/);
  await assert.rejects(ownedBrowser.navigate(
    session.session_id,attemptedUrl,switchedStatus.tab_id,originalStatus.snapshot_version
  ),/Stale snapshot/);
  assert.equal(ownedBrowser.status()?.snapshot_version,switchedStatus.snapshot_version);
  assert.equal(ownedBrowser.status()?.uncertain,false);
  const selectedPage=ownedBrowser.context.pages().at(-1);
  assert.equal(selectedPage?.url(),"about:blank");
  console.log("WINDOWS_PACKAGED_BROWSER_NAVIGATION_STALE_REJECTION=PASS");

  // Positive path uses a synthetic public URL fulfilled entirely in Chrome;
  // no external request, user device or signed Owner DO is involved.
  const fixtureUrl="https://example.com/browser-fixture";
  await selectedPage.route(fixtureUrl,route=>route.fulfill({
    status:200,contentType:"text/html",
    body:'<!doctype html><title>Browser fixture</title><button>Continue</button>',
  }));
  const fresh=ownedBrowser.status();
  await ownedBrowser.navigate(
    session.session_id,fixtureUrl,fresh.tab_id,fresh.snapshot_version
  );
  assert.equal(selectedPage.url(),fixtureUrl);
  assert.match((await ownedBrowser.snapshot(session.session_id)).text,/Continue/);
  console.log("WINDOWS_PACKAGED_BROWSER_FRESH_NAVIGATION_OFFLINE=PASS");

  await ownedBrowser.close(session.session_id);
  assert.equal(ownedBrowser.status(),null);

  // A normal close must release the private Profile for a fresh headed session.
  // Reopening may preserve cookies, but must not silently take over a restored
  // nonblank page; users should be able to reopen after a completed session.
  const reopened=await ownedBrowser.start();
  assert.notEqual(reopened.session_id,session.session_id);
  assert.ok(reopened.tab_id);
  assert.equal(reopened.uncertain,false);
  const blankTabs=await ownedBrowser.tabs(reopened.session_id,"list");
  assert.ok(blankTabs.tabs.length>=1);
  assert.ok(blankTabs.tabs.every(tab=>tab.url==="about:blank"));
  const firstTab=reopened.tab_id;
  const created=await ownedBrowser.tabs(reopened.session_id,"new");
  const secondTab=created.selected_tab_id;
  assert.ok(secondTab && secondTab!==firstTab);
  const selected=await ownedBrowser.tabs(reopened.session_id,"select",firstTab);
  assert.equal(selected.selected_tab_id,firstTab);
  const afterClose=await ownedBrowser.tabs(reopened.session_id,"close",secondTab);
  assert.equal(afterClose.selected_tab_id,firstTab);
  assert.ok(!afterClose.tabs.some(tab=>tab.tab_id===secondTab));
  // Closing the final page directly is equivalent to the user closing the
  // last Chrome window: it must not leave a stale reusable Agent session.
  const lastPage=ownedBrowser.context.pages()[0];
  await lastPage.close();
  assert.equal(ownedBrowser.status(),null);
  const afterWindowClose=await ownedBrowser.start();
  assert.notEqual(afterWindowClose.session_id,reopened.session_id);
  await ownedBrowser.close(afterWindowClose.session_id);
  assert.equal(ownedBrowser.status(),null);
  console.log("WINDOWS_PACKAGED_BROWSER_REOPEN_AND_TABS=PASS");
  console.log("P3_REAL_PACKAGED_AGENT_BROWSER_MANAGER_START_SNAPSHOT_CLOSE=PASS");
}finally{
  const session=ownedBrowser?.status();
  if(session)await ownedBrowser.close(session.session_id);
  await rm(ownStore,{recursive:true,force:true});
}
try{
  const originalManager=await readFile(managerPath);
  try{
    await writeFile(managerPath,"// malicious replacement");
    assert.throws(()=>inspectWindowsPreview(stage),/checksum/);
    await assert.rejects(createPackagedBrowserForWindows(
      path.join(stage,"untrusted-store"),pathToFileURL(compiledAgent).href),/checksum/);
  }finally{
    await writeFile(managerPath,originalManager);
  }
  console.log("P3_TAMPERED_COMPILED_BROWSER_MANAGER_DENIED_BEFORE_LOAD=PASS");
}catch(e){throw e;}
try{
  const bundle=path.join(pkg,"lib/coreBundle.js");
  await writeFile(bundle,Buffer.from("invalid vendored payload"));
  assert.throws(()=>inspectWindowsPreview(stage),/checksum/);
  await writeFile(bundle,original);
  const bad=JSON.parse(originalManifest.toString("utf8"));
  const target=pinned.files[0];
  bad.hashes[target]="f".repeat(64);
  await writeFile(manifestFile,JSON.stringify(bad)+"\n");
  assert.throws(()=>inspectWindowsPreview(stage),/manifest/);
  console.log("P3_WINDOWS_PINNED_FILE_CORRUPTION_AND_MANIFEST_TAMPER_REJECTED=PASS");
}finally{
  await writeFile(path.join(pkg,"lib/coreBundle.js"),original);
  await writeFile(manifestFile,originalManifest);
}
assert.equal(inspectWindowsPreview(stage).files,results.files);
console.log(JSON.stringify({step:"WINDOWS_PINNED_CORE_RUNTIME",result:"PASS",files:results.files}));
