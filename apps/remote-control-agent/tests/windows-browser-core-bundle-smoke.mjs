import assert from "node:assert/strict";
import {createHash} from "node:crypto";
import {mkdtemp,readFile,writeFile,rm} from "node:fs/promises";
import {spawnSync} from "node:child_process";
import {pathToFileURL} from "node:url";
import os from "node:os";
import path from "node:path";
import {inspectWindowsPreview} from "../scripts/verify-windows-preview.mjs";

// Invoked only by the isolated windows-2025 CI runner, not by a paired Agent.
const stage=process.argv[2];
if(process.platform!=="win32" || !stage || !path.isAbsolute(stage))
  throw Error("Native Windows absolute staging directory required");
const results=inspectWindowsPreview(stage);
assert.equal(results.version,"v0.0.1-ci");
assert.ok(results.files<=41 && results.files>=20);
const manifestFile=path.join(stage,"bundle.json");
const manifest=JSON.parse(await readFile(manifestFile,"utf8"));
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
  await ownedBrowser.close(session.session_id);
  assert.equal(ownedBrowser.status(),null);
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
