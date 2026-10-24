import assert from "node:assert/strict";
import {createServer} from "node:http";
import {mkdtemp, rm} from "node:fs/promises";
import {pathToFileURL} from "node:url";
import path from "node:path";
import os from "node:os";

// #33 source-only candidate integration in disposable Windows CI.
// The DNS resolver deliberately maps an apparently public DNS name to the
// test runner's loopback listener. No real LAN or metadata endpoint is used.
if (process.platform !== "win32" || process.env.GITHUB_ACTIONS !== "true")
  throw Error("Disposable Windows CI only.");
const stage=process.argv[2], channel=process.argv[3];
if (!stage || !path.isAbsolute(stage) || !["chrome","msedge"].includes(channel))
  throw Error("Pinned stage and supported browser required.");
const {chromium}=await import(pathToFileURL(path.join(stage,
  "apps/remote-control-agent/node_modules/playwright-core/index.mjs")).href);
const {startCandidateBrowserEgressProxy}=await import(pathToFileURL(path.join(
  process.cwd(), "apps/remote-control-agent/candidates/browser-egress-proxy.ts")).href);

let localConnections=0, localHits=0, lookups=0;
const privateListener=createServer((_req,res)=>{
  localHits++;
  res.writeHead(200);res.end("PROHIBITED_LOOPBACK");
});
privateListener.on("connection",socket=>{
  localConnections++;
  socket.on("error",()=>{});
});
await new Promise((resolve,reject)=>{
  privateListener.once("error",reject);
  privateListener.listen(0,"127.0.0.1",resolve);
});
const localPort=privateListener.address().port;
const proxy=await startCandidateBrowserEgressProxy(async host=>{
  lookups++;
  if(host!=="public.example.com") throw Error("Unexpected public hostname");
  return [{address:"127.0.0.1",family:4}];
});
const privateStore=await mkdtemp(path.join(os.tmpdir(),"rca-candidate-proxy-"));
let context;
let proxyClosed=false;
try {
  context=await chromium.launchPersistentContext(
    path.join(privateStore,"profile-"+channel),{
      channel,headless:true,serviceWorkers:"block",acceptDownloads:false,
      timeout:20000,
      proxy:{server:proxy.server,bypass:"<-loopback>"},
      args:["--proxy-bypass-list=<-loopback>","--disable-quic",
        "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1",
        "--webrtc-ip-handling-policy=disable_non_proxied_udp"],
    }
  );
  const page=context.pages()[0]??await context.newPage();
  const response=await page.goto("http://public.example.com/private",{
    waitUntil:"domcontentloaded",timeout:10000,
  });
  assert.equal(response?.status(),403,"Private DNS target must return 403 from actual candidate proxy.");
  // HTTPS CONNECT for this same apparently public name must be refused as
  // well; do not assume browser HTTPS errors alone imply private isolation.
  await assert.rejects(page.goto("https://public.example.com/private",{
    waitUntil:"domcontentloaded",timeout:8000,
  }));
  // Both direct localhost and a public-looking hostname resolving to localhost
  // are attempted from the page; neither may connect to the listener.
  // Chromium can asynchronously install its error page after a rejected
  // HTTPS CONNECT. Use a new page so that transition cannot race this probe.
  await page.close().catch(()=>{});
  const probePage=await context.newPage();
  await probePage.setContent('<img src="http://public.example.com/private-image">');
  await probePage.evaluate(url=>{
    const ws=new WebSocket(url);
    ws.onerror=()=>{};
  },"ws://127.0.0.1:"+localPort+"/socket");
  await probePage.waitForTimeout(350);
  assert.ok(lookups>=2,"Actual proxy resolver must evaluate HTTP and HTTPS requests.");
  assert.equal(localConnections,0,"Browser bypassed proxy and reached local TCP.");
  assert.equal(localHits,0,"Browser or candidate proxy contacted forbidden local HTTP.");

  // A dead proxy MUST NOT trigger a DIRECT fallback, including for loopback.
  // This is the exact kind of gap that can invalidate an otherwise correct
  // DNS/redirect filter when a page triggers reconnect/retry.
  await proxy.close();
  proxyClosed=true;
  try {
    await probePage.goto("http://127.0.0.1:"+localPort+"/proxy-down",{timeout:2500});
  } catch { /* fail-closed proxy connection is expected */ }
  await probePage.waitForTimeout(200);
  assert.equal(localConnections,0,"Browser fell back to direct local TCP after proxy shutdown.");
  assert.equal(localHits,0,"Browser directly reached local HTTP after proxy shutdown.");
  console.log("WINDOWS_CANDIDATE_PROXY_PRIVATE_DNS="+channel+":PASS");
  console.log(JSON.stringify({channel,lookups,localConnections,localHits,
    dnsPrivateDenied:true,httpConnectDenied:true,proxyDownFallbackDenied:true,
    actualProductionIsolation:"NOT_TESTED"}));
} finally {
  await context?.close().catch(()=>{});
  if(!proxyClosed) await proxy.close();
  await new Promise(resolve=>privateListener.close(resolve));
  await rm(privateStore,{recursive:true,force:true});
}
