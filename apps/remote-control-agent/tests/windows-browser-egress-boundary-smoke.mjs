import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtemp, rm } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import os from "node:os";
import path from "node:path";

// Disposable Windows CI proof ONLY. This does not change the deployed Agent,
// create a system-wide proxy or claim complete SSRF isolation.
if (process.platform !== "win32") throw Error("Native Windows CI only.");
const stage = process.argv[2];
const browserChannel = process.argv[3] ?? "chrome";
if (!["chrome", "msedge"].includes(browserChannel)) throw Error("Unsupported test browser.");
if (!stage || !path.isAbsolute(stage)) throw Error("Pinned absolute candidate path required.");
const modulePath = path.join(stage, "apps/remote-control-agent/node_modules/playwright-core/index.mjs");
const { chromium } = await import(pathToFileURL(modulePath).href);

const onLoopback = (server, bindAddress="127.0.0.1") => new Promise((resolve, reject) => {
  server.once("error", reject);
  server.listen(0, bindAddress, () => resolve(server.address().port));
});
const closeServer = server => new Promise(resolve => server.close(resolve));

let localConnections = 0;
let localHttpHits = 0;
const local = createServer((_request, response) => {
  localHttpHits++;
  response.writeHead(200, { "content-type": "text/plain" });
  response.end("ISOLATED_TEST_LISTENER");
});
local.on("connection", socket => {
  localConnections++;
  socket.on("error", () => {});
});

const seen = [];
let denied = 0;
let context;
const privateStore = await mkdtemp(path.join(os.tmpdir(), "rca-ci-egress-proxy-"));
const localPort = await onLoopback(local);
const localUrl = `http://127.0.0.1:${localPort}/no-access`;
let localIPv6Connections=0, localIPv6HttpHits=0;
const localIPv6=createServer((_request,response)=>{
  localIPv6HttpHits++;
  response.writeHead(200,{"content-type":"text/plain"});
  response.end("IPV6_LOCAL_LISTENER_REACHED");
});
localIPv6.on("connection", socket=>{
  localIPv6Connections++;
  socket.on("error",()=>{});
});
const localIPv6Port=await onLoopback(localIPv6,"::1");
const localIPv6Url=`http://[::1]:${localIPv6Port}/no-access`;
const proxy = createServer((request, response) => {
  const raw = request.url ?? "";
  seen.push(raw);
  let url;
  try { url = new URL(raw); } catch {
    response.writeHead(400); response.end(); return;
  }
  if (url.hostname === "public.browser-egress.test" && url.pathname === "/ok") {
    response.writeHead(200, { "content-type": "text/html" });
    response.end("<!doctype html><title>Proxy fixture</title><p>PUBLIC_TEST_OK</p>");
    return;
  }
  if (url.hostname === "public.browser-egress.test" && url.pathname === "/redirect") {
    response.writeHead(302, { location: localUrl, "cache-control": "no-store" });
    response.end();
    return;
  }
  denied++;
  response.writeHead(403, { "content-type": "text/plain" });
  response.end("BLOCKED_BY_ISOLATED_TEST_PROXY");
});
proxy.on("connect", (request, socket) => {
  socket.on("error", () => {}); // Chromium may reset a denied tunnel.
  seen.push("CONNECT " + request.url);
  denied++;
  socket.end("HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n");
});
proxy.on("connection", socket => socket.on("error", () => {}));
const proxyPort = await onLoopback(proxy);
try {
  // Chrome's default implicit localhost proxy bypass MUST be overridden;
  // never consider merely setting proxy.server to be a security guarantee.
  context = await chromium.launchPersistentContext(
    path.join(privateStore, "profile-" + browserChannel),
    {
      channel: browserChannel, headless: true, acceptDownloads: false,
      serviceWorkers: "block", timeout: 20_000,
      proxy: { server: `http://127.0.0.1:${proxyPort}`, bypass: "<-loopback>" },
      args: ["--proxy-bypass-list=<-loopback>", "--disable-quic",
        "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1"],
    }
  );
  const page = context.pages()[0] ?? await context.newPage();
  await page.goto("http://public.browser-egress.test/ok", { waitUntil: "domcontentloaded" });
  assert.match(await page.textContent("body"), /PUBLIC_TEST_OK/, "Public fixture must work via proxy");
  assert.ok(seen.some(x => x.includes("public.browser-egress.test/ok")));

  try { await page.goto("http://public.browser-egress.test/redirect", {timeout: 8000}); }
  catch { /* A denied redirected navigation is expected. */ }
  await page.setContent(`<img src="${localUrl}/image"><iframe src="${localUrl}/frame"></iframe>
    <img src="${localIPv6Url}/image"><iframe src="${localIPv6Url}/frame"></iframe>`);
  // A WebSocket is not caught by Playwright HTTP context.route(); this test
  // checks whether Chrome's own proxy settings capture its network attempt.
  for (const url of [localUrl,localIPv6Url]) {
    await page.evaluate(target => {
      const ws = new WebSocket(target.replace(/^http/, "ws") + "/socket");
      ws.onerror = () => {};
    }, url);
  }
  await page.waitForTimeout(600);

  assert.equal(localConnections, 0,
    "Local TCP listener received a bypassed socket; browser proxy not isolated.");
  assert.equal(localHttpHits, 0, "Local HTTP listener was reached.");
  assert.equal(localIPv6Connections, 0, "IPv6 loopback TCP listener reached.");
  assert.equal(localIPv6HttpHits, 0, "IPv6 loopback HTTP listener reached.");
  assert.ok(denied > 0, "No negative destination requests reached proxy.");
  console.log("WINDOWS_PROXY_BOUNDARY_FIXTURE=" + browserChannel + ":PASS");
  console.log(JSON.stringify({
    browserChannel,
    publicFixture: true,
    redirectedOrLocalDenied: denied,
    observedProxyRequests: seen.length,
    localTcpConnections: localConnections,
    localHttpHits,
    localIPv6Connections,
    localIPv6HttpHits,
    actualAgentIsolation: "NOT_TESTED",
    dnsPinning: "NOT_TESTED",
    browserOtherTransports: "NOT_TESTED",
  }));
} finally {
  await context?.close().catch(() => {});
  await closeServer(proxy);
  await closeServer(local);
  await closeServer(localIPv6);
  await rm(privateStore, { recursive: true, force: true });
}
