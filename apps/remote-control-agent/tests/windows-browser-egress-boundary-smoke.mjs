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

const onLoopback = server => new Promise((resolve, reject) => {
  server.once("error", reject);
  server.listen(0, "127.0.0.1", () => resolve(server.address().port));
});
const closeServer = server => new Promise(resolve => server.close(resolve));

let localConnections = 0;
let localHttpHits = 0;
const local = createServer((_request, response) => {
  localHttpHits++;
  response.writeHead(200, { "content-type": "text/plain" });
  response.end("ISOLATED_TEST_LISTENER");
});
local.on("connection", () => { localConnections++; });

const seen = [];
let denied = 0;
let context;
const privateStore = await mkdtemp(path.join(os.tmpdir(), "rca-ci-egress-proxy-"));
const localPort = await onLoopback(local);
const localUrl = `http://127.0.0.1:${localPort}/no-access`;
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
  seen.push("CONNECT " + request.url);
  denied++;
  socket.end("HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n");
});
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
      args: ["--proxy-bypass-list=<-loopback>", "--disable-quic"],
    }
  );
  const page = context.pages()[0] ?? await context.newPage();
  await page.goto("http://public.browser-egress.test/ok", { waitUntil: "domcontentloaded" });
  assert.match(await page.textContent("body"), /PUBLIC_TEST_OK/, "Public fixture must work via proxy");
  assert.ok(seen.some(x => x.includes("public.browser-egress.test/ok")));

  try { await page.goto("http://public.browser-egress.test/redirect", {timeout: 8000}); }
  catch { /* A denied redirected navigation is expected. */ }
  await page.setContent(`<img src="${localUrl}/image"><iframe src="${localUrl}/frame"></iframe>`);
  // A WebSocket is not caught by Playwright HTTP context.route(); this test
  // checks whether Chrome's own proxy settings capture its network attempt.
  await page.evaluate(url => {
    const ws = new WebSocket(url.replace(/^http/, "ws") + "/socket");
    ws.onerror = () => {};
  }, localUrl);
  await page.waitForTimeout(600);

  assert.equal(localConnections, 0,
    "Local TCP listener received a bypassed socket; browser proxy not isolated.");
  assert.equal(localHttpHits, 0, "Local HTTP listener was reached.");
  assert.ok(denied > 0, "No negative destination requests reached proxy.");
  console.log("WINDOWS_PROXY_BOUNDARY_FIXTURE=" + browserChannel + ":PASS");
  console.log(JSON.stringify({
    browserChannel,
    publicFixture: true,
    redirectedOrLocalDenied: denied,
    observedProxyRequests: seen.length,
    localTcpConnections: localConnections,
    localHttpHits,
    actualAgentIsolation: "NOT_TESTED",
    dnsPinning: "NOT_TESTED",
    browserOtherTransports: "NOT_TESTED",
  }));
} finally {
  await context?.close().catch(() => {});
  await closeServer(proxy);
  await closeServer(local);
  await rm(privateStore, { recursive: true, force: true });
}
