import assert from "node:assert/strict";
import { lookup } from "node:dns/promises";
import { mkdtemp, rm } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import path from "node:path";
import os from "node:os";

// Characterization only: exercise real public TLS over the candidate proxy.
// No production device, private address, DNS override or certificate exception.
if (process.platform !== "win32" || process.env.GITHUB_ACTIONS !== "true") {
  throw Error("Disposable Windows CI only.");
}
const stage = process.argv[2], channel = process.argv[3];
if (!stage || !path.isAbsolute(stage) || !["chrome", "msedge"].includes(channel)) {
  throw Error("Pinned stage and supported browser required.");
}
const { chromium } = await import(pathToFileURL(path.join(stage,
  "apps/remote-control-agent/node_modules/playwright-core/index.mjs")).href);
const { startCandidateBrowserEgressProxy } = await import(pathToFileURL(path.join(
  process.cwd(), "apps/remote-control-agent/candidates/browser-egress-proxy.ts")).href);

const profile = await mkdtemp(path.join(os.tmpdir(), "rca-ci-public-tls-"));
let proxy, context, proxyClosed = false;
let rebind = false, rebindChecks = 0;
try {
  // First resolve through real public DNS; only a later, fresh TLS CONNECT
  // attempt to the SAME hostname receives the synthetic local DNS answer.
  // No actual private/LAN service is contacted on any runner.
  proxy = await startCandidateBrowserEgressProxy(async hostname => {
    if (hostname === "example.com" && rebind) {
      rebindChecks++;
      return [{ address: "127.0.0.1", family: 4 }];
    }
    return (await lookup(hostname, { all: true }))
      .map(({ address, family }) => ({ address, family }));
  });
  const launchOptions = {
    channel, headless: true, timeout: 25_000,
    acceptDownloads: false, serviceWorkers: "block",
    proxy: { server: proxy.server, bypass: "<-loopback>" },
    args: ["--proxy-bypass-list=<-loopback>", "--disable-quic",
      "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1",
      "--webrtc-ip-handling-policy=disable_non_proxied_udp"],
  };
  context = await chromium.launchPersistentContext(path.join(profile, channel), launchOptions);
  const page = context.pages()[0] ?? await context.newPage();
  // ignoreHTTPSErrors must remain false. A successful result verifies
  // browser TLS, hostname validation/SNI and a real CONNECT through
  // the DNS-pinned numeric socket path, not just a synthetic 403.
  const response = await page.goto("https://example.com/", {
    waitUntil: "domcontentloaded", timeout: 22_000,
  });
  assert.equal(response?.status(), 200, "Public HTTPS must work with verified TLS.");
  assert.match(await page.title(), /Example Domain/i);
  assert.equal(new URL(page.url()).hostname, "example.com");

  // Close the first Chromium process to prevent reuse of the already pinned
  // public TLS tunnel; a new browser with the SAME candidate proxy must
  // resolve example.com again. A private rebound must be denied before dial.
  await context.close();
  context = undefined;
  rebind = true;
  context = await chromium.launchPersistentContext(
    path.join(profile, channel + "-rebound"), launchOptions);
  const rebindingPage = context.pages()[0] ?? await context.newPage();
  await assert.rejects(rebindingPage.goto("https://example.com/?rca-rebind=ci", {
    waitUntil: "domcontentloaded", timeout: 10_000,
  }), "Rebound private DNS result unexpectedly established a TLS tunnel.");
  assert.ok(rebindChecks > 0,
    "Rebinding check was not exercised by a new browser TLS CONNECT.");

  // A real verified HTTPS response alone cannot exclude a browser DIRECT
  // fallback. Tear down the candidate proxy and retry a cache-distinct HTTPS
  // navigation in the SAME browser context: it must fail rather than escape.
  await proxy.close();
  proxyClosed = true;
  // A separate page makes sure a previous Chromium error navigation cannot
  // be mistaken for a new failed request.
  const disconnected = await context.newPage();
  await assert.rejects(disconnected.goto("https://example.com/?rca-proxy-down=ci", {
    waitUntil: "domcontentloaded", timeout: 10_000,
  }), "Public HTTPS navigated after its sole approved proxy was closed.");
  console.log("WINDOWS_CANDIDATE_PROXY_PUBLIC_TLS=" + channel + ":PASS");
  console.log(JSON.stringify({ channel, tlsVerifiedByBrowser: true,
    publicSite: "example.com", httpStatus: response.status(),
    proxyDownPublicTlsDenied: true, reboundTlsDenied: true,
    reboundChecks: rebindChecks, isolatedFixture: false,
    productionIsolation: "NOT_TESTED" }));
} finally {
  await context?.close().catch(() => {});
  if (proxy && !proxyClosed) await proxy.close();
  await rm(profile, { recursive: true, force: true });
}
