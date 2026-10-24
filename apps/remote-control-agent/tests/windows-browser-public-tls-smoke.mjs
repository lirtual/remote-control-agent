import assert from "node:assert/strict";
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
let proxy, context;
try {
  proxy = await startCandidateBrowserEgressProxy();
  context = await chromium.launchPersistentContext(path.join(profile, channel), {
    channel, headless: true, timeout: 25_000,
    acceptDownloads: false, serviceWorkers: "block",
    proxy: { server: proxy.server, bypass: "<-loopback>" },
    args: ["--proxy-bypass-list=<-loopback>", "--disable-quic",
      "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1",
      "--webrtc-ip-handling-policy=disable_non_proxied_udp"],
  });
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
  console.log("WINDOWS_CANDIDATE_PROXY_PUBLIC_TLS=" + channel + ":PASS");
  console.log(JSON.stringify({ channel, tlsVerifiedByBrowser: true,
    publicSite: "example.com", httpStatus: response.status(),
    isolatedFixture: false, productionIsolation: "NOT_TESTED" }));
} finally {
  await context?.close().catch(() => {});
  await proxy?.close();
  await rm(profile, { recursive: true, force: true });
}
