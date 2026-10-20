import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { chromium, type BrowserContext } from "playwright-core";
import { BrowserOfflineCore } from "../src/browser-offline.ts";
import { createPlaywrightOfflineDriver } from "../src/browser-playwright.ts";

/**
 * Real Chromium negative baseline using only 127.0.0.1.
 *
 * This tests the existing offline-only browser mode, not an arbitrary public
 * navigation policy. A positive unprotected browser control proves that zero
 * guarded fixture requests aren't explained by a broken localhost listener.
 */
test("real offline BrowserCore prevents request delivery to an otherwise reachable simulated target", {
  skip: process.env.RCA_REAL_PLAYWRIGHT_SMOKE !== "1",
  timeout: 90_000,
}, async () => {
  const requests: string[] = [];
  const server = createServer((req, res) => {
    const pathname = new URL(req.url ?? "/", "http://fixture.invalid").pathname;
    requests.push(pathname);
    if (pathname === "/public") {
      res.writeHead(302, { location: "/simulated-sensitive" });
      res.end();
    } else {
      res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
      res.end("<!doctype html><html><body>LOOPBACK_ONLY_FIXTURE</body></html>");
    }
  });
  const root = await mkdtemp(path.join(os.tmpdir(), "rc-browser-deny-fixture-"));
  let context: BrowserContext | undefined;
  let baseline: BrowserContext | undefined;
  const core = new BrowserOfflineCore(createPlaywrightOfflineDriver({
    async launchPersistentContext(...args: Parameters<typeof chromium.launchPersistentContext>) {
      context = await chromium.launchPersistentContext(...args);
      return context;
    },
  } as typeof chromium), root);
  try {
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });
    const address = server.address();
    if (!address || typeof address === "string") throw Error("No ephemeral loopback port.");
    const base = "http://127.0.0.1:" + address.port;

    // A deliberately unguarded browser must traverse the fixture redirect.
    // This is local-only and never uses real metadata/LAN/production services.
    baseline = await chromium.launchPersistentContext(path.join(root, "unguarded-profile"), {
      headless: true, serviceWorkers: "block", javaScriptEnabled: false,
    });
    const publicPage = await baseline.newPage();
    await publicPage.goto(base + "/public", { waitUntil: "domcontentloaded", timeout: 5_000 });
    assert.match(await publicPage.content(), /LOOPBACK_ONLY_FIXTURE/);
    assert.deepEqual(requests.filter(x => x !== "/favicon.ico"), ["/public", "/simulated-sensitive"]);
    await baseline.close();
    baseline = undefined;
    requests.length = 0;

    // The real protected context has offline emulation, all-route abort and
    // WebSocket denial installed. We try to bypass the restricted Core API
    // from test-only captured Playwright context to challenge that boundary.
    const session = await core.start();
    assert.equal(session.mode, "offline-only");
    const page = context!.pages()[0];
    assert.ok(page, "Protected offline page must exist");

    await assert.rejects(
      page.goto(base + "/public", { waitUntil: "domcontentloaded", timeout: 3_000 }),
      /ERR_|Navigation|net::|aborted|offline|closed/i,
    );
    // Exercise subresource and child-frame creation using trusted synthetic HTML
    // even though no caller-controlled HTML interface exists in the product.
    await page.setContent(
      `<!doctype html><body><img src="${base}/simulated-sensitive?via=image"><iframe src="${base}/simulated-sensitive?via=iframe"></iframe><link rel="stylesheet" href="${base}/simulated-sensitive?via=css"></body>`,
      { waitUntil: "domcontentloaded", timeout: 5_000 },
    );
    await page.waitForTimeout(300);
    assert.deepEqual(requests, [], "Guarded Chromium sent a request to the synthetic sensitive target");
    assert.equal(core.status()?.session_id, session.session_id);
    await core.close();
  } finally {
    await core.close();
    if (baseline) await baseline.close();
    await new Promise<void>((resolve, reject) => server.close(err => err ? reject(err) : resolve()));
    await rm(root, { recursive: true, force: true });
  }
});
