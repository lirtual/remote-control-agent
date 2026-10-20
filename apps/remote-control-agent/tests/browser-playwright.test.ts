import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { chromium } from "playwright-core";
import { BrowserOfflineCore } from "../src/browser-offline.ts";
import { createPlaywrightOfflineDriver } from "../src/browser-playwright.ts";

/**
 * Actual Playwright/Chromium integration smoke, not an external-network
 * safety certification. The CI step installs only the matching headless shell
 * into an isolated runner cache. No live Agent, Worker, network navigation,
 * remote debugging service or production browser Profile is used.
 */
test("real pinned Playwright launches an offline Chromium and captures bounded ARIA", {
  skip: process.env.RCA_REAL_PLAYWRIGHT_SMOKE !== "1",
  timeout: 60_000,
}, async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "rc-real-playwright-"));
  const core = new BrowserOfflineCore(createPlaywrightOfflineDriver(chromium), root);
  try {
    const session = await core.start();
    assert.equal(session.mode, "offline-only");
    assert.equal(session.tab_id, "offline-1");
    const snapshot = await core.snapshot(session.session_id);
    assert.equal(snapshot.truncated, false);
    assert.match(snapshot.text, /Offline inspection/);
    assert.equal(core.status()?.session_id, session.session_id);
    await core.close();
    assert.equal(core.status(), null);
  } finally {
    await core.close();
    await rm(root, { recursive: true, force: true });
  }
});
