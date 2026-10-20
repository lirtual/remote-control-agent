/**
 * Real unpublished BUNDLE acceptance: loader, version-matched headless shell,
 * isolated persistent Profile, ARIA snapshot, and cleanup.
 * No outside URL is accepted, no live Agent connection or account involved.
 */
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { inspectWindowsPreview } from "./verify-windows-preview.mjs";

if (process.argv.length !== 3 || !path.isAbsolute(process.argv[2])) {
  throw Error("Expected one absolute extracted candidate root.");
}
const stage = process.argv[2];
const verified = inspectWindowsPreview(stage);
assert.equal(verified.target, "windows-x64");
const libraryRoot = path.join(stage, "apps/remote-control-agent/vendor/playwright-core");
process.env.PLAYWRIGHT_BROWSERS_PATH = path.join(stage, "apps/remote-control-agent/vendor/browsers");
const { chromium } = await import(pathToFileURL(path.join(libraryRoot, "index.mjs")).href);
const { BrowserOfflineCore } = await import(pathToFileURL(
  path.join(stage, "apps/remote-control-agent/src/browser-offline.js")).href);
const { createPlaywrightOfflineDriver } = await import(pathToFileURL(
  path.join(stage, "apps/remote-control-agent/src/browser-playwright.js")).href);
const profileRoot = mkdtempSync(path.join(os.tmpdir(), "rc-bundled-playwright-"));
const core = new BrowserOfflineCore(createPlaywrightOfflineDriver(chromium), profileRoot);
try {
  const session = await core.start();
  assert.equal(session.mode, "offline-only");
  const snapshot = await core.snapshot(session.session_id);
  assert.match(snapshot.text, /Offline inspection/);
  assert.equal(snapshot.truncated, false);
  await core.close();
  assert.equal(core.status(), null);
  console.log(JSON.stringify({
    result: "BUNDLED_OFFLINE_CHROMIUM_PASS",
    runtime: "playwright-core@1.64.1",
    bundledFiles: verified.files,
  }));
} finally {
  await core.close();
  rmSync(profileRoot, { recursive: true, force: true });
}
