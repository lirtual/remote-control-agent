import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import {
  BrowserOfflineCore,
  BROWSER_SNAPSHOT_MAX_CHARS,
  type BrowserOfflineContext,
  type BrowserOfflineDriver,
  type BrowserBlockedRoute,
  type BrowserBlockedWebSocket,
} from "../src/browser-offline.ts";

function fakeDriver(options: { websocket?: boolean; snapshot?: string; failPage?: boolean } = {}) {
  const calls: string[] = [];
  let routeHandler: ((route: BrowserBlockedRoute) => Promise<void>) | undefined;
  let websocketHandler: ((ws: BrowserBlockedWebSocket) => Promise<void>) | undefined;
  const context: BrowserOfflineContext = {
    async route(glob, handler) {
      calls.push("route:" + glob);
      routeHandler = handler;
    },
    ...(options.websocket === false ? {} : {
      async routeWebSocket(glob: string, handler: (ws: BrowserBlockedWebSocket) => Promise<void>) {
        calls.push("socket:" + glob);
        websocketHandler = handler;
      },
    }),
    async newPage() {
      calls.push("newPage");
      if (options.failPage) throw new Error("Synthetic page error");
      return {
        async setContent(content: string) {
          calls.push("content:" + content.slice(0, 15));
          assert.match(content, /Offline inspection/);
          assert.doesNotMatch(content, /https?:\/\//i);
        },
        async ariaSnapshot() { return options.snapshot ?? '- heading "Offline inspection"'; },
      };
    },
    async close() { calls.push("close"); },
  };
  const driver: BrowserOfflineDriver = {
    async launchPersistentContext(profile, flags) {
      calls.push("launch");
      assert.ok(path.isAbsolute(profile));
      assert.equal(flags.headless, true);
      assert.equal(flags.offline, true);
      assert.equal(flags.javaScriptEnabled, false);
      assert.equal(flags.serviceWorkers, "block");
      assert.equal(flags.acceptDownloads, false);
      assert.deepEqual(flags.permissions, []);
      return context;
    },
  };
  return { driver, calls, blockedRoute: () => routeHandler, blockedSocket: () => websocketHandler };
}

test("offline inspection initializes network/WebSocket denials before opening a fixed page", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "rc-browser-safe-"));
  const mock = fakeDriver();
  const core = new BrowserOfflineCore(mock.driver, root);
  try {
    assert.equal(core.status(), null);
    const session = await core.start();
    assert.equal(session.mode, "offline-only");
    assert.equal(session.tab_id, "offline-1");
    assert.deepEqual(mock.calls.slice(0, 4), ["launch", "route:**/*", "socket:**/*", "newPage"]);
    assert.ok(mock.blockedRoute());
    assert.ok(mock.blockedSocket());
    let routeDenied = false;
    await mock.blockedRoute()!({ abort: async code => {
      assert.equal(code, "blockedbyclient"); routeDenied = true;
    } });
    let websocketDenied = false;
    await mock.blockedSocket()!({ close: async options => {
      assert.equal(options.code, 1008); websocketDenied = true;
    } });
    assert.equal(routeDenied, true);
    assert.equal(websocketDenied, true);
    assert.deepEqual(await core.snapshot(session.session_id), {
      text: '- heading "Offline inspection"', truncated: false,
    });
    await assert.rejects(core.start(), /already in use/);
    await assert.rejects(core.snapshot("unknown-session"), /Unknown or closed/);
    await core.close();
    assert.equal(core.status(), null);
    assert.ok(mock.calls.includes("close"));
  } finally {
    await core.close();
    await rm(root, { recursive: true, force: true });
  }
});

test("runtime missing WebSocket denial fails closed and closes Chromium context", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "rc-browser-deny-"));
  const mock = fakeDriver({ websocket: false });
  const core = new BrowserOfflineCore(mock.driver, root);
  try {
    await assert.rejects(core.start(), /cannot block WebSockets/);
    assert.equal(core.status(), null);
    assert.deepEqual(mock.calls, ["launch", "route:**/*", "close"]);
  } finally {
    await core.close();
    await rm(root, { recursive: true, force: true });
  }
});

test("failed synthetic page setup closes context without publishing a session", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "rc-browser-fail-"));
  const mock = fakeDriver({ failPage: true });
  const core = new BrowserOfflineCore(mock.driver, root);
  try {
    await assert.rejects(core.start(), /Synthetic page error/);
    assert.equal(core.status(), null);
    assert.ok(mock.calls.includes("close"));
  } finally {
    await core.close();
    await rm(root, { recursive: true, force: true });
  }
});

test("ARIA snapshots are bounded and never accept arbitrary navigation", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "rc-browser-bounded-"));
  const mock = fakeDriver({ snapshot: "s".repeat(BROWSER_SNAPSHOT_MAX_CHARS + 1200) });
  const core = new BrowserOfflineCore(mock.driver, root);
  try {
    const session = await core.start();
    const snapshot = await core.snapshot(session.session_id);
    assert.equal(snapshot.truncated, true);
    assert.equal(snapshot.text.length, BROWSER_SNAPSHOT_MAX_CHARS);
    assert.equal("navigate" in core, false);
    assert.equal("evaluate" in core, false);
    assert.equal("click" in core, false);
  } finally {
    await core.close();
    await rm(root, { recursive: true, force: true });
  }
});
