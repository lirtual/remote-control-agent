import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { BrowserCliAdapter, type BrowserCliRunner } from "../src/browser-cli.ts";

async function fixture(
  impl: (args: readonly string[]) => string | Promise<string> = () => "OK",
  idleMsForTests = 60_000,
) {
  const store = await mkdtemp(path.join(os.tmpdir(), "rca-browser-cli-test-"));
  const commands: string[][] = [];
  const runner: BrowserCliRunner = async args => {
    commands.push([...args]);
    return impl(args);
  };
  const adapter = new BrowserCliAdapter({
    entrypoint: path.join(store, "package", "bin", "agent-browser.js"),
    agentStore: store, runnerForTests: runner, idleMsForTests,
  });
  return { adapter, commands, store, cleanup: () => rm(store, { recursive: true, force: true }) };
}

test("start is an isolated Profile and one fixed named session; reuse, close, no raw CLI", async () => {
  const f = await fixture();
  try {
    const status = await f.adapter.start();
    assert.equal(status.backend, "agent-browser");
    assert.equal(status.tab_id, "tab-1");
    assert.equal(status.uncertain, false);
    assert.match(status.session_id, /^[a-f0-9-]{36}$/);
    assert.deepEqual(f.commands[0], [
      "--session", "rca-" + status.session_id, "--profile",
      path.join(f.store, "browser-automation-profile"), "open",
    ]);
    await assert.rejects(f.adapter.start(), /already active/);
    await assert.rejects(f.adapter.snapshot("another-session"), /Unknown or closed/);
    await f.adapter.close(status.session_id);
    assert.deepEqual(f.commands.at(-1), ["--session", "rca-" + status.session_id, "close"]);
    assert.equal(f.adapter.status(), null);
    await assert.rejects(f.adapter.close(status.session_id), /Unknown or closed/);
    assert.equal("execute" in f.adapter, false);
    assert.equal("evaluate" in f.adapter, false);
    assert.equal("click" in f.adapter, false); // No unsanctioned high-impact action surface.
  } finally { await f.cleanup(); }
});

test("normal page navigation and compact snapshot, with session scope enforced", async () => {
  const f = await fixture(args => args.includes("snapshot") ? "- textbox \"Demo\" [ref=e1]\n" : "OK");
  try {
    const { session_id } = await f.adapter.start();
    await f.adapter.navigate(session_id, "https://demo.playwright.dev/todomvc/");
    assert.deepEqual(f.commands.at(-1), [
      "--session", "rca-" + session_id, "open", "https://demo.playwright.dev/todomvc/",
    ]);
    assert.deepEqual(await f.adapter.snapshot(session_id), {
      text: "- textbox \"Demo\" [ref=e1]\n", truncated: false,
    });
    assert.deepEqual(f.commands.at(-1), ["--session", "rca-" + session_id, "snapshot", "-i"]);
    await f.adapter.close(session_id);
  } finally { await f.cleanup(); }
});

test("deny file/javascript/URL credentials/local IP and shell-looking strings", async () => {
  const f = await fixture();
  try {
    const { session_id } = await f.adapter.start();
    for (const input of [
      "file:///etc/passwd", "javascript:alert(1)", "http://localhost:3333/",
      "http://127.0.0.1/", "http://192.168.1.1/",
      "https://user:pass@example.com/", "https://example.com/\n--execute",
      "https://[::1]/", "https://printer.local/", "https://admin.internal/",
    ]) {
      await assert.rejects(f.adapter.navigate(session_id, input));
    }
    assert.equal(f.commands.length, 1, "invalid URL must not reach the CLI");
    await f.adapter.close(session_id);
  } finally { await f.cleanup(); }
});

test("CLI timeout/uncertain effect cannot silently replay or create a second session", async () => {
  let fail = true;
  const f = await fixture(args => {
    if (args.includes("https://example.com/") && fail) throw Error("synthetic lost reply");
    return "OK";
  });
  try {
    const { session_id } = await f.adapter.start();
    await assert.rejects(f.adapter.navigate(session_id, "https://example.com/"), /synthetic lost reply/);
    assert.equal(f.adapter.status()?.uncertain, true);
    fail = false;
    await assert.rejects(f.adapter.navigate(session_id, "https://example.com/"), /replay refused/);
    await assert.rejects(f.adapter.start(), /already active/);
    assert.equal(f.commands.filter(args => args.includes("https://example.com/")).length, 1);
    await f.adapter.close(session_id);
    assert.equal(f.adapter.status(), null);
  } finally { await f.cleanup(); }
});

test("unconfirmed startup remains tracked; caller can explicitly close and recover", async () => {
  let fail = true;
  const f = await fixture(args => {
    if (args.includes("open") && fail) throw Error("startup failed");
    return "OK";
  });
  try {
    await assert.rejects(f.adapter.start(), /startup not confirmed/);
    const id = f.adapter.status()?.session_id;
    assert.ok(id);
    assert.equal(f.adapter.status()?.uncertain, true);
    await assert.rejects(f.adapter.start(), /already active/);
    fail = false;
    await f.adapter.close(id);
    assert.equal(f.adapter.status(), null);
  } finally { await f.cleanup(); }
});

test("bounded snapshots do not routinely return large page output", async () => {
  const f = await fixture(args => args.includes("snapshot") ? "x".repeat(9000) : "OK");
  try {
    const { session_id } = await f.adapter.start();
    const value = await f.adapter.snapshot(session_id);
    assert.equal(value.truncated, true);
    assert.equal(value.text.length, 8000);
    await f.adapter.close(session_id);
  } finally { await f.cleanup(); }
});

test("rejects concurrent operations, never allowing overlapping CLI commands", async () => {
  let release!: () => void;
  const gate = new Promise<void>(resolve => { release = resolve; });
  const f = await fixture(async args => {
    if (args.includes("snapshot")) await gate;
    return "OK";
  });
  try {
    const { session_id } = await f.adapter.start();
    const pending = f.adapter.snapshot(session_id);
    await assert.rejects(f.adapter.close(session_id), /already in progress/);
    release();
    await pending;
    await f.adapter.close(session_id);
  } finally { release(); await f.cleanup(); }
});

test("does not accept relative executable/store paths", () => {
  assert.throws(() => new BrowserCliAdapter({ entrypoint: "npx", agentStore: "/tmp" }));
  assert.throws(() => new BrowserCliAdapter({ entrypoint: "/trusted/cli.js", agentStore: "./profile" }));
  assert.throws(() => new BrowserCliAdapter({
    entrypoint: "/trusted/cli.js", agentStore: "/tmp", nodeExecutable: "node",
  }));
  assert.throws(() => new BrowserCliAdapter({
    entrypoint: "/trusted/cli.js", agentStore: "/tmp", browserExecutable: "chrome",
  }));
});
