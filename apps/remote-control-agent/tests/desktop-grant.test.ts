import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, symlink } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  readDesktopGrant, enableDesktopGrantLocally, stopDesktopGrant,
  assertDesktopGrantGeneration,
} from "../src/desktop-grant.ts";

test("a paired device has no implicit Desktop Grant; Stop is durable across fresh readers", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "desktop-grant-"));
  try {
    assert.deepEqual(await readDesktopGrant(dir), { state: "stopped", generation: null });
    const enabled = await enableDesktopGrantLocally(dir);
    assert.equal(enabled.state, "enabled");
    assert.match(enabled.generation!, /^[0-9a-f-]{36}$/);
    assert.deepEqual(await readDesktopGrant(dir), enabled);
    await assertDesktopGrantGeneration(dir, enabled.generation);
    const stopped = await stopDesktopGrant(dir);
    assert.equal(stopped.state, "stopped");
    assert.notEqual(stopped.generation, enabled.generation);
    assert.deepEqual(await readDesktopGrant(dir), stopped);
    await assert.rejects(assertDesktopGrantGeneration(dir, enabled.generation), /desktop_stopped/);
    assert.deepEqual(await readDesktopGrant(dir), stopped);
    const persisted = JSON.parse(await readFile(path.join(dir, "desktop-stop.json"), "utf8"));
    assert.equal(persisted.generation, stopped.generation);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test("corrupt and linked state fails closed, never silently enables desktop control", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "desktop-grant-"));
  const external = path.join(dir, "foreign");
  try {
    await symlink(external, path.join(dir, "desktop-grant.json"));
    await assert.rejects(readDesktopGrant(dir), /desktop_grant_unavailable/);
    await assert.rejects(enableDesktopGrantLocally(dir), /desktop_grant_unavailable/);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test("stale generation cannot dispatch after local Stop and subsequent explicit reenable", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "desktop-grant-"));
  try {
    const a = await enableDesktopGrantLocally(dir);
    await stopDesktopGrant(dir);
    const b = await enableDesktopGrantLocally(dir);
    assert.notEqual(a.generation, b.generation);
    await assert.rejects(assertDesktopGrantGeneration(dir, a.generation), /stale_target/);
    await assertDesktopGrantGeneration(dir, b.generation);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test("computer_status reports a denied desktop even for an authorized but noninteractive device", async () => {
  const { executeV2SessionRead } = await import("../src/v2-connection-lifecycle.ts");
  const dir = await mkdtemp(path.join(os.tmpdir(), "desktop-grant-"));
  try {
    const fake = { executeTool: async () => { throw Error("must not access other tools"); } } as any;
    const text = await executeV2SessionRead(fake, "computer_status", {}, new AbortController().signal, dir);
    const status = JSON.parse(text as string);
    assert.equal(status.desktop_grant, process.platform === "win32" || process.platform === "darwin" ? "stopped" : "stopped");
    assert.equal(status.operable, false);
    assert.equal(await executeV2SessionRead(fake, "computer_status", { extra: true }, new AbortController().signal, dir), null);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test("computer_stop applies a durable local Stop through the existing receipt engine, without blind replay", async () => {
  const { createAgentExecutionEngine } = await import("../src/execution.ts");
  const dir = await mkdtemp(path.join(os.tmpdir(), "desktop-stop-"));
  try {
    const state = await enableDesktopGrantLocally(dir);
    const receiptDir = path.join(dir, "receipts");
    const { mkdir } = await import("node:fs/promises");
    await mkdir(receiptDir, { mode: 0o700 });
    const engine = createAgentExecutionEngine({
      receiptDirectory: receiptDir, desktopDirectory: dir,
    });
    try {
      const operation_id = "desktop-stop-0001";
      const input = { tool: "computer_stop", arguments: {}, operation_id };
      const first = await engine.executeTool(input, new AbortController().signal);
      assert.equal((first?.body as any)?.status, "completed");
      assert.equal((await readDesktopGrant(dir)).state, "stopped");
      const firstGeneration = (await readDesktopGrant(dir)).generation;
      const repeated = await engine.executeTool(input, new AbortController().signal);
      assert.equal((repeated?.body as any)?.status, "completed");
      assert.equal((await readDesktopGrant(dir)).generation, firstGeneration);
      const saved = await engine.getReceipt(operation_id);
      assert.equal(saved?.tool_name, "computer_stop");
      assert.equal(saved?.state, "completed");
      const invalid = await engine.executeTool({
        tool: "computer_stop", arguments: { unexpected: "x" },
        operation_id: "desktop-stop-invalid",
      }, new AbortController().signal);
      assert.equal(invalid?.status, 400);
      const conflict = await engine.executeTool({
        tool: "computer_stop", arguments: {}, operation_id: "desktop-stop-invalid",
      }, new AbortController().signal);
      assert.equal((conflict?.body as any)?.status, "completed");
    } finally { await engine.close(); }
    assert.equal((await readDesktopGrant(dir)).state, "stopped");
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test("signed WSS Computer Stop is routed without Shell authority and suppresses a repeated effect", async () => {
  const { monitorDeviceSocket } = await import("../src/v2-connection-lifecycle.ts");
  const { createAgentExecutionEngine } = await import("../src/execution.ts");
  const { mkdir } = await import("node:fs/promises");
  const dir = await mkdtemp(path.join(os.tmpdir(), "desktop-stop-wss-"));
  try {
    await enableDesktopGrantLocally(dir);
    const receiptDirectory = path.join(dir, "receipts");
    await mkdir(receiptDirectory, { mode: 0o700 });
    const engine = createAgentExecutionEngine({ desktopDirectory: dir, receiptDirectory });
    const signal = new AbortController();
    class Socket extends EventTarget {
      readyState = 1;
      sent: Array<Record<string, any>> = [];
      send(data: string) {
        this.sent.push(JSON.parse(data));
        this.dispatchEvent(new Event("sent"));
      }
      close() { this.readyState = 3; }
      receive(body: unknown) {
        this.dispatchEvent(new MessageEvent("message", { data: JSON.stringify(body) }));
      }
    }
    const socket = new Socket();
    const waitForResponses = async (count: number): Promise<void> => {
      if (socket.sent.length >= count) return;
      await new Promise<void>((resolve, reject) => {
        const onSent = () => {
          if (socket.sent.length < count) return;
          clearTimeout(timeout);
          socket.removeEventListener("sent", onSent);
          resolve();
        };
        const timeout = setTimeout(() => {
          socket.removeEventListener("sent", onSent);
          reject(Error(`Expected ${count} WSS responses`));
        }, 5_000);
        socket.addEventListener("sent", onSent);
        onSent();
      });
    };
    try {
      const monitoring = monitorDeviceSocket(socket as unknown as WebSocket, signal.signal,
        { intervalMs: 10000, timeoutMs: 2000 },
        undefined,
        async (tool, args, operationId, abort) =>
          (await engine.executeTool({ tool, arguments: args, operation_id: operationId }, abort))
            ?.body as Record<string, unknown> ?? null,
        false);
      const request = {
        kind: "operation", request_id: "55555555-5555-4555-8555-555555555555",
        tool: "computer_stop", arguments: {}, operation_id: "wss-desktop-stop-1",
      };
      socket.receive(request);
      await waitForResponses(1);
      assert.equal(socket.sent[0]?.kind, "operation_result");
      assert.equal(socket.sent[0]?.result?.status, "completed");
      const first = await readDesktopGrant(dir);
      assert.equal(first.state, "stopped");
      socket.receive({ ...request, request_id: "66666666-6666-4666-8666-666666666666" });
      await waitForResponses(2);
      assert.equal(socket.sent[1]?.result?.status, "completed");
      assert.deepEqual(await readDesktopGrant(dir), first);
      signal.abort();
      assert.equal(await monitoring, "aborted");
    } finally { signal.abort(); await engine.close(); }
  } finally { await rm(dir, { recursive: true, force: true }); }
});
