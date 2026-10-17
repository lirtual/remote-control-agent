import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { createAgentExecutionEngine } from "../src/execution.ts";
import { startAgent } from "../src/server.ts";

test("shared mutation executor preserves atomic operation_id idempotency and receipt after restart", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "rc-shared-write-"));
  const file = path.join(root, "append.txt");
  const receipts = path.join(root, "receipts");
  const call = { tool: "write_file", operation_id: "shared-append-01", arguments: {
    path: file, content: "once\n", mode: "append",
  } };
  let executor = createAgentExecutionEngine({ receiptDirectory: receipts });
  try {
    await writeFile(file, "prefix\n", "utf8");
    const both = await Promise.all([
      executor.executeTool(call, new AbortController().signal),
      executor.executeTool(call, new AbortController().signal),
    ]);
    assert.equal(both[0]?.status, 200);
    assert.equal(both[1]?.status, 200);
    assert.equal(await readFile(file, "utf8"), "prefix\nonce\n",
      "concurrent same operation ID must append once");
    const before = await executor.getReceipt("shared-append-01");
    assert.equal(before?.state, "completed");
    assert.equal(before?.tool_name, "write_file");

    const conflict = await executor.executeTool({
      ...call, arguments: { ...call.arguments, content: "different" },
    }, new AbortController().signal);
    assert.equal(conflict?.status, 409);
    assert.equal((conflict?.body as { error: string }).error, "conflict");
    await executor.close();
    executor = createAgentExecutionEngine({ receiptDirectory: receipts });
    const repeated = await executor.executeTool(call, new AbortController().signal);
    assert.equal(repeated?.status, 200);
    assert.equal(await readFile(file, "utf8"), "prefix\nonce\n",
      "durable receipt must suppress replay after restart");
    assert.equal((await executor.getReceipt("shared-append-01"))?.state, "completed");
  } finally {
    await executor.close();
    await rm(root, { recursive: true, force: true });
  }
});

test("v1 HTTP is an authenticated adapter to the same mutation and receipt executor", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "rc-http-execution-"));
  const file = path.join(root, "data.txt");
  const receipts = path.join(root, "receipts");
  const agent = await startAgent({ deviceToken: "fixture-device-token", receiptDirectory: receipts });
  try {
    await writeFile(file, "initial\n", "utf8");
    const call = { tool: "write_file", operation_id: "http-operation-01", arguments: {
      path: file, mode: "append", content: "only-once\n",
    } };
    const request = async (credential: boolean, body: object) => {
      const response = await fetch(agent.baseUrl + "/internal/call", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          ...(credential ? { "x-device-credential": "fixture-device-token" } : {}),
        },
        body: JSON.stringify(body),
      });
      return { status: response.status, body: await response.json() as Record<string, unknown> };
    };
    assert.equal((await request(false, call)).status, 401);
    assert.equal(await readFile(file, "utf8"), "initial\n");
    const first = await request(true, call);
    assert.equal(first.status, 200);
    assert.equal(first.body.status, "completed");
    assert.equal((await request(true, call)).status, 200);
    assert.equal(await readFile(file, "utf8"), "initial\nonly-once\n");
    const conflicting = await request(true, { ...call,
      arguments: { ...call.arguments, content: "change" },
    });
    assert.equal(conflicting.status, 409);
    const receipt = await fetch(agent.baseUrl + "/internal/operations/http-operation-01", {
      headers: { "x-device-credential": "fixture-device-token" },
    });
    assert.equal(receipt.status, 200);
    const record = await receipt.json() as { state: string; operation_id: string; tool_name: string };
    assert.deepEqual([record.operation_id, record.tool_name, record.state],
      ["http-operation-01", "write_file", "completed"]);
  } finally {
    await agent.close();
    await rm(root, { recursive: true, force: true });
  }
});

test("trusted executor shares Shell/session validation but does not bypass operation receipts", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "rc-shell-seam-"));
  const engine = createAgentExecutionEngine({ receiptDirectory: path.join(root, "receipts") });
  try {
    const signal = new AbortController().signal;
    const missingId = await engine.executeTool({
      tool: "start_process", arguments: { command: "printf safe-output" },
    }, signal);
    assert.equal(missingId?.status, 400);
    const valid = await engine.executeTool({ tool: "list_sessions", arguments: {} }, signal);
    assert.equal(valid?.status, 200);
    const invalid = await engine.executeTool({
      tool: "force_terminate", operation_id: "session-test", arguments: { session_id: "not-a-uuid" },
    }, signal);
    assert.equal(invalid?.status, 400);
    const missing = await engine.getReceipt("session-test");
    assert.equal(missing, null, "invalid session action must never receive a receipt");

    const start = await engine.executeTool({
      tool: "start_process", operation_id: "shell-action-01",
      arguments: { command: "printf shared-executor-session", timeout_ms: 1000 },
    }, signal);
    assert.equal(start?.status, 200, "trusted engine must use the existing native Shell supervisor");
    const recorded = await engine.getReceipt("shell-action-01");
    assert.equal(recorded?.tool_name, "start_process");
    assert.ok(["completed", "running", "failed", "unknown"].includes(recorded?.state ?? ""));
    const replay = await engine.executeTool({
      tool: "start_process", operation_id: "shell-action-01",
      arguments: { command: "printf shared-executor-session", timeout_ms: 1000 },
    }, signal);
    assert.equal(replay?.status, 200);
    const different = await engine.executeTool({
      tool: "start_process", operation_id: "shell-action-01",
      arguments: { command: "printf other-session", timeout_ms: 1000 },
    }, signal);
    assert.equal(different?.status, 409, "same operation ID with different Shell command must conflict");
  } finally {
    await engine.close();
    await rm(root, { recursive: true, force: true });
  }
});
