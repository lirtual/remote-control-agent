import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { createAgentExecutionEngine, defaultAgentShellPath } from "../src/execution.ts";
import { windowsManagedShellArguments } from "../src/sessions.ts";

test("native Windows full mode selects a fixed system shell without invoking cmd.exe", () => {
  assert.equal(defaultAgentShellPath("win32", "C:\\Windows"),
    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
  assert.throws(() => defaultAgentShellPath("win32", "\\\\server\\share"));
  assert.deepEqual(windowsManagedShellArguments("Write-Output RCA_TEST"),
    ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "Write-Output RCA_TEST"]);
});

test("Windows paired engine supports file effects, receipts and bounded native sessions", {
  skip: process.platform !== "win32",
  timeout: 30_000,
}, async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "rc-win-full-ci-"));
  const filePath = path.join(root, "roundtrip.txt");
  const receiptDirectory = path.join(root, "receipts");
  const engine = createAgentExecutionEngine({ receiptDirectory, sessionMaxLifetimeMs: 15_000 });
  const controller = new AbortController();
  const invoke = async (tool: string, args: unknown, id = "win-" + randomUUID()) =>
    await engine.executeTool({ tool, arguments: args, operation_id: id }, controller.signal);
  try {
    const writeId = "win-" + randomUUID();
    const written = await invoke("write_file", {
      path: filePath, content: "windows-full-ok", mode: "rewrite",
    }, writeId);
    assert.equal(written?.status, 200);
    assert.equal(await readFile(filePath, "utf8"), "windows-full-ok");
    assert.equal((await engine.getReceipt(writeId))?.state, "completed");

    const edited = await invoke("edit_block", {
      file_path: filePath, old_string: "windows", new_string: "native-windows",
    });
    assert.equal(edited?.status, 200);
    assert.equal(await readFile(filePath, "utf8"), "native-windows-full-ok");

    const shellId = "win-" + randomUUID();
    const launched = await invoke("start_process", {
      command: "Write-Output RCA_WINDOWS_OK", timeout_ms: 4_000,
    }, shellId);
    assert.equal(launched?.status, 200);
    const receipt = await engine.getReceipt(shellId);
    assert.ok(receipt?.session_id, "An Agent-owned session ID must be persisted");
    const output = await engine.executeTool({
      tool: "read_process_output",
      arguments: { session_id: receipt.session_id, offset: 0, length: 4096 },
    }, controller.signal);
    assert.equal(output?.status, 200);
    const data = (output.body as { result: { content: Array<{ text: string }> } }).result.content[0]!.text;
    const page = JSON.parse(data) as { output: string };
    assert.match(page.output, /RCA_WINDOWS_OK/);

    const sleeper = await invoke("start_process", {
      command: "Start-Sleep -Seconds 60", timeout_ms: 0,
    });
    assert.equal(sleeper?.status, 200);
    const sessionId = (sleeper?.body as { session_id?: string })?.session_id;
    assert.ok(sessionId);
    const stopped = await invoke("force_terminate", { session_id: sessionId });
    assert.equal(stopped?.status, 200);
    assert.notEqual((stopped?.body as { status: string }).status, "unknown",
      "Windows session must not claim successful termination without exit evidence");

    // Revoke while a real native command is still running; cleanup must
    // terminate Agent-owned work and prevent a new process from starting.
    const duringRevoke = await invoke("start_process", {
      command: "Start-Sleep -Seconds 60", timeout_ms: 0,
    });
    assert.equal(duringRevoke?.status, 200);
    assert.equal((duringRevoke?.body as { status: string }).status, "running");
    assert.equal(await engine.stopOwnedForRevocation(), "confirmed");
    const deniedAfterRevoke = await invoke("start_process", {
      command: "Write-Output MUST_NOT_RUN_AFTER_REVOKE", timeout_ms: 1000,
    });
    assert.equal(deniedAfterRevoke?.status, 200);
    assert.equal((deniedAfterRevoke?.body as { status: string }).status, "failed");
    const sessions = await engine.executeTool({ tool: "list_sessions", arguments: {} }, controller.signal);
    assert.equal(sessions?.status, 200);
    const visible = JSON.parse(
      (sessions.body as { result: { content: Array<{ text: string }> } }).result.content[0]!.text
    ) as Array<{ state: string }>;
    assert.ok(visible.every(s => s.state !== "running" && s.state !== "unknown"));

  } finally {
    controller.abort();
    await engine.close();
    await rm(root, { recursive: true, force: true });
  }
});
