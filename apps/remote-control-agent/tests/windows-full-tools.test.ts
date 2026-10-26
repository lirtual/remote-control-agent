import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { setTimeout as delay } from "node:timers/promises";
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
      command: "Write-Output RCA_WINDOWS_OK", timeout_ms: 8_000,
    }, shellId);
    assert.equal(launched?.status, 200);
    const receipt = await engine.getReceipt(shellId);
    assert.ok(receipt?.session_id, "An Agent-owned session ID must be persisted");
    // A new native PowerShell session can be running before it has emitted stdout.
    // Read from offset zero until output arrives, the process exits, or the bounded
    // deadline expires; never treat one legitimate empty page as lost output.
    const deadline = Date.now() + 7_000;
    let page: { output: string; eof: boolean; state: string; exit_code: number | null };
    do {
      const output = await engine.executeTool({
        tool: "read_process_output",
        arguments: { session_id: receipt.session_id, offset: 0, length: 4096 },
      }, controller.signal);
      assert.equal(output?.status, 200);
      const data = (output.body as { result: { content: Array<{ text: string }> } }).result.content[0]!.text;
      page = JSON.parse(data) as typeof page;
      if (/RCA_WINDOWS_OK/.test(page.output) || page.eof) break;
      await delay(100);
    } while (Date.now() < deadline);
    assert.match(page.output, /RCA_WINDOWS_OK/,
      `PowerShell output missing (state=${page.state}, exit=${page.exit_code}, eof=${page.eof})`);

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
    assert.equal(duringRevoke?.status, 200, `Unexpected native process admission: ${JSON.stringify(duringRevoke?.body)}`);
    assert.equal((duringRevoke?.body as { status: string }).status, "running");
    assert.equal(await engine.stopOwnedForRevocation(), "confirmed");
    const deniedAfterRevoke = await invoke("start_process", {
      command: "Write-Output MUST_NOT_RUN_AFTER_REVOKE", timeout_ms: 1000,
    });
    // Revocation is a global admission barrier: no tool, including previously
    // allowed status/list reads, can disclose the revoked device's state.
    assert.equal(deniedAfterRevoke?.status, 503);
    assert.equal((deniedAfterRevoke?.body as { status: string }).status, "failed");
    const sessions = await engine.executeTool({ tool: "list_sessions", arguments: {} }, controller.signal);
    assert.equal(sessions?.status, 503);

  } finally {
    controller.abort();
    await engine.close();
    await rm(root, { recursive: true, force: true });
  }
});
