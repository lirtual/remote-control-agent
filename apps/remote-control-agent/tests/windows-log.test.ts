import assert from "node:assert/strict";
import { mkdtempSync, rmSync, readFileSync, writeFileSync, symlinkSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { recordWindowsEvent, readWindowsEvents } from "../src/windows-log.ts";
import { parseWindowsAgentArgs } from "../src/windows-v2.ts";

test("Windows logs stay private, bounded and contain only fixed events", () => {
  const folder = mkdtempSync(path.join(os.tmpdir(), "rca-log-test-"));
  try {
    assert.match(readWindowsEvents(folder), /No local Windows Agent events/);
    recordWindowsEvent(folder, "starting");
    recordWindowsEvent(folder, "connected");
    const result = readWindowsEvents(folder);
    assert.match(result, /"event":"starting"/);
    assert.match(result, /"event":"connected"/);
    assert.doesNotMatch(result, /endpoint|pem|device_id|pairing_code/);
    assert.equal(parseWindowsAgentArgs(["logs"]).action, "logs");
    assert.throws(() => parseWindowsAgentArgs(["logs", "--endpoint", "https://example.org/"]));
    // An edited local log cannot be used to trick rca logs into echoing secrets.
    writeFileSync(path.join(folder, "agent-events.ndjson"),
      '{"utc":"2026-01-01T00:00:00Z","event":"connected","secret":"PRIVATE"}\n');
    assert.doesNotMatch(readWindowsEvents(folder), /PRIVATE/);
    for (let i = 0; i < 20000; i++) recordWindowsEvent(folder, "connected");
    assert.ok(readFileSync(path.join(folder, "agent-events.ndjson")).length < 300000);
    assert.ok(readWindowsEvents(folder).split("\n").length <= 82);
  } finally {
    rmSync(folder, { recursive: true, force: true });
  }
});
