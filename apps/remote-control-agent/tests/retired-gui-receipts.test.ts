import assert from "node:assert/strict";
import test from "node:test";
import { DatabaseSync } from "node:sqlite";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createAgentExecutionEngine } from "../src/execution.ts";
import { operationDigest, ReceiptStore } from "../src/operations.ts";

test("legacy GUI/upgrade/ordinary JSON receipts migrate read-only and survive SQLite restart", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "rca-retired-receipts-"));
  const now = new Date().toISOString();
  const historic = [
    ["old-browser", "browser_start", "unknown"],
    ["old-computer", "computer_stop", "admitted"],
    ["old-upgrade", "upgrade_agent", "completed"],
    ["old-write", "write_file", "completed"],
  ] as const;
  const records = historic.map(([operation_id, tool_name, state]) => ({
    operation_id, tool_name, state, argument_digest: operationDigest(tool_name, {}),
    created_at: now, updated_at: now,
  }));
  await writeFile(path.join(dir, "operation-receipts.json"),
    JSON.stringify({ version: 1, receipts: records }), { mode: 0o600 });
  try {
    for (const pass of [1, 2]) {
      const engine = createAgentExecutionEngine({receiptDirectory: dir});
      try {
        for (const [id, name, state] of historic) {
          const found = await engine.getReceipt(id);
          assert.equal(found?.tool_name, name, id);
          assert.equal(found?.state, state === "admitted" ? "unknown" : state, id);
        }
        const refusedId = "new-browser-" + pass;
        const refused = await engine.executeTool({
          tool: "browser_start", arguments: {}, operation_id: refusedId,
        }, new AbortController().signal);
        assert.equal(refused?.status, 400);
        assert.equal(await engine.getReceipt(refusedId), null);
      } finally { await engine.close(); }
    }
    const source = await readFile(path.join(dir, "operation-receipts.json"), "utf8");
    assert.deepEqual(JSON.parse(source).receipts, records, "legacy source must remain untouched");
    const store = new ReceiptStore(dir);
    await store.open();
    try {
      for (const tool of ["browser_start", "browser_click", "computer_stop"] as const) {
        await assert.rejects(store.admit("disallowed-"+tool, tool, operationDigest(tool, {})),
          /Retired GUI/);
        assert.equal(await store.get("disallowed-"+tool), null);
      }
      assert.equal((await store.get("old-browser"))?.state, "unknown");
    } finally { await store.close(); }
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test("previous SQLite GUI operation remains readable after opening a simplified Agent", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "rca-retired-sqlite-"));
  const store = new ReceiptStore(dir);
  try {
    await store.open();
    await store.close();
    const db = new DatabaseSync(path.join(dir,"operation-receipts.sqlite"));
    try {
      const now = new Date().toISOString();
      db.prepare("INSERT INTO receipts (operation_id,tool_name,argument_digest,state,created_at,updated_at,guarded) VALUES (?,?,?,?,?,?,?)")
        .run("old-sqlite-gui", "browser_navigate", operationDigest("browser_navigate",{}), "unknown", now, now, 1);
    } finally { db.close(); }
    const agent = createAgentExecutionEngine({receiptDirectory: dir});
    try {
      assert.equal((await agent.getReceipt("old-sqlite-gui"))?.state, "unknown");
      assert.equal((await agent.getReceipt("old-sqlite-gui"))?.tool_name, "browser_navigate");
    } finally {await agent.close();}
  } finally { await rm(dir,{recursive:true,force:true}); }
});
