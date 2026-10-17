import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { startAgent } from "../src/server.ts";
import { createLoopbackTransport } from "../src/loopback-transport.ts";

test("local transport uses existing Agent validation, operation receipts and loopback auth", async () => {
  const home = await mkdtemp(path.join(tmpdir(), "remote-v2-adapter-"));
  const agent = await startAgent({ deviceToken: "local-only-credential", receiptDirectory: path.join(home, "receipts") });
  try {
    const filename = path.join(home, "fixture.txt");
    await writeFile(filename, "v2-adapter-sentinel", "utf8");
    const adapter = createLoopbackTransport(agent.baseUrl, "local-only-credential");
    const read = await adapter.execute("read_file", { path: filename });
    assert.equal(read.status, 200);
    assert.match(JSON.stringify(read.body), /v2-adapter-sentinel/);
    const id = "v2-adapter-write-once";
    const write = await adapter.execute("write_file", { path: filename, content: "changed", mode: "rewrite" }, id);
    assert.equal(write.status, 200);
    const status = await adapter.operationStatus(id);
    assert.equal(status.status, 200);
    assert.equal((status.body as { state?: string }).state, "completed");
    assert.equal(await readFile(filename, "utf8"), "changed");
    const replay = await adapter.execute("write_file", { path: filename, content: "changed", mode: "rewrite" }, id);
    assert.equal(replay.status, 200);
    assert.equal(await readFile(filename, "utf8"), "changed");
    const wrong = createLoopbackTransport(agent.baseUrl, "wrong");
    assert.equal((await wrong.execute("read_file", { path: filename })).status, 401);
  } finally {
    await agent.close();
    await rm(home, { recursive: true, force: true });
  }
});

test("local transport rejects non-loopback destinations, bad IDs and oversized payloads", async () => {
  for (const address of ["https://example.com:1000", "http://localhost:1000", "http://10.0.0.1:1000", "http://127.0.0.1:1000/private", "http://u:p@127.0.0.1:1000"]) {
    assert.throws(() => createLoopbackTransport(address, "credential"), /loopback/);
  }
  assert.throws(() => createLoopbackTransport("http://127.0.0.1:8888/", ""), /credential/);
  const adapter = createLoopbackTransport("http://127.0.0.1:8888/", "credential");
  assert.throws(() => adapter.operationStatus("../secret"), /identifier/);
  await assert.rejects(adapter.execute("read_file", { path: "a".repeat(70000) }), /size/);
});
