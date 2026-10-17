import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { executeReadTool } from "../src/read-execution.ts";
import { SearchSessions } from "../src/search.ts";
import { startAgent } from "../src/server.ts";

test("trusted in-process read executor and v1 authenticated HTTP return identical read results", async () => {
  const folder = await mkdtemp(path.join(os.tmpdir(), "rc-exec-seam-"));
  const file = path.join(folder, "read-fixture.txt");
  const searches = new SearchSessions();
  let agent: Awaited<ReturnType<typeof startAgent>> | undefined;
  try {
    await writeFile(file, "line-one\nline-two\n", "utf8");
    const args = { path: file, offset: 0, length: 2 };
    const direct = await executeReadTool("read_file", args, searches, new AbortController().signal);
    assert.deepEqual(direct, {
      kind: "completed", event: "read_completed", text: "line-one\nline-two",
    });

    agent = await startAgent({ deviceToken: "isolated-test-token" });
    const send = async (credential: string | undefined, tool: string, argumentsValue: object) => {
      const headers: Record<string, string> = { "content-type": "application/json" };
      if (credential) headers["x-device-credential"] = credential;
      const r = await fetch(agent!.baseUrl + "/internal/call", {
        method: "POST", headers, body: JSON.stringify({ tool, arguments: argumentsValue }),
      });
      return { status: r.status, result: await r.json() as Record<string, unknown> };
    };
    const authorized = await send("isolated-test-token", "read_file", args);
    assert.equal(authorized.status, 200);
    assert.deepEqual(authorized.result, {
      status: "completed", result: { content: [{ type: "text", text: direct.text }] },
    });
    const forbidden = await send(undefined, "read_file", args);
    assert.equal(forbidden.status, 401, "the transport must authenticate before invoking executor");
  } finally {
    if (agent) await agent.close();
    await searches.close();
    await rm(folder, { recursive: true, force: true });
  }
});

test("shared executor applies the same validation and cannot execute writes or Shell", async () => {
  const searches = new SearchSessions();
  try {
    const signal = new AbortController().signal;
    for (const unsafe of ["write_file", "start_process", "force_terminate", "delete_file"]) {
      const result = await executeReadTool(unsafe, { path: "/tmp/not-allowed" }, searches, signal);
      assert.deepEqual(result, { kind: "rejected", message: "The requested tool is not available." });
    }
    const forbidden = await executeReadTool("read_file",
      { path: "file:///etc/hostname" }, searches, signal);
    assert.deepEqual(forbidden, { kind: "rejected", message: "The requested tool call was rejected." });
  } finally { await searches.close(); }
});

test("shared executor supports directory and search with local session lifecycle", async () => {
  const folder = await mkdtemp(path.join(os.tmpdir(), "rc-exec-search-"));
  const nested = path.join(folder, "nested");
  const file = path.join(nested, "lookup.txt");
  const searches = new SearchSessions();
  try {
    await mkdir(nested);
    await writeFile(file, "needle-unique-content\n", "utf8");
    const signal = new AbortController().signal;
    const listing = await executeReadTool("list_directory", { path: folder, depth: 2 }, searches, signal);
    assert.equal(listing.kind, "completed");
    if (listing.kind === "completed") assert.match(listing.text, /lookup\.txt/);
    const log: string[] = [];
    const search = await executeReadTool("start_search",
      { path: folder, pattern: "lookup.txt", search_type: "filename" },
      searches, signal, () => log.push("search_started"));
    assert.deepEqual(log, ["search_started"]);
    assert.equal(search.kind, "completed");
    if (search.kind === "completed") assert.match(search.text, /lookup\.txt/);
  } finally {
    await searches.close();
    await rm(folder, { recursive: true, force: true });
  }
});
