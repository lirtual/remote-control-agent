import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { beginDeviceEnrollment } from "../src/pair-device.ts";

test("pending-only installer posts public material and displays only a short code", async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), "remote-v2-local-pair-"));
  const file = path.join(home, "state", "device.pem");
  let calls = 0;
  try {
    const result = await beginDeviceEnrollment(
      "home",
      "https://example.test/",
      file,
      async (url, init) => {
        calls++;
        assert.equal(String(url), "https://example.test/agent/pair/start");
        assert.equal(init?.method, "POST");
        assert.equal(init?.redirect, "error");
        const request = JSON.parse(String(init?.body)) as Record<string, unknown>;
        assert.equal(request.name, "home");
        assert.equal(typeof request.public_key, "string");
        assert.match(String(request.code_verifier), /^[a-f0-9]{64}$/);
        assert.equal(typeof request.proof, "string");
        assert.equal(JSON.stringify(request).includes("PRIVATE KEY"), false);
        return new Response(JSON.stringify({ status: "pending" }), { status: 202 });
      },
    );
    assert.equal(calls, 1);
    assert.match(result.code, /^[A-Z2-7]{10}$/);
    assert.equal(result.keyPath, file);
    assert.ok(result.expiresAt > Date.now());
    assert.equal((await stat(file)).mode & 0o777, 0o600);
    assert.match(await readFile(file, "utf8"), /PRIVATE KEY/);
    await assert.rejects(beginDeviceEnrollment("new", "https://example.test/", file, async () => {
      throw new Error("Existing key should reject before network.");
    }), { code: "EEXIST" });
    assert.equal(calls, 1);
  } finally { await rm(home, { recursive: true, force: true }); }
});

test("pending-only installer fails closed, cleans newly-created key after non-202 or network loss", async () => {
  for (const result of [new Response("unavailable", { status: 503 }), new Response(null, { status: 302 })]) {
    const home = await mkdtemp(path.join(os.tmpdir(), "remote-v2-failed-pair-"));
    const key = path.join(home, "id.pem");
    try {
      await assert.rejects(beginDeviceEnrollment("cloud", "https://example.test/", key, async () => result), /could not be completed/);
      await assert.rejects(stat(key), { code: "ENOENT" });
    } finally { await rm(home, { recursive: true, force: true }); }
  }
});

test("pending-only installer rejects arbitrary HTTP/URL credentials before key creation", async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), "remote-v2-url-pair-"));
  try {
    for (const endpoint of [
      "http://example.test/",
      "https://user:pass@example.test/",
      "https://example.test/?token=secret",
      "https://example.test/other",
      "http://127.0.0.2:8787/",
    ]) {
      await assert.rejects(beginDeviceEnrollment("lab", endpoint, path.join(home, "private.pem")), /HTTPS endpoint/);
    }
    await assert.rejects(stat(path.join(home, "private.pem")), { code: "ENOENT" });
  } finally { await rm(home, { recursive: true, force: true }); }
});
