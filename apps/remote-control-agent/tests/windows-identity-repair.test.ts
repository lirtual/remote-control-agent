import assert from "node:assert/strict";
import { test } from "node:test";
import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { readFileSync, existsSync } from "node:fs";
import path from "node:path";
import os from "node:os";
import { replaceSignedDeviceId, repairWindowsIdentity } from "../src/windows-identity-repair.ts";
import { DeviceSessionRejectedError } from "../src/v2-session-client.ts";

const OLD = "11111111-1111-4111-8111-111111111111";
const NEW = "22222222-2222-4222-8222-222222222222";
const ENDPOINT = "https://rca.example.test/";

async function fixture(run: (keyPath: string) => Promise<void>) {
  const dir = await mkdtemp(path.join(os.tmpdir(), "rca-repair-"));
  const file = path.join(dir, "v2-identity.pem");
  const pem = generateKeyPairSync("ed25519").privateKey.export({
    type: "pkcs8", format: "pem",
  }).toString();
  await writeFile(file, pem, { mode: 0o600 });
  await writeFile(file + ".device-id", OLD + "\n", { mode: 0o600 });
  try { await run(file); }
  finally { await rm(dir, { recursive: true, force: true }); }
}

test("signed same-key approval with original ID is a no-op, never creates pending grant", async () => {
  await fixture(async file => {
    let calls = 0, sealed = 0, pending = 0;
    const result = await repairWindowsIdentity({
      endpoint: ENDPOINT, keyPath: file, currentId: OLD, name: "WIN-TEST",
      seal: () => { sealed++; },
      onPending: () => { pending++; },
      verify: async () => OLD,
      send: async () => { calls++; throw Error("Unexpected enrollment"); },
    });
    assert.equal(result, "unchanged");
    assert.deepEqual([calls, sealed, pending], [0, 0, 0]);
    assert.equal((await readFile(file + ".device-id", "utf8")).trim(), OLD);
  });
});

test("different signed approval is recovered without creating duplicate registration", async () => {
  await fixture(async file => {
    let sealed = 0;
    const result = await repairWindowsIdentity({
      endpoint: ENDPOINT, keyPath: file, currentId: OLD, name: "WIN-TEST",
      seal: () => {
        sealed++;
        assert.equal(existsSync(file + ".device-id.pending"), true);
        assert.equal(readFileSync(file + ".device-id", "utf8").trim(), OLD);
        assert.equal(readFileSync(file + ".device-id.pending", "utf8").trim(), NEW);
      },
      onPending: () => { throw Error("Unexpected pairing code"); },
      verify: async () => NEW,
      send: async () => { throw Error("Unexpected enrollment"); },
    });
    assert.equal(result, "restored");
    assert.equal(sealed, 1);
    assert.equal((await readFile(file + ".device-id", "utf8")).trim(), NEW);
  });
});

test("404 grants may request pending approval, but only signed verification writes a new ID", async () => {
  await fixture(async file => {
    let calls = 0, pending = 0, sealed = 0;
    const result = await repairWindowsIdentity({
      endpoint: ENDPOINT, keyPath: file, currentId: OLD, name: "WIN-TEST",
      seal: () => { sealed++; },
      onPending: (code, fingerprint) => {
        pending++;
        assert.match(code, /^[A-Z2-7]{10}$/);
        assert.match(fingerprint, /^[a-f0-9]{24}$/);
      },
      verify: async () => {
        calls++;
        if (calls === 1) throw new DeviceSessionRejectedError("not found", 404);
        assert.equal((await readFile(file + ".device-id", "utf8")).trim(), OLD);
        return NEW;
      },
      send: async (_url, init) => {
        assert.equal(init?.method, "POST");
        assert.match(String(init?.body), /single-code-v1/);
        return new Response(null, { status: 202 });
      },
      sleep: async () => {},
    });
    assert.equal(result, "restored");
    assert.equal(pending, 1);
    assert.equal(sealed, 1);
    assert.equal((await readFile(file + ".device-id", "utf8")).trim(), NEW);
  });
});

test("403 and transient errors must not create a pending approval or change local ID", async () => {
  for (const failure of [new DeviceSessionRejectedError("forbidden", 403), new Error("network")]) {
    await fixture(async file => {
      await assert.rejects(repairWindowsIdentity({
        endpoint: ENDPOINT, keyPath: file, currentId: OLD, name: "WIN-TEST",
        seal: () => { throw Error("must not seal"); },
        onPending: () => { throw Error("must not prompt"); },
        verify: async () => { throw failure; },
        send: async () => { throw Error("must not enroll"); },
      }), error => error === failure);
      assert.equal((await readFile(file + ".device-id", "utf8")).trim(), OLD);
    });
  }
});

test("pending enrollment refusal retains old ID, no owner approval is fabricated", async () => {
  await fixture(async file => {
    await assert.rejects(repairWindowsIdentity({
      endpoint: ENDPOINT, keyPath: file, currentId: OLD, name: "WIN-TEST",
      seal: () => { throw Error("must not seal"); },
      onPending: () => { throw Error("must not prompt"); },
      verify: async () => { throw new DeviceSessionRejectedError("not found", 404); },
      send: async () => new Response(null, { status: 409 }),
    }), /not accepted/);
    assert.equal((await readFile(file + ".device-id", "utf8")).trim(), OLD);
  });
});

test("local ID mismatch refuses replacement even with a different signed ID", async () => {
  await fixture(async file => {
    await writeFile(file + ".device-id", NEW + "\n");
    await assert.rejects(replaceSignedDeviceId(file, OLD, NEW,
      () => { throw Error("must not seal"); }), /changed/);
    assert.equal((await readFile(file + ".device-id", "utf8")).trim(), NEW);
  });
});

test("ACL seal rejection retains original device ID and removes staging file", async () => {
  await fixture(async file => {
    await assert.rejects(replaceSignedDeviceId(file, OLD, NEW, () => {
      assert.equal(readFileSync(file + ".device-id", "utf8").trim(), OLD);
      assert.equal(existsSync(file + ".device-id.pending"), true);
      throw Error("ACL seal rejected");
    }), /ACL seal rejected/);
    assert.equal((await readFile(file + ".device-id", "utf8")).trim(), OLD);
    assert.equal(existsSync(file + ".device-id.pending"), false);
  });
});

test("pre-existing pending file blocks concurrent identity repair without altering either file", async () => {
  await fixture(async file => {
    await writeFile(file + ".device-id.pending", NEW + "\n");
    await assert.rejects(replaceSignedDeviceId(file, OLD, NEW, () => {
      throw Error("must not seal an existing staged ID");
    }), /EEXIST/);
    assert.equal((await readFile(file + ".device-id", "utf8")).trim(), OLD);
    assert.equal((await readFile(file + ".device-id.pending", "utf8")).trim(), NEW);
  });
});

test("pending approval timeout never overwrites existing device ID", async () => {
  await fixture(async file => {
    let pending = 0;
    await assert.rejects(repairWindowsIdentity({
      endpoint: ENDPOINT, keyPath: file, currentId: OLD, name: "WIN-TEST",
      seal: () => { throw Error("no approved ID to seal"); },
      onPending: () => { pending++; },
      verify: async () => { throw new DeviceSessionRejectedError("not found", 404); },
      send: async () => new Response(null, { status: 202 }),
      timeoutMs: 0,
    }), /approval not confirmed/);
    assert.equal(pending, 1);
    assert.equal((await readFile(file + ".device-id", "utf8")).trim(), OLD);
    assert.equal(existsSync(file + ".device-id.pending"), false);
  });
});

test("429 or 503 response to pending registration never changes device ID", async () => {
  for (const status of [429, 503]) {
    await fixture(async file => {
      await assert.rejects(repairWindowsIdentity({
        endpoint: ENDPOINT, keyPath: file, currentId: OLD, name: "WIN-TEST",
        seal: () => { throw Error("must not seal"); },
        onPending: () => { throw Error("must not announce approval"); },
        verify: async () => { throw new DeviceSessionRejectedError("not found", 404); },
        send: async () => new Response(null, { status }),
      }), /not accepted/);
      assert.equal((await readFile(file + ".device-id", "utf8")).trim(), OLD);
    });
  }
});
