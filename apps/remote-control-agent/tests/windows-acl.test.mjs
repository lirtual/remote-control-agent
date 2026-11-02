import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { writeFileSync, rmSync, readFileSync, existsSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { replaceSignedDeviceId } from "../src/windows-identity-repair.ts";

// Only disposable GitHub-hosted Windows CI: never create/remove an actual user identity.
test("Windows native store starts with a protected current-user ACL", { skip:
  process.platform !== "win32" || process.env.GITHUB_ACTIONS !== "true" }, async () => {
  const root = path.win32.join(process.env.LOCALAPPDATA, "mcp-workers", "remote-control");
  const script = path.win32.join(path.dirname(fileURLToPath(import.meta.url)),
    "..", "scripts", "windows-private-store.ps1");
  const ps = path.win32.join(process.env.SystemRoot, "System32",
    "WindowsPowerShell", "v1.0", "powershell.exe");
  function run(action, target, fileName) {
    return spawnSync(ps, ["-NoProfile", "-NonInteractive", "-ExecutionPolicy",
      "Bypass", "-File", script, "-Action", action, "-Directory", target,
      ...(fileName ? ["-FileName", fileName] : [])],
      { encoding: "utf8", windowsHide: true, timeout: 30_000 });
  }
  const init = run("Init", root);
  if (init.status !== 0) {
    // CI fixture only. No identity key, URL, user token or store contents.
    const diagnostic = [String(init.stderr || "").slice(0, 1600), init.error?.code ?? "", init.signal ?? ""].filter(Boolean).join(" ");
    assert.fail("Current-user ACL initialized: " + diagnostic);
  }
  assert.equal(run("Check", root).status, 0, "ACL recheck");
  assert.notEqual(run("Check", path.win32.join(os.tmpdir(), "wrong")).status, 0,
    "Outside-Locals AppData targets must be rejected");

  const key = path.win32.join(root, "v2-identity.pem");
  // A synthetic marker, not a real key, is enough to prove inherited private ACL.
  writeFileSync(key, "TEST_ONLY_NO_PRIVATE_KEY", { flag: "wx" });
  try {
    const sealed = run("Seal", root, "v2-identity.pem");
    assert.equal(sealed.status, 0, "Fresh identity file sealed: " + String(sealed.stderr || "").slice(0, 900));
    assert.equal(run("Check", root).status, 0, "Sealed new identity file has private ACL");
    assert.notEqual(run("Seal", root, "other.pem").status, 0, "Other files cannot be sealed");
  } finally {
    rmSync(key);
  }

  // Owner Stop persists as an independent current-user-only marker, never an
  // activation-pending marker; its ACL must be enforced by the real OS helper.
  const stopped = path.win32.join(root,"v2-identity.pem.owner-stopped");
  writeFileSync(stopped,"stopped\n",{flag:"wx"});
  try {
    assert.equal(run("Seal",root,"v2-identity.pem.owner-stopped").status,0,
      "Owner STOP marker must inherit protected native Windows ACL");
    assert.equal(run("Check",root).status,0,"Owner STOP remains private across normal service checks");
    assert.equal(readFileSync(stopped,"utf8"),"stopped\n");
    assert.notEqual(run("Seal",root,"foreign.owner-stopped").status,0,
      "Owner STOP helper cannot seal arbitrary files");
  } finally {
    rmSync(stopped,{force:true});
  }

  // Actual native Windows rename behavior with the same ACL helper that the
  // interactive re-pair CLI will use. No cloud traffic, identity or task.
  const oldId = "11111111-1111-4111-8111-111111111111";
  const newId = "22222222-2222-4222-8222-222222222222";
  const localId = path.win32.join(root, "v2-identity.pem.device-id");
  const pending = path.win32.join(root, "v2-identity.pem.device-id.pending");
  writeFileSync(localId, oldId + "\n", { flag: "wx" });
  try {
    assert.equal(run("Seal", root, "v2-identity.pem.device-id").status, 0);
    await replaceSignedDeviceId(path.win32.join(root, "v2-identity.pem"), oldId, newId, () => {
      assert.equal(readFileSync(localId, "utf8").trim(), oldId);
      assert.equal(existsSync(pending), true);
      const sealed = run("Seal", root, "v2-identity.pem.device-id.pending");
      assert.equal(sealed.status, 0,
        "Staged ID ACL seal failed: " + String(sealed.stderr || "").slice(0, 400));
    });
    assert.equal(readFileSync(localId, "utf8").trim(), newId);
    assert.equal(existsSync(pending), false);
    assert.equal(run("Check", root).status, 0, "Replaced ID must retain verified private ACL");
    await assert.rejects(replaceSignedDeviceId(path.win32.join(root, "v2-identity.pem"),
      newId, oldId, () => { throw Error("simulated seal failure"); }), /simulated seal failure/);
    assert.equal(readFileSync(localId, "utf8").trim(), newId);
    assert.equal(existsSync(pending), false);
  } finally {
    rmSync(localId, { force: true });
    rmSync(pending, { force: true });
  }
});
