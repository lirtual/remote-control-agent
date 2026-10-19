import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { writeFileSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

// Only disposable GitHub-hosted Windows CI: never create/remove an actual user identity.
test("Windows native store starts with a protected current-user ACL", { skip:
  process.platform !== "win32" || process.env.GITHUB_ACTIONS !== "true" }, () => {
  const root = path.win32.join(process.env.LOCALAPPDATA, "mcp-workers", "remote-control");
  const script = path.win32.join(path.dirname(fileURLToPath(import.meta.url)),
    "..", "scripts", "windows-private-store.ps1");
  const ps = path.win32.join(process.env.SystemRoot, "System32",
    "WindowsPowerShell", "v1.0", "powershell.exe");
  function run(action, target, fileName) {
    return spawnSync(ps, ["-NoProfile", "-NonInteractive", "-ExecutionPolicy",
      "Bypass", "-File", script, "-Action", action, "-Directory", target,
      ...(fileName ? ["-FileName", fileName] : [])],
      { encoding: "utf8", windowsHide: true, timeout: 15_000 });
  }
  const init = run("Init", root);
  if (init.status !== 0) {
    // CI fixture only. No identity key, URL, user token or store contents.
    const diagnostic = String(init.stderr || "").slice(0, 1600);
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
});
