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
  function run(action, target) {
    return spawnSync(ps, ["-NoProfile", "-NonInteractive", "-ExecutionPolicy",
      "Bypass", "-File", script, "-Action", action, "-Directory", target],
      { encoding: "utf8", windowsHide: true, timeout: 15_000 });
  }
  assert.equal(run("Init", root).status, 0, "Current-user ACL initialized");
  assert.equal(run("Check", root).status, 0, "ACL recheck");
  assert.notEqual(run("Check", path.win32.join(os.tmpdir(), "wrong")).status, 0,
    "Outside-Locals AppData targets must be rejected");

  const key = path.win32.join(root, "v2-identity.pem");
  // A synthetic marker, not a real key, is enough to prove inherited private ACL.
  writeFileSync(key, "TEST_ONLY_NO_PRIVATE_KEY", { flag: "wx" });
  try {
    assert.equal(run("Check", root).status, 0, "New identity file inherited private ACL");
  } finally {
    rmSync(key);
  }
});
