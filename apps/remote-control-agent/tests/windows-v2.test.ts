import assert from "node:assert/strict";
import { test } from "node:test";
import { isPermittedLocalPath, parseLocalRead, parseListDirectory } from "../src/local-read.ts";
import { parseWindowsAgentArgs, windowsAgentStore } from "../src/windows-v2.ts";

test("Windows drive paths accepted without relaxing URI/UNC/ADS checks", () => {
  for (const value of ["C:\\Users\\Alice\\test.txt", "D:/data/readme.txt", "c:\\"]) {
    assert.equal(isPermittedLocalPath(value, "win32"), true);
  }
  for (const value of [
    "C:relative", "\\\\server\\share\\secret", "\\\\?\\C:\\x",
    "file:///C:/secret", "https://example.com", "C:\\secret:ads",
    "/Windows/System32", "C:\\CON", "C:\\folder\\NUL.txt", "C:\\x\0y",
  ]) assert.equal(isPermittedLocalPath(value, "win32"), false, value);
  assert.equal(isPermittedLocalPath("C:\\Windows\\win.ini", "linux"), false);
  assert.equal(isPermittedLocalPath("/etc/os-release", "linux"), true);
});
test("All Windows filesystem parsers reuse the same checked path contract", () => {
  if (process.platform !== "win32") return;
  assert.deepEqual(parseLocalRead({ path: "C:\\Windows\\win.ini" }),
    { path: "C:\\Windows\\win.ini" });
  assert.deepEqual(parseListDirectory({ path: "C:\\" }),
    { path: "C:\\", depth: 1 });
  assert.equal(parseLocalRead({ path: "\\\\server\\share\\file" }), null);
  assert.equal(parseListDirectory({ path: "C:\\secret:stream" }), null);
});
test("Windows preview CLI fails closed on untrusted flags and endpoints", () => {
  assert.equal(parseWindowsAgentArgs(["status"]).action, "status");
  assert.equal(parseWindowsAgentArgs(["task-status"]).action, "task-status");
  assert.equal(parseWindowsAgentArgs(["enable", "--endpoint", "https://rca.example.test/"]).action, "enable");
  assert.equal(parseWindowsAgentArgs(["pair", "--endpoint", "https://rca.example.test/"]).action, "pair");
  assert.equal(parseWindowsAgentArgs(["upgrade", "--version", "v0.1.9"]).version, "v0.1.9");
  assert.equal(parseWindowsAgentArgs(["rollback", "--version", "v0.1.8"]).action, "rollback");
  for (const args of [
    ["pair", "--endpoint", "http://example.test/"],
    ["run", "--endpoint", "https://example.test/secret"],
    ["run", "--endpoint", "https://example.test/?token=x"],
    ["run", "--endpoint", "https://u:p@example.test/"],
    ["run", "--endpoint", "https://example.test/", "--name", "inject"],
    ["pair", "--endpoint", "https://example.test/", "--endpoint", "https://other.test/"],
    ["status", "--endpoint", "https://example.test/"],
    ["disable", "--endpoint", "https://example.test/"],
    ["enable", "--endpoint", "https://example.test/", "--name", "injected"],
    ["upgrade", "--endpoint", "https://example.test/"],
    ["upgrade", "--version", "../foo"],
    ["rollback", "--version", "v0.1.8", "--endpoint", "https://example.test/"],
    ["status", "--version", "v0.1.9"],
  ]) assert.throws(() => parseWindowsAgentArgs(args));
  assert.equal(windowsAgentStore("C:\\Users\\ray\\AppData\\Local"),
    "C:\\Users\\ray\\AppData\\Local\\mcp-workers\\remote-control");
  assert.throws(() => windowsAgentStore("\\\\server\\data"));
});
