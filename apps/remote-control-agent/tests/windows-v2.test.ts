import assert from "node:assert/strict";
import { test } from "node:test";
import { isPermittedLocalPath, parseLocalRead, parseListDirectory } from "../src/local-read.ts";
import { parseWindowsAgentArgs, windowsAgentStore, startApprovedTemporaryAgent, assertSignedWindowsGrant, assertWindowsAutostartMode, resumePendingWindowsActivation } from "../src/windows-v2.ts";

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
  assert.equal(parseWindowsAgentArgs(["onboard", "--endpoint", "https://rca.example.test/"]).action, "onboard");
  assert.throws(() => parseWindowsAgentArgs(["onboard", "--endpoint", "https://rca.example.test/", "--grant", "temporary"]));
  assert.equal(parseWindowsAgentArgs(["task-status"]).action, "task-status");
  assert.equal(parseWindowsAgentArgs(["enable", "--endpoint", "https://rca.example.test/"]).action, "enable");
  assert.equal(parseWindowsAgentArgs(["pair", "--endpoint", "https://rca.example.test/"]).action, "pair");
  assert.equal(parseWindowsAgentArgs(["re-pair", "--endpoint", "https://rca.example.test/"]).action, "re-pair");
  assert.throws(() => parseWindowsAgentArgs(["re-pair", "--endpoint", "https://rca.example.test/", "--grant", "temporary"]));
  const temporaryPair = parseWindowsAgentArgs(["pair", "--endpoint", "https://rca.example.test/",
    "--name", "P13-disposable", "--grant", "temporary"]);
  assert.equal(temporaryPair.grant, "temporary");
  assert.equal(temporaryPair.name, "P13-disposable");
  assert.equal(parseWindowsAgentArgs(["pair", "--endpoint", "https://rca.example.test/"]).grant, undefined);
  assert.equal(parseWindowsAgentArgs(["upgrade", "--version", "v0.1.9"]).version, "v0.1.9");
  assert.equal(parseWindowsAgentArgs(["rollback", "--version", "v0.1.8"]).action, "rollback");
  for (const args of [
    ["pair", "--endpoint", "http://example.test/"],
    ["re-pair"],
    ["re-pair", "--endpoint", "http://example.test/"],
    ["re-pair", "--endpoint", "https://example.test/", "--version", "v0.1.0"],
    ["pair", "--endpoint", "https://example.test/", "--grant", "permanent"],
    ["pair", "--endpoint", "https://example.test/", "--grant", "temporary", "--grant", "temporary"],
    ["pair", "--endpoint", "https://example.test/", "--grant", "invalid"],
    ["run", "--endpoint", "https://example.test/", "--grant", "temporary"],
    ["enable", "--endpoint", "https://example.test/", "--grant", "temporary"],
    ["upgrade", "--version", "v0.1.9", "--grant", "temporary"],
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


test("temporary approved retry resumes only the foreground session, without re-pair or user task", async () => {
  const actions: string[][] = [];
  await startApprovedTemporaryAgent("https://rca.example.test/", async args => {
    actions.push(args);
  });
  assert.deepEqual(actions, [["run", "--endpoint", "https://rca.example.test/"]]);
});


test("Windows task enable requires the active signed grant, not only a local device-id file", async () => {
  const id = "cdc1ba24-ed48-4f2e-9191-875ce6be5af0";
  const checks: string[][] = [];
  const verifier = async (endpoint: string, keyPath: string) => {
    checks.push([endpoint, keyPath]);
    return id;
  };
  const url = "https://rca.example.test/";
  const key = "C:\\Users\\Test\\v2-identity.pem";
  assert.equal(await assertSignedWindowsGrant(url, key, id, verifier), id);
  assert.deepEqual(checks, [[url, key]]);
  await assert.rejects(assertSignedWindowsGrant(url, key,
    "00000000-0000-0000-0000-000000000000", verifier), /conflict|signed|grant/i);
  await assert.rejects(assertSignedWindowsGrant(url, key, id,
    async () => { throw new Error("owner grant revoked"); }), /revoked/);
  assert.equal(checks.length, 2, "one verifier invocation per local claim");
});


test("Windows user-logon task cannot be enabled for temporary or malformed grant modes", () => {
  assert.equal(assertWindowsAutostartMode("permanent"), true);
  assert.throws(() => assertWindowsAutostartMode(undefined), /permanent|unknown/i); // older pair also allowed temporary grants
  assert.throws(() => assertWindowsAutostartMode("temporary"), /permanent/i);
  assert.throws(() => assertWindowsAutostartMode("unknown"), /permanent/i);
});


test("Windows onboarding resumes only a marked incomplete activation", async () => {
  const calls: string[] = [];
  const task = (action: "Enable" | "Start") => { calls.push(action); };
  const cleared = async () => { calls.push("Clear"); };
  // Enable succeeded, Start failed: the task exists but is not running.
  await resumePendingWindowsActivation(true, {installed:true, running:false}, task, cleared);
  assert.deepEqual(calls, ["Start", "Clear"]);
  calls.length = 0;
  // Owner stopped a previously completed Agent: no marker, no restart.
  await resumePendingWindowsActivation(false, {installed:true, running:false}, task, cleared);
  assert.deepEqual(calls, []);
  // A terminated first registration may need both operations.
  await resumePendingWindowsActivation(true, {installed:false, running:false}, task, cleared);
  assert.deepEqual(calls, ["Enable", "Start", "Clear"]);
  calls.length = 0;
  await resumePendingWindowsActivation(true, {installed:true, running:true}, task, cleared);
  assert.deepEqual(calls, ["Clear"]);
});

test("Windows onboarding retains pending state on failed task activation", async () => {
  const calls: string[] = [];
  await assert.rejects(resumePendingWindowsActivation(true, {installed:true,running:false},
    () => { throw Error("Task Start failed"); }, async () => {calls.push("Clear");}), /Start failed/);
  assert.equal(calls.length, 0);
  await assert.rejects(resumePendingWindowsActivation(true, {installed:false,running:false},
    (action) => {calls.push(action); if(action==="Start") throw Error("Task Start failed");},
    async () => {calls.push("Clear");}), /Start failed/);
  assert.deepEqual(calls, ["Enable","Start"]);
});
