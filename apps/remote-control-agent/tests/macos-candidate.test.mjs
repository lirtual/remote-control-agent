import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdtempSync, readdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { parseArgs, machOMachine } from "../scripts/build-v2-release.mjs";
import { parseTemporaryMacArgs, privateDirectory, privateFileIfPresent } from "../src/macos-temporary.ts";

const sha = "a".repeat(64);
test("#658 unpublished Darwin ARM64 candidate accepts only a pinned native Node without Linux helper", () => {
  assert.deepEqual(parseArgs(["--version","v0.0.0-ci","--target","darwin-arm64",
    "--node-bin","/tmp/native-node","--node-sha256",sha,"--out","/tmp/bundle"]), {
    version:"v0.0.0-ci",target:"darwin-arm64",nodeBin:"/tmp/native-node",
    nodeSha256:sha,out:"/tmp/bundle",
  });
  assert.throws(() => parseArgs(["--version","v0.0.0-ci","--target","darwin-x64",
    "--node-bin","/tmp/node","--node-sha256",sha,"--out","/tmp/bundle"]), /supported target/);
  assert.throws(() => parseArgs(["--version","v0.0.0-ci","--target","darwin-arm64",
    "--node-bin","/tmp/node","--native","/tmp/linux-supervisor","--node-sha256",sha,
    "--native-sha256",sha,"--out","/tmp/bundle"]));
});
test("#658 native Mach-O validation rejects ELF, non-native CPU and malformed fat headers", () => {
  const arm64 = Buffer.alloc(64);
  arm64.writeUInt32LE(0xfeedfacf,0);
  arm64.writeUInt32LE(0x0100000c,4);
  arm64.writeUInt32LE(2,12);
  assert.equal(machOMachine(arm64), "arm64");
  const intel = Buffer.from(arm64);
  intel.writeUInt32LE(0x01000007,4);
  assert.equal(machOMachine(intel), "x64");
  assert.throws(() => machOMachine(Buffer.from("ELF")));
  assert.throws(() => machOMachine(Buffer.alloc(64)));
  assert.throws(() => machOMachine(Buffer.from([0xca,0xfe,0xba,0xbe,...Buffer.alloc(60)])));
});
test("#658 macOS onboarding rejects Linux before creating identities or receipts", () => {
  if (process.platform !== "linux") return;
  const home = mkdtempSync(path.join(os.tmpdir(),"rca658-"));
  try {
    const result = spawnSync(process.execPath,["--experimental-strip-types",
      "src/macos-temporary.ts","--endpoint","https://rca.example.test/"],
      {cwd:path.resolve(path.dirname(fileURLToPath(import.meta.url)),".."),env:{...process.env,HOME:home},
      encoding:"utf8",timeout:5000});
    assert.notEqual(result.status,0);
    assert.match(result.stderr, /macOS 15\+ ARM64/);
    assert.deepEqual(readdirSync(home),[]);
  } finally {rmSync(home,{recursive:true,force:true});}
});

test("#658 native entrypoint honors realpath alias (/var -> /private/var) rather than silently exiting", () => {
  if (process.platform !== "linux") return;
  const home = mkdtempSync(path.join(os.tmpdir(),"rca658-alias-"));
  try {
    const actual=path.resolve(path.dirname(fileURLToPath(import.meta.url)),"../src/macos-temporary.ts");
    const alias=path.join(home,"symlink-alias.ts");
    symlinkSync(actual,alias);
    const result=spawnSync(process.execPath,["--experimental-strip-types",alias,
      "--endpoint","https://rca.example.test/"],{
      env:{...process.env,HOME:home},encoding:"utf8",timeout:5000,
    });
    assert.equal(result.status,1,"entrypoint must run and reject unsupported host, never silently exit 0");
    assert.match(result.stderr,/macOS 15\+ ARM64/);
    assert.deepEqual(readdirSync(home),["symlink-alias.ts"]);
  } finally {rmSync(home,{recursive:true,force:true});}
});

test("#658 explicit temporary retry uses existing identity and never silently resumes or rotates", () => {
  const endpoint = ["--endpoint","https://rca.example.test/"];
  assert.deepEqual(parseTemporaryMacArgs(endpoint), {
    endpoint:"https://rca.example.test/", name:undefined, resume:false, retryPairing:false,
  });
  assert.equal(parseTemporaryMacArgs([...endpoint,"--retry-pairing"]).retryPairing,true);
  assert.equal(parseTemporaryMacArgs([...endpoint,"--resume"]).resume,true);
  for (const flags of [
    ["--retry-pairing","--resume"],["--resume","--retry-pairing"],
    ["--retry-pairing","--retry-pairing"],["--resume","--resume"],
  ]) assert.throws(()=>parseTemporaryMacArgs([...endpoint,...flags]), /Invalid macOS temporary/);
  for (const invalid of [
    "http://rca.example.test/","https://user:password@rca.example.test/",
    "https://rca.example.test/other","https://rca.example.test/?token=secret",
  ]) assert.throws(()=>parseTemporaryMacArgs(["--endpoint",invalid]),/trusted HTTPS/);
});

test("#658 private identity and SQLite receipt paths fail closed on insecure permissions or symlinks", async () => {
  if (typeof process.getuid !== "function") return;
  const home=mkdtempSync(path.join(os.tmpdir(),"rca658-private-"));
  try {
    const parts=[".local","state","mcp-workers","remote-control-agent"];
    const directory=await privateDirectory(home,parts);
    const key=path.join(directory,"id.pem");
    assert.equal(await privateFileIfPresent(key),false);
    writeFileSync(key,"synthetic key",{mode:0o600});
    assert.equal(await privateFileIfPresent(key),true);
    chmodSync(key,0o644);
    await assert.rejects(privateFileIfPresent(key),/Unsafe macOS key/);
    chmodSync(key,0o600);
    const alias=path.join(directory,"alias.pem");
    symlinkSync(key,alias);
    await assert.rejects(privateFileIfPresent(alias),/Unsafe macOS key/);
    const sqlite=path.join(directory,"receipts.sqlite");
    writeFileSync(sqlite,"synthetic sqlite fixture",{mode:0o600});
    chmodSync(sqlite,0o644);
    await assert.rejects(privateFileIfPresent(sqlite),/Unsafe macOS key/);
    chmodSync(path.join(home,".local","state","mcp-workers"),0o755);
    await assert.rejects(privateDirectory(home,parts),/Unsafe macOS identity or receipt directory/);
    chmodSync(path.join(home,".local","state","mcp-workers"),0o700);
    chmodSync(path.join(home,".local"),0o777);
    await assert.rejects(privateDirectory(home,parts),/Unsafe macOS identity or receipt directory/);
  } finally {rmSync(home,{recursive:true,force:true});}
});
