import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readdirSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { parseArgs, machOMachine } from "../scripts/build-v2-release.mjs";

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
