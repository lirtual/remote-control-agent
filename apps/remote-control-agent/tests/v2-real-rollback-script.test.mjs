import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";
import test from "node:test";

const script=path.resolve(path.dirname(fileURLToPath(import.meta.url)),
  "../scripts/check-v2-real-rollback.sh");

test("#77 operator rollback script has valid bash syntax",()=>{
  const result=spawnSync("bash",["-n",script],{encoding:"utf8"});
  assert.equal(result.status,0,result.stderr);
});

test("#77 operator rollback script refuses any non-target WSL distro before operations",()=>{
  const result=spawnSync("bash",[script],{
    encoding:"utf8",
    env:{...process.env,WSL_DISTRO_NAME:"rc-v011-lab"},
  });
  assert.notEqual(result.status,0);
  assert.match(result.stderr,/RC77_BLOCKED: Wrong WSL distribution/);
});

test("#77 operator rollback script refuses an unknown WSL distro before operations",()=>{
  const env={...process.env};
  delete env.WSL_DISTRO_NAME;
  const result=spawnSync("bash",[script],{encoding:"utf8",env});
  assert.notEqual(result.status,0);
  assert.match(result.stderr,/RC77_BLOCKED: Wrong WSL distribution/);
});
