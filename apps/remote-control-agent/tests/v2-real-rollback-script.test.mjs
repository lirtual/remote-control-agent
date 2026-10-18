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

test("#77 operator rollback receipt is recorded after cleanup; never predeclared",async()=>{
  const {readFileSync}=await import("node:fs");
  const source=readFileSync(script,"utf8");
  assert.match(source,/RC77_STATUS=STARTED/);
  assert.match(source,/RC77_STATUS=PRODUCT_ROLLBACK_PASS/);
  assert.match(source,/RC77_STATUS=EMERGENCY_RECOVERY_USED/);
  assert.match(source,/RC77_STATUS=INCOMPLETE_OR_FAILED/);
  assert.match(source,/RC77_UPGRADE_EXIT=%s/);
  assert.match(source,/test "\$product_verified" -eq 1 && test "\$emergency_used" -eq 0/);
  const cleanupAt=source.indexOf("cleanup() {");
  const successReceiptAt=source.indexOf("RC77_STATUS=PRODUCT_ROLLBACK_PASS");
  assert.ok(cleanupAt>0&&successReceiptAt>cleanupAt);
  assert.match(source,/test -n "\$\(systemctl --user show "\$svc" -p DropInPaths --value\)"/);
  assert.match(source,/test ! -e "\$verdict" \|\| die/);
});
