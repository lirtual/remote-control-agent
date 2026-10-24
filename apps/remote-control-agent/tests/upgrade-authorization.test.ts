import test from "node:test";
import assert from "node:assert/strict";
import {validateUpgradeRequest} from "../src/upgrade-authorization.ts";
const device="2a83dae6-600c-49cc-b643-ab0d5ec7e0c8";
const sha="a".repeat(64),commit="b".repeat(40),asset="c".repeat(64),now=1792845000000;
const approved={version:"v0.1.23",commit,sha256:asset,platform:"windows-x64"};
const base={operation_id:"upgrade-20261024-1",device_id:device,source_version:"v0.1.22",target_version:"v0.1.23",target_commit:commit,target_sha256:asset,target_platform:"windows-x64",identity_sha256:sha,authorized_until:now+120000};
const context={deviceId:device,installedVersion:"v0.1.22",identityDigest:sha,platform:"windows-x64",now,approvedRelease:approved};
test("exact approved upgrade pins to immutable device identity release and operation",()=>{
 assert.deepEqual(validateUpgradeRequest(base,context),base);
});
test("rejects unknown fields and any arbitrary URL or alternate endpoint",()=>{
 for(const key of ["url","endpoint","command","token","path"]){
  assert.throws(()=>validateUpgradeRequest({...base,[key]:"https://bad.example/"},context),/Unrecognized/);
 }
});
test("refuses stale cross-device and changed identity permissions",()=>{
 assert.throws(()=>validateUpgradeRequest({...base,device_id:"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"},context),/device mismatch/);
 assert.throws(()=>validateUpgradeRequest({...base,identity_sha256:"d".repeat(64)},context),/identity mismatch/);
 assert.throws(()=>validateUpgradeRequest({...base,authorized_until:now-1},context),/expired/);
 assert.throws(()=>validateUpgradeRequest({...base,authorized_until:now+3600000},context),/unbounded/);
});
test("refuses downgrade same-version preview version and cross-platform",()=>{
 for(const v of ["v0.1.21","v0.1.22","v0.1.23-rc.2","v1.0.0-rc"])
  assert.throws(()=>validateUpgradeRequest({...base,target_version:v},context),/version/);
 assert.throws(()=>validateUpgradeRequest({...base,target_platform:"linux-x64-glibc"},context),/platform/);
 assert.throws(()=>validateUpgradeRequest({...base,source_version:"v0.1.20"},context),/version/);
});
test("refuses unpublished and tampered release assets",()=>{
 assert.throws(()=>validateUpgradeRequest(base,{...context,approvedRelease:null}),/not approved/);
 assert.throws(()=>validateUpgradeRequest({...base,target_commit:"d".repeat(40)},context),/not approved/);
 assert.throws(()=>validateUpgradeRequest({...base,target_sha256:"d".repeat(64)},context),/not approved/);
});
test("rejects malformed operation IDs without any external effect",()=>{
  for(const id of ["", "..", "x/y", "x\\y", "a".repeat(129)]) {
    assert.throws(()=>validateUpgradeRequest({...base,operation_id:id},context),/operation\/device mismatch/);
  }
});

test("rejects spoofed field-key separators and excessively long versions",()=>{
  const forged: Record<string, unknown>={...base};
  delete forged.target_sha256;
  delete forged.target_commit;
  forged["target_commit|target_sha256"]="not trusted";
  assert.throws(()=>validateUpgradeRequest(forged as unknown as typeof base,context),/Unrecognized/);
  assert.throws(()=>validateUpgradeRequest({...base,target_version:"v"+("9".repeat(200))+".0.0"},context),/version/);
});
