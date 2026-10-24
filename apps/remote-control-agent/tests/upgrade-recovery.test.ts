import test from "node:test";
import assert from "node:assert/strict";
import {operationDigest, type OperationReceipt} from "../src/operations.ts";
import {assessUpgradeAfterReconnect, type TrustedUpgradeEvidence} from "../src/upgrade-recovery.ts";
import type {UpgradeRequest} from "../src/upgrade-authorization.ts";

const request:UpgradeRequest = {
  operation_id:"remote-upgrade-2026-1",
  device_id:"2a83dae6-600c-49cc-b643-ab0d5ec7e0c8",
  source_version:"v0.1.22",target_version:"v0.1.23",
  target_commit:"b".repeat(40),target_sha256:"c".repeat(64),
  target_platform:"windows-x64",identity_sha256:"a".repeat(64),
  authorized_until:1792845120000,
};
const receipt:OperationReceipt={
  operation_id:request.operation_id,tool_name:"upgrade_agent",
  argument_digest:operationDigest("upgrade_agent",request),
  state:"unknown",created_at:"2026-10-24T00:00:00.000Z",
  updated_at:"2026-10-24T00:01:00.000Z",
};
const evidence:TrustedUpgradeEvidence={
  deviceId:request.device_id,identitySha256:request.identity_sha256,
  runningVersion:request.target_version,platform:request.target_platform,
  immutableReleaseCommit:request.target_commit,
  immutableReleaseAssetSha256:request.target_sha256,
  serviceActive:true,serviceExecutableVerified:true,
  durableReceiptsReadable:true,authenticatedSameDevice:true,
};
const assess=(r:OperationReceipt|null=receipt,e:TrustedUpgradeEvidence=evidence,q:UpgradeRequest=request)=>
  assessUpgradeAfterReconnect(q,r,e);
test("restarted unknown receipt becomes verifiable only with complete local evidence",()=>{
  assert.deepEqual(assess(),{kind:"verified",operationId:request.operation_id});
});
test("missing, forged, failed or cross-tool receipts cannot establish a verified upgrade",()=>{
  assert.equal(assess(null).kind,"unresolved");
  for (const altered of [
    {...receipt,operation_id:"different"},
    {...receipt,tool_name:"start_process" as const},
    {...receipt,argument_digest:"f".repeat(64)},
    {...receipt,state:"failed" as const},
    {...receipt,state:"admitted" as const},
  ]) assert.deepEqual(assess(altered),{kind:"unresolved",operationId:request.operation_id,reason:"receipt"});
});
test("prior upgrade authorization is cryptographically bound to the same exact request",()=>{
  for(const mutated of [
    {...request,target_sha256:"d".repeat(64)},
    {...request,authorized_until:request.authorized_until+1000},
    {...request,device_id:"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"},
  ])assert.equal(assess(receipt,evidence,mutated).kind,"unresolved");
});
test("running newer executable or same version alone cannot prove full upgrade",()=>{
  for (const mutation of [
    {runningVersion:"v0.1.22"},
    {immutableReleaseCommit:"d".repeat(40)},
    {immutableReleaseAssetSha256:"e".repeat(64)},
    {platform:"linux-x64-glibc"},
  ])assert.deepEqual(assess(receipt,{...evidence,...mutation}),{
    kind:"unresolved",operationId:request.operation_id,reason:"release",
  });
});
test("device identity mismatch cannot be masked by valid release or signed WSS",()=>{
  for (const mutation of [
    {identitySha256:"d".repeat(64)},
    {deviceId:"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"},
  ]) assert.deepEqual(assess(receipt,{...evidence,...mutation}),{
    kind:"unresolved",operationId:request.operation_id,reason:"identity",
  });
});
test("inactive or unverifiable OS task/service and inaccessible durable receipts stay unknown",()=>{
  for(const mutation of [
    {serviceActive:false},
    {serviceExecutableVerified:false},
    {durableReceiptsReadable:false},
  ])assert.deepEqual(assess(receipt,{...evidence,...mutation}),{
    kind:"unresolved",operationId:request.operation_id,reason:"service",
  });
});
test("same-device authenticated reconnection is mandatory before completion",()=>{
  assert.deepEqual(assess(receipt,{...evidence,authenticatedSameDevice:false}),{
    kind:"unresolved",operationId:request.operation_id,reason:"connection",
  });
});
