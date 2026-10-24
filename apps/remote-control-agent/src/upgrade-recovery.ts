/**
 * Offline-only verdict for a prior approved upgrade after the Agent reconnects.
 *
 * The evidence MUST come from a trusted owner-local inspector (identity key,
 * executable, signed Release manifest, OS service/task, and authenticated
 * same-device WSS). It must never be accepted from an MCP caller.
 *
 * This helper does not switch a service, write a receipt or infer success
 * solely from the Agent's version string.
 */
import {timingSafeEqual} from "node:crypto";
import {operationDigest, type OperationReceipt} from "./operations.ts";
import type {UpgradeRequest} from "./upgrade-authorization.ts";

export interface TrustedUpgradeEvidence {
  deviceId: string;
  identitySha256: string;
  runningVersion: string;
  platform: string;
  immutableReleaseCommit: string;
  immutableReleaseAssetSha256: string;
  serviceActive: boolean;
  serviceExecutableVerified: boolean;
  durableReceiptsReadable: boolean;
  authenticatedSameDevice: boolean;
}

export type UpgradeRecoveryVerdict =
  | Readonly<{kind:"verified"; operationId:string}>
  | Readonly<{kind:"unresolved"; operationId:string; reason:
      "receipt" | "identity" | "release" | "service" | "connection"}>;

const DIGEST=/^[a-f0-9]{64}$/;
function sameDigest(left:string,right:string):boolean {
  if(!DIGEST.test(left)||!DIGEST.test(right))return false;
  return timingSafeEqual(Buffer.from(left,"hex"),Buffer.from(right,"hex"));
}

export function assessUpgradeAfterReconnect(
  request: Readonly<UpgradeRequest>,
  receipt: OperationReceipt | null,
  observed: Readonly<TrustedUpgradeEvidence>,
): UpgradeRecoveryVerdict {
  // Require a previously durable admitted upgrade with unchanged arguments.
  // A remote status query or a forged journal alone is never authorization.
  if(!receipt || receipt.operation_id!==request.operation_id ||
      receipt.tool_name!=="upgrade_agent" ||
      !sameDigest(receipt.argument_digest,operationDigest("upgrade_agent",request)) ||
      !["running","unknown","completed"].includes(receipt.state))
    return {kind:"unresolved",operationId:request.operation_id,reason:"receipt"};
  if(observed.deviceId!==request.device_id ||
      !sameDigest(observed.identitySha256,request.identity_sha256))
    return {kind:"unresolved",operationId:request.operation_id,reason:"identity"};
  if(observed.runningVersion!==request.target_version ||
      observed.platform!==request.target_platform ||
      observed.immutableReleaseCommit!==request.target_commit ||
      !sameDigest(observed.immutableReleaseAssetSha256,request.target_sha256))
    return {kind:"unresolved",operationId:request.operation_id,reason:"release"};
  if(!observed.serviceActive || !observed.serviceExecutableVerified ||
      !observed.durableReceiptsReadable)
    return {kind:"unresolved",operationId:request.operation_id,reason:"service"};
  if(!observed.authenticatedSameDevice)
    return {kind:"unresolved",operationId:request.operation_id,reason:"connection"};
  return {kind:"verified",operationId:request.operation_id};
}
