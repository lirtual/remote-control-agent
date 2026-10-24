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
import {operationDigest, type OperationReceipt, type ReceiptStore} from "./operations.ts";
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


/**
 * Reconcile a prior durable upgrade record, never initiate or retry an OS
 * installer. Only the owner-local Agent reconnection path may provide this
 * trusted evidence inspector. Do not route it from an incoming MCP argument.
 */
export async function finalizeUpgradeAfterReconnect(
  receipts: ReceiptStore,
  operationId: string,
  inspectTrustedLocalState: (approved: Readonly<UpgradeRequest>) => Promise<Readonly<TrustedUpgradeEvidence>>,
): Promise<UpgradeRecoveryVerdict> {
  const unresolved = (reason: Extract<UpgradeRecoveryVerdict,{kind:"unresolved"}>["reason"]):
    UpgradeRecoveryVerdict => ({kind:"unresolved",operationId,reason});
  if (!/^(?!\.{1,2}$)[A-Za-z0-9._:-]{1,128}$/.test(operationId))
    return unresolved("receipt");
  let receipt: OperationReceipt | null;
  let target: UpgradeRequest | null;
  try {
    receipt = await receipts.get(operationId);
    if (!receipt || receipt.tool_name !== "upgrade_agent") return unresolved("receipt");
    const loaded = await receipts.getUpgradeIntent(operationId);
    if (!loaded || typeof loaded !== "object" || Array.isArray(loaded) ||
        (loaded as {operation_id?:unknown}).operation_id !== operationId)
      return unresolved("receipt");
    target = loaded as UpgradeRequest;
  } catch { return unresolved("receipt"); }
  let observed: Readonly<TrustedUpgradeEvidence>;
  try { observed = await inspectTrustedLocalState(target); }
  catch { return unresolved("service"); }
  const verdict = assessUpgradeAfterReconnect(target,receipt,observed);
  if (verdict.kind !== "verified") return verdict;
  try {
    // CAS inside the same SQLite transaction prevents an asynchronous
    // inspector from finalizing an operation concurrently marked failed.
    await receipts.completeVerifiedUpgrade(operationId,receipt.argument_digest);
  } catch { return unresolved("receipt"); }
  return verdict;
}
