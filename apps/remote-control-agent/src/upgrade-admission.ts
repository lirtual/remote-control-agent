/**
 * Persist an owner-authorized upgrade intent using the SAME SQLite operation
 * receipts as other Agent mutations. This module never runs an installer.
 *
 * The only caller permitted to provide verifyOwnerApproval must be the trusted
 * Agent/Worker approval boundary. The request contract alone is NOT approval.
 */
import { operationDigest, type OperationReceipt, type ReceiptStore } from "./operations.ts";
import {
  validateUpgradeRequest, type UpgradeRequest, type UpgradeValidationContext,
} from "./upgrade-authorization.ts";

export type UpgradeAdmission = Readonly<
  | { kind: "new"; receipt: OperationReceipt }
  | { kind: "existing"; receipt: OperationReceipt }
  | { kind: "conflict"; receipt: OperationReceipt }
  | { kind: "busy" }
>;

export async function admitOwnerApprovedUpgrade(
  receipts: ReceiptStore,
  request: UpgradeRequest,
  context: UpgradeValidationContext,
  verifyOwnerApproval: (request: Readonly<UpgradeRequest>) => Promise<boolean>,
): Promise<UpgradeAdmission> {
  // Validate release and device BEFORE testing authorization or opening a
  // record. An expired/changed grant must not be revived by repeat calls.
  const verified = validateUpgradeRequest(request, context);
  if (await verifyOwnerApproval(verified) !== true) {
    throw new Error("Owner upgrade approval missing or expired");
  }
  const digest = operationDigest("upgrade_agent", verified);
  const admitted = await receipts.admit(verified.operation_id, "upgrade_agent", digest);
  if (admitted.kind === "full") return { kind: "busy" };
  if (!admitted.receipt) throw new Error("Upgrade receipt not durable");
  if (admitted.kind === "conflict") return { kind: "conflict", receipt: admitted.receipt };
  if (admitted.kind === "same") return { kind: "existing", receipt: admitted.receipt };
  return { kind: "new", receipt: admitted.receipt };
}
