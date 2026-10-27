/** Agent-local durable admission for an already authenticated, independently
 * owner-approved Worker request. Deliberately does NOT download or switch a
 * Windows Task: a separate updater must pass the native rollback gate first.
 *
 * This is not a public Shell RPC. Caller must be the signed v2 WSS upgrade
 * handler, after the owner Durable Object consumed its one-time approval.
 */
import { createHash, createPrivateKey, createPublicKey } from "node:crypto";
import { operationDigest, ReceiptStore } from "./operations.ts";

const ID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const OP = /^(?!\.{1,2}$)[A-Za-z0-9._:-]{1,128}$/;
const VERSION = /^v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[a-z0-9][a-z0-9.-]*)?$/;
const HEX40 = /^[a-f0-9]{40}$/, HEX64 = /^[a-f0-9]{64}$/, HEX24 = /^[a-f0-9]{24}$/;

export interface RemoteUpgradeDispatch {
  operation_id: string;
  device_id: string;
  fingerprint: string;
  current_version: string;
  target: {
    tag: string;
    commit: string;
    windows_asset_sha256: string;
  };
  approved_at: number;
  expires_at: number;
}
export type RemoteUpgradeAdmission =
  | { status: "admitted"; operation_id: string }
  | { status: "duplicate" | "conflict" | "refused" | "unavailable"; operation_id?: string };

export function localUpgradeFingerprint(privateKeyPem: string): string {
  const key = createPrivateKey(privateKeyPem);
  if (key.asymmetricKeyType !== "ed25519") throw Error("Invalid paired upgrade identity.");
  return createHash("sha256")
    .update(createPublicKey(key).export({ format: "der", type: "spki" }))
    .digest("hex").slice(0, 24);
}
export function parseRemoteUpgradeDispatch(input: unknown): RemoteUpgradeDispatch | null {
  if (!input || typeof input !== "object" || Array.isArray(input)) return null;
  const row = input as Record<string, unknown>;
  const target = row.target;
  if (Object.keys(row).sort().join("|") !==
      "approved_at|current_version|device_id|expires_at|fingerprint|operation_id|target" ||
      !target || typeof target !== "object" || Array.isArray(target)) return null;
  const pin = target as Record<string, unknown>;
  if (Object.keys(pin).sort().join("|") !== "commit|tag|windows_asset_sha256" ||
      typeof row.operation_id !== "string" || !OP.test(row.operation_id) ||
      typeof row.device_id !== "string" || !ID.test(row.device_id) ||
      typeof row.fingerprint !== "string" || !HEX24.test(row.fingerprint) ||
      typeof row.current_version !== "string" || row.current_version.length > 64 ||
      !VERSION.test(row.current_version) ||
      typeof pin.tag !== "string" || pin.tag.length > 64 || !VERSION.test(pin.tag) ||
      pin.tag === row.current_version ||
      typeof pin.commit !== "string" || !HEX40.test(pin.commit) ||
      typeof pin.windows_asset_sha256 !== "string" ||
      !HEX64.test(pin.windows_asset_sha256) ||
      typeof row.approved_at !== "number" || !Number.isSafeInteger(row.approved_at) ||
      typeof row.expires_at !== "number" || !Number.isSafeInteger(row.expires_at) ||
      row.expires_at - row.approved_at > 300_000 ||
      row.expires_at <= row.approved_at) return null;
  return input as RemoteUpgradeDispatch;
}
export async function admitOwnerApprovedUpgrade(
  receipts: Pick<ReceiptStore, "admit">,
  untrusted: unknown,
  local: {
    signedDeviceId: string;
    originalVersion: string;
    privateKeyPem: string;
    platform?: NodeJS.Platform;
    now?: number;
    /** True only after the Worker OWNER DO atomically claimed approval. */
    confirmedByAuthenticatedWorker: boolean;
  },
): Promise<RemoteUpgradeAdmission> {
  const p = parseRemoteUpgradeDispatch(untrusted);
  if (!p || !local.confirmedByAuthenticatedWorker ||
      (local.platform ?? process.platform) !== "win32" ||
      p.device_id !== local.signedDeviceId ||
      p.current_version !== local.originalVersion ||
      !Number.isSafeInteger(local.now ?? Date.now()) ||
      (local.now ?? Date.now()) < p.approved_at ||
      (local.now ?? Date.now()) >= p.expires_at) return { status: "refused" };
  try {
    if (localUpgradeFingerprint(local.privateKeyPem) !== p.fingerprint)
      return { status: "refused" };
    // Persist the exact bound operation before any external process is created.
    // An interrupted admission is guarded as unknown by existing SQLite recovery.
    const result = await receipts.admit(p.operation_id, "upgrade_agent",
      operationDigest("upgrade_agent", p));
    if (result.kind === "new") return { status: "admitted", operation_id: p.operation_id };
    return { status: result.kind === "same" ? "duplicate" :
      result.kind === "conflict" ? "conflict" : "unavailable", operation_id: p.operation_id };
  } catch {
    return { status: "unavailable" };
  }
}
