/** Owner-approved, one-shot Agent upgrade request contract.
 * Does NOT invoke a process or grant approval by itself.
 */
import { timingSafeEqual } from "node:crypto";
const HEX40=/^[a-f0-9]{40}$/;
const HEX64=/^[a-f0-9]{64}$/;
const UUID=/^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/;
const VERSION=/^v(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$/;
const OP=/^(?!\.{1,2}$)[A-Za-z0-9._:-]{1,128}$/;
const PROFILE=/^(windows-x64|linux-x64-glibc|linux-arm64-glibc)$/;
export interface UpgradeRequest {
  operation_id: string;
  device_id: string;
  source_version: string;
  target_version: string;
  target_commit: string;
  target_sha256: string;
  target_platform: string;
  identity_sha256: string;
  authorized_until: number;
}
export interface ApprovedUpgradeRelease {
  version: string; commit: string; sha256: string; platform: string;
}
export interface UpgradeValidationContext {
  deviceId: string; installedVersion: string; identityDigest: string;
  platform: string; now?: number; approvedRelease?: ApprovedUpgradeRelease | null;
}
const keys=["operation_id","device_id","source_version","target_version","target_commit","target_sha256","target_platform","identity_sha256","authorized_until"];
function checkExact(value: unknown,allowed: readonly string[]): asserts value is Record<string, unknown> {
 if(!value||typeof value!=="object"||Array.isArray(value)||(Object.keys(value).length!==allowed.length || Object.keys(value).some(key=>!allowed.includes(key))))
  throw Error("Unrecognized upgrade request fields");
}
function newer(next: string,current: string): boolean {
 const n=VERSION.exec(next),o=VERSION.exec(current);
 if(!n||!o)throw Error("Invalid stable Agent version");
 for(let i=1;i<4;i++){
  const a=BigInt(n[i]!),b=BigInt(o[i]!);
  if(a!==b)return a>b;
 }
 return false;
}
export function validateUpgradeRequest(value: UpgradeRequest,{deviceId,installedVersion,identityDigest,platform,now=Date.now(),approvedRelease}: UpgradeValidationContext): Readonly<UpgradeRequest> {
 checkExact(value,keys);
 if(!OP.test(value.operation_id)||!UUID.test(value.device_id)||value.device_id!==deviceId)
  throw Error("Upgrade operation/device mismatch");
 if(!HEX64.test(value.identity_sha256)||!HEX64.test(identityDigest||"")||
    !timingSafeEqual(Buffer.from(value.identity_sha256,"hex"),Buffer.from(identityDigest,"hex")))
  throw Error("Upgrade identity mismatch");
 if(!PROFILE.test(value.target_platform)||value.target_platform!==platform||
    value.source_version!==installedVersion||!newer(value.target_version,installedVersion))
  throw Error("Upgrade version or platform mismatch");
 if(!HEX40.test(value.target_commit)||!HEX64.test(value.target_sha256))
  throw Error("Upgrade release pin invalid");
 if(!Number.isSafeInteger(value.authorized_until)||value.authorized_until<=now||
    value.authorized_until>now+5*60*1000)
  throw Error("Upgrade authorization expired or unbounded");
 if(!approvedRelease||approvedRelease.version!==value.target_version||
    approvedRelease.commit!==value.target_commit||
    approvedRelease.sha256!==value.target_sha256||
    approvedRelease.platform!==value.target_platform)
  throw Error("Upgrade release is not approved");
 return Object.freeze({...value});
}
