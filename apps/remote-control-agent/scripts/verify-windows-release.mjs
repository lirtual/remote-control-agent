/**
 * Official immutable Windows Release evidence.
 *
 * Share the Linux installer's pinned GitHub Release metadata, redirect,
 * asset-id, commit, size and SHA-256 trust boundary. This intentionally does
 * not install, extract, run, authorize, or claim installed-file equality.
 * A trusted owner-local caller must compare the returned ZIP to the private
 * installed tree and separately verify the same device's OS task/WSS.
 */
import { resolvePinnedRelease, downloadPinnedAsset } from "./verify-v2-release.mjs";

const COMMIT=/^[a-f0-9]{40}$/;
const SHA=/^[a-f0-9]{64}$/;
const TAG=/^v(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})$/;

export async function fetchApprovedWindowsRelease({
  tag,commit,sha256,send=fetch,
}) {
  if(!TAG.test(tag)||!COMMIT.test(commit)||!SHA.test(sha256))
    throw Error("Stable approved Windows Release tag, commit and digest required.");
  const pinned=await resolvePinnedRelease({tag,commit,target:"windows-x64",send});
  if(pinned.digest!==sha256)
    throw Error("Approved Windows ZIP digest differs from published immutable Release.");
  const archive=await downloadPinnedAsset(pinned,send);
  return Object.freeze({tag,commit,sha256,archive});
}
