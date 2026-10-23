/** Explicit Windows same-key reauthorization. No local grant is trusted without
 * a fresh, server-signed recovery. Never rotate or delete the private key. */
import { createHash, createPrivateKey } from "node:crypto";
import { open, readFile, rename, unlink } from "node:fs/promises";
import { setTimeout as delay } from "node:timers/promises";
import { newEnrollment } from "./v2-enrollment.ts";
import { verifyApprovedDeviceId, DeviceSessionRejectedError } from "./v2-session-client.ts";

const UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;

export async function replaceSignedDeviceId(
  keyPath: string, originalId: string, approvedId: string,
  seal: () => void, assertStopped: () => void = () => {},
): Promise<boolean> {
  if (!UUID.test(originalId) || !UUID.test(approvedId)) throw Error("Invalid signed device identity.");
  if ((await readFile(keyPath + ".device-id", "utf8")).trim() !== originalId) {
    throw Error("Device identity changed during reauthorization; refusing to overwrite.");
  }
  if (originalId === approvedId) return false;
  // A fixed, owner-only pending filename is a one-operation lock. The native
  // ACL helper must seal this pending file BEFORE replacing the approved ID.
  const stage = keyPath + ".device-id.pending";
  let staged = false;
  try {
    const file = await open(stage, "wx", 0o600);
    staged = true;
    try { await file.writeFile(approvedId + "\n", "utf8"); await file.sync(); }
    finally { await file.close(); }
    // On Windows, a new file may inherit an unsafe/default ACL despite mode
    // 0600. Seal and validate the staged file before any identity replacement.
    seal();
    if ((await readFile(keyPath + ".device-id", "utf8")).trim() !== originalId) {
      throw Error("Device identity changed while staging recovery.");
    }
    // The owner may start a stopped task while the 10-minute approval is pending.
    // Fail without switching the ID if it has become active meanwhile.
    assertStopped();
    // An already sealed file keeps its ACL through an atomic same-volume rename.
    // A failed swap retains the original approved ID.
    await rename(stage, keyPath + ".device-id");
    staged = false;
    return true;
  } finally {
    if (staged) await unlink(stage).catch(() => {});
  }
}

export async function repairWindowsIdentity(options: {
  endpoint: string; keyPath: string; currentId: string; name: string;
  seal: () => void; assertStopped?: () => void;
  onPending: (code: string, fingerprint: string) => void;
  send?: typeof fetch;
  verify?: (endpoint: string, keyPath: string, send: typeof fetch) => Promise<string>;
  sleep?: (milliseconds: number) => Promise<unknown>;
  timeoutMs?: number;
}): Promise<"unchanged" | "restored"> {
  const {endpoint, keyPath, currentId, name, seal, onPending} = options;
  if (!UUID.test(currentId)) throw Error("Invalid existing device identity.");
  const send = options.send ?? fetch;
  const verify = options.verify ?? verifyApprovedDeviceId;
  const wait = options.sleep ?? (ms => delay(ms));
  const existingPem = await readFile(keyPath, "utf8");
  if (createPrivateKey(existingPem).asymmetricKeyType !== "ed25519") {
    throw Error("Unsupported device identity key.");
  }
  // If another ID is approved for this SAME key, signed recovery suffices:
  // never ask the owner to create a redundant second cloud grant.
  let approvedId: string | undefined;
  try { approvedId = await verify(endpoint, keyPath, send); }
  catch (err) {
    if (!(err instanceof DeviceSessionRejectedError) || err.status !== 404) throw err;
  }
  if (!approvedId) {
    const enrollment = newEnrollment(name, existingPem, "permanent");
    const response = await send(new URL("/agent/pair/start", endpoint), {
      method: "POST", headers: {"content-type":"application/json"},
      body: JSON.stringify(enrollment.request),
      redirect: "error", signal: AbortSignal.timeout(10_000),
    });
    if (response.status !== 202) throw Error("Same-key reauthorization not accepted; local identity unchanged.");
    const fingerprint = createHash("sha256")
      .update(Buffer.from(enrollment.request.public_key, "base64")).digest("hex").slice(0, 24);
    onPending(enrollment.code, fingerprint);
    const expiresAt = Date.now() + (options.timeoutMs ?? 600_000);
    while (!approvedId && Date.now() < expiresAt) {
      await wait(Math.min(5000, Math.max(0, expiresAt - Date.now())));
      try { approvedId = await verify(endpoint, keyPath, send); }
      catch (err) {
        if (!(err instanceof DeviceSessionRejectedError) || err.status !== 404) throw err;
      }
    }
    if (!approvedId) throw Error("Owner approval not confirmed; old identity retained. Repeat re-pair after approval.");
  }
  // A signed device ID from the production challenge/recover route always
  // proves the server accepted the SAME local private key.
  if (!UUID.test(approvedId)) throw Error("Invalid signed device approval.");
  await replaceSignedDeviceId(keyPath, currentId, approvedId, seal, options.assertStopped);
  return approvedId === currentId ? "unchanged" : "restored";
}
