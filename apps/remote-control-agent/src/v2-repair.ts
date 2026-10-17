/** Signed read-only negative approval check; no deleted-ID historic binding proof. */
import { createPrivateKey, createPublicKey, sign } from "node:crypto";
import { readFile } from "node:fs/promises";

export async function assertRemoteRevocation(
  endpoint: string, keyPath: string, deviceId: string, send: typeof fetch = fetch,
): Promise<void> {
  if (!/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(deviceId)) {
    throw new Error("Invalid prior device identity.");
  }
  const base = new URL(endpoint);
  const loopback = base.protocol === "http:" &&
    base.hostname === "127.0.0.1" && !!base.port;
  if ((!loopback && base.protocol !== "https:") || base.username || base.password ||
      base.search || base.hash || base.pathname !== "/") {
    throw new Error("A trusted HTTPS endpoint is required.");
  }
  const privateKey = createPrivateKey(await readFile(keyPath, "utf8"));
  if (privateKey.asymmetricKeyType !== "ed25519") {
    throw new Error("Only an existing Ed25519 identity may be replaced.");
  }
  const public_key = Buffer.from(createPublicKey(privateKey)
    .export({ type: "spki", format: "der" })).toString("base64");
  const issued_at = Date.now();
  const transcript = "remote-control:v2:re-pair-revoked:" +
    deviceId + ":" + public_key + ":" + issued_at;
  const proof = Buffer.from(sign(null, Buffer.from(transcript), privateKey)).toString("base64");
  const response = await send(new URL("/agent/re-pair/status", base), {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ device_id: deviceId, public_key, issued_at, proof }),
    redirect: "error", signal: AbortSignal.timeout(10_000),
  });
  // Never interpret 404, 401, 409, 429, 503 or connection failure as revocation.
  if (response.status !== 200) throw new Error("Revocation cannot be verified; existing identity preserved.");
  const payload = await response.json() as {status?: unknown; device_id?: unknown};
  if (payload.status !== "not_approved" || payload.device_id !== deviceId) {
    throw new Error("Revocation cannot be verified; existing identity preserved.");
  }
}
