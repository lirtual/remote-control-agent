/**
 * Explicit v2 *pending-only* Agent enrolment. This does not authorize remote
 * calls, create a command connection, or install a running background service.
 */
import { createHash } from "node:crypto";
import { lstat, mkdir, readFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { newEnrollment, saveNewPrivateKey } from "./v2-enrollment.ts";

const DEFAULT_KEY_FILE = path.join(
  os.homedir(), ".local", "share", "mcp-workers", "remote-control", "v2-identity.pem",
);

export interface PendingEnrollmentResult {
  code: string;
  fingerprint: string;
  expiresAt: number;
  keyPath: string;
}

export class PendingIdentityConflictError extends Error {
  constructor() { super("An approved or revoked identity cannot be enrolled again."); }
}

export async function beginDeviceEnrollment(
  name: string,
  endpoint: string,
  keyPath = DEFAULT_KEY_FILE,
  send: typeof fetch = fetch,
  reuseExistingKey = false,
  grantType: "permanent" | "temporary" = "permanent",
): Promise<PendingEnrollmentResult> {
  const base = new URL(endpoint);
  const local = base.protocol === "http:" && base.hostname === "127.0.0.1";
  if ((!local && base.protocol !== "https:") || base.username || base.password ||
      base.search || base.hash || base.pathname !== "/" || (local && !base.port)) {
    throw new Error("Enrollment requires a trusted HTTPS endpoint (or local test endpoint).");
  }

  let savedPem: string | undefined;
  if (reuseExistingKey) {
    // The retry path must not follow a symlink, replace, or loosen a key.
    const key = await lstat(keyPath);
    if (!key.isFile() || key.isSymbolicLink() || key.uid !== process.getuid?.() ||
        (key.mode & 0o777) !== 0o600) {
      throw new Error("The existing private identity has unsafe ownership or permissions.");
    }
    savedPem = await readFile(keyPath, "utf8");
  }
  const material = newEnrollment(name, savedPem, grantType);
  if (!reuseExistingKey) {
    await mkdir(path.dirname(keyPath), { recursive: true, mode: 0o700 });
    await saveNewPrivateKey(keyPath, material.privateKeyPem);
  }
  try {
    const result = await send(new URL("/agent/pair/start", base), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(material.request),
      redirect: "error",
      signal: AbortSignal.timeout(10_000),
    });
    if (result.status === 409 && reuseExistingKey) throw new PendingIdentityConflictError();
    if (result.status !== 202) {
      throw new Error("Pending enrollment was not accepted.");
    }
    // Same first 12 bytes of SHA-256(SPKI DER) displayed by the Owner DO.
    // Public metadata only: do not print the private key or bearer token.
    const fingerprint = createHash("sha256")
      .update(Buffer.from(material.request.public_key, "base64"))
      .digest("hex").slice(0, 24);
    return { code: material.code, fingerprint, expiresAt: material.request.issued_at + 600_000, keyPath };
  } catch (error) {
    // Keep a freshly generated owner-only key too: a 202 reply can be lost
    // after the server records a pending request. Removing it would force a
    // new Ed25519 identity on retry, severing the original pending approval.
    // A definitive non-202 rejection is still NOT approval; retries must
    // independently prove the same key and never create a second grant.
    if (error instanceof PendingIdentityConflictError) throw error;
    throw new Error("Pending enrollment could not be completed.");
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const endpoint = process.env.REMOTE_CONTROL_V2_ENDPOINT;
  if (!endpoint) {
    process.stderr.write("REMOTE_CONTROL_V2_ENDPOINT must be configured.\n");
    process.exitCode = 1;
  } else {
    try {
      const device = await beginDeviceEnrollment(process.argv[2] || os.hostname(), endpoint);
      process.stdout.write(
        `Pending device. Pairing code: ${device.code}\nPublic key fingerprint: ${device.fingerprint}\nExpires after 10 minutes. Compare the fingerprint shown by your authenticated Remote Control MCP.\n`,
      );
    } catch {
      process.stderr.write("Pending device enrollment failed. Check the endpoint and local key path.\n");
      process.exitCode = 1;
    }
  }
}
