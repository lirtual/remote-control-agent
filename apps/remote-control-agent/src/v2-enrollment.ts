/**
 * v2 device enrollment material. Only the device owns its private key and code.
 * This is preparation for an owner-reviewed pairing, NOT Shell authorization.
 */
import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { open } from "node:fs/promises";

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
export const ENROLLMENT_DOMAIN = "remote-control:v2:pending:";

export interface EnrollmentRequest {
  name: string;
  public_key: string;
  code_verifier: string;
  proof: string;
  issued_at: number;
  grant_type?: "temporary"; // Omitted for permanent grant
  pairing_protocol: "single-code-v1"; // Signed enrollment version; old pending cannot be silently approved
}

export function pairingVerifier(code: string): string {
  if (!/^[A-Z2-7]{10}$/.test(code)) throw new Error("Invalid pairing code.");
  return createHash("sha256").update(ENROLLMENT_DOMAIN + code).digest("hex");
}

export function newEnrollment(name: string, existingPrivateKeyPem?: string, grantType: "permanent" | "temporary" = "permanent"): {
  code: string;
  privateKeyPem: string;
  request: EnrollmentRequest;
} {
  if (typeof name !== "string" || name.length < 1 || name.length > 64 || /[\r\n\x00-\x1f]/.test(name)) {
    throw new Error("Invalid device label.");
  }
  if (!["permanent", "temporary"].includes(grantType)) throw new Error("Invalid grant type.");
  // Each of 256 byte values maps to a Base32 symbol uniformly: 8 values/symbol.
  const code = [...randomBytes(10)].map((b) => ALPHABET[b & 31]).join("");
  // Retry after an interrupted install with the SAME device identity.
  // Never rotate a key implicitly; revocation remains an explicit boundary.
  const privateKey = existingPrivateKeyPem
    ? createPrivateKey(existingPrivateKeyPem)
    : generateKeyPairSync("ed25519").privateKey;
  if (privateKey.asymmetricKeyType !== "ed25519") throw new Error("Only Ed25519 device identity is supported.");
  const publicKey = createPublicKey(privateKey);
  const publicSpki = Buffer.from(publicKey.export({ type: "spki", format: "der" }) as Buffer).toString("base64");
  const verifier = pairingVerifier(code);
  const issuedAt = Date.now();
  const transcript = Buffer.from(ENROLLMENT_DOMAIN + verifier + ":" + publicSpki + ":" + name + ":" + issuedAt + (grantType === "temporary" ? ":temporary" : "") + ":single-code-v1");
  const proof = Buffer.from(sign(null, transcript, privateKey)).toString("base64");
  return {
    code,
    privateKeyPem: String(privateKey.export({ type: "pkcs8", format: "pem" })),
    request: { name, public_key: publicSpki, code_verifier: verifier, proof, issued_at: issuedAt,
      pairing_protocol: "single-code-v1",
      ...(grantType === "temporary" ? { grant_type: "temporary" as const } : {}) },
  };
}

export async function saveNewPrivateKey(filePath: string, pem: string): Promise<void> {
  const handle = await open(filePath, "wx", 0o600);
  try {
    await handle.writeFile(pem, "utf8");
    await handle.sync();
  } finally {
    await handle.close();
  }
}
