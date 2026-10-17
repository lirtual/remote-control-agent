/**
 * First pairing must be confirmed from the NEW Agent's own interactive terminal.
 * No Portal credential enters the device and the MCP cannot approve by itself.
 */
import { createPrivateKey, createPublicKey, sign } from "node:crypto";
import { access, open, readFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import readline from "node:readline/promises";
import { fileURLToPath } from "node:url";
import { pairingVerifier } from "./v2-enrollment.ts";

const CONFIRM_DOMAIN = "remote-control:v2:local-confirm:";
const DEFAULT_KEY_FILE = path.join(os.homedir(), ".local", "share", "mcp-workers", "remote-control", "v2-identity.pem");

export async function confirmDeviceLocally(
  code: string,
  challenge: string,
  endpoint: string,
  keyPath = DEFAULT_KEY_FILE,
  send: typeof fetch = fetch,
): Promise<string> {
  const normalizedCode = code.trim().toUpperCase();
  const normalizedChallenge = challenge.trim().toUpperCase();
  if (!/^[A-Z2-7]{10}$/.test(normalizedCode) || !/^[A-Z2-7]{12}$/.test(normalizedChallenge)) {
    throw new Error("Invalid pairing code or confirmation challenge.");
  }
  const base = new URL(endpoint);
  const local = base.protocol === "http:" && base.hostname === "127.0.0.1";
  if ((!local && base.protocol !== "https:") || base.username || base.password ||
      base.search || base.hash || base.pathname !== "/" || (local && !base.port)) {
    throw new Error("A trusted HTTPS endpoint (or local test endpoint) is required.");
  }
  try {
    await access(keyPath + ".device-id");
    throw new Error("This installation already has a paired device ID.");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  const privateKey = createPrivateKey(await readFile(keyPath, "utf8"));
  const publicSpki = Buffer.from(createPublicKey(privateKey).export({ type: "spki", format: "der" })).toString("base64");
  const verifier = pairingVerifier(normalizedCode);
  // The verifier indexes exactly one pending record and its immutable public key.
  // Owner review and the one-time server challenge are bound to that same record.
  const transcript = Buffer.from(CONFIRM_DOMAIN + verifier + ":" + normalizedChallenge + ":" + publicSpki);
  const proof = Buffer.from(sign(null, transcript, privateKey)).toString("base64");
  const response = await send(new URL("/agent/pair/complete", base), {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ verifier, challenge: normalizedChallenge, proof }),
    redirect: "error",
    signal: AbortSignal.timeout(10_000),
  });
  if (response.status !== 200) throw new Error("Confirmation denied, expired or already consumed.");
  const result = await response.json() as { status?: unknown; device_id?: unknown };
  if (result.status !== "paired" || typeof result.device_id !== "string" ||
      !/^[a-f0-9-]{36}$/.test(result.device_id)) {
    throw new Error("Unrecognized pairing response; outcome must be checked, not blindly retried.");
  }
  const f = await open(keyPath + ".device-id", "wx", 0o600);
  try {
    await f.writeFile(result.device_id + "\n", "utf8");
    await f.sync();
  } finally { await f.close(); }
  return result.device_id;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const endpoint = process.env.REMOTE_CONTROL_V2_ENDPOINT;
  if (!endpoint || !process.stdin.isTTY) {
    process.stderr.write("Set REMOTE_CONTROL_V2_ENDPOINT and run confirmation interactively on the NEW device.\n");
    process.exitCode = 1;
  } else {
    const terminal = readline.createInterface({ input: process.stdin, output: process.stdout });
    try {
      const code = await terminal.question("Original 10-character pairing code: ");
      const challenge = await terminal.question("12-character challenge shown by the MCP: ");
      const id = await confirmDeviceLocally(code, challenge, endpoint);
      process.stdout.write("Device identity paired: " + id + "\n");
    } catch {
      process.stderr.write("Local confirmation failed or outcome uncertain; do not blindly repeat.\n");
      process.exitCode = 1;
    } finally { terminal.close(); }
  }
}
