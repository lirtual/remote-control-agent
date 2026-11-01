/** Device-key-authenticated WSS, deliberately without remote operation handlers. */
import { createPrivateKey, createPublicKey, sign } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";

const SESSION_DOMAIN = "remote-control:v2:session:";

/** A permanent identity rejection: operator action is required, not retry/backoff. */
export class DeviceSessionRejectedError extends Error {
  readonly status?: number;
  constructor(message = "Device identity is not authorized.", status?: number) {
    super(message);
    this.name = "DeviceSessionRejectedError";
    this.status = status;
  }
}

function rejectPermanentStatus(status: number, message?: string): void {
  if (status === 401 || status === 403 || status === 404) {
    throw new DeviceSessionRejectedError(message, status);
  }
}
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;

function endpoint(baseAddress: string): URL {
  const value = new URL(baseAddress);
  const local = value.protocol === "http:" && value.hostname === "127.0.0.1" && !!value.port;
  if ((!local && value.protocol !== "https:") || value.username || value.password ||
      value.search || value.hash || value.pathname !== "/") {
    throw new Error("A trusted HTTPS endpoint (or IPv4 loopback test endpoint) is required.");
  }
  return value;
}

function encode64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

export function signedSessionProof(pem: string, deviceId: string, nonce: string): {
  proof: string; public_key: string;
} {
  if (!UUID.test(deviceId) || !/^[A-Za-z0-9_-]{24}$/.test(nonce)) {
    throw new Error("Invalid device session challenge.");
  }
  const privateKey = createPrivateKey(pem);
  const public_key = Buffer.from(createPublicKey(privateKey).export({ type: "spki", format: "der" })).toString("base64");
  const body = Buffer.from(SESSION_DOMAIN + deviceId + ":" + nonce + ":" + public_key);
  return { proof: encode64url(Buffer.from(sign(null, body, privateKey))), public_key };
}

async function postJson(
  base: URL, path: string, body: object, send: typeof fetch, signal?: AbortSignal,
): Promise<{ status: number; result: any }> {
  signal?.throwIfAborted();
  const deadline = AbortSignal.timeout(10_000);
  const requestSignal = signal ? AbortSignal.any([signal, deadline]) : deadline;
  const response = await send(new URL(path, base), {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify(body), redirect: "error", signal: requestSignal,
  });
  if (response.status !== 200) return { status: response.status, result: {} };
  const result: unknown = await response.json();
  if (!result || typeof result !== "object" || Array.isArray(result)) throw new Error("Invalid server response.");
  return { status: response.status, result };
}

export async function verifyApprovedDeviceId(
  baseAddress: string, keyPath: string, send: typeof fetch = fetch,
  signal?: AbortSignal,
): Promise<string> {
  signal?.throwIfAborted();
  const base = endpoint(baseAddress);
  const privatePem = await readFile(keyPath, "utf8");
  const publicKey = Buffer.from(createPublicKey(createPrivateKey(privatePem)).export({ type: "spki", format: "der" })).toString("base64");
  const challenged = await postJson(base, "/agent/session/challenge", { public_key: publicKey }, send, signal);
  rejectPermanentStatus(challenged.status, "No approved device identity matches this key.");
  if (challenged.status !== 200 || !UUID.test(challenged.result.device_id) ||
      !/^[A-Za-z0-9_-]{24}$/.test(challenged.result.nonce)) {
    throw new Error("No approved device identity matches this key.");
  }
  const { proof } = signedSessionProof(privatePem, challenged.result.device_id, challenged.result.nonce);
  const result = await postJson(base, "/agent/session/recover", {
    device_id: challenged.result.device_id, nonce: challenged.result.nonce, proof,
  }, send, signal);
  rejectPermanentStatus(result.status);
  if (result.status !== 200 || result.result.status !== "verified" ||
      result.result.device_id !== challenged.result.device_id) {
    throw new Error("Signed device identity recovery failed.");
  }
  return challenged.result.device_id;
}

/** Distinct Ed25519 intent domain; ordinary signed WSS cannot authorize local owner OFF/Resume. */
export function signedOwnerIntentProof(pem:string,action:'stop'|'resume',id:string,nonce:string,generation:number):string {
  if(!UUID.test(id)||!/^[A-Za-z0-9_-]{24}$/.test(nonce)||
      !Number.isSafeInteger(generation)||generation<0||generation>=Number.MAX_SAFE_INTEGER)
    throw Error('Invalid signed local owner intent.');
  const privateKey=createPrivateKey(pem);
  const publicKey=Buffer.from(createPublicKey(privateKey).export({type:'spki',format:'der'})).toString('base64');
  const transcript=`remote-control:v2:owner-intent:v1:${action}:${id}:${generation}:${nonce}:${publicKey}`;
  return Buffer.from(sign(null,Buffer.from(transcript),privateKey)).toString('base64url');
}

/** Explicit owner CLI only: durable signed Stop/Resume result is never inferred from a timeout. */
export async function sendSignedOwnerIntent(
  origin:string,keyPath:string,action:'stop'|'resume',send:typeof fetch=fetch,
):Promise<{status:'stopped'|'resume_pending';idle_expires_at:number}> {
  const base=endpoint(origin);
  const id=(await readFile(keyPath+'.device-id','utf8')).trim();
  if(!UUID.test(id))throw Error('Invalid existing device identity.');
  const pem=await readFile(keyPath,'utf8');
  const challenged=await postJson(base,'/agent/owner/intent/challenge',{action,device_id:id},send);
  rejectPermanentStatus(challenged.status);
  const c=challenged.result as {action?:unknown;device_id?:unknown;nonce?:unknown;generation?:unknown};
  if(challenged.status!==200||c.device_id!==id||c.action!==action||
     typeof c.nonce!=='string'||!/^[A-Za-z0-9_-]{24}$/.test(c.nonce)||
     !Number.isSafeInteger(c.generation)||Number(c.generation)<0)throw Error('Owner intent challenge unavailable.');
  const generation=Number(c.generation);
  const proof=signedOwnerIntentProof(pem,action,id,c.nonce,generation);
  const result=await postJson(base,'/agent/owner/intent',{
    action,device_id:id,nonce:c.nonce,generation,proof,
  },send);
  rejectPermanentStatus(result.status);
  if(result.status!==200||result.result.device_id!==id||
     result.result.status!==(action==='stop'?'stopped':'resume_pending')||
     !Number.isSafeInteger(result.result.idle_expires_at))
    throw Error('Cloud owner intent was not confirmed.');
  return {status:result.result.status,idle_expires_at:result.result.idle_expires_at};
}

/** Read-only signed approval proof; never creates an incomplete .device-id file. */
export async function recoverDeviceId(
  baseAddress: string, keyPath: string, send: typeof fetch = fetch,
  signal?: AbortSignal,
): Promise<string> {
  const approvedId = await verifyApprovedDeviceId(baseAddress, keyPath, send, signal);
  signal?.throwIfAborted();
  // This is an identity recovery, NOT a replay of an uncertain Shell mutation.
  // A lost recovery response may be handled by a fresh nonce/challenge.
  try {
    await writeFile(keyPath + ".device-id", approvedId + "\n", { encoding: "utf8", flag: "wx", mode: 0o600 });
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
    const existing = (await readFile(keyPath + ".device-id", "utf8")).trim();
    if (existing !== approvedId) {
      throw new DeviceSessionRejectedError("Device ID on disk does not match authenticated identity.");
    }
  }
  return approvedId;
}

/** Fixed, credential-free connection checkpoints for job-private diagnostics. */
export type SocketConnectionStage =
  "challenge_start" | "challenge_ok" | "challenge_rejected" |
  "wss_start" | "wss_open" | "wss_error" | "wss_policy" | "wss_timeout";

export async function openAuthenticatedDeviceSocket(
  baseAddress: string, keyPath: string, send: typeof fetch = fetch,
  makeSocket: (url: string, protocols: string[]) => WebSocket = (url, protocols) => new WebSocket(url, protocols),
  signal?: AbortSignal,
  onStage?: (stage: SocketConnectionStage) => void,
): Promise<{ device_id: string; socket: WebSocket }> {
  signal?.throwIfAborted();
  const base = endpoint(baseAddress);
  const privatePem = await readFile(keyPath, "utf8");
  let deviceId: string;
  try { deviceId = (await readFile(keyPath + ".device-id", "utf8")).trim(); }
  catch (e) {
    if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e;
    deviceId = await recoverDeviceId(baseAddress, keyPath, send, signal);
  }
  if (!UUID.test(deviceId)) throw new DeviceSessionRejectedError("Invalid local device ID.");
  onStage?.("challenge_start");
  const challenged = await postJson(base, "/agent/session/challenge", { device_id: deviceId }, send, signal);
  if ([401,403,404].includes(challenged.status)) onStage?.("challenge_rejected");
  rejectPermanentStatus(challenged.status);
  if (challenged.status !== 200 || challenged.result.device_id !== deviceId ||
      !/^[A-Za-z0-9_-]{24}$/.test(challenged.result.nonce)) {
    throw new Error("Could not obtain a valid session challenge.");
  }
  onStage?.("challenge_ok");
  const { proof } = signedSessionProof(privatePem, deviceId, challenged.result.nonce);
  const wsUrl = new URL("/agent/connect/" + deviceId, base);
  wsUrl.protocol = base.protocol === "https:" ? "wss:" : "ws:";
  signal?.throwIfAborted();
  onStage?.("wss_start");
  const socket = makeSocket(wsUrl.toString(), ["rc-v2", "rcv2." + challenged.result.nonce + "." + proof]);
  await new Promise<void>((resolve, reject) => {
    let finished = false;
    const cleanup = () => {
      clearTimeout(timeout);
      socket.removeEventListener("open", onOpen);
      socket.removeEventListener("error", onError);
      socket.removeEventListener("close", onClose);
      signal?.removeEventListener("abort", onAbort);
    };
    const fail = (message: string, permanent = false) => {
      if (finished) return;
      finished = true;
      cleanup();
      try { socket.close(); } catch { /* already closed */ }
      reject(permanent ? new DeviceSessionRejectedError(message) : new Error(message));
    };
    const onOpen = () => {
      if (finished) return;
      // WebSocket may negotiate any one of the offered subprotocols. Only the
      // non-credential rc-v2 marker is allowed as the server's selection.
      if (socket.protocol !== "rc-v2") {
        fail("WSS returned an unexpected protocol.", true);
        return;
      }
      if (socket.readyState !== WebSocket.OPEN) {
        fail("WSS returned an unexpected state.");
        return;
      }
      finished = true;
      onStage?.("wss_open");
      cleanup();
      resolve();
    };
    const onAbort = () => fail("WSS login aborted.");
    const onError = () => { onStage?.("wss_error"); fail("WSS authentication failed."); };
    const onClose = (event: Event) => {
      // A policy close can race the browser/Node OPEN event. Treat an early
      // 1008 exactly like a post-open policy rejection, not a retryable outage.
      const policyDenied = (event as CloseEvent).code === 1008;
      onStage?.(policyDenied ? "wss_policy" : "wss_error");
      fail("WSS authentication was rejected.", policyDenied);
    };
    const timeout = setTimeout(() => { onStage?.("wss_timeout"); fail("WSS login timed out."); }, 10_000);
    socket.addEventListener("open", onOpen);
    socket.addEventListener("error", onError);
    socket.addEventListener("close", onClose);
    signal?.addEventListener("abort", onAbort, { once: true });
    if (signal?.aborted) { onAbort(); return; }
    // Protect the factory's extremely rare already-open/closed synchronous case.
    if (socket.readyState === WebSocket.OPEN) onOpen();
    else if (socket.readyState === WebSocket.CLOSED) onClose(new Event("close"));
  });
  return { device_id: deviceId, socket };
}
