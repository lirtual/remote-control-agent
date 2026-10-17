/**
 * v2 transport adapter for the existing v1 Agent execution server.
 *
 * A v2 outbound WebSocket client can forward an authenticated request to the
 * existing local Agent without duplicating its validation, receipts or Shell.
 * The credential remains on the local machine and is NEVER forwarded to DO.
 */
const MAX_RESPONSE_BYTES = 512_000;
const MAX_REQUEST_BYTES = 65_536;

export interface LoopbackTransport {
  execute(tool: string, args: unknown, operationId?: string): Promise<{ status: number; body: unknown }>;
  operationStatus(operationId: string): Promise<{ status: number; body: unknown }>;
}

export function createLoopbackTransport(
  localBaseUrl: string,
  localDeviceToken: string,
  localFetch: typeof fetch = fetch,
): LoopbackTransport {
  const base = new URL(localBaseUrl);
  if (
    base.protocol !== "http:" ||
    base.hostname !== "127.0.0.1" ||
    base.username !== "" ||
    base.password !== "" ||
    base.search !== "" ||
    base.hash !== "" ||
    base.pathname !== "/" ||
    !base.port
  ) {
    throw new Error("An explicit IPv4 loopback Agent endpoint is required.");
  }
  if (!localDeviceToken) throw new Error("The local Agent credential is required.");

  async function request(path: string, body?: unknown): Promise<{ status: number; body: unknown }> {
    const json = body === undefined ? undefined : JSON.stringify(body);
    if (json !== undefined && Buffer.byteLength(json) > MAX_REQUEST_BYTES) {
      throw new Error("Local Agent request size exceeded.");
    }
    const response = await localFetch(new URL(path, base), {
      method: json === undefined ? "GET" : "POST",
      headers: {
        "x-device-credential": localDeviceToken,
        ...(json === undefined ? {} : { "content-type": "application/json" }),
      },
      ...(json === undefined ? {} : { body: json }),
      signal: AbortSignal.timeout(30_000),
    });
    if (Number(response.headers.get("content-length")) > MAX_RESPONSE_BYTES) {
      await response.body?.cancel();
      throw new Error("Local Agent response size exceeded.");
    }
    if (!response.body) throw new Error("The local Agent returned an empty response.");
    const reader = response.body.getReader();
    const parts: Uint8Array[] = [];
    let size = 0;
    try {
      for (;;) {
        const item = await reader.read();
        if (item.done) break;
        size += item.value.byteLength;
        if (size > MAX_RESPONSE_BYTES) {
          await reader.cancel();
          throw new Error("Local Agent response size exceeded.");
        }
        parts.push(item.value);
      }
    } finally {
      reader.releaseLock();
    }
    const bytes = new Uint8Array(size);
    let at = 0;
    for (const part of parts) {
      bytes.set(part, at);
      at += part.byteLength;
    }
    const text = new TextDecoder().decode(bytes);
    try {
      return { status: response.status, body: JSON.parse(text) as unknown };
    } catch {
      throw new Error("The local Agent returned an unreadable response.");
    }
  }

  return {
    execute(tool, args, operationId) {
      if (!tool || typeof tool !== "string") throw new Error("Invalid local tool.");
      return request("/internal/call", {
        tool,
        arguments: args,
        ...(operationId === undefined ? {} : { operation_id: operationId }),
      });
    },
    operationStatus(operationId) {
      if (!/^(?!\.{1,2}$)[A-Za-z0-9._:-]{1,128}$/.test(operationId)) {
        throw new Error("Invalid operation identifier.");
      }
      return request("/internal/operations/" + encodeURIComponent(operationId));
    },
  };
}
