/**
 * v2 Agent lifecycle with separately gated read-only and T07 file-write capabilities.
 *
 * Hibernation heartbeat responses do not wake the DO. Both remote access
 * capabilities are disabled by default; this handler never executes Shell.
 */
import { DeviceSessionRejectedError, openAuthenticatedDeviceSocket } from "./v2-session-client.ts";
import { executeReadTool } from "./read-execution.ts";
import { parseLocalRead, parseReadMultiple, parseListDirectory, parseFileInfo, parseSearchStart, parseSearchSessionId, parseLocalWriteFile, parseLocalCreateDirectory, parseLocalEditBlock, parseLocalMoveFile, parseLocalDeleteFile, parseOperationId } from "./local-read.ts";
import { SearchSessions } from "./search.ts";
import { createAgentExecutionEngine, type AgentExecutionEngine } from "./execution.ts";
import { parseStartProcess, parseListSessions, parseReadProcessOutput, parseInteractWithProcess, parseForceTerminate } from "./sessions.ts";

/** One bounded Session read adapter, shared by the Agent and MCP/WSS tests. */
export async function executeV2SessionRead(
  execution: AgentExecutionEngine,
  tool: string,
  args: unknown,
  signal: AbortSignal,
): Promise<string | null> {
  if (tool !== "list_sessions" && tool !== "read_process_output") return null;
  try {
    const answer = await execution.executeTool({ tool, arguments: args }, signal);
    if (answer?.status !== 200) return null;
    const body = answer.body as { result?: { content?: Array<{ text?: unknown }> } };
    const text = body?.result?.content?.[0]?.text;
    return typeof text === "string" && text.length <= 65_536 ? text : null;
  } catch { return null; }
}

type V2FileOperation = "write_file" | "create_directory" | "edit_block" | "move_file" | "delete_file" | "start_process" | "interact_with_process" | "force_terminate" | "get_operation_status";

/** One adapter shared by production and tests; no new mutation executor. */
export async function executeV2FileOperation(
  execution: AgentExecutionEngine,
  tool: V2FileOperation,
  args: unknown,
  operationId: string,
  signal: AbortSignal,
): Promise<Record<string, unknown>> {
  try {
    if (tool === "get_operation_status") {
      const receipt = await execution.getReceipt(operationId);
      return { operation_id: operationId, status: receipt?.state ?? "not_found",
        ...(receipt ? { receipt } : {}) };
    }
    const outcome = await execution.executeTool({
      tool, arguments: args, operation_id: operationId,
    }, signal);
    if (outcome?.status === 409) return { operation_id: operationId, status: "conflict" };
    if (outcome?.status === 400) return { operation_id: operationId, status: "bad_request" };
    const body = outcome?.body;
    if (outcome?.status !== 200 || !body || typeof body !== "object" || Array.isArray(body)) {
      return { operation_id: operationId, status: "unavailable" };
    }
    return body as Record<string, unknown>;
  } catch {
    return { operation_id: operationId, status: "unavailable" };
  }
}

export type SocketEnd = "aborted" | "closed" | "offline" | "policy";
const PING = "rc-v2:ping";
const PONG = "rc-v2:pong";
const AUTH_REQUEST = "rc-v2:auth:";
const AUTH_RESPONSE = "rc-v2:auth-ok:";
const AUTH_INTERVAL_MS = 900_000; // 15 minutes; a deliberate, rare DO wake-up.
const HEARTBEAT_INTERVAL_MS = 60_000;
const HEARTBEAT_TIMEOUT_MS = 20_000;

export function monitorDeviceSocket(
  socket: WebSocket,
  signal: AbortSignal,
  timing: { intervalMs: number; timeoutMs: number; authIntervalMs?: number } = {
    intervalMs: HEARTBEAT_INTERVAL_MS, timeoutMs: HEARTBEAT_TIMEOUT_MS,
  },
  readOnly?: (tool: string, args: unknown, signal: AbortSignal) => Promise<string | null>,
  operation?: (tool: V2FileOperation, args: unknown, operationId: string, signal: AbortSignal) => Promise<Record<string, unknown> | null>,
  allowShell = false,
  revokeCleanup?: () => Promise<"confirmed" | "uncertain">,
): Promise<SocketEnd> {
  const authEvery = timing.authIntervalMs ?? AUTH_INTERVAL_MS;
  if (!Number.isFinite(timing.intervalMs) || timing.intervalMs <= 0 ||
      !Number.isFinite(timing.timeoutMs) || timing.timeoutMs <= 0 ||
      timing.timeoutMs >= timing.intervalMs ||
      !Number.isFinite(authEvery) || authEvery <= timing.timeoutMs) {
    throw new Error("Invalid Agent heartbeat interval.");
  }
  return new Promise((resolve) => {
    let settled = false;
    // A socket incarnation owns its pending reads; a reconnect must not
    // inherit their cancellation scope or keep them running after disconnect.
    const socketWork = new AbortController();
    let awaitingPong = false;
    let revocationStarted = false;
    let readsInFlight = 0;
    let awaitingAuth: string | undefined;
    let watchdog: ReturnType<typeof setTimeout> | undefined;
    let authWatchdog: ReturnType<typeof setTimeout> | undefined;
    let interval: ReturnType<typeof setInterval> | undefined;
    let authInterval: ReturnType<typeof setInterval> | undefined;
    const cleanup = () => {
      if (interval) clearInterval(interval);
      if (authInterval) clearInterval(authInterval);
      if (watchdog) clearTimeout(watchdog);
      if (authWatchdog) clearTimeout(authWatchdog);
      signal.removeEventListener("abort", onAbort);
      socket.removeEventListener("message", onMessage);
      socket.removeEventListener("close", onClose);
      socket.removeEventListener("error", onError);
    };
    const finish = (why: SocketEnd) => {
      if (settled) return;
      settled = true;
      socketWork.abort();
      cleanup();
      if (why !== "closed") {
        try { socket.close(); } catch { /* connection already gone */ }
      }
      resolve(why);
    };
    const onAbort = () => finish("aborted");
    const onClose = (event: Event) => {
      const { code, reason } = event as Event & { code?: number; reason?: string };
      finish(code === 1008 ? "policy" : code === 1000 && reason === "superseded" ? "closed" : "offline");
    };
    const onError = () => finish("offline");
    const onMessage = (event: MessageEvent) => {
      // Once an authenticated owner revocation arrives, no further ordinary
      // frames can dispatch work, even during the bounded cleanup attempt.
      if (revocationStarted) return;
      if (event.data === PONG) {
        if (!awaitingPong) return; // Ignore late duplicate pongs.
        awaitingPong = false;
        if (watchdog) clearTimeout(watchdog);
        watchdog = undefined;
        return;
      }
      if (typeof event.data === "string" && event.data.startsWith(AUTH_RESPONSE)) {
        // A delayed reply to an older check can never satisfy this request.
        // Ignore stale/duplicate replies, but retain the active deadline.
        if (!awaitingAuth || event.data !== AUTH_RESPONSE + awaitingAuth) return;
        awaitingAuth = undefined;
        if (authWatchdog) clearTimeout(authWatchdog);
        authWatchdog = undefined;
        return;
      }
      if (typeof event.data === "string" && event.data.length <= 65_536 &&
          event.data.startsWith("{") && (readOnly || operation || revokeCleanup)) {
        let request: Record<string, unknown> | undefined;
        try {
          const decoded = JSON.parse(event.data) as unknown;
          if (decoded && typeof decoded === "object" && !Array.isArray(decoded)) {
            request = decoded as Record<string, unknown>;
          }
        } catch { /* Not an authorized read frame. */ }
        if (request?.kind === "revoke_cleanup" &&
            Object.keys(request).length === 2 &&
            typeof request.request_id === "string" &&
            /^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(request.request_id) &&
            allowShell && revokeCleanup) {
          revocationStarted = true;
          socketWork.abort();
          const requestId = request.request_id;
          void Promise.resolve().then(revokeCleanup).then(status => {
            if (settled || socket.readyState !== WebSocket.OPEN) return;
            socket.send(JSON.stringify({
              kind: "revoke_cleanup_result", request_id: requestId,
              status: status === "confirmed" ? "confirmed" : "uncertain",
            }));
          }).catch(() => {
            if (!settled && socket.readyState === WebSocket.OPEN) {
              try { socket.send(JSON.stringify({
                kind: "revoke_cleanup_result", request_id: requestId, status: "uncertain",
              })); } catch { /* DO will report uncertain */ }
            }
          }).finally(() => finish("policy"));
          return;
        }
        const readParsers: Record<string, (args: unknown) => unknown> = {
          read_file: parseLocalRead, read_multiple_files: parseReadMultiple,
          list_directory: parseListDirectory, get_file_info: parseFileInfo,
          start_search: parseSearchStart, get_more_search_results: parseSearchSessionId,
          stop_search: parseSearchSessionId,
          list_sessions: parseListSessions, read_process_output: parseReadProcessOutput,
        };
        if (readOnly && request?.kind === "read" && typeof request.tool === "string" &&
            Object.hasOwn(readParsers, request.tool) &&
            typeof request.request_id === "string" &&
            /^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(request.request_id) &&
            Object.keys(request).length === 4 && readParsers[request.tool]?.(request.arguments) &&
            readsInFlight < 4) {
          readsInFlight++;
          const id = request.request_id;
          const tool = request.tool;
          void Promise.resolve().then(() => readOnly(tool, request.arguments, socketWork.signal))
            .then(text => {
              if (settled || signal.aborted || socket.readyState !== WebSocket.OPEN) return;
              const valid = typeof text === "string" && text.length <= 65_536;
              socket.send(JSON.stringify({
                kind: "read_result", request_id: id,
                status: valid ? "completed" : "failed",
                ...(valid ? { text } : {}),
              }));
            }).catch(() => {
              if (!settled && !signal.aborted && socket.readyState === WebSocket.OPEN) {
                try { socket.send(JSON.stringify({ kind: "read_result", request_id: id, status: "failed" })); }
                catch { finish("offline"); }
              }
            }).finally(() => { readsInFlight--; });
          return;
        }
        const mutationParsers: Record<string, (input: unknown) => unknown> = {
          write_file: parseLocalWriteFile, create_directory: parseLocalCreateDirectory,
          edit_block: parseLocalEditBlock, move_file: parseLocalMoveFile,
          delete_file: parseLocalDeleteFile, start_process: parseStartProcess,
          interact_with_process: parseInteractWithProcess, force_terminate: parseForceTerminate,
        };
        // A paired but read-only Agent must deny valid unsupported operations
        // without disconnecting its otherwise healthy signed WSS session.
        // Malformed or unrecognized frames still fail closed below.
        const mutationTool = typeof request?.tool === "string" &&
          Object.hasOwn(mutationParsers, request.tool);
        const shellTool = ["start_process", "interact_with_process", "force_terminate"]
          .includes(String(request?.tool));
        const validOperation = request?.kind === "operation" &&
          typeof request.tool === "string" &&
          (request.tool === "get_operation_status" || mutationTool) &&
          typeof request.operation_id === "string" &&
          Boolean(parseOperationId({ operation_id: request.operation_id })) &&
          typeof request.request_id === "string" &&
          /^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(request.request_id) &&
          Object.keys(request).length === 5 &&
          (request.tool === "get_operation_status"
            ? Boolean(parseOperationId(request.arguments)) &&
              (request.arguments as { operation_id: string }).operation_id === request.operation_id
            : Boolean(mutationParsers[request.tool]?.(request.arguments)));
        if (validOperation && (!operation || (shellTool && !allowShell))) {
          try {
            socket.send(JSON.stringify({
              kind: "operation_result", request_id: request!.request_id,
              result: { operation_id: request!.operation_id, status: "unavailable" },
            }));
          } catch { finish("offline"); }
          return;
        }
        if (operation && request?.kind === "operation" && typeof request.tool === "string" &&
            (request.tool === "get_operation_status" ||
              (Object.hasOwn(mutationParsers, request.tool) &&
                (!["start_process", "interact_with_process", "force_terminate"].includes(request.tool) || allowShell))) &&
            typeof request.operation_id === "string" &&
            parseOperationId({ operation_id: request.operation_id }) &&
            typeof request.request_id === "string" &&
            /^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(request.request_id) &&
            Object.keys(request).length === 5 &&
            (request.tool === "get_operation_status"
              ? Boolean(parseOperationId(request.arguments)) &&
                (request.arguments as { operation_id: string }).operation_id === request.operation_id
              : Boolean(mutationParsers[request.tool]?.(request.arguments))) &&
            readsInFlight < 4) {
          readsInFlight++;
          const requestId = request.request_id;
          const operationId = request.operation_id;
          const tool = request.tool as V2FileOperation;
          void Promise.resolve().then(() => operation(tool, request.arguments, operationId, socketWork.signal))
            .then(result => {
              if (settled || socketWork.signal.aborted || socket.readyState !== WebSocket.OPEN) return;
              const wire = JSON.stringify({ kind: "operation_result", request_id: requestId,
                result: result ?? { operation_id: operationId, status: "unavailable" } });
              if (wire.length > 65_536) throw new Error("operation response too large");
              socket.send(wire);
            }).catch(() => {
              if (!settled && !socketWork.signal.aborted && socket.readyState === WebSocket.OPEN) {
                try { socket.send(JSON.stringify({ kind: "operation_result", request_id: requestId,
                  result: { operation_id: operationId, status: "unavailable" } })); }
                catch { finish("offline"); }
              }
            }).finally(() => { readsInFlight--; });
          return;
        }
      }
      finish("policy"); // Never interpret unapproved remote traffic as a command.
    };
    if (signal.aborted) { finish("aborted"); return; }
    if (socket.readyState !== WebSocket.OPEN) { finish("offline"); return; }
    signal.addEventListener("abort", onAbort, { once: true });
    socket.addEventListener("message", onMessage);
    socket.addEventListener("close", onClose);
    socket.addEventListener("error", onError);
    interval = setInterval(() => {
      if (socket.readyState !== WebSocket.OPEN) { finish("offline"); return; }
      if (awaitingPong) return;
      awaitingPong = true;
      watchdog = setTimeout(() => finish("offline"), timing.timeoutMs);
      try { socket.send(PING); } catch { finish("offline"); }
    }, timing.intervalMs);
    // Automatic pongs prove transport liveness only. This separate low-frequency
    // check intentionally wakes the DO to verify the current device/epoch.
    authInterval = setInterval(() => {
      if (socket.readyState !== WebSocket.OPEN) { finish("offline"); return; }
      if (awaitingAuth) return;
      // Every authority check has a unique identifier. No fixed-string ACK
      // from an earlier check may authorize a later one after network delay.
      awaitingAuth = crypto.randomUUID().replace(/-/g, "");
      authWatchdog = setTimeout(() => finish("offline"), timing.timeoutMs);
      try { socket.send(AUTH_REQUEST + awaitingAuth); } catch { finish("offline"); }
    }, authEvery);
  });
}

/**
 * Bounded retry delay. Every reconnection obtains a FRESH signed nonce via
 * openAuthenticatedDeviceSocket; no ambiguous command or old nonce is replayed.
 * A policy close stops retrying until an operator restarts the Agent.
 */
export async function maintainAuthenticatedDeviceSession(
  baseAddress: string,
  keyPath: string,
  signal: AbortSignal,
  options: {
    send?: typeof fetch;
    makeSocket?: (url: string, protocols: string[]) => WebSocket;
    heartbeat?: { intervalMs: number; timeoutMs: number; authIntervalMs?: number };
    // Explicit opt-in for isolated T05 tests. Default remains authentication only.
    readOnly?: boolean;
    // Independent T07 capabilities. Both disabled in the shipped entrypoint.
    writeFile?: boolean;
    shell?: boolean;
    wait?: (milliseconds: number, signal: AbortSignal) => Promise<void>;
    onState?: (status: "connected" | "disconnected" | "rejected") => void;
  } = {},
): Promise<void> {
  const delay = options.wait ?? ((ms: number, abort: AbortSignal) =>
    new Promise<void>((resolve) => {
      if (abort.aborted) { resolve(); return; }
      const done = () => { clearTimeout(timer); abort.removeEventListener("abort", done); resolve(); };
      const timer = setTimeout(done, ms);
      abort.addEventListener("abort", done, { once: true });
    }));
  // One receipt engine for the Agent lifetime, not one per reconnect. The
  // original local receipt store owns idempotency; DO never stores/replays it.
  const execution = (options.writeFile || options.shell) ? createAgentExecutionEngine() : undefined;
  let failures = 0;
  try {
  while (!signal.aborted) {
    try {
      const connection = await openAuthenticatedDeviceSocket(
        baseAddress, keyPath, options.send, options.makeSocket, signal,
      );
      if (signal.aborted) { connection.socket.close(); break; }
      const connectedAt = performance.now();
      options.onState?.("connected");
      // Search cursors are scoped to one authenticated WSS incarnation.
      // Reconnect never inherits a stale/other-device cursor or replays a call.
      const searches = options.readOnly ? new SearchSessions() : undefined;
      let outcome: SocketEnd;
      try {
        outcome = await monitorDeviceSocket(connection.socket, signal, options.heartbeat,
          (options.readOnly || options.shell) ? async (tool, args, requestSignal) => {
            if (tool === "list_sessions" || tool === "read_process_output") {
              if (!options.shell || !execution) return null;
              return executeV2SessionRead(execution, tool, args, requestSignal);
            }
            if (!options.readOnly || !searches) return null;
            // Reuse the original bounded file/search engine.
            const reply = await executeReadTool(tool, args, searches, requestSignal);
            return reply.kind === "completed" ? reply.text : null;
          } : undefined,
          execution ? (tool, args, operationId, requestSignal) =>
            (["start_process", "interact_with_process", "force_terminate"].includes(tool) ? options.shell : options.writeFile)
              ? executeV2FileOperation(execution, tool, args, operationId, requestSignal)
              : Promise.resolve({ operation_id: operationId, status: "unavailable" }) : undefined,
          options.shell === true,
          options.shell && execution ? () => execution.stopOwnedForRevocation() : undefined);
      } finally {
        await searches?.close();
      }
      if (outcome === "aborted" || outcome === "closed") return;
      if (outcome === "policy") { options.onState?.("rejected"); return; }
      // Opening a socket is not evidence of stability. If an Agent loops
      // through brief successful handshakes, keep the escalating backoff.
      // After two healthy heartbeat periods, reset for fast future recovery.
      const intervalMs = options.heartbeat?.intervalMs ?? HEARTBEAT_INTERVAL_MS;
      if (performance.now() - connectedAt >= intervalMs * 2) failures = 0;
    } catch (error) {
      if (signal.aborted) break;
      if (error instanceof DeviceSessionRejectedError) {
        options.onState?.("rejected");
        return;
      }
      // Temporary transport faults remain retryable; no credential material or
      // raw exception objects are written to logs.
    }
    if (signal.aborted) break;
    options.onState?.("disconnected");
    const capped = Math.min(30_000, 1000 * 2 ** Math.min(failures, 5));
    failures++;
    await delay(capped, signal);
  }
  } finally {
    await execution?.close();
  }
}
