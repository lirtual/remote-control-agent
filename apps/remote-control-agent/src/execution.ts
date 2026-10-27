/**
 * Reusable in-process Agent operation engine.
 * No transport authentication lives here. Only an already-authorized Agent
 * transport with an explicit capability grant may invoke executeTool().
 * T02 intentionally does not connect this engine to unauthenticated v2 WSS.
 */
import { createManagedHandoff, type ProtectedTunnelConfig } from "./protected-tunnel.ts";
import { BrowserHandoff, HANDOFF_TOOLS, parseHandoffArguments } from "./browser-handoff.ts";
import { appendFile, link, lstat, mkdir, readFile, unlink, writeFile } from "node:fs/promises";
import path from "node:path";
import {
  parseLocalWriteFile, parseLocalCreateDirectory, parseLocalEditBlock,
  parseLocalMoveFile, parseLocalDeleteFile, parseOperationId,
} from "./local-read.ts";
import { operationDigest, ReceiptStore, type OperationReceipt } from "./operations.ts";
import { admitOwnerApprovedUpgrade, type RemoteUpgradeAdmission } from "./remote-upgrade-admission.ts";
import { stageAndLaunchApprovedWindowsUpgrade, readNativeUpgradeOutcome } from "./windows-upgrade-executor.ts";
import { collectDeviceInfo } from "./device-info.ts";
import { fileURLToPath } from "node:url";
import { BrowserOperationGateway, BROWSER_READ_TOOLS, BROWSER_EFFECT_TOOLS, browserToolIsRead } from "./browser-operations.ts";
import type { BrowserBackend } from "./browser-backend.ts";
import { executeReadTool } from "./read-execution.ts";
import { SearchSessions } from "./search.ts";
import {
  ManagedSessions, parseForceTerminate, parseInteractWithProcess,
  parseListSessions, parseReadProcessOutput, parseStartProcess,
} from "./sessions.ts";

export interface AgentExecutionOptions {
  log?: (event: string) => void;
  /** Native deployment validation, never selected through MCP. */
  verifyHandoffPrerequisites?: () => ProtectedTunnelConfig | void;
  /** Bound only after signed device authentication. */
  handoffDeviceId?: () => string | undefined;
  /** Windows-only private receipt ACL sealing; never controlled by MCP. */
  sealHandoffEvidence?: (kind: "directory" | "pending") => void;
  searchSessionTtlMs?: number;
  receiptDirectory?: string;
  shellPath?: string;
  /** Source-staged, explicitly injected browser backend; absent in production. */
  browser?: BrowserBackend;
  /** Test-only managed Tunnel factory; production always uses createManagedHandoff. */
  handoffFactory?: typeof createManagedHandoff;
  /** Local-only test seam: production uses the 60-minute deadline. */
  sessionMaxLifetimeMs?: number;
  /** Local-only storage error probe, never routed through MCP. */
  receiptFaultForTests?: (phase: "begin" | "commit") => boolean;
  /** Explicit operator-verified historical backup, never selected by remote callers. */
  receiptHistoricalBackupPath?: string;
}
export interface AgentExecutionReply {
  status: number;
  body: unknown;
}
export interface AgentExecutionEngine {
  executeTool(
    body: { tool?: unknown; arguments?: unknown; operation_id?: unknown },
    signal: AbortSignal,
  ): Promise<AgentExecutionReply | undefined>;
  getReceipt(id: string): Promise<(Partial<OperationReceipt> & Pick<OperationReceipt,"operation_id" | "state">) | null>;
  /** Only callable by an authenticated WSS upgrade handler after owner-DO claim.
   * Validates and records but does NOT yet spawn an updater or switch versions. */
  admitUpgrade(input: unknown, local: {
    signedDeviceId: string; originalVersion: string; privateKeyPem: string;
    confirmedByAuthenticatedWorker: boolean;
  }): Promise<RemoteUpgradeAdmission>;
  handoffGeneration(): number;
  handoffBlocked(): boolean;
  resetReadSessions(): Promise<void>;
  stopOwnedForRevocation(): Promise<"confirmed" | "uncertain">;
  freezeForUpgrade(): boolean;
  releaseUpgradeFreeze(): void;
  close(): Promise<void>;
}

/** Native Windows uses its bundled PowerShell, not Linux /bin/sh. */
export function defaultAgentShellPath(
  platform = process.platform,
  systemRoot = process.env.SystemRoot,
): string {
  if (platform !== "win32") return process.env.SHELL ?? "/bin/sh";
  if (!systemRoot || !path.win32.isAbsolute(systemRoot) ||
      !/^[A-Za-z]:[\\\\/]/.test(systemRoot) || systemRoot.startsWith("\\\\\\\\")) {
    throw Error("A native Windows SystemRoot is required for managed commands.");
  }
  return path.win32.join(systemRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
}

/** Must be constructed once per Agent process: shared inFlight map and receipts. */
export function createAgentExecutionEngine(options: AgentExecutionOptions = {}): AgentExecutionEngine {
  const emit = (log: AgentExecutionOptions["log"], event: string) => log?.(event);
  const log = options.log;
  const searches = new SearchSessions(options.searchSessionTtlMs);
  const sessions = new ManagedSessions(options.shellPath ?? defaultAgentShellPath(), options.sessionMaxLifetimeMs);
  const receipts = new ReceiptStore(options.receiptDirectory, options.receiptFaultForTests, options.receiptHistoricalBackupPath);
  let receiptsReady: Promise<void> | undefined;
  const ensureReceipts = () => (receiptsReady ??= receipts.open().catch(error => {
    receiptsReady = undefined;
    throw error;
  }));
  const inFlight = new Map<string, Promise<OperationReceipt | undefined>>();
  const handoff = new BrowserHandoff(receipts.directory, options.sealHandoffEvidence);
  let activeCalls = 0;
  let upgradeFrozen = false;
  let stopped = false;
  // Detached preparation must join shutdown before SQLite receipts are closed.
  let handoffPreparation: Promise<void> | undefined;
  const browser = options.browser ? new BrowserOperationGateway(options.browser, receipts, ensureReceipts) : undefined;

  type MutationTool = "write_file" | "create_directory" | "edit_block" | "move_file" | "delete_file";
  type MutationArgs =
    | NonNullable<ReturnType<typeof parseLocalWriteFile>>
    | NonNullable<ReturnType<typeof parseLocalCreateDirectory>>
    | NonNullable<ReturnType<typeof parseLocalEditBlock>>
    | NonNullable<ReturnType<typeof parseLocalMoveFile>>
    | NonNullable<ReturnType<typeof parseLocalDeleteFile>>;

  async function performMutation(id: string, tool: MutationTool, args: MutationArgs): Promise<OperationReceipt | undefined> {
    await receipts.update(id, "running", "Operation is in progress.");
    try {
      if (tool === "write_file") {
        const write = args as NonNullable<ReturnType<typeof parseLocalWriteFile>>;
        if (write.mode === "append") await appendFile(write.path, write.content, "utf8");
        else await writeFile(write.path, write.content, "utf8");
      } else if (tool === "create_directory") {
        await mkdir((args as NonNullable<ReturnType<typeof parseLocalCreateDirectory>>).path);
      } else if (tool === "edit_block") {
        const edit = args as NonNullable<ReturnType<typeof parseLocalEditBlock>>;
        const originalBytes = await readFile(edit.filePath);
        const original = Buffer.from(originalBytes).toString("utf8");
        if (!Buffer.from(original, "utf8").equals(originalBytes)) {
          await receipts.update(id, "failed", "The file is not valid UTF-8 text.", undefined, true);
          emit(log, "edit_failed");
          return await receipts.get(id) ?? undefined;
        }
        let count = 0;
        for (let offset = 0; (offset = original.indexOf(edit.oldString, offset)) !== -1; offset += edit.oldString.length) count += 1;
        if (count !== edit.expectedReplacements) {
          await receipts.update(id, "failed", "Expected text replacement count did not match.", undefined, true);
          emit(log, "edit_failed");
          return await receipts.get(id) ?? undefined;
        }
        await writeFile(edit.filePath, original.split(edit.oldString).join(edit.newString), "utf8");
      } else if (tool === "delete_file") {
        const target = (args as NonNullable<ReturnType<typeof parseLocalDeleteFile>>).path;
        const info = await lstat(target);
        if (!info.isFile()) {
          await receipts.update(id, "failed", "The target is not a regular file.", undefined, true);
          emit(log, "delete_failed");
          return await receipts.get(id) ?? undefined;
        }
        await unlink(target);
      } else {
        const move = args as NonNullable<ReturnType<typeof parseLocalMoveFile>>;
        const source = path.resolve(move.source);
        const destination = path.resolve(move.destination);
        if (source === destination) {
          await receipts.update(id, "failed", "Source and destination must differ.", undefined, true);
          emit(log, "move_failed");
          return await receipts.get(id) ?? undefined;
        }
        const sourceInfo = await lstat(source);
        if (!sourceInfo.isFile()) {
          await receipts.update(id, "failed", "The source is not a regular file.", undefined, true);
          emit(log, "move_failed");
          return await receipts.get(id) ?? undefined;
        }
        await link(source, destination);
        try {
          await unlink(source);
        } catch {
          try {
            await unlink(destination);
          } catch {
            return await receipts.update(id, "unknown", "Move outcome cannot be established.");
          }
          emit(log, "move_failed");
          return await receipts.update(id, "failed", "Move did not complete.");
        }
      }
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      const knownNoEffect = ["EACCES", "EPERM", "ENOENT", "EISDIR", "ENOTDIR", "EEXIST", "EINVAL", "EXDEV", "EOPNOTSUPP", "ENOTSUP"].includes(code ?? "");
      emit(log, tool === "write_file" ? "write_failed" : tool === "create_directory" ? "directory_failed" : tool === "edit_block" ? "edit_failed" : tool === "delete_file" ? "delete_failed" : "move_failed");
      try {
        return await receipts.update(id, knownNoEffect ? "failed" : "unknown", "Operation did not complete.", undefined, knownNoEffect);
      } catch { return undefined; }
    }
    emit(log, tool === "write_file" ? "write_completed" : tool === "create_directory" ? "directory_completed" : tool === "edit_block" ? "edit_completed" : tool === "delete_file" ? "delete_completed" : "move_completed");
    try { return await receipts.update(id, "completed", "Operation completed."); }
    catch { return undefined; }
  }

  async function performSessionAction(
    id: string,
    tool: "interact_with_process" | "force_terminate",
    sessionId: string,
    args: unknown,
    action: () => Promise<"completed" | "failed" | "unknown" | "not_found">,
  ): Promise<{ statusCode: number; status: string; receipt?: OperationReceipt }> {
    const digest = operationDigest(tool, args);
    let admitted: Awaited<ReturnType<typeof receipts.admit>>;
    try {
      await ensureReceipts();
      const existing = await receipts.get(id);
      if (!existing && !sessions.get(sessionId)) return { statusCode: 404, status: "not_found" };
      admitted = await receipts.admit(id, tool, digest);
    } catch {
      // When storage is unavailable, the authenticated owner retains only
      // the narrow emergency stop for an already Agent-owned session.
      if (tool === "force_terminate" && ["running", "unknown"].includes(sessions.get(sessionId)?.state ?? "")) {
        try { await sessions.terminate(sessionId); } catch { /* Outcome remains unknown. */ }
        return { statusCode: 200, status: "unknown" };
      }
      return { statusCode: 503, status: "unavailable" };
    }
    if (admitted.kind === "conflict") {
      emit(log, "operation_conflict");
      return { statusCode: 409, status: "conflict" };
    }
    if (admitted.kind === "full") return { statusCode: 503, status: "unavailable" };

    let pending = inFlight.get(id);
    if (admitted.kind === "new") {
      emit(log, "operation_admitted");
      pending = (async () => {
        await receipts.update(id, "running", "Session action is in progress.", sessionId);
        let outcome: "completed" | "failed" | "unknown" | "not_found";
        try { outcome = await action(); }
        catch { outcome = "unknown"; }
        const state = outcome === "not_found" ? "failed" : outcome;
        const summary = outcome === "completed" ? "Session action completed."
          : outcome === "failed" || outcome === "not_found" ? "Session action was rejected."
            : "Session action outcome is unknown.";
        return await receipts.update(id, state, summary, sessionId);
      })();
      inFlight.set(id, pending);
      void pending.then(() => inFlight.delete(id), () => inFlight.delete(id));
    }
    if (!pending && admitted.receipt && (admitted.receipt.state === "admitted" || admitted.receipt.state === "running")) {
      const unknown = await receipts.update(id, "unknown", "Effect cannot be established.", sessionId);
      return { statusCode: 200, status: "unknown", receipt: unknown };
    }
    try {
      const receipt = pending ? await pending : admitted.receipt;
      return { statusCode: 200, status: receipt?.state ?? "unknown", receipt };
    } catch {
      return { statusCode: 200, status: "unknown" };
    }
  }

  async function executeToolCore(
    body: { tool?: unknown; arguments?: unknown; operation_id?: unknown },
    signal: AbortSignal,
  ): Promise<AgentExecutionReply | undefined> {
    let reply: AgentExecutionReply | undefined;
    const respond = (status: number, result: unknown): void => { reply = { status, body: result }; };
    if (typeof body.tool === "string" &&
        ([...BROWSER_READ_TOOLS, ...BROWSER_EFFECT_TOOLS] as string[]).includes(body.tool)) {
      if (!browser) { respond(503, { status: "unavailable" }); return reply; }
      if (browserToolIsRead(body.tool, body.arguments)) {
        const result = await browser.read(body.tool as typeof BROWSER_READ_TOOLS[number], body.arguments);
        respond(result === null ? 400 : 200, result === null
          ? { status: "failed" } : { status: "completed", result: { content: [{ type: "text", text: result }] } });
      } else {
        const id = typeof body.operation_id === "string" ? body.operation_id : "";
        const result = await browser.submit(body.tool as typeof BROWSER_EFFECT_TOOLS[number], body.arguments, id);
        respond(result.status === "bad_request" ? 400 : result.status === "conflict" ? 409 : 200, result);
      }
      return reply;
    }
    if (body.tool === "write_file" || body.tool === "create_directory" || body.tool === "edit_block" || body.tool === "move_file" || body.tool === "delete_file") {
      const id = typeof body.operation_id === "string" ? body.operation_id : null;
      if (!id || !parseOperationId({ operation_id: id })) {
        emit(log, "rejected");
        respond(400, { error: "bad_request", message: "A valid operation id is required." });
        return reply;
      }
      const mutation = body.tool === "write_file" ? parseLocalWriteFile(body.arguments)
        : body.tool === "create_directory" ? parseLocalCreateDirectory(body.arguments)
          : body.tool === "edit_block" ? parseLocalEditBlock(body.arguments)
            : body.tool === "move_file" ? parseLocalMoveFile(body.arguments)
              : parseLocalDeleteFile(body.arguments);
      if (!mutation) {
        emit(log, "rejected");
        respond(400, { operation_id: id, error: "bad_request", message: "The operation request was rejected." });
        return reply;
      }
      const normalized = body.tool === "write_file"
        ? { ...(mutation as NonNullable<ReturnType<typeof parseLocalWriteFile>>), path: path.resolve((mutation as NonNullable<ReturnType<typeof parseLocalWriteFile>>).path) }
        : body.tool === "create_directory"
          ? { path: path.resolve((mutation as NonNullable<ReturnType<typeof parseLocalCreateDirectory>>).path) }
          : body.tool === "edit_block"
            ? { ...(mutation as NonNullable<ReturnType<typeof parseLocalEditBlock>>), filePath: path.resolve((mutation as NonNullable<ReturnType<typeof parseLocalEditBlock>>).filePath) }
            : body.tool === "move_file"
              ? { source: path.resolve((mutation as NonNullable<ReturnType<typeof parseLocalMoveFile>>).source), destination: path.resolve((mutation as NonNullable<ReturnType<typeof parseLocalMoveFile>>).destination) }
              : { path: path.resolve((mutation as NonNullable<ReturnType<typeof parseLocalDeleteFile>>).path) };
      const digest = operationDigest(body.tool, normalized);
      let admitted: Awaited<ReturnType<typeof receipts.admit>>;
      try {
        await ensureReceipts();
        admitted = await receipts.admit(id, body.tool, digest);
      } catch {
        respond(503, { operation_id: id, status: "unavailable", error: "unavailable", message: "The operation could not be admitted." });
        return reply;
      }
      if (admitted.kind === "conflict") {
        emit(log, "operation_conflict");
        respond(409, { operation_id: id, error: "conflict", message: "The operation id is already used for different parameters." });
        return reply;
      }
      if (admitted.kind === "full") {
        respond(503, { operation_id: id, status: "unavailable", error: "unavailable", message: "Operation receipts are at capacity." });
        return reply;
      }
      let pending = inFlight.get(id);
      if (admitted.kind === "new") {
        emit(log, "operation_admitted");
        pending = performMutation(id, body.tool, normalized);
        inFlight.set(id, pending);
        void pending.then(() => inFlight.delete(id), () => inFlight.delete(id));
      }
      if (!pending && admitted.receipt && (admitted.receipt.state === "admitted" || admitted.receipt.state === "running")) {
        const unknown = await receipts.update(id, "unknown", "Effect cannot be established.");
        respond(200, { operation_id: id, status: "unknown", receipt: unknown });
        return reply;
      }
      let receipt: OperationReceipt | undefined;
      try {
        receipt = pending ? await pending : admitted.receipt;
      } catch {
        respond(200, {
          operation_id: id,
          status: "unknown",
          error: { code: "timeout_unknown", message: "The write outcome is unknown." },
        });
        return reply;
      }
      if (signal.aborted) return;
      const state = receipt?.state ?? "unknown";
      if (state === "failed") {
        respond(200, { operation_id: id, status: "failed", error: { code: "bad_request", message: "The operation failed." }, receipt });
      } else if (state === "unknown") {
        respond(200, { operation_id: id, status: "unknown", error: { code: "timeout_unknown", message: "The operation outcome is unknown." }, receipt });
      } else {
        respond(200, { operation_id: id, status: state, result: { content: [{ type: "text", text: "Operation completed." }] }, receipt });
      }
      return reply;
    }
    if (body.tool === "start_process") {
      const id = typeof body.operation_id === "string" ? body.operation_id : null;
      const processArgs = parseStartProcess(body.arguments);
      if (!id || !parseOperationId({ operation_id: id }) || !processArgs) {
        emit(log, "rejected");
        respond(400, { error: "bad_request", message: "The process request was rejected." });
        return reply;
      }
      const digest = operationDigest(body.tool, processArgs);
      let admitted: Awaited<ReturnType<typeof receipts.admit>>;
      try {
        await ensureReceipts();
        admitted = await receipts.admit(id, "start_process", digest);
      } catch {
        respond(503, { operation_id: id, status: "unavailable", error: "unavailable", message: "The operation could not be admitted." });
        return reply;
      }
      if (admitted.kind === "conflict") {
        emit(log, "operation_conflict");
        respond(409, { operation_id: id, error: "conflict", message: "The operation id is already used for different parameters." });
        return reply;
      }
      if (admitted.kind === "full") {
        respond(503, { operation_id: id, status: "unavailable", error: "unavailable", message: "Operation receipts are at capacity." });
        return reply;
      }
      let pending = inFlight.get(id);
      if (admitted.kind === "new") {
        emit(log, "operation_admitted");
        pending = (async () => {
          await receipts.update(id, "running", "Development command is starting.");
          try {
            const session = await sessions.start(processArgs.command, processArgs.timeoutMs, async (exited) => {
              await receipts.update(id, exited.state, exited.termination_reason === "deadline_exceeded"
                ? "Managed command exceeded the 60-minute deadline."
                : "Development command session ended.", exited.session_id);
            });
            // On quick exits the exit callback may settle first: never overwrite
            // a completed/failed receipt with an earlier running snapshot.
            const latest = await receipts.get(id);
            if (latest && ["completed", "failed", "unknown"].includes(latest.state)) return latest;
            return await receipts.update(id, session.state, "Development command session recorded.", session.session_id);
          } catch (error) {
            // Only classify known Agent-generated failures: never persist arbitrary
            // exception messages, commands, file paths, or environment values.
            const message = error instanceof Error ? error.message : "";
            const reason = message === "Session capacity reached."
              ? "session_capacity"
              : message === "The managed Shell supervisor is unavailable on this Linux kernel."
                ? "supervisor_unavailable"
                : message === "The development command could not be started."
                  ? "process_spawn_failed"
                  : "process_start_internal";
            emit(log, "process_failed");
            return await receipts.update(id, "failed", "Development command start failed: " + reason, undefined, reason === "session_capacity");
          }
        })();
        inFlight.set(id, pending);
        void pending.then(() => inFlight.delete(id), () => inFlight.delete(id));
      }
      const existingSession = admitted.receipt?.session_id ? sessions.get(admitted.receipt.session_id) : null;
      if (!pending && admitted.receipt && (admitted.receipt.state === "admitted" || admitted.receipt.state === "running") && !existingSession) {
        const unknown = await receipts.update(id, "unknown", "Effect cannot be established.");
        respond(200, { operation_id: id, status: "unknown", receipt: unknown });
        return reply;
      }
      let receipt: OperationReceipt | undefined;
      try {
        receipt = pending ? await pending : admitted.receipt;
      } catch {
        respond(200, { operation_id: id, status: "unknown", error: { code: "timeout_unknown", message: "The command outcome is unknown." } });
        return reply;
      }
      if (signal.aborted) return;
      const state = existingSession?.state ?? receipt?.state ?? "unknown";
      if (state === "failed") {
        emit(log, "process_failed");
        respond(200, { operation_id: id, status: state, session_id: receipt?.session_id, error: { code: "process_start_failed", message: "The development command failed. Check the operation receipt for a safe failure reason." }, receipt });
      } else {
        emit(log, "process_started");
        respond(200, { operation_id: id, status: state, session_id: receipt?.session_id });
      }
      return reply;
    }

    if (body.tool === "interact_with_process" || body.tool === "force_terminate") {
      const id = typeof body.operation_id === "string" ? body.operation_id : null;
      const interaction = body.tool === "interact_with_process" ? parseInteractWithProcess(body.arguments) : null;
      const termination = body.tool === "force_terminate" ? parseForceTerminate(body.arguments) : null;
      const operation = interaction ?? termination;
      if (!id || !parseOperationId({ operation_id: id }) || !operation) {
        emit(log, "rejected");
        respond(400, { error: "bad_request", message: "The session action was rejected." });
        return reply;
      }
      const sessionId = operation.sessionId;
      const args = body.tool === "interact_with_process"
        ? { session_id: sessionId, input: interaction?.input }
        : { session_id: sessionId };
      const outcome = await performSessionAction(
        id,
        body.tool,
        sessionId,
        args,
        () => body.tool === "interact_with_process"
          ? sessions.writeInput(sessionId, interaction?.input ?? "")
          : sessions.terminate(sessionId),
      );
      if (signal.aborted) return;
      if (outcome.statusCode !== 200) {
        const message = outcome.status === "conflict"
          ? "The operation id is already used for different parameters."
          : outcome.status === "not_found" ? "The session was not found."
            : "The session action could not be admitted.";
        respond(outcome.statusCode, {
          operation_id: id,
          status: outcome.status,
          error: outcome.status === "conflict" ? "conflict" : outcome.status === "not_found" ? "not_found" : "unavailable",
          message,
        });
        return reply;
      }
      if (outcome.status === "failed") {
        emit(log, "process_action_failed");
        respond(200, { operation_id: id, status: "failed", error: { code: "bad_request", message: "The session action could not be completed." }, receipt: outcome.receipt });
      } else if (outcome.status === "unknown") {
        respond(200, { operation_id: id, status: "unknown", error: { code: "timeout_unknown", message: "The session action outcome is unknown." }, receipt: outcome.receipt });
      } else {
        emit(log, body.tool === "force_terminate" ? "process_terminated" : "process_input_sent");
        respond(200, { operation_id: id, status: "completed", session_id: sessionId, receipt: outcome.receipt });
      }
      return reply;
    }

    if (body.tool === "list_sessions") {
      if (!parseListSessions(body.arguments)) {
        emit(log, "rejected");
        respond(400, { error: "bad_request", message: "The session request was rejected." });
        return reply;
      }
      emit(log, "process_listed");
      respond(200, { status: "completed", result: { content: [{ type: "text", text: JSON.stringify(sessions.list()) }] } });
      return reply;
    }

    if (body.tool === "read_process_output") {
      const outputRequest = parseReadProcessOutput(body.arguments);
      if (!outputRequest) {
        emit(log, "rejected");
        respond(400, { error: "bad_request", message: "The process output request was rejected." });
        return reply;
      }
      const page = sessions.read(outputRequest.sessionId, outputRequest.offset, outputRequest.length);
      if (!page) {
        emit(log, "not_found");
        respond(404, { error: "not_found", message: "The session was not found." });
        return reply;
      }
      emit(log, "process_output_read");
      respond(200, { status: "completed", result: { content: [{ type: "text", text: JSON.stringify(page) }] } });
      return reply;
    }
    const outcome = await executeReadTool(
      body.tool, body.arguments, searches, signal, () => emit(log, "search_started"),
    );
    if (signal.aborted) return;
    if (outcome.kind === "rejected") {
      emit(log, "rejected");
      respond(400, {
        error: "bad_request",
        message: outcome.message,
      });
      return reply;
    }
    if (outcome.kind === "failed") {
      emit(log, outcome.event);
      respond(200, {
        status: "failed",
        error: { code: outcome.code, message: outcome.message },
      });
      return reply;
    }
    if (outcome.kind === "unavailable") {
      emit(log, "unavailable");
      respond(503, {
        error: "unavailable",
        message: "The local file service is unavailable.",
      });
      return reply;
    }
    emit(log, outcome.event);
    respond(200, {
      status: "completed",
      result: { content: [{ type: "text", text: outcome.text }] },
    });
    return reply;
  }

  // Count admissions from BEFORE the first await. An async SQLite admit or
  // process spawn must not be invisible to the in-process upgrade handshake.
  async function executeTool(
    body: { tool?: unknown; arguments?: unknown; operation_id?: unknown },
    signal: AbortSignal,
  ): Promise<AgentExecutionReply | undefined> {
    if ((HANDOFF_TOOLS as readonly unknown[]).includes(body.tool)) {
      if (!parseHandoffArguments(String(body.tool),body.arguments)) return {status:400,body:{status:"bad_request"}};
      if (body.tool === "browser_handoff_status") return {status:200,body:handoff.status()};
      if (body.tool === "browser_handoff_return") {
        return {status:200,body:await handoff.explicitReturn(async () => {
          if (activeCalls || browser?.hasPending() || inFlight.size) throw Error("Effects still pending.");
          // Once the human controller has been revoked and all input has settled,
          // explicit owner return may reconcile an uncertain human input without
          // replaying it. Invalidation forces a new tab list and fresh snapshot.
          if (options.browser?.status() && !options.browser.invalidateHandoffReferences) throw Error("Reference invalidation unavailable.");
          await options.browser?.invalidateHandoffReferences?.();
          await searches.close();
        })};
      }
      if (stopped || upgradeFrozen) return {status:503,body:{status:"unavailable"}};
      if (!options.browser && !handoff.isBlocked()) return {status:503,body:{status:"unavailable"}};
      const sessionId = (body.arguments as {session_id:string}).session_id;
      // Same authorized owner/session may claim an already prepared URL only once.
      // A claim never spawns another Tunnel and consumes the in-memory link
      // synchronously before the WSS response is sent.
      if (!handoff.begin(sessionId)) {
        const link=handoff.claim(sessionId);
        return {status:200,body:{...handoff.status(),...(link ?? {})}};
      }
      const handoffGeneration = handoff.generation();
      // First call must return immediately: ChatGPT/MCP ingress may time out
      // before the bounded 90s Cloudflare challenge finishes. The device-wide
      // barrier and durable marker were written synchronously by begin().
      const preparation=(async () => {
        try {
          // Block first, then allow previously admitted work to settle. Never
          // replay an external browser effect after a transport timeout.
          const drainDeadline=Date.now()+10_000;
          while (!stopped && !handoff.preparationCancelled() && (activeCalls || browser?.hasPending() || inFlight.size) && Date.now()<drainDeadline)
            await new Promise(resolve=>setTimeout(resolve,20));
          if (stopped || handoff.preparationCancelled()) throw Error("handoff_cancelled");
          const current=options.browser?.status();
          if (activeCalls || browser?.hasPending() || inFlight.size || current?.uncertain) {
            handoff.failed("in_flight_effect_unknown"); return;
          }
          if (!current || current.session_id!==sessionId) {
            handoff.failed("browser_session_unavailable"); return;
          }
          await ensureReceipts();
          if (stopped || handoff.preparationCancelled()) throw Error("handoff_cancelled");
          if (receipts.hasUnresolvedBrowserOperations(sessionId)) {
            handoff.failed("browser_receipt_unknown"); return;
          }
          const config=options.verifyHandoffPrerequisites?.();
          const deviceId=options.handoffDeviceId?.();
          if (!config || !deviceId || !options.browser || stopped || handoff.preparationCancelled()) throw Error("handoff_prerequisites_unverified");
          const access=(options.handoffFactory ?? createManagedHandoff)({
            directory:receipts.directory,config,browser:options.browser,deviceId,sessionId,
            connected:()=>handoff.connected(),
            diagnostic:code=>handoff.reportControllerDiagnostic(code,handoffGeneration),
            explicitReturn:async()=>executeTool({tool:"browser_handoff_return",arguments:{}},new AbortController().signal),
          });
          handoff.attach(access);
          const ready=await access.start();
          if (stopped || handoff.preparationCancelled()) { await handoff.stopAccess(); throw Error("handoff_cancelled"); }
          handoff.ready(access,ready.expiresAt,{sessionId,url:ready.url});
        } catch {
          const cleanup=await handoff.stopAccess();
          handoff.failed(cleanup==="confirmed" ? "protected_tunnel_readiness_unverified" : "cleanup_unknown");
        }
      })().catch(()=>handoff.failed("cleanup_unknown"));
      handoffPreparation=preparation;
      void preparation.then(()=>{ if (handoffPreparation===preparation) handoffPreparation=undefined; });
      return {status:200,body:handoff.status()};
    }
    if (stopped) return {status:503,body:{status:"failed"}};
    if (handoff.isBlocked()) return {status:423,body:{status:"handoff_blocked"}};
    const generation = handoff.generation();
    if (upgradeFrozen) return {status:503,body:{status:"unavailable"}};
    activeCalls++;
    try {
      const result = await executeToolCore(body, signal);
      // A call admitted before handoff can never return its old sensitive payload,
      // even if explicit return completed while the result was being computed.
      return generation !== handoff.generation() || handoff.isBlocked()
        ? {status:423,body:{status:"handoff_blocked",
          ...(typeof body.operation_id === "string" ? {operation_id:body.operation_id} : {})}}
        : result;
    } finally { activeCalls--; }
  }

  return {
    executeTool,
    admitUpgrade: async (input, local) => {
      if (stopped || upgradeFrozen || handoff.isBlocked() ||
          activeCalls > 0 || inFlight.size > 0 ||
          (browser?.hasPending() ?? false) || Boolean(options.browser?.status()) ||
          !sessions.isQuiescentForUpgrade()) return { status: "unavailable" };
      upgradeFrozen = true;
      try {
        await ensureReceipts();
        const receipt = await admitOwnerApprovedUpgrade(receipts,input,{
          ...local,platform:process.platform,
        });
        if (receipt.status !== "admitted" || !receipt.operation_id) {
          upgradeFrozen = false;
          return receipt;
        }
        // The WSS operation ACK is an ADMISSION, never an upgrade success.
        // Subsequent staging occurs independently; the Agent remains frozen
        // until the Task switch stops it or failure is recorded locally.
        const approvedId = receipt.operation_id;
        const task = (async () => {
          try {
            await receipts.update(approvedId,"running","Immutable release staging pending.");
            const sourceRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)),"..","..","..");
            const receiptRoot = options.receiptDirectory;
            if (!receiptRoot) throw Error("Missing installed native receipts directory.");
            const result = await stageAndLaunchApprovedWindowsUpgrade(input,{
              installedRoot:sourceRoot,
              stateRoot:path.dirname(receiptRoot),
              systemRoot:process.env.SystemRoot ?? "",
            });
            if (result !== "launched") throw Error("No isolated updater was launched.");
            // Do not mark completed until a NEW authenticated WSS incarnation
            // proves the installed target and watchdog records a local result.
          } catch {
            try {
              // The child could have started before WMI transport returned;
              // unknown must remain replay-guarded even on a timeout.
              await receipts.update(approvedId,"unknown","Native upgrade effect needs reconciliation.");
            } catch { /* Never declare success after a persistence failure. */ }
            upgradeFrozen = false;
          }
        })();
        // Keep shutdown waiting for pre-switch staging, but never request
        // or simulate a local console Y confirmation.
        void task.catch(()=>{upgradeFrozen=false;});
        return receipt;
      } catch {
        upgradeFrozen = false;
        return { status: "unavailable" };
      }
    },
    handoffGeneration: () => handoff.generation(),
    handoffBlocked: () => handoff.isBlocked(),
    resetReadSessions: () => searches.close(),
    freezeForUpgrade: () => {
      if (upgradeFrozen || handoff.isBlocked()) return false;
      // Setting this first excludes any new admission in the same JS event loop.
      upgradeFrozen = true;
      if (activeCalls > 0 || inFlight.size > 0 ||
          (browser?.hasPending() ?? false) || Boolean(options.browser?.status()) ||
          !sessions.isQuiescentForUpgrade()) {
        upgradeFrozen = false;
        return false;
      }
      return true;
    },
    releaseUpgradeFreeze: () => { upgradeFrozen = false; },
    getReceipt: async (id: string) => {
      const generation = handoff.generation();
      await ensureReceipts();
      let receipt = await receipts.get(id);
      if (receipt?.tool_name === "upgrade_agent" &&
          ["admitted","running","unknown"].includes(receipt.state) &&
          options.receiptDirectory && process.platform === "win32" &&
          !handoff.isBlocked() && generation === handoff.generation()) {
        const observed = await readNativeUpgradeOutcome(
          options.receiptDirectory,id,collectDeviceInfo().agent_version);
        if (observed === "completed") {
          receipt = await receipts.update(id,"completed",
            "New Agent signed WSS, exact native Task and watchdog outcome verified.");
        } else if (observed === "rolled_back") {
          receipt = await receipts.update(id,"failed",
            "Watchdog restored original native user Task; owner review required.");
        }
      }
      return receipt && (handoff.isBlocked() || generation !== handoff.generation())
        ? {operation_id:receipt.operation_id,state:receipt.state} : receipt;
    },
    stopOwnedForRevocation: async () => {
      stopped = true;
      // Operations already admitted before the tombstone may still be
      // starting a supervised process: never overclaim complete cleanup.
      const accessOutcome = await handoff.stopAccess();
      await handoffPreparation;
      const pendingEffects = inFlight.size > 0 || (browser?.hasPending() ?? false) || accessOutcome !== "confirmed";
      let browserOutcome: "confirmed" | "uncertain" = "confirmed";
      const active = options.browser?.status();
      if (options.browser?.stopOwnedForRevocation) {
        try { browserOutcome = await options.browser.stopOwnedForRevocation(); }
        catch { browserOutcome = "uncertain"; }
      } else if (active) {
        try { await options.browser!.close(active.session_id); }
        catch { browserOutcome = "uncertain"; }
      }
      const result = await sessions.stopOwnedForRevocation();
      return pendingEffects || browserOutcome === "uncertain" ? "uncertain" : result;
    },
    close: async () => {
      stopped = true;
      await handoff.stopAccess();
      await handoffPreparation;
      await searches.close();
      // Agent shutdown must not leave an owned Chromium behind merely because
      // a page navigation holds the ordinary browser operation mutex.
      // Reuse the same owned-context cancellation as device revocation; no
      // arbitrary process killing or personal Chrome Profile access.
      const active = options.browser?.status();
      if (options.browser?.stopOwnedForRevocation) {
        try { await options.browser.stopOwnedForRevocation(); }
        catch { /* Failed cleanup is never reported as a confirmed result. */ }
      } else if (active) {
        try { await options.browser!.close(active.session_id); }
        catch { /* Never kill an unknown browser process or wipe a Profile. */ }
      }
      await sessions.close();
      if (receiptsReady) await receipts.close();
    },
  };
}
