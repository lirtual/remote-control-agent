/**
 * A thin, source-staged browser operation boundary. Reuses the Agent's SAME
 * durable receipt store, rather than creating a second browser task database.
 * Only explicitly typed browser commands are accepted.
 */
import { operationDigest, type OperationReceipt, type ReceiptStore } from "./operations.ts";
import { parseOperationId } from "./local-read.ts";
import type { BrowserCliAdapter } from "./browser-cli.ts";

export const BROWSER_EFFECT_TOOLS = ["browser_start", "browser_navigate", "browser_close"] as const;
export const BROWSER_READ_TOOLS = ["browser_status", "browser_snapshot"] as const;
type Effect = typeof BROWSER_EFFECT_TOOLS[number];
type Read = typeof BROWSER_READ_TOOLS[number];
type EffectArgs = { session_id: string; url?: string } | Record<string, never>;

function record(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}
function hasKeys(input: Record<string, unknown>, keys: string[]): boolean {
  return Object.keys(input).length === keys.length && keys.every(key => Object.hasOwn(input, key));
}
const SESSION_ID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;

/** Public contracts intentionally exclude arbitrary shell, JS, profile and CLI flags. */
export function parseBrowserArguments(tool: string, raw: unknown): EffectArgs | null {
  if (!record(raw)) return null;
  if (tool === "browser_start" || tool === "browser_status") {
    return hasKeys(raw, []) ? {} : null;
  }
  if (tool === "browser_close" || tool === "browser_snapshot") {
    return hasKeys(raw, ["session_id"]) && typeof raw.session_id === "string" &&
      SESSION_ID.test(raw.session_id) ? { session_id: raw.session_id } : null;
  }
  if (tool === "browser_navigate") {
    return hasKeys(raw, ["session_id", "url"]) &&
      typeof raw.session_id === "string" && SESSION_ID.test(raw.session_id) &&
      typeof raw.url === "string" && raw.url.length > 0 && raw.url.length <= 2048
      ? { session_id: raw.session_id, url: raw.url } : null;
  }
  return null;
}

export type BrowserOperationResult = {
  operation_id: string;
  status: "running" | "completed" | "failed" | "unknown" | "conflict" | "unavailable" | "bad_request";
  session_id?: string;
};

/** Borrow the EXISTING Agent-local receipts. No second store or migration. */
export class BrowserOperationGateway {
  private readonly inFlight = new Map<string, Promise<OperationReceipt>>();
  private readonly adapter: Pick<BrowserCliAdapter, "start" | "status" | "navigate" | "snapshot" | "close">;
  private readonly receipts: Pick<ReceiptStore, "admit" | "update" | "get">;
  private readonly ensureReceipts: () => Promise<void>;
  constructor(
    adapter: Pick<BrowserCliAdapter, "start" | "status" | "navigate" | "snapshot" | "close">,
    receipts: Pick<ReceiptStore, "admit" | "update" | "get">,
    ensureReceipts: () => Promise<void>,
  ) {
    this.adapter = adapter;
    this.receipts = receipts;
    this.ensureReceipts = ensureReceipts;
  }

  hasPending(): boolean { return this.inFlight.size > 0; }

  async read(tool: Read, raw: unknown): Promise<string | null> {
    const args = parseBrowserArguments(tool, raw);
    if (!args) return null;
    if (tool === "browser_status") return JSON.stringify(this.adapter.status());
    const id = (args as {session_id: string}).session_id;
    const current = this.adapter.status();
    if (!current || current.session_id !== id) return null;
    try {
      const page = await this.adapter.snapshot(id);
      // Page data is returned to the explicitly requesting caller, never
      // written to receipts or routine diagnostics.
      return JSON.stringify({ session_id: id, ...page });
    } catch { return null; }
  }

  async submit(tool: Effect, raw: unknown, operationId: string): Promise<BrowserOperationResult> {
    const args = parseBrowserArguments(tool, raw);
    if (!args || !parseOperationId({ operation_id: operationId })) {
      return { operation_id: operationId, status: "bad_request" };
    }
    let admitted: Awaited<ReturnType<ReceiptStore["admit"]>>;
    try {
      await this.ensureReceipts();
      admitted = await this.receipts.admit(operationId, tool, operationDigest(tool, args));
    } catch {
      return { operation_id: operationId, status: "unavailable" };
    }
    if (admitted.kind === "conflict") return { operation_id: operationId, status: "conflict" };
    if (admitted.kind === "full") return { operation_id: operationId, status: "unavailable" };
    let pending = this.inFlight.get(operationId);
    if (admitted.kind === "new") {
      pending = (async () => {
        await this.receipts.update(operationId, "running", "Browser action in progress.");
        try {
          const sessionId = "session_id" in args ? args.session_id as string : undefined;
          let completedSession = sessionId;
          if (tool === "browser_start") {
            completedSession = (await this.adapter.start()).session_id;
          } else if (tool === "browser_navigate") {
            await this.adapter.navigate(sessionId!, (args as {url: string}).url);
          } else {
            await this.adapter.close(sessionId!);
          }
          return this.receipts.update(operationId, "completed", "Browser action completed.", completedSession);
        } catch {
          // An exception or a disconnected response is never proof of no
          // external effect. No retry, even after a restart.
          return this.receipts.update(operationId, "unknown", "Browser action outcome is uncertain.");
        }
      })();
      this.inFlight.set(operationId, pending);
      void pending.finally(() => this.inFlight.delete(operationId)).catch(() => {});
    }
    if (!pending) {
      const prior = admitted.receipt;
      if (!prior) return { operation_id: operationId, status: "unknown" };
      if (prior.state === "admitted" || prior.state === "running") {
        // Recovery after an Agent restart: never blindly reissue the call.
        const uncertain = await this.receipts.update(operationId, "unknown", "Browser action outcome is uncertain.");
        return { operation_id: operationId, status: "unknown", ...(uncertain.session_id ? {session_id: uncertain.session_id} : {}) };
      }
      return { operation_id: operationId,
        status: prior.state === "completed" ? "completed" : prior.state === "failed" ? "failed" : "unknown",
        ...(prior.session_id ? { session_id: prior.session_id } : {}) };
    }
    // The remote DO has a 5-second response budget. This returns a durable
    // 'running' ID well before that deadline; owner polls get_operation_status.
    const result = await Promise.race([
      pending.then(r => r),
      new Promise<null>(resolve => setTimeout(() => resolve(null), 150)),
    ]).catch(() => null);
    if (!result) return { operation_id: operationId, status: "running" };
    return { operation_id: operationId,
      status: result.state === "completed" ? "completed" : "unknown",
      ...(result.session_id ? { session_id: result.session_id } : {}) };
  }
}
