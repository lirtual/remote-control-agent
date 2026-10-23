/**
 * Browser calls reuse the Agent's durable SQLite operation receipts.
 * No generic JS/CDP tool or second queue. A returned "running" receipt is not
 * proof the browser-side operation has finished.
 */
import { operationDigest, type OperationReceipt, type ReceiptStore } from "./operations.ts";
import { parseOperationId } from "./local-read.ts";
import type { BrowserBackend, BrowserTabAction, BrowserTarget } from "./browser-backend.ts";

export const BROWSER_EFFECT_TOOLS = [
  "browser_start", "browser_navigate", "browser_close", "browser_click", "browser_fill",
  "browser_press_key", "browser_select_option", "browser_tabs",
] as const;
export const BROWSER_READ_TOOLS = ["browser_status", "browser_snapshot", "browser_tabs"] as const;
type Effect = typeof BROWSER_EFFECT_TOOLS[number];
type Read = typeof BROWSER_READ_TOOLS[number];
type Args = Record<string, string | number>;

function record(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}
function exact(input: Record<string, unknown>, keys: string[]): boolean {
  return Object.keys(input).length === keys.length && keys.every(key => Object.hasOwn(input, key));
}
const SESSION_ID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const TAB_ID = /^tab-[1-9]\d{0,6}$/;
const ROLES = new Set([
  "button", "link", "textbox", "searchbox", "combobox", "checkbox", "radio",
  "tab", "menuitem", "option",
]);

export function parseBrowserArguments(tool: string, raw: unknown): Args | null {
  if (!record(raw)) return null;
  const session = typeof raw.session_id === "string" && SESSION_ID.test(raw.session_id);
  if (tool === "browser_start" || tool === "browser_status") return exact(raw, []) ? {} : null;
  if (tool === "browser_close")
    return session && exact(raw, ["session_id"]) ? {session_id: raw.session_id as string} : null;
  if (tool === "browser_snapshot") {
    if (!session || !(exact(raw, ["session_id"]) || exact(raw, ["session_id", "offset"]))) return null;
    if (Object.hasOwn(raw, "offset") && (!Number.isSafeInteger(raw.offset) ||
        (raw.offset as number) < 0 || (raw.offset as number) > 200_000)) return null;
    return {session_id: raw.session_id as string,
      ...(Object.hasOwn(raw, "offset") ? {offset: raw.offset as number} : {})};
  }
  if (tool === "browser_navigate")
    return session && exact(raw, ["session_id", "url", "tab_id", "snapshot_version"]) &&
      typeof raw.url === "string" && raw.url.length > 0 && raw.url.length <= 2048 &&
      typeof raw.tab_id === "string" && TAB_ID.test(raw.tab_id) &&
      Number.isSafeInteger(raw.snapshot_version) && (raw.snapshot_version as number) >= 0
      ? {session_id: raw.session_id as string, url: raw.url, tab_id:raw.tab_id,
          snapshot_version:raw.snapshot_version as number} : null;
  if (tool === "browser_tabs") {
    if (!session || typeof raw.action !== "string" ||
        !["list", "select", "new", "close"].includes(raw.action)) return null;
    const targeted = raw.action === "select" || raw.action === "close";
    if (!exact(raw, targeted ? ["session_id", "action", "tab_id"] : ["session_id", "action"]) ||
        targeted && (typeof raw.tab_id !== "string" || !TAB_ID.test(raw.tab_id))) return null;
    return {session_id: raw.session_id as string, action: raw.action,
      ...(targeted ? {tab_id: raw.tab_id as string} : {})};
  }
  if (tool === "browser_press_key") {
    return session && exact(raw, ["session_id", "key", "snapshot_version"]) &&
      typeof raw.key === "string" && raw.key.length <= 30 &&
      Number.isSafeInteger(raw.snapshot_version) && (raw.snapshot_version as number) >= 0
      ? {session_id: raw.session_id as string, key: raw.key, snapshot_version: raw.snapshot_version as number} : null;
  }
  if (["browser_click", "browser_fill", "browser_select_option"].includes(tool)) {
    const keys = ["session_id", "role", "name", "snapshot_version",
      ...(tool === "browser_fill" ? ["text"] : tool === "browser_select_option" ? ["value"] : [])];
    if (!session || !exact(raw, keys) || typeof raw.role !== "string" || !ROLES.has(raw.role) ||
        typeof raw.name !== "string" || !raw.name || raw.name.length > 200 ||
        !Number.isSafeInteger(raw.snapshot_version) || (raw.snapshot_version as number) < 0) return null;
    if (tool === "browser_fill" && (typeof raw.text !== "string" || raw.text.length > 5_000)) return null;
    if (tool === "browser_select_option" && (typeof raw.value !== "string" || raw.value.length > 512)) return null;
    return raw as Args;
  }
  return null;
}

/** Split browser_tabs(list) from browser_tabs(effect), never conflate their WSS permissions. */
export function browserToolIsRead(tool: string, raw: unknown): boolean {
  return tool === "browser_status" || tool === "browser_snapshot" ||
    (tool === "browser_tabs" && record(raw) && raw.action === "list");
}

export type BrowserOperationResult = {
  operation_id: string;
  status: "running" | "completed" | "failed" | "unknown" | "conflict" | "unavailable" | "bad_request";
  session_id?: string;
};

export class BrowserOperationGateway {
  private readonly inFlight = new Map<string, Promise<OperationReceipt>>();
  private readonly adapter: BrowserBackend;
  private readonly receipts: Pick<ReceiptStore, "admit" | "update" | "get">;
  private readonly ensureReceipts: () => Promise<void>;
  constructor(
    adapter: BrowserBackend,
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
    if (!args || !browserToolIsRead(tool, args)) return null;
    if (tool === "browser_status") return JSON.stringify(this.adapter.status());
    const id = args.session_id as string;
    const current = this.adapter.status();
    if (!current || current.session_id !== id) return null;
    try {
      if (tool === "browser_tabs") {
        return JSON.stringify({session_id: id, ...(await this.adapter.tabs(id, "list"))});
      }
      const page = await this.adapter.snapshot(id, args.offset as number | undefined);
      return JSON.stringify({ session_id: id, ...page });
    } catch { return null; }
  }

  async submit(tool: Effect, raw: unknown, operationId: string): Promise<BrowserOperationResult> {
    const args = parseBrowserArguments(tool, raw);
    if (!args || browserToolIsRead(tool, args) || !parseOperationId({operation_id: operationId}))
      return { operation_id: operationId, status: "bad_request" };
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
          const id = args.session_id as string | undefined;
          let completedSession = id;
          const target: BrowserTarget = {
            role: args.role as string, name: args.name as string,
            snapshot_version: args.snapshot_version as number,
          };
          switch (tool) {
            case "browser_start":
              completedSession = (await this.adapter.start()).session_id;
              break;
            case "browser_navigate":
              await this.adapter.navigate(id!, args.url as string,
                args.tab_id as string,args.snapshot_version as number); break;
            case "browser_close":
              await this.adapter.close(id!); break;
            case "browser_tabs":
              await this.adapter.tabs(id!, args.action as BrowserTabAction, args.tab_id as string | undefined); break;
            case "browser_click":
              await this.adapter.click(id!, target); break;
            case "browser_fill":
              await this.adapter.fill(id!, target, args.text as string); break;
            case "browser_press_key":
              await this.adapter.pressKey(id!, args.key as string, args.snapshot_version as number); break;
            case "browser_select_option":
              await this.adapter.selectOption(id!, target, args.value as string); break;
          }
          // Never include form text, semantic locators or page content in receipts.
          return this.receipts.update(operationId, "completed", "Browser action completed.", completedSession);
        } catch {
          // External effects may have succeeded even if their response was lost.
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
        const uncertain = await this.receipts.update(operationId, "unknown", "Browser action outcome is uncertain.");
        return { operation_id: operationId, status: "unknown", ...(uncertain.session_id ? {session_id: uncertain.session_id} : {}) };
      }
      return {
        operation_id: operationId,
        status: prior.state === "completed" ? "completed" : prior.state === "failed" ? "failed" : "unknown",
        ...(prior.session_id ? {session_id: prior.session_id} : {}),
      };
    }
    // DO's reply budget is bounded. Keep the lock until the actual Promise settles.
    const result = await Promise.race([
      pending.then(receipt => receipt),
      new Promise<null>(resolve => setTimeout(() => resolve(null), 150)),
    ]).catch(() => null);
    if (!result) return {operation_id: operationId, status: "running"};
    return {
      operation_id: operationId, status: result.state === "completed" ? "completed" : "unknown",
      ...(result.session_id ? {session_id: result.session_id} : {}),
    };
  }
}
