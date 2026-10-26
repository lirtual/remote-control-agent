/** Device-wide admission barrier. Only control metadata is persisted. */
import { closeSync, fsyncSync, lstatSync, mkdirSync, openSync, unlinkSync, writeFileSync } from "node:fs";
import path from "node:path";
import { CHILD_MARKER, cleanupOrphanTunnel } from "./protected-tunnel.ts";
import { randomUUID } from "node:crypto";

export const HANDOFF_TOOLS = ["browser_handoff_request", "browser_handoff_status", "browser_handoff_return"] as const;
export function parseHandoffArguments(tool: string, value: unknown): boolean {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const args = value as Record<string, unknown>;
  return tool === "browser_handoff_request"
    ? Object.keys(args).length === 1 && typeof args.session_id === "string" && /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(args.session_id)
    : (tool === "browser_handoff_status" || tool === "browser_handoff_return") && Object.keys(args).length === 0;
}
export type HandoffStatus = {
  state: "ai" | "preparing" | "pending_return" | "link_ready" | "interactive" | "expired";
  remaining_ms: number;
  reason?: string;
};
export interface HumanAccess {
  /** Must revoke credentials/endpoints synchronously, before awaiting cleanup. */
  close(): Promise<"confirmed" | "uncertain">;
}
export class BrowserHandoff {
  private readonly marker: string;
  private blocked = false;
  private epoch = 0;
  private state: HandoffStatus["state"] = "ai";
  private reason?: string;
  private deadline = 0;
  private access?: HumanAccess;
  private cleanup?: Promise<"confirmed" | "uncertain">;
  private preparing = false;
  private returning = false;
  private sessionId?: string;
  private unclaimedUrl?: string;
  private preparation?: Promise<void>;
  private readonly directory: string;
  private readonly sealEvidence?: (kind: "directory" | "pending") => void;
  constructor(directory: string, sealEvidence?: (kind: "directory" | "pending") => void) {
    this.directory = directory;
    this.sealEvidence = sealEvidence;
    this.marker = path.join(directory, "browser-handoff-pending.json");
    // On Windows, lstat(file\\child) may report ENOENT rather than ENOTDIR.
    // Validate the parent itself before interpreting missing markers as clean.
    try {
      const parent = lstatSync(directory);
      if (!parent.isDirectory() || parent.isSymbolicLink()) throw Error("invalid_private_store");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
        this.blocked = true; this.state = "pending_return"; this.reason = "private_store_unavailable";
        return;
      }
    }
    try {
      // Any marker (including malformed data) is evidence requiring return.
      try { lstatSync(this.marker); } catch (e) {
        if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e;
        lstatSync(path.join(directory,CHILD_MARKER));
      }
      this.blocked = true;
      this.state = "pending_return";
      this.reason = "agent_restarted_browser_session_not_restored";
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
        this.blocked = true; this.state = "pending_return"; this.reason = "private_store_unavailable";
      }
    }
    // Reap the previous process's tunnel at startup, while preserving explicit-return admission.
    if (this.blocked) void this.stopAccess();
  }
  isBlocked(): boolean { return this.blocked; }
  generation(): number { return this.epoch; }
  status(): HandoffStatus {
    if (this.deadline && Date.now() >= this.deadline && this.blocked) {
      this.state = "expired";
      this.unclaimedUrl = undefined;
      void this.stopAccess();
    }
    return { state: this.state, remaining_ms: Math.max(0, this.deadline - Date.now()), ...(this.reason ? {reason:this.reason} : {}) };
  }
  /** Synchronous entry, before the first await or browser state inspection. */
  begin(sessionId: string): boolean {
    if (this.blocked || this.returning) return false;
    this.blocked = true; this.epoch++; this.state = "preparing"; this.preparing = true;
    this.sessionId = sessionId; this.unclaimedUrl = undefined;
    try {
      mkdirSync(this.directory, {recursive:true,mode:0o700});
      this.sealEvidence?.("directory");
      const fd = openSync(this.marker, "wx", 0o600);
      try {
        writeFileSync(fd, JSON.stringify({handoff_id:randomUUID(), session_id:sessionId, created_at:Date.now()}));
        fsyncSync(fd);
      } finally { closeSync(fd); }
      this.sealEvidence?.("pending");
      if (process.platform !== "win32") {
        const directoryFd = openSync(this.directory,"r");
        try { fsyncSync(directoryFd); } finally { closeSync(directoryFd); }
      }
    } catch {
      this.reason = "pending_marker_unavailable";
      this.state = "pending_return";
      this.preparing = false;
      return false;
    }
    return true;
  }
  isPreparing(): boolean { return this.blocked && this.preparing && !this.returning; }
  trackPreparation(work: Promise<void>): void { this.preparation = work; }
  failed(reason: string): void {
    if (this.returning || !this.blocked) return;
    this.reason = reason; this.state = "pending_return"; this.preparing = false;
    this.unclaimedUrl = undefined;
  }
  attach(access: HumanAccess): void {
    if (!this.isPreparing()) throw Error("handoff_cancelled");
    this.access = access;
  }
  ready(access: HumanAccess, deadline: number, url: string): void {
    if (!this.isPreparing()) throw Error("handoff_cancelled");
    this.access = access; this.deadline = deadline; this.unclaimedUrl = url;
    this.state = "link_ready"; this.reason = undefined; this.preparing = false;
  }
  /** Claim is one-shot, bound to the originally requested browser session. */
  claim(sessionId: string): HandoffStatus & {url?: string; expires_at?: number} {
    const status = this.status();
    if (status.state !== "link_ready" || this.sessionId !== sessionId || !this.unclaimedUrl) return status;
    const url = this.unclaimedUrl;
    this.unclaimedUrl = undefined; // Consume before any WSS/connector await.
    return {...status,url,expires_at:this.deadline};
  }
  connected(): void { if (this.blocked && Date.now() < this.deadline) this.state = "interactive"; }
  stopAccess(): Promise<"confirmed" | "uncertain"> {
    this.unclaimedUrl = undefined;
    if (!this.cleanup) {
      try { this.cleanup = (this.access?.close() ?? cleanupOrphanTunnel(this.directory)).catch(() => "uncertain"); }
      catch { this.cleanup = Promise.resolve("uncertain"); }
    }
    return this.cleanup;
  }
  async explicitReturn(invalidate: () => Promise<void>): Promise<HandoffStatus> {
    if (!this.blocked) return this.status();
    if (this.returning) { this.reason = "lifecycle_busy"; return this.status(); }
    // Synchronously revoke pending admission. Background preparation observes
    // this flag after every await and cannot subsequently publish an entry URL.
    this.returning = true; this.preparing = false; this.unclaimedUrl = undefined;
    try {
      const stopped = this.stopAccess();
      await this.preparation?.catch(() => {});
      if (await stopped !== "confirmed") { this.reason = "cleanup_unknown"; this.state = "pending_return"; return this.status(); }
      await invalidate();
      // A damaged store is never treated as a successful explicit return.
      try { unlinkSync(this.marker); }
      catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
      this.epoch++; this.blocked = false; this.state = "ai"; this.reason = undefined; this.deadline = 0;
      this.access = undefined; this.cleanup = undefined; this.preparation = undefined;
      this.sessionId = undefined; this.unclaimedUrl = undefined;
    } catch { this.failed("return_unknown"); }
    finally { this.returning = false; }
    return this.status();
  }
}
