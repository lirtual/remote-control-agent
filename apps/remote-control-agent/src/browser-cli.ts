/**
 * Phase-one candidate: an Agent-local, trusted-device adapter for the pinned
 * agent-browser CLI. Not connected to MCP/WSS; no browser tools are advertised.
 *
 * The CLI is only an implementation detail. Callers cannot supply executable,
 * Profile paths, CLI flags, scripts, CDP commands, cookies, or raw JavaScript.
 * This is NOT an OS/container/network sandbox for untrusted agents.
 */
import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdir } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";

const executeFile = promisify(execFile);
const SNAPSHOT_LIMIT = 8_000;
const MAX_CLI_OUTPUT = 65_536;
const NORMAL_IDLE_MS = 30 * 60_000;
const UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;

/** Injected only in unit tests. Never supplied through MCP/WSS requests. */
export type BrowserCliRunner = (args: readonly string[], timeoutMs: number) => Promise<string>;

export interface BrowserCliOptions {
  /** Absolute installed, trusted agent-browser package entrypoint, never from a tool call. */
  entrypoint: string;
  /** Existing Agent-private directory, never selected by the remote caller. */
  agentStore: string;
  nodeExecutable?: string;
  /** Optional locally configured Chrome/Chromium executable, never a tool argument. */
  browserExecutable?: string;
  /** Test-only runner; production always uses shell:false execFile. */
  runnerForTests?: BrowserCliRunner;
  /** Test-only deadline; production has a 30-minute inactivity limit. */
  idleMsForTests?: number;
}

export interface BrowserCliStatus {
  session_id: string;
  tab_id: "tab-1";
  backend: "agent-browser";
  /** True when a navigation outcome cannot be established; never blindly retry. */
  uncertain: boolean;
}

function safeNavigationUrl(value: string): string {
  if (typeof value !== "string" || value.length > 2048 || /[\x00-\x20\x7f]/.test(value)) {
    throw Error("Invalid browser navigation URL.");
  }
  let url: URL;
  try { url = new URL(value); } catch { throw Error("Invalid browser navigation URL."); }
  if ((url.protocol !== "https:" && url.protocol !== "http:") ||
      !url.hostname || url.username || url.password || url.hash.length > 1024) {
    throw Error("Only explicit HTTP(S) navigation without embedded credentials is supported.");
  }
  // This is a small phase-one hygiene check, NOT an SSRF/rebinding or egress
  // barrier. Hostile/untrusted execution needs a separately proven OS sandbox.
  if (url.hostname === "localhost" || url.hostname.endsWith(".localhost") ||
      url.hostname.endsWith(".local") || url.hostname.endsWith(".internal") ||
      /^\d+\.\d+\.\d+\.\d+$/.test(url.hostname) || url.hostname.startsWith("[") ||
      !url.hostname.includes(".")) {
    throw Error("Direct local/internal/IP-literal destinations are not in phase-one scope.");
  }
  return url.toString();
}

export class BrowserCliAdapter {
  private readonly profile: string;
  private readonly browserExecutable: string | undefined;
  private readonly runner: BrowserCliRunner;
  private readonly idleMs: number;
  private sessionId: string | null = null;
  private busy = false;
  private uncertain = false;
  private idleTimer: ReturnType<typeof setTimeout> | undefined;

  constructor(options: BrowserCliOptions) {
    if (!path.isAbsolute(options.entrypoint) || !path.isAbsolute(options.agentStore)) {
      throw Error("Trusted absolute local browser paths are required.");
    }
    if (options.nodeExecutable !== undefined && !path.isAbsolute(options.nodeExecutable)) {
      throw Error("Trusted absolute Node executable is required.");
    }
    if (options.browserExecutable !== undefined && !path.isAbsolute(options.browserExecutable)) {
      throw Error("Trusted absolute browser executable is required.");
    }
    this.browserExecutable = options.browserExecutable;
    this.profile = path.join(options.agentStore, "browser-automation-profile");
    this.idleMs = options.idleMsForTests ?? NORMAL_IDLE_MS;
    this.runner = options.runnerForTests ?? (async (args, timeoutMs) => {
      const { stdout } = await executeFile(
        options.nodeExecutable ?? process.execPath,
        [options.entrypoint, ...args],
        {
          shell: false, windowsHide: true, timeout: timeoutMs,
          maxBuffer: MAX_CLI_OUTPUT, encoding: "utf8",
          cwd: options.agentStore,
        },
      );
      return stdout;
    });
    if (this.idleMs < 1) throw Error("Invalid idle deadline.");
  }

  status(): BrowserCliStatus | null {
    return this.sessionId === null ? null : {
      session_id: this.sessionId, tab_id: "tab-1",
      backend: "agent-browser", uncertain: this.uncertain,
    };
  }

  private sessionArgs(): string[] {
    if (!this.sessionId) throw Error("Unknown or closed browser session.");
    return ["--session", "rca-" + this.sessionId];
  }

  private verifySession(id: string): void {
    if (!UUID.test(id) || this.sessionId !== id) {
      throw Error("Unknown or closed browser session.");
    }
  }

  private async exclusive<T>(action: () => Promise<T>): Promise<T> {
    if (this.busy) throw Error("A browser operation is already in progress.");
    this.busy = true;
    try { return await action(); }
    finally { this.busy = false; }
  }

  private touch(): void {
    if (this.idleTimer) clearTimeout(this.idleTimer);
    this.idleTimer = setTimeout(() => {
      const id = this.sessionId;
      if (id) void this.close(id).catch(() => { /* unresolved: keep explicit status */ });
    }, this.idleMs);
    this.idleTimer.unref?.();
  }

  async start(): Promise<BrowserCliStatus> {
    return this.exclusive(async () => {
      if (this.sessionId) throw Error("An automation Profile session is already active.");
      await mkdir(this.profile, { mode: 0o700, recursive: true });
      this.sessionId = randomUUID();
      this.uncertain = true;
      this.touch(); // Even a partially launched, unconfirmed session is idle-bounded.
      try {
        await this.runner([...this.sessionArgs(), "--profile", this.profile,
          ...(this.browserExecutable ? ["--executable-path", this.browserExecutable] : []),
          "open"], 30_000);
        this.uncertain = false;
        this.touch();
        return this.status()!;
      } catch {
        // The CLI may have launched a browser before failing. A new start
        // cannot silently reuse the Profile: preserve unknown state.
        throw Error("Browser startup not confirmed; close the uncertain session before retrying.");
      }
    });
  }

  async navigate(sessionId: string, inputUrl: string): Promise<void> {
    const url = safeNavigationUrl(inputUrl);
    return this.exclusive(async () => {
      this.verifySession(sessionId);
      if (this.uncertain) throw Error("Browser outcome uncertain; navigation replay refused.");
      this.uncertain = true;
      // Never auto-retry an effectful navigation after a lost CLI response.
      await this.runner([...this.sessionArgs(), "open", url], 30_000);
      this.uncertain = false;
      this.touch();
    });
  }

  async snapshot(sessionId: string): Promise<{ text: string; truncated: boolean }> {
    return this.exclusive(async () => {
      this.verifySession(sessionId);
      const output = await this.runner([...this.sessionArgs(), "snapshot", "-i"], 15_000);
      this.touch();
      return {
        text: output.slice(0, SNAPSHOT_LIMIT),
        truncated: output.length > SNAPSHOT_LIMIT,
      };
    });
  }

  async close(sessionId: string): Promise<void> {
    return this.exclusive(async () => {
      this.verifySession(sessionId);
      // On a CLI error keep the session tracked and explicitly uncertain.
      this.uncertain = true;
      await this.runner([...this.sessionArgs(), "close"], 15_000);
      if (this.idleTimer) clearTimeout(this.idleTimer);
      this.idleTimer = undefined;
      this.sessionId = null;
      this.uncertain = false;
      // Deliberately preserve the dedicated automation Profile after close.
    });
  }
}
