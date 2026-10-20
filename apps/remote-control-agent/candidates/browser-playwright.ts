/**
 * One Agent-local browser backend using the existing Node runtime and
 * Playwright's official API. SOURCE-STAGED ONLY: not constructed by the
 * installed Agent and not advertised through MCP until platform acceptance.
 *
 * A dedicated Profile is never taken from a remote caller. No JS/CDP,
 * arbitrary executable, OS shell, or existing personal browser attachment.
 */
import { randomUUID } from "node:crypto";
import { mkdir } from "node:fs/promises";
import path from "node:path";
import { chromium, type BrowserContext, type BrowserType, type Page } from "playwright-core";
import type { BrowserBackend, BrowserStatus } from "../src/browser-backend.ts";

const ID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const SNAPSHOT_LIMIT = 8_000;
const IDLE_MS = 30 * 60_000;

export interface PlaywrightBrowserOptions {
  /** Already managed Agent-private location, NEVER received from MCP input. */
  agentStore: string;
  /** Trusted local executable chosen at installation, never from an MCP tool. */
  browserExecutable?: string;
  /** Tests may inject a BrowserType; no second runtime adapter is introduced. */
  chromiumForTests?: BrowserType<{}>;
  idleMsForTests?: number;
}

function checkedUrl(value: string): string {
  if (typeof value !== "string" || !value || value.length > 2048 ||
      /[\x00-\x20\x7f]/.test(value)) throw Error("Invalid navigation URL.");
  let url: URL;
  try { url = new URL(value); } catch { throw Error("Invalid navigation URL."); }
  if (!["https:", "http:"].includes(url.protocol) || !url.hostname ||
      url.username || url.password ||
      url.hostname === "localhost" || url.hostname.endsWith(".localhost") ||
      url.hostname.endsWith(".local") || url.hostname.endsWith(".internal") ||
      /^\d+\.\d+\.\d+\.\d+$/.test(url.hostname) ||
      url.hostname.startsWith("[") || !url.hostname.includes(".")) {
    throw Error("Navigation target outside first-phase public HTTP(S) scope.");
  }
  // NOT an SSRF/redirect/subresource firewall; hostile egress remains unverified.
  return url.toString();
}

export class PlaywrightBrowserManager implements BrowserBackend {
  private readonly profile: string;
  private readonly executable?: string;
  private readonly driver: BrowserType<{}>;
  private readonly idleMs: number;
  private context: BrowserContext | null = null;
  private page: Page | null = null;
  private sessionId: string | null = null;
  private uncertain = false;
  private busy = false;
  private version = 0;
  private idleTimer: ReturnType<typeof setTimeout> | undefined;

  constructor(options: PlaywrightBrowserOptions) {
    if (!path.isAbsolute(options.agentStore)) throw Error("Agent-private browser path must be absolute.");
    if (options.browserExecutable !== undefined && !path.isAbsolute(options.browserExecutable)) {
      throw Error("Installed browser executable path must be absolute.");
    }
    this.profile = path.join(options.agentStore, "browser-automation-profile");
    this.executable = options.browserExecutable;
    this.driver = options.chromiumForTests ?? chromium;
    this.idleMs = options.idleMsForTests ?? IDLE_MS;
    if (!Number.isFinite(this.idleMs) || this.idleMs < 1) throw Error("Invalid browser inactivity deadline.");
  }

  status(): BrowserStatus | null {
    return !this.context || !this.sessionId ? null : {
      session_id: this.sessionId, tab_id: "tab-1", backend: "playwright",
      uncertain: this.uncertain, snapshot_version: this.version,
    };
  }

  private validate(id: string): void {
    if (!ID.test(id) || id !== this.sessionId || !this.page || !this.context) {
      throw Error("Unknown or closed browser session.");
    }
  }

  private async exclusive<T>(work: () => Promise<T>): Promise<T> {
    if (this.busy) throw Error("Browser operation already in progress.");
    this.busy = true;
    try { return await work(); } finally { this.busy = false; }
  }

  private touch(): void {
    if (this.idleTimer) clearTimeout(this.idleTimer);
    this.idleTimer = setTimeout(() => {
      const id = this.sessionId;
      if (id) void this.close(id).catch(() => { this.touch(); });
    }, this.idleMs);
    this.idleTimer.unref?.();
  }

  async start(): Promise<BrowserStatus> {
    return this.exclusive(async () => {
      if (this.context || this.sessionId) throw Error("Automation Profile is already in use.");
      await mkdir(this.profile, { recursive: true, mode: 0o700 });
      const context = await this.driver.launchPersistentContext(this.profile, {
        headless: true, ...(this.executable ? { executablePath: this.executable } : {}),
        acceptDownloads: false, serviceWorkers: "block",
      });
      try {
        const pages = context.pages();
        // A persistent Profile may restore tabs. Never operate pre-existing pages.
        if (pages.some(page => page.url() !== "about:blank")) {
          throw Error("Automation Profile restored an unexpected page.");
        }
        for (const page of pages) await page.close();
        this.page = await context.newPage();
        this.page.setDefaultTimeout(5_000);
        this.context = context;
        this.sessionId = randomUUID();
        this.uncertain = false;
        this.version = 0;
        this.touch();
        return this.status()!;
      } catch (e) {
        await context.close().catch(() => {});
        this.page = null;
        throw e;
      }
    });
  }

  async navigate(sessionId: string, requestedUrl: string): Promise<void> {
    const url = checkedUrl(requestedUrl);
    return this.exclusive(async () => {
      this.validate(sessionId);
      if (this.uncertain) throw Error("Uncertain browser navigation; no implicit replay.");
      this.uncertain = true;
      this.version++; // invalidate prior Ref generation before an effect
      try {
        await this.page!.goto(url, { waitUntil: "domcontentloaded", timeout: 20_000 });
        this.uncertain = false;
        this.touch();
      } catch (e) {
        // A browser timeout does not prove that navigation had no effect.
        this.touch();
        throw e;
      }
    });
  }

  async snapshot(sessionId: string): Promise<{text: string; truncated: boolean; snapshot_version: number}> {
    return this.exclusive(async () => {
      this.validate(sessionId);
      // Even when a navigation outcome is unknown, observations are allowed.
      const raw = await this.page!.ariaSnapshot({ mode: "ai", timeout: 10_000 });
      this.version++;
      this.touch();
      return { text: raw.slice(0, SNAPSHOT_LIMIT), truncated: raw.length > SNAPSHOT_LIMIT,
        snapshot_version: this.version };
    });
  }

  async close(sessionId: string): Promise<void> {
    return this.exclusive(async () => {
      this.validate(sessionId);
      this.uncertain = true;
      await this.context!.close();
      if (this.idleTimer) clearTimeout(this.idleTimer);
      this.idleTimer = undefined;
      this.context = null;
      this.page = null;
      this.sessionId = null;
      this.uncertain = false;
      // Separate automation Profile intentionally retained; never wipe owner data.
    });
  }
}
