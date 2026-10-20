/**
 * Candidate offline-only Playwright-compatible browser core.
 *
 * NOT connected to a paired-device tool or shipped in the Agent runtime.
 * The browser package is injected by the future approved loader; this module
 * cannot install binaries, navigate to sites, execute JS, upload files or
 * publish external effects. No public-network security claim is made.
 */
import { randomUUID } from "node:crypto";
import { mkdir } from "node:fs/promises";
import path from "node:path";

export const BROWSER_OFFLINE_IDLE_MS = 30 * 60 * 1000;
export const BROWSER_SNAPSHOT_MAX_CHARS = 8_000;
const OFFLINE_HTML = "<!doctype html><html lang=\"en\"><head><title>Remote Control Offline</title></head>" +
  "<body><main><h1>Offline inspection</h1></main></body></html>";

export interface BrowserBlockedRoute {
  abort(errorCode: "blockedbyclient"): Promise<void>;
}
export interface BrowserBlockedWebSocket {
  close(options: { code: number; reason: string }): Promise<void>;
}
export interface BrowserOfflinePage {
  setContent(content: string, options: { waitUntil: "domcontentloaded"; timeout: number }): Promise<void>;
  ariaSnapshot(): Promise<string>;
}
export interface BrowserOfflineContext {
  route(glob: string, handler: (route: BrowserBlockedRoute) => Promise<void>): Promise<void>;
  routeWebSocket?(glob: string, handler: (socket: BrowserBlockedWebSocket) => Promise<void>): Promise<void>;
  /** Persistent Chromium may have restored a tab before we register routes. */
  pages(): Array<{ url(): string; close(): Promise<void> }>;
  newPage(): Promise<BrowserOfflinePage>;
  close(): Promise<void>;
}
export interface BrowserOfflineDriver {
  launchPersistentContext(profile: string, options: {
    headless: true;
    offline: true;
    javaScriptEnabled: false;
    serviceWorkers: "block";
    acceptDownloads: false;
    permissions: [];
    args: string[];
  }): Promise<BrowserOfflineContext>;
}
export interface BrowserOfflineStatus {
  session_id: string;
  tab_id: "offline-1";
  mode: "offline-only";
}

/**
 * One active offline-only session per Agent-local profile; never accepts a
 * client-supplied URL, HTML snippet, script, executable or profile path.
 * Deliberately not a network-enforcement mechanism for public navigation.
 */
export class BrowserOfflineCore {
  private readonly driver: BrowserOfflineDriver;
  private readonly profile: string;
  private context: BrowserOfflineContext | undefined;
  private page: BrowserOfflinePage | undefined;
  private sessionId: string | undefined;
  private starting = false;
  private idleTimer: ReturnType<typeof setTimeout> | undefined;

  constructor(driver: BrowserOfflineDriver, privateAgentStore: string) {
    if (!path.isAbsolute(privateAgentStore)) throw new Error("An absolute Agent-private store is required.");
    this.driver = driver;
    this.profile = path.join(privateAgentStore, "browser-offline-profile");
  }

  status(): BrowserOfflineStatus | null {
    if (!this.context || !this.page || !this.sessionId) return null;
    return { session_id: this.sessionId, tab_id: "offline-1", mode: "offline-only" };
  }

  async start(): Promise<BrowserOfflineStatus> {
    if (this.context || this.starting) throw new Error("The browser offline profile is already in use.");
    this.starting = true;
    let context: BrowserOfflineContext | undefined;
    try {
      await mkdir(this.profile, { recursive: true, mode: 0o700 });
      context = await this.driver.launchPersistentContext(this.profile, {
        headless: true,
        offline: true,
        javaScriptEnabled: false,
        serviceWorkers: "block",
        acceptDownloads: false,
        permissions: [],
        args: [
          "--disable-background-networking",
          "--disable-component-update",
          "--disable-sync",
          "--disable-extensions",
        ],
      });
      // Install both denials before the first tab can be opened.
      await context.route("**/*", route => route.abort("blockedbyclient"));
      if (typeof context.routeWebSocket !== "function") {
        throw new Error("The runtime cannot block WebSockets; offline session denied.");
      }
      await context.routeWebSocket("**/*", socket =>
        socket.close({ code: 1008, reason: "Offline browser session" }));
      // Persistent Chromium can restore an existing tab before routes are
      // installed. Refuse all non-blank startup state, never silently inspect
      // or navigate a restored real website. Blank tabs are closed before the
      // fixed synthetic page is created.
      const restored = context.pages();
      if (restored.some(page => page.url() !== "about:blank")) {
        throw new Error("Persistent browser profile contains a restored page.");
      }
      for (const blank of restored) await blank.close();
      const page = await context.newPage();
      await page.setContent(OFFLINE_HTML, { waitUntil: "domcontentloaded", timeout: 5000 });
      this.context = context;
      this.page = page;
      this.sessionId = randomUUID();
      this.touch();
      return this.status()!;
    } catch (error) {
      if (context) {
        try { await context.close(); } catch { /* Never replace original launch error. */ }
      }
      throw error;
    } finally {
      this.starting = false;
    }
  }

  async snapshot(sessionId: string): Promise<{ text: string; truncated: boolean }> {
    if (!this.page || !this.sessionId || this.sessionId !== sessionId) {
      throw new Error("Unknown or closed browser session.");
    }
    const content = await this.page.ariaSnapshot();
    this.touch();
    return content.length <= BROWSER_SNAPSHOT_MAX_CHARS
      ? { text: content, truncated: false }
      : { text: content.slice(0, BROWSER_SNAPSHOT_MAX_CHARS), truncated: true };
  }

  async close(): Promise<void> {
    if (this.idleTimer) clearTimeout(this.idleTimer);
    this.idleTimer = undefined;
    const context = this.context;
    this.context = undefined;
    this.page = undefined;
    this.sessionId = undefined;
    if (context) await context.close();
    // Retain the dedicated profile according to Q13. No profile wipe.
  }

  private touch(): void {
    if (this.idleTimer) clearTimeout(this.idleTimer);
    this.idleTimer = setTimeout(() => { void this.close().catch(() => {}); }, BROWSER_OFFLINE_IDLE_MS);
    this.idleTimer.unref?.();
  }
}
