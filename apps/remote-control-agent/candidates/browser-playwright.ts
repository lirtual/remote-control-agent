/**
 * Agent-owned headed Chrome/Edge context. No separate service, no personal
 * browser profile and no browser-driven Cloudflare polling.
 * Network route checks are hostname hygiene, NOT redirect/DNS SSRF isolation.
 */
import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdir } from "node:fs/promises";
import path from "node:path";
import { chromium, type BrowserContext, type BrowserType, type Page } from "playwright-core";
import type {
  BrowserBackend, BrowserStatus, BrowserTabAction, BrowserTabsResult, BrowserTarget,
} from "../src/browser-backend.ts";

const ID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const SNAPSHOT_LIMIT = 8_000;
type Channel = "chrome" | "msedge";

export interface PlaywrightBrowserOptions {
  agentStore: string;
  /** Installer/test-owned executable, never provided by the MCP caller. */
  browserExecutable?: string;
  chromiumForTests?: BrowserType<{}>;
  browserChannelForTests?: Channel;
}

function defaultWindowsChannel(): Channel {
  const protocols = ["http", "https"] as const;
  const channels = protocols.map(protocol => {
    const key = `HKCU\\Software\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\${protocol}\\UserChoice`;
    let output: string;
    try {
      output = execFileSync("reg.exe", ["query", key, "/v", "ProgId"], {
        encoding: "utf8", timeout: 5_000, windowsHide: true,
      });
    } catch { throw Error("Windows default browser association is unavailable."); }
    const progId = /ProgId\s+REG_SZ\s+(\S+)/i.exec(output)?.[1] ?? "";
    if (/^ChromeHTML(?:\..+)?$/i.test(progId)) return "chrome";
    if (/^MSEdgeHTM(?:\..+)?$/i.test(progId)) return "msedge";
    throw Error("Default HTTP(S) browser must be Chrome or Edge.");
  });
  if (channels[0] !== channels[1]) throw Error("HTTP and HTTPS defaults must agree.");
  return channels[0]!;
}

function checkedUrl(value: string, initialNavigation = true): string {
  if (typeof value !== "string" || !value ||
      (initialNavigation && value.length > 2048) ||
      /[\x00-\x20\x7f]/.test(value)) throw Error("Invalid navigation URL.");
  let url: URL;
  try { url = new URL(value); } catch { throw Error("Invalid navigation URL."); }
  const hostname = url.hostname.replace(/\.+$/, "");
  if (!["https:", "http:"].includes(url.protocol) || !hostname ||
      url.username || url.password ||
      hostname === "localhost" || hostname.endsWith(".localhost") ||
      hostname.endsWith(".local") || hostname.endsWith(".internal") ||
      /^\d+\.\d+\.\d+\.\d+$/.test(hostname) ||
      hostname.startsWith("[") || !hostname.includes(".")) {
    throw Error("Navigation target outside first-phase public HTTP(S) scope.");
  }
  return url.toString();
}

const SAFE_KEYS = new Set([
  "Enter", "Tab", "Escape", "Backspace", "Delete", "ArrowUp", "ArrowDown",
  "ArrowLeft", "ArrowRight", "Home", "End", "PageUp", "PageDown", "Space",
  "Control+A", "Meta+A",
]);

export class PlaywrightBrowserManager implements BrowserBackend {
  private readonly store: string;
  private readonly executable?: string;
  private readonly driver: BrowserType<{}>;
  private readonly channelForTests?: Channel;
  private browserFamily: Channel = "chrome";
  private context: BrowserContext | null = null;
  private sessionId: string | null = null;
  private readonly pages = new Map<string, Page>();
  private readonly ids = new Map<Page, string>();
  private nextTab = 1;
  private selectedTabId: string | null = null;
  private uncertain = false;
  private busy = false;
  private revoked = false;
  private version = 0;

  constructor(options: PlaywrightBrowserOptions) {
    if (!path.isAbsolute(options.agentStore)) throw Error("Agent-private browser path must be absolute.");
    if (options.browserExecutable !== undefined && !path.isAbsolute(options.browserExecutable)) {
      throw Error("Installed browser executable path must be absolute.");
    }
    this.store = options.agentStore;
    this.executable = options.browserExecutable;
    this.driver = options.chromiumForTests ?? chromium;
    this.channelForTests = options.browserChannelForTests;
  }

  status(): BrowserStatus | null {
    return !this.context || !this.sessionId ? null : {
      session_id: this.sessionId, tab_id: this.selectedTabId, backend: "playwright",
      browser_family: this.browserFamily, uncertain: this.uncertain, snapshot_version: this.version,
    };
  }

  private requireContext(id: string): BrowserContext {
    if (!ID.test(id) || id !== this.sessionId || !this.context)
      throw Error("Unknown or closed browser session.");
    return this.context;
  }

  private selected(id: string): Page {
    this.requireContext(id);
    const page = this.selectedTabId && this.pages.get(this.selectedTabId);
    if (!page || page.isClosed()) throw Error("No selected live tab; list and select a tab.");
    return page;
  }

  private assertFresh(version: number): void {
    if (!Number.isSafeInteger(version) || version !== this.version)
      throw Error("Stale snapshot; observe again before acting.");
    if (this.uncertain) throw Error("Previous browser effect is uncertain; no implicit replay.");
  }

  private register(page: Page): string {
    const known = this.ids.get(page);
    if (known) return known;
    const id = `tab-${this.nextTab++}`;
    this.ids.set(page, id);
    this.pages.set(id, page);
    page.on?.("close", () => {
      this.ids.delete(page);
      this.pages.delete(id);
      if (this.selectedTabId === id) this.selectedTabId = null;
      this.version++;
    });
    return id;
  }

  private reset(active?: BrowserContext): void {
    if (active && active !== this.context) return;
    this.context = null;
    this.sessionId = null;
    this.selectedTabId = null;
    this.ids.clear();
    this.pages.clear();
    this.version = 0;
  }

  private async exclusive<T>(work: () => Promise<T>): Promise<T> {
    if (this.busy) throw Error("Browser operation already in progress.");
    this.busy = true;
    try { return await work(); } finally { this.busy = false; }
  }

  async start(): Promise<BrowserStatus> {
    return this.exclusive(async () => {
      if (this.revoked) throw Error("Browser ownership revoked; startup denied.");
      if (this.context && this.sessionId) return this.status()!;
      const channel = this.channelForTests ??
        (process.platform === "win32" ? defaultWindowsChannel() : "chrome");
      const profile = path.join(this.store, `browser-automation-profile-${channel}`);
      await mkdir(profile, { recursive: true, mode: 0o700 });
      // A pre-existing Profile lock is an explicit error, not a license to
      // take over or terminate another browser process.
      const context = await this.driver.launchPersistentContext(profile, {
        headless: false,
        ...(this.executable ? { executablePath: this.executable } : { channel }),
        acceptDownloads: false, serviceWorkers: "block",
      });
      try {
        await context.route("**/*", async route => {
          try { checkedUrl(route.request().url(), false); }
          catch {
            await route.abort("blockedbyclient").catch(() => {});
            return;
          }
          await route.continue();
        });
        if (this.revoked) throw Error("Browser ownership revoked during startup.");
        const restored = context.pages();
        if (restored.some(page => page.url() !== "about:blank"))
          throw Error("Automation Profile restored an unexpected page.");
        this.browserFamily = channel;
        this.context = context;
        this.sessionId = randomUUID();
        this.uncertain = false;
        this.version = 0;
        this.nextTab = 1;
        context.on?.("page", page => { this.register(page); });
        context.on?.("close", () => { this.reset(context); });
        const page = restored[0] ?? await context.newPage();
        // Other blank tabs, including manually added tabs, are visible to list.
        for (const open of context.pages()) this.register(open);
        const id = this.register(page);
        this.selectedTabId = id;
        page.setDefaultTimeout(5_000);
        if (this.revoked) throw Error("Browser ownership revoked during startup.");
        return this.status()!;
      } catch (error) {
        await context.close().catch(() => {});
        this.reset(context);
        throw error;
      }
    });
  }

  async navigate(sessionId: string, requestedUrl: string): Promise<void> {
    const url = checkedUrl(requestedUrl);
    return this.exclusive(async () => {
      const page = this.selected(sessionId);
      if (this.revoked) throw Error("Browser ownership revoked; navigation denied.");
      if (this.uncertain) throw Error("Uncertain browser navigation; no implicit replay.");
      this.uncertain = true;
      this.version++;
      try {
        await page.goto(url, { waitUntil: "domcontentloaded", timeout: 20_000 });
        if (this.revoked) throw Error("Browser ownership revoked during navigation.");
        this.uncertain = false;
      } catch (error) { throw error; }
    });
  }

  async snapshot(sessionId: string, offset = 0): Promise<{text: string; truncated: boolean; snapshot_version: number; next_offset?: number}> {
    return this.exclusive(async () => {
      const page = this.selected(sessionId);
      if (this.revoked) throw Error("Browser ownership revoked; observation denied.");
      if (!Number.isSafeInteger(offset) || offset < 0 || offset > 200_000)
        throw Error("Invalid snapshot offset.");
      const raw = await page.ariaSnapshot({ mode: "ai", timeout: 10_000 });
      if (this.revoked) throw Error("Browser ownership revoked during observation.");
      this.version++;
      const end = Math.min(raw.length, offset + SNAPSHOT_LIMIT);
      return {
        text: raw.slice(offset, end), truncated: end < raw.length,
        snapshot_version: this.version,
        ...(end < raw.length ? {next_offset: end} : {}),
      };
    });
  }

  async tabs(sessionId: string, action: BrowserTabAction, tabId?: string): Promise<BrowserTabsResult> {
    return this.exclusive(async () => {
      const context = this.requireContext(sessionId);
      // Reconcile manually opened tabs even if a test context does not emit events.
      for (const page of context.pages()) if (!page.isClosed()) this.register(page);
      if (action === "select") {
        const page = tabId && this.pages.get(tabId);
        if (!page || page.isClosed()) throw Error("Unknown or closed tab.");
        this.selectedTabId = tabId!;
        await page.bringToFront();
        this.version++;
      } else if (action === "new") {
        const page = await context.newPage();
        this.selectedTabId = this.register(page);
        page.setDefaultTimeout(5_000);
        this.version++;
      } else if (action === "close") {
        const page = tabId && this.pages.get(tabId);
        if (!page || page.isClosed()) throw Error("Unknown or closed tab.");
        this.uncertain = true;
        await page.close();
        this.uncertain = false;
        this.version++;
      } else if (action !== "list") throw Error("Invalid tab action.");
      const tabs = await Promise.all([...this.pages].filter(([, page]) => !page.isClosed()).map(async ([id, page]) => ({
        tab_id: id, url: page.url(), title: (await page.title()).slice(0, 160),
      })));
      return { selected_tab_id: this.selectedTabId, tabs };
    });
  }

  private async withTarget(sessionId: string, target: BrowserTarget, act: (locator: ReturnType<Page["getByRole"]>) => Promise<void>): Promise<void> {
    return this.exclusive(async () => {
      const page = this.selected(sessionId);
      this.assertFresh(target.snapshot_version);
      if (!/^[a-z][a-z0-9_-]{1,30}$/.test(target.role) || !target.name || target.name.length > 200)
        throw Error("Invalid semantic target.");
      const locator = page.getByRole(target.role as Parameters<Page["getByRole"]>[0], { name: target.name, exact: true });
      if (await locator.count() !== 1) throw Error("Semantic target is not unique.");
      this.uncertain = true;
      this.version++;
      await act(locator);
      if (this.revoked) throw Error("Browser ownership revoked during action.");
      this.uncertain = false;
    });
  }

  async click(id: string, target: BrowserTarget): Promise<void> {
    return this.withTarget(id, target, locator => locator.click({timeout: 5_000}));
  }
  async fill(id: string, target: BrowserTarget, text: string): Promise<void> {
    return this.withTarget(id, target, locator => locator.fill(text, {timeout: 5_000}));
  }
  async selectOption(id: string, target: BrowserTarget, value: string): Promise<void> {
    return this.withTarget(id, target, async locator => { await locator.selectOption(value, {timeout: 5_000}); });
  }
  async pressKey(id: string, key: string, version: number): Promise<void> {
    return this.exclusive(async () => {
      const page = this.selected(id);
      this.assertFresh(version);
      if (!SAFE_KEYS.has(key)) throw Error("Key is outside the allowed set.");
      this.uncertain = true;
      this.version++;
      await page.keyboard.press(key);
      if (this.revoked) throw Error("Browser ownership revoked during key action.");
      this.uncertain = false;
    });
  }

  async stopOwnedForRevocation(): Promise<"confirmed" | "uncertain"> {
    this.revoked = true;
    this.uncertain = true;
    const active = this.context;
    if (!active) return "confirmed";
    try {
      await active.close();
      this.reset(active);
      return "confirmed";
    } catch { return "uncertain"; }
  }

  async close(sessionId: string): Promise<void> {
    return this.exclusive(async () => {
      const context = this.requireContext(sessionId);
      this.uncertain = true;
      await context.close();
      this.reset(context);
      this.uncertain = false;
      // Persist the separate Agent-owned Profile; never delete user data.
    });
  }
}
