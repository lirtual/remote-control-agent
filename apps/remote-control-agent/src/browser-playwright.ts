/**
 * Real Playwright adapter for the existing offline-only core.
 *
 * It consumes an explicitly supplied Playwright Chromium BrowserType rather
 * than importing/installing a browser from the live Agent. This is still
 * source-only: packaging and authenticated MCP tool dispatch are not enabled.
 */
import type { chromium as ChromiumBrowserType } from "playwright-core";
import type {
  BrowserOfflineContext, BrowserOfflineDriver, BrowserOfflinePage,
} from "./browser-offline.ts";

/** Real Chromium launch via the matching Playwright version's browser cache. */
export function createPlaywrightOfflineDriver(
  chromium: typeof ChromiumBrowserType,
): BrowserOfflineDriver {
  return {
    async launchPersistentContext(profile, options): Promise<BrowserOfflineContext> {
      const context = await chromium.launchPersistentContext(profile, {
        headless: options.headless,
        offline: options.offline,
        javaScriptEnabled: options.javaScriptEnabled,
        serviceWorkers: options.serviceWorkers,
        acceptDownloads: options.acceptDownloads,
        permissions: options.permissions,
        args: options.args,
        // Never inherit an arbitrary existing user's default Chrome profile.
        // A caller-selected executable, channel or remote debugging port is
        // intentionally not accepted through this adapter.
      });
      return {
        pages: () => context.pages().map(page => ({
          url: () => page.url(),
          close: () => page.close(),
        })),
        route: (glob, handler) =>
          context.route(glob, route => handler({
            abort: code => route.abort(code),
          })),
        routeWebSocket: (glob, handler) =>
          context.routeWebSocket(glob, socket => handler({
            close: options => socket.close(options),
          })),
        async newPage(): Promise<BrowserOfflinePage> {
          const page = await context.newPage();
          page.setDefaultTimeout(5_000);
          return {
            setContent: (html, options) => page.setContent(html, options),
            ariaSnapshot: () => page.ariaSnapshot({ timeout: 5_000 }),
          };
        },
        close: () => context.close(),
      };
    },
  };
}
