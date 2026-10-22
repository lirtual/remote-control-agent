/** Shared typed browser contract for the existing signed Agent execution engine. */
export interface BrowserTab {
  tab_id: string;
  url: string;
  title: string;
}
export interface BrowserStatus {
  session_id: string;
  tab_id: string | null;
  browser_family: "chrome" | "msedge";
  backend: "playwright";
  uncertain: boolean;
  snapshot_version: number;
}
export type BrowserTabAction = "list" | "select" | "new" | "close";
export interface BrowserTabsResult {
  selected_tab_id: string | null;
  tabs: BrowserTab[];
}
export interface BrowserTarget {
  role: string;
  name: string;
  snapshot_version: number;
}
export interface BrowserBackend {
  start(): Promise<BrowserStatus>;
  status(): BrowserStatus | null;
  navigate(sessionId: string, url: string, expectedTabId: string, snapshotVersion: number): Promise<void>;
  snapshot(sessionId: string, offset?: number): Promise<{text:string;truncated:boolean;snapshot_version:number;next_offset?:number}>;
  tabs(sessionId: string, action: BrowserTabAction, tabId?: string): Promise<BrowserTabsResult>;
  click(sessionId: string, target: BrowserTarget): Promise<void>;
  fill(sessionId: string, target: BrowserTarget, text: string): Promise<void>;
  pressKey(sessionId: string, key: string, snapshotVersion: number): Promise<void>;
  selectOption(sessionId: string, target: BrowserTarget, value: string): Promise<void>;
  close(sessionId: string): Promise<void>;
  /** Locally trusted revocation: cancel owned browser, including in-flight page work. */
  stopOwnedForRevocation?(): Promise<"confirmed" | "uncertain">;
}
