/** Shared typed browser contract only. The Playwright runtime is a P1 candidate
 * outside the installed Agent source graph until packaging/security acceptance. */
export interface BrowserStatus {
  session_id: string;
  tab_id: "tab-1";
  backend: "playwright";
  uncertain: boolean;
  snapshot_version: number;
}
export interface BrowserBackend {
  start(): Promise<BrowserStatus>;
  status(): BrowserStatus | null;
  navigate(sessionId: string, url: string): Promise<void>;
  snapshot(sessionId: string): Promise<{text:string;truncated:boolean;snapshot_version:number}>;
  close(sessionId: string): Promise<void>;
}
