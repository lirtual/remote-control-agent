/**
 * Local, bounded Windows Agent diagnostics. Only fixed events and timestamps
 * are stored: never endpoint URLs, device IDs, usernames, pairing codes,
 * private keys, operation arguments or raw exceptions.
 *
 * This is diagnostic telemetry, NOT an audit/operation receipt store.
 */
import { appendFileSync, lstatSync, readFileSync, renameSync, statSync, unlinkSync } from "node:fs";
import path from "node:path";

export type WindowsEvent =
  | "starting" | "connected" | "disconnected" | "rejected" | "stopping";

const MAX_BYTES = 256 * 1024;
const MAX_VIEW_BYTES = 64 * 1024;
const MAX_LINES = 80;
const LOG_NAME = "agent-events.ndjson";

function safeLogPath(directory: string): string {
  const result = path.resolve(directory, LOG_NAME);
  if (path.dirname(result) !== path.resolve(directory)) {
    throw Error("Unsafe Windows log path.");
  }
  return result;
}

function assertRegularFile(p: string): boolean {
  try {
    const st = lstatSync(p);
    if (!st.isFile() || st.isSymbolicLink()) throw Error("Unsafe Windows Agent log.");
    return true;
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw e;
  }
}

/** Intentionally best effort: diagnostic failures never interrupt signed WSS. */
export function recordWindowsEvent(directory: string, event: WindowsEvent): void {
  if (!["starting", "connected", "disconnected", "rejected", "stopping"].includes(event)) return;
  try {
    const log = safeLogPath(directory);
    if (assertRegularFile(log) && statSync(log).size > MAX_BYTES) {
      const backup = safeLogPath(directory).replace(/\.ndjson$/, ".previous.ndjson");
      if (assertRegularFile(backup)) unlinkSync(backup);
      renameSync(log, backup);
    }
    // Append only a fixed enum and UTC time; inherited directory ACL is private.
    appendFileSync(log, JSON.stringify({
      utc: new Date().toISOString(), event,
    }) + "\n", { encoding: "utf8", flag: "a", mode: 0o600 });
  } catch {
    // No raw errors or filesystem paths are logged to stdout/stderr.
  }
}


/** A bounded local-only view of fixed diagnostic events. */
export function readWindowsEvents(directory: string): string {
  const log = safeLogPath(directory);
  if (!assertRegularFile(log)) return "No local Windows Agent events.\n";
  const st = statSync(log);
  if (st.size > 1024 * 1024) throw Error("Unexpected Windows Agent log size.");
  const bytes = readFileSync(log);
  const tail = bytes.subarray(Math.max(0, bytes.length - MAX_VIEW_BYTES)).toString("utf8");
  const lines = tail.split("\n").filter(Boolean).slice(-MAX_LINES);
  // Never reflect arbitrary file content: accept only known event shapes.
  const cleaned: string[] = [];
  for (const line of lines) {
    try {
      const item = JSON.parse(line) as { utc?: unknown; event?: unknown };
      if (typeof item.utc === "string" && !Number.isNaN(Date.parse(item.utc)) &&
          typeof item.event === "string" &&
          ["starting", "connected", "disconnected", "rejected", "stopping"].includes(item.event) &&
          Object.keys(item).length === 2) {
        cleaned.push(JSON.stringify({ utc: item.utc, event: item.event }));
      }
    } catch { /* ignore truncated historical line */ }
  }
  return cleaned.length ? cleaned.join("\n") + "\n" : "No valid local Windows Agent events.\n";
}
