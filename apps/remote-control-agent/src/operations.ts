import { createHash } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { constants } from "node:fs";
import { chmod, copyFile, mkdir, readFile, stat } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

export type OperationState = "admitted" | "running" | "completed" | "failed" | "unknown";

export interface OperationReceipt {
  operation_id: string;
  tool_name: "write_file" | "create_directory" | "edit_block" | "move_file" | "delete_file" | "start_process" | "interact_with_process" | "force_terminate";
  argument_digest: string;
  state: OperationState;
  created_at: string;
  updated_at: string;
  safe_result_summary?: string;
  session_id?: string;
}

interface LegacyData {
  version: 1;
  receipts: OperationReceipt[];
}

interface StoredRow extends Record<string, string | number | null> {
  operation_id: string;
  tool_name: OperationReceipt["tool_name"];
  argument_digest: string;
  state: OperationState;
  created_at: string;
  updated_at: string;
  safe_result_summary: string | null;
  session_id: string | null;
  guarded: number;
}

const RECEIPT_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const RECEIPT_STATES = new Set<OperationState>(["admitted", "running", "completed", "failed", "unknown"]);
const RECEIPT_TOOLS = new Set<OperationReceipt["tool_name"]>([
  "write_file", "create_directory", "edit_block", "move_file", "delete_file",
  "start_process", "interact_with_process", "force_terminate",
]);
function canonical(value: unknown): string {
  if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
  if (value !== null && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return "{" + Object.keys(record).sort().map((key) => JSON.stringify(key) + ":" + canonical(record[key])).join(",") + "}";
  }
  return JSON.stringify(value);
}

export function operationDigest(tool: string, args: unknown): string {
  return createHash("sha256").update(canonical({ tool, arguments: args })).digest("hex");
}

function validDate(date: unknown): date is string {
  return typeof date === "string" && Number.isFinite(Date.parse(date));
}

function fromRow(row: StoredRow): OperationReceipt {
  return {
    operation_id: row.operation_id,
    tool_name: row.tool_name,
    argument_digest: row.argument_digest,
    state: row.state,
    created_at: row.created_at,
    updated_at: row.updated_at,
    ...(row.safe_result_summary === null ? {} : { safe_result_summary: row.safe_result_summary }),
    ...(row.session_id === null ? {} : { session_id: row.session_id }),
  };
}

function parseLegacy(source: string): OperationReceipt[] {
  let data: unknown;
  try { data = JSON.parse(source) as unknown; } catch { throw new Error("Invalid legacy receipt JSON."); }
  if (!data || typeof data !== "object" || (data as LegacyData).version !== 1 ||
      !Array.isArray((data as LegacyData).receipts)) throw new Error("Unsupported legacy receipt schema.");
  const unique = new Set<string>();
  return (data as LegacyData).receipts.map((receipt) => {
    if (!receipt || typeof receipt !== "object" ||
        typeof receipt.operation_id !== "string" || !/^(?!\.{1,2}$)[A-Za-z0-9._:-]{1,128}$/.test(receipt.operation_id) ||
        !RECEIPT_TOOLS.has(receipt.tool_name) ||
        typeof receipt.argument_digest !== "string" || !/^[a-f0-9]{64}$/.test(receipt.argument_digest) ||
        !RECEIPT_STATES.has(receipt.state) ||
        !validDate(receipt.created_at) || !validDate(receipt.updated_at) ||
        (receipt.safe_result_summary !== undefined && typeof receipt.safe_result_summary !== "string") ||
        (receipt.session_id !== undefined && typeof receipt.session_id !== "string") ||
        unique.has(receipt.operation_id)) throw new Error("Legacy receipt validation failed.");
    unique.add(receipt.operation_id);
    return receipt;
  });
}

function reconcile(current: OperationReceipt[], historical: OperationReceipt[]): OperationReceipt[] {
  const entries = new Map<string, OperationReceipt>();
  // Current is authoritative, but no known uncertain effect can be downgraded
  // to a safely replayable outcome simply because a later snapshot was trimmed.
  for (const record of historical) entries.set(record.operation_id, record);
  for (const record of current) {
    const previous = entries.get(record.operation_id);
    if (previous && (previous.tool_name !== record.tool_name || previous.argument_digest !== record.argument_digest ||
        previous.created_at !== record.created_at)) throw new Error("Conflicting legacy operation identity.");
    entries.set(record.operation_id, previous &&
        (previous.state === "unknown" || previous.state === "failed") &&
        previous.state !== record.state
      ? { ...record, state: "unknown", safe_result_summary: "Effect needs operator reconciliation." }
      : record);
  }
  return [...entries.values()];
}

export class ReceiptStore {
  readonly directory: string;
  private readonly file: string;
  private readonly legacyFile: string;
  private database: DatabaseSync | undefined;
  private readonly testPersistenceUnavailable?: (phase: "begin" | "commit") => boolean;
  private readonly historicalBackupPath?: string;

  constructor(
    directory = path.join(os.homedir(), ".local", "state", "mcp-workers", "remote-control-agent"),
    testPersistenceUnavailable?: (phase: "begin" | "commit") => boolean,
    historicalBackupPath?: string,
  ) {
    this.directory = directory;
    this.testPersistenceUnavailable = testPersistenceUnavailable;
    if (historicalBackupPath && !path.isAbsolute(historicalBackupPath)) throw new Error("Historical backup path must be absolute.");
    this.historicalBackupPath = historicalBackupPath;
    this.file = path.join(directory, "operation-receipts.sqlite");
    this.legacyFile = path.join(directory, "operation-receipts.json");
  }

  private db(): DatabaseSync {
    if (!this.database) throw new Error("Receipt store is unavailable.");
    return this.database;
  }

  private getStored(id: string): StoredRow | undefined {
    return this.db().prepare("SELECT * FROM receipts WHERE operation_id = ?").get(id) as StoredRow | undefined;
  }

  private transaction<T>(action: () => T): T {
    // A local-only failure probe enables public-boundary failure tests without
    // mutating or corrupting a real SQLite file. Not exposed through MCP.
    if (this.testPersistenceUnavailable?.("begin")) throw new Error("Receipt persistence is unavailable.");
    const db = this.db();
    db.exec("BEGIN IMMEDIATE");
    try {
      const result = action();
      if (this.testPersistenceUnavailable?.("commit")) throw new Error("Receipt commit is unavailable.");
      db.exec("COMMIT");
      return result;
    } catch (error) {
      try { db.exec("ROLLBACK"); } catch { /* The store must fail closed. */ }
      throw error;
    }
  }

  private cleanup(): void {
    const cutoff = new Date(Date.now() - RECEIPT_TTL_MS).toISOString();
    this.db().prepare("DELETE FROM receipts WHERE guarded = 0 AND state IN ('completed','failed') AND created_at < ?").run(cutoff);
    this.db().prepare("UPDATE receipts SET safe_result_summary = NULL, session_id = NULL WHERE guarded = 1 AND created_at < ? AND (safe_result_summary IS NOT NULL OR session_id IS NOT NULL)").run(cutoff);
  }

  private async exists(file: string): Promise<boolean> {
    try { await stat(file); return true; } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
      throw error;
    }
  }

  private async preserveLegacy(source: string): Promise<void> {
    const backup = path.join(this.directory, "operation-receipts.pre-sqlite.json");
    try {
      await copyFile(this.legacyFile, backup, constants.COPYFILE_EXCL);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST" ||
          (await readFile(backup, "utf8")) !== source) throw error;
    }
    await chmod(backup, 0o600);
  }

  async open(): Promise<void> {
    if (this.database) return;
    await mkdir(this.directory, { recursive: true, mode: 0o700 });
    await chmod(this.directory, 0o700);
    // The kernel releases SQLite's exclusive file lock on a crash; a second
    // Agent pointing at the same state directory fails rather than co-writing.
    const db = new DatabaseSync(this.file);
    this.database = db;
    try {
      // Do not expose a newly created database with the platform umask mode.
      await chmod(this.file, 0o600);
      db.exec("PRAGMA busy_timeout = 0; PRAGMA locking_mode = EXCLUSIVE; PRAGMA synchronous = FULL;");
      const versionRow = db.prepare("PRAGMA user_version").get() as { user_version: number };
      if (versionRow.user_version !== 0 && versionRow.user_version !== 1) {
        throw new Error("Unsupported receipt database version.");
      }
      if (versionRow.user_version === 0) {
        const legacyPresent = await this.exists(this.legacyFile);
        let records: OperationReceipt[] = [];
        if (legacyPresent) {
          const original = await readFile(this.legacyFile, "utf8");
          const current = parseLegacy(original);
          // Operators with a known trimmed history supply this exact path and
          // must not accidentally migrate without it. Other Agent instances
          // do not get an invented 300-record special case.
          // Never silently import a similarly named file: history must be
          // explicitly selected and verified by the operator for this Agent.
          const historical = this.historicalBackupPath
            ? parseLegacy(await readFile(this.historicalBackupPath, "utf8"))
            : [];
          if (this.historicalBackupPath && historical.length < current.length) {
            throw new Error("Required historical receipt backup is incomplete.");
          }
          records = reconcile(current, historical);
          await this.preserveLegacy(original);
          if ((await readFile(this.legacyFile, "utf8")) !== original) throw new Error("Legacy receipt source changed.");
        }
        this.transaction(() => {
          db.exec("CREATE TABLE IF NOT EXISTS receipts (operation_id TEXT PRIMARY KEY NOT NULL, tool_name TEXT NOT NULL, argument_digest TEXT NOT NULL, state TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, safe_result_summary TEXT, session_id TEXT, guarded INTEGER NOT NULL CHECK(guarded IN (0, 1)));");
          const insert = db.prepare("INSERT INTO receipts (operation_id, tool_name, argument_digest, state, created_at, updated_at, safe_result_summary, session_id, guarded) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
          for (const receipt of records) {
            const interrupted = receipt.state === "admitted" || receipt.state === "running";
            const state = interrupted ? "unknown" : receipt.state;
            const guarded = state === "unknown" || state === "failed";
            insert.run(
              receipt.operation_id, receipt.tool_name, receipt.argument_digest, state,
              receipt.created_at, new Date().toISOString(),
              interrupted ? "Effect cannot be established after restart." : (receipt.safe_result_summary?.slice(0, 128) ?? null),
              null, guarded ? 1 : 0,
            );
          }
          db.exec("PRAGMA user_version = 1");
        });
      }
      // A query forces exclusive ownership before opening the Agent for requests.
      db.prepare("SELECT operation_id FROM receipts LIMIT 1").get();
      this.transaction(() => {
        db.exec("UPDATE receipts SET state = 'unknown', guarded = 1, session_id = NULL, safe_result_summary = 'Effect cannot be established after restart.' WHERE state IN ('admitted','running')");
        db.exec("UPDATE receipts SET session_id = NULL WHERE tool_name IN ('start_process','interact_with_process','force_terminate')");
        this.cleanup();
      });
      await chmod(this.file, 0o600);
    } catch (error) {
      try { db.close(); } catch { /* Return the original error. */ }
      this.database = undefined;
      throw error;
    }
  }

  async admit(operationId: string, toolName: OperationReceipt["tool_name"], digest: string):
    Promise<{ kind: "new" | "same" | "conflict" | "full"; receipt?: OperationReceipt }> {
    return this.transaction(() => {
      const prior = this.getStored(operationId);
      if (prior) {
        return { kind: prior.tool_name === toolName && prior.argument_digest === digest ? "same" as const : "conflict" as const, receipt: fromRow(prior) };
      }
      this.cleanup();
      const now = new Date().toISOString();
      this.db().prepare("INSERT INTO receipts (operation_id, tool_name, argument_digest, state, created_at, updated_at, safe_result_summary, session_id, guarded) VALUES (?, ?, ?, 'admitted', ?, ?, NULL, NULL, 1)")
        .run(operationId, toolName, digest, now, now);
      return { kind: "new" as const, receipt: fromRow(this.getStored(operationId)!) };
    });
  }

  async update(operationId: string, state: OperationState, summary: string, sessionId?: string, knownNoEffect = false): Promise<OperationReceipt> {
    return this.transaction(() => {
      if (!this.getStored(operationId)) throw new Error("Receipt disappeared.");
      // Nonzero process exit is not proof of zero effects. Unknown/uncertain
      // failures keep their replay guard after normal retention.
      const guarded = state === "unknown" || state === "admitted" || state === "running" ||
        (state === "failed" && !knownNoEffect);
      this.db().prepare("UPDATE receipts SET state = ?, updated_at = ?, safe_result_summary = ?, session_id = COALESCE(?, session_id), guarded = ? WHERE operation_id = ?")
        .run(state, new Date().toISOString(), summary.slice(0, 128), sessionId ?? null, guarded ? 1 : 0, operationId);
      return fromRow(this.getStored(operationId)!);
    });
  }

  async get(operationId: string): Promise<OperationReceipt | null> {
    return this.transaction(() => {
      this.cleanup();
      const prior = this.getStored(operationId);
      return prior ? fromRow(prior) : null;
    });
  }

  async close(): Promise<void> {
    if (!this.database) return;
    this.database.close();
    this.database = undefined;
  }
}
