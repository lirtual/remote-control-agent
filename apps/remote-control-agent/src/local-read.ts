/** Local read_file arguments accepted by the agent. Enforced here, not only by the Worker. */
export interface LocalRead {
  path: string;
  offset?: number;
  length?: number;
}

const ALLOWED_KEYS = new Set(["path", "offset", "length", "isUrl"]);
const MAX_PATH_LENGTH = 4096;
const MIN_OFFSET = -100_000;
const MAX_OFFSET = 1_000_000;
const MAX_LENGTH = 1000;

function isIntegerInRange(value: unknown, min: number, max: number): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= min && value <= max;
}

/** Linux paths only. A scheme such as http: or file: is a URL read, not a local path. */
function hasUriScheme(path: string): boolean {
  return /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(path);
}

export function parseLocalRead(input: unknown): LocalRead | null {
  if (input === null || typeof input !== "object" || Array.isArray(input)) return null;

  const record = input as Record<string, unknown>;
  for (const key of Object.keys(record)) {
    if (!ALLOWED_KEYS.has(key)) return null;
  }

  if (record.isUrl !== undefined && record.isUrl !== false) return null;

  const filePath = record.path;
  if (typeof filePath !== "string") return null;
  if (filePath.length === 0 || filePath.length > MAX_PATH_LENGTH) return null;
  if (filePath.includes("\0") || filePath.startsWith("//") || hasUriScheme(filePath)) return null;

  const read: LocalRead = { path: filePath };
  if (record.offset !== undefined) {
    if (!isIntegerInRange(record.offset, MIN_OFFSET, MAX_OFFSET)) return null;
    read.offset = record.offset;
  }
  if (record.length !== undefined) {
    if (!isIntegerInRange(record.length, 1, MAX_LENGTH)) return null;
    read.length = record.length;
  }
  return read;
}

export const MAX_BATCH_FILES = 8;
export const MAX_DIRECTORY_DEPTH = 3;
export const DEFAULT_DIRECTORY_DEPTH = 1;
export const MAX_DIRECTORY_ENTRIES = 100;

export interface LocalReadMultiple {
  paths: string[];
}

export interface LocalListDirectory {
  path: string;
  depth: number;
}

export interface LocalFileInfo {
  path: string;
}

export interface LocalSearch {
  path: string;
  pattern: string;
  searchType: "filename" | "content";
}

export interface SearchSessionId {
  sessionId: string;
}

export interface LocalWriteFile {
  path: string;
  content: string;
  mode: "rewrite" | "append";
}

export interface OperationId {
  operationId: string;
}

export interface LocalCreateDirectory { path: string }
export interface LocalEditBlock { filePath: string; oldString: string; newString: string; expectedReplacements: number }
export interface LocalMoveFile { source: string; destination: string }
export interface LocalDeleteFile { path: string }

const MAX_WRITE_CONTENT_BYTES = 49_152;
const OPERATION_ID = /^(?!\.{1,2}$)[A-Za-z0-9._:-]{1,128}$/;

export function parseLocalCreateDirectory(input: unknown): LocalCreateDirectory | null {
  if (input === null || typeof input !== "object" || Array.isArray(input)) return null;
  const record = input as Record<string, unknown>;
  if (Object.keys(record).some((key) => key !== "path")) return null;
  const directory = parsePath(record.path);
  return directory ? { path: directory } : null;
}

export function parseLocalEditBlock(input: unknown): LocalEditBlock | null {
  if (input === null || typeof input !== "object" || Array.isArray(input)) return null;
  const record = input as Record<string, unknown>;
  if (Object.keys(record).some((key) => !["file_path", "old_string", "new_string", "expected_replacements"].includes(key))) return null;
  const filePath = parsePath(record.file_path);
  if (!filePath || typeof record.old_string !== "string" || record.old_string.length === 0 || typeof record.new_string !== "string") return null;
  if (record.old_string.includes("\0") || record.new_string.includes("\0") || Buffer.byteLength(record.old_string, "utf8") > MAX_WRITE_CONTENT_BYTES || Buffer.byteLength(record.new_string, "utf8") > MAX_WRITE_CONTENT_BYTES) return null;
  const expected = record.expected_replacements === undefined ? 1 : record.expected_replacements;
  if (typeof expected !== "number" || !Number.isSafeInteger(expected) || expected < 1 || expected > 1000) return null;
  return { filePath, oldString: record.old_string, newString: record.new_string, expectedReplacements: expected };
}

export function parseLocalMoveFile(input: unknown): LocalMoveFile | null {
  if (input === null || typeof input !== "object" || Array.isArray(input)) return null;
  const record = input as Record<string, unknown>;
  if (Object.keys(record).some((key) => !["source", "destination"].includes(key))) return null;
  const source = parsePath(record.source); const destination = parsePath(record.destination);
  if (!source || !destination || source === destination) return null;
  return { source, destination };
}

export function parseLocalDeleteFile(input: unknown): LocalDeleteFile | null {
  return parseLocalCreateDirectory(input);
}

export function parseLocalWriteFile(input: unknown): LocalWriteFile | null {
  if (input === null || typeof input !== "object" || Array.isArray(input)) return null;
  const record = input as Record<string, unknown>;
  if (Object.keys(record).some((key) => !["path", "content", "mode"].includes(key))) return null;
  const filePath = parsePath(record.path);
  if (!filePath || typeof record.content !== "string" || Buffer.byteLength(record.content, "utf8") > MAX_WRITE_CONTENT_BYTES) return null;
  if (record.content.includes("\0") || (record.mode !== "rewrite" && record.mode !== "append")) return null;
  return { path: filePath, content: record.content, mode: record.mode };
}

export function parseOperationId(input: unknown): OperationId | null {
  if (input === null || typeof input !== "object" || Array.isArray(input)) return null;
  const record = input as Record<string, unknown>;
  if (Object.keys(record).length !== 1 || Object.keys(record)[0] !== "operation_id") return null;
  if (typeof record.operation_id !== "string" || !OPERATION_ID.test(record.operation_id)) return null;
  return { operationId: record.operation_id };
}

const MAX_SEARCH_PATTERN_LENGTH = 256;
const SEARCH_SESSION_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

function parsePath(value: unknown): string | null {
  if (typeof value !== "string") return null;
  if (value.length === 0 || value.length > MAX_PATH_LENGTH) return null;
  if (value.includes("\0") || value.startsWith("//") || hasUriScheme(value)) return null;
  return value;
}

export function parseReadMultiple(input: unknown): LocalReadMultiple | null {
  if (input === null || typeof input !== "object" || Array.isArray(input)) return null;
  const record = input as Record<string, unknown>;
  if (Object.keys(record).some((key) => key !== "paths")) return null;
  if (!Array.isArray(record.paths) || record.paths.length === 0 || record.paths.length > MAX_BATCH_FILES) {
    return null;
  }
  const paths: string[] = [];
  for (const entry of record.paths) {
    const filePath = parsePath(entry);
    if (!filePath) return null;
    paths.push(filePath);
  }
  return { paths };
}

export function parseListDirectory(input: unknown): LocalListDirectory | null {
  if (input === null || typeof input !== "object" || Array.isArray(input)) return null;
  const record = input as Record<string, unknown>;
  if (Object.keys(record).some((key) => key !== "path" && key !== "depth")) return null;
  const directoryPath = parsePath(record.path);
  if (!directoryPath) return null;
  if (record.depth === undefined) return { path: directoryPath, depth: DEFAULT_DIRECTORY_DEPTH };
  if (!isIntegerInRange(record.depth, 1, MAX_DIRECTORY_DEPTH)) return null;
  return { path: directoryPath, depth: record.depth };
}

export function parseFileInfo(input: unknown): LocalFileInfo | null {
  if (input === null || typeof input !== "object" || Array.isArray(input)) return null;
  const record = input as Record<string, unknown>;
  if (Object.keys(record).some((key) => key !== "path")) return null;
  const filePath = parsePath(record.path);
  if (!filePath) return null;
  return { path: filePath };
}

export function parseSearchStart(input: unknown): LocalSearch | null {
  if (input === null || typeof input !== "object" || Array.isArray(input)) return null;
  const record = input as Record<string, unknown>;
  if (Object.keys(record).some((key) => !["path", "pattern", "search_type"].includes(key))) return null;
  const searchPath = parsePath(record.path);
  const pattern = record.pattern;
  const searchType = record.search_type;
  if (!searchPath || typeof pattern !== "string" || pattern.length === 0 || pattern.length > MAX_SEARCH_PATTERN_LENGTH) {
    return null;
  }
  if (pattern.includes("\0") || (searchType !== "filename" && searchType !== "content")) return null;
  return { path: searchPath, pattern, searchType };
}

export function parseSearchSessionId(input: unknown): SearchSessionId | null {
  if (input === null || typeof input !== "object" || Array.isArray(input)) return null;
  const record = input as Record<string, unknown>;
  if (Object.keys(record).length !== 1 || Object.keys(record)[0] !== "session_id") return null;
  if (typeof record.session_id !== "string" || !SEARCH_SESSION_ID.test(record.session_id)) return null;
  return { sessionId: record.session_id };
}
