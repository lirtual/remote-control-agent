import { randomUUID } from "node:crypto";
import { constants, createReadStream } from "node:fs";
import { lstat, opendir, open, stat, type FileHandle } from "node:fs/promises";
import path from "node:path";
import type { LocalSearch } from "./local-read.ts";

export type SearchResult =
  | { path: string }
  | { path: string; line: number; text: string };

export interface SearchPage {
  session_id?: string;
  results: SearchResult[];
  has_more: boolean;
  truncated: boolean;
  status: "running" | "complete" | "stopped";
}

export class SearchFailed extends Error {
  readonly code: "failed" | "not_found" | "conflict";

  constructor(code: "failed" | "not_found" | "conflict") {
    super(code);
    this.name = "SearchFailed";
    this.code = code;
  }
}

const PAGE_SIZE = 20;
const MAX_ACTIVE_SEARCHES = 4;
const MAX_SEARCH_DURATION_MS = 15_000;
const SEARCH_SESSION_TTL_MS = 60_000;
const MAX_DEPTH = 8;
const MAX_ENTRIES = 20_000;
const MAX_RESULTS = 500;
const MAX_TOTAL_BYTES = 32 * 1024 * 1024;
const MAX_FILE_BYTES = 2 * 1024 * 1024;
const MAX_MATCH_TEXT = 240;
const MAX_LINE_CHARS = 16_384;

interface SearchState {
  startedAt: number;
  entries: number;
  results: number;
  bytes: number;
  truncated: boolean;
  signal: AbortSignal;
}

interface SearchSession {
  id: string;
  iterator: AsyncGenerator<SearchResult>;
  state: SearchState;
  controller: AbortController;
  timer: ReturnType<typeof setTimeout>;
  pending?: SearchResult;
  busy: boolean;
}

function isExpectedFsError(error: unknown): boolean {
  if (!(error instanceof Error) || !("code" in error)) return false;
  const code = (error as NodeJS.ErrnoException).code;
  return ["ENOENT", "EACCES", "EPERM", "ENOTDIR", "ELOOP", "ENAMETOOLONG", "EINVAL", "EIO", "EBUSY", "EAGAIN"].includes(
    code ?? "",
  );
}

function checkActive(state: SearchState): boolean {
  if (state.signal.aborted) return false;
  if (state.bytes >= MAX_TOTAL_BYTES) {
    state.truncated = true;
    return false;
  }
  if (Date.now() - state.startedAt >= MAX_SEARCH_DURATION_MS) {
    state.truncated = true;
    return false;
  }
  return true;
}

async function* walkFiles(
  directory: string,
  relativeDirectory: string,
  depth: number,
  state: SearchState,
): AsyncGenerator<{ fullPath: string; relativePath: string; file: boolean; directory: boolean }> {
  if (!checkActive(state)) return;

  let handle;
  try {
    const info = await lstat(directory);
    if (!info.isDirectory() || info.isSymbolicLink()) throw new SearchFailed("failed");
    handle = await opendir(directory);
  } catch (error) {
    if (state.signal.aborted) return;
    if (isExpectedFsError(error)) throw new SearchFailed("failed");
    throw error;
  }

  try {
    for await (const entry of handle) {
      if (!checkActive(state)) return;
      state.entries += 1;
      if (state.entries > MAX_ENTRIES) {
        state.truncated = true;
        return;
      }
      const relativePath = relativeDirectory ? path.join(relativeDirectory, entry.name) : entry.name;
      const fullPath = path.join(directory, entry.name);
      const file = entry.isFile();
      const isDirectory = entry.isDirectory();
      yield { fullPath, relativePath, file, directory: isDirectory };
      if (isDirectory && depth < MAX_DEPTH) {
        yield* walkFiles(fullPath, relativePath, depth + 1, state);
      }
    }
  } catch (error) {
    if (state.signal.aborted) return;
    if (error instanceof SearchFailed) throw error;
    if (isExpectedFsError(error)) throw new SearchFailed("failed");
    throw error;
  }
}

async function* contentMatches(
  fullPath: string,
  relativePath: string,
  pattern: string,
  state: SearchState,
): AsyncGenerator<SearchResult> {
  let fileInfo;
  try {
    fileInfo = await stat(fullPath);
  } catch (error) {
    if (state.signal.aborted) return;
    if (isExpectedFsError(error)) throw new SearchFailed("failed");
    throw error;
  }
  if (fileInfo.size > MAX_FILE_BYTES) {
    state.truncated = true;
    return;
  }

  let lineNumber = 1;
  let line = "";
  let oversizedLine = false;
  let input: ReturnType<typeof createReadStream>;
  let fileHandle: FileHandle | undefined;
  try {
    fileHandle = await open(fullPath, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    if (!(await fileHandle.stat()).isFile()) {
      await fileHandle.close();
      return;
    }
    input = fileHandle.createReadStream({ encoding: "utf8", signal: state.signal });
  } catch (error) {
    await fileHandle?.close().catch(() => undefined);
    if (state.signal.aborted) return;
    if (isExpectedFsError(error)) throw new SearchFailed("failed");
    throw error;
  }

  try {
    for await (const chunkValue of input) {
      if (!checkActive(state)) return;
      const chunk = String(chunkValue);
      state.bytes += Buffer.byteLength(chunk);
      if (state.bytes > MAX_TOTAL_BYTES) {
        state.truncated = true;
        return;
      }
      let start = 0;
      for (let index = 0; index < chunk.length; index += 1) {
        if (chunk[index] !== "\n") continue;
        const part = chunk.slice(start, index);
        if (!oversizedLine) {
          line += part;
          const value = line.endsWith("\r") ? line.slice(0, -1) : line;
          if (value.includes(pattern)) {
            state.results += 1;
            yield { path: relativePath, line: lineNumber, text: value.slice(0, MAX_MATCH_TEXT) };
            if (state.results >= MAX_RESULTS) {
              state.truncated = true;
              return;
            }
          }
        }
        lineNumber += 1;
        line = "";
        oversizedLine = false;
        start = index + 1;
      }
      const remainder = chunk.slice(start);
      if (!oversizedLine) {
        if (line.length + remainder.length > MAX_LINE_CHARS) {
          line = "";
          oversizedLine = true;
          state.truncated = true;
        } else {
          line += remainder;
        }
      }
    }
  } catch (error) {
    if (state.signal.aborted) return;
    if (error instanceof SearchFailed) throw error;
    if (isExpectedFsError(error)) throw new SearchFailed("failed");
    throw error;
  }

  if (!oversizedLine && line.includes(pattern) && checkActive(state)) {
    state.results += 1;
    yield { path: relativePath, line: lineNumber, text: line.slice(0, MAX_MATCH_TEXT) };
    if (state.results >= MAX_RESULTS) state.truncated = true;
  }
}

async function* searchMatches(input: LocalSearch, state: SearchState): AsyncGenerator<SearchResult> {
  let rootInfo;
  try {
    rootInfo = await lstat(input.path);
  } catch (error) {
    if (isExpectedFsError(error)) throw new SearchFailed("failed");
    throw error;
  }
  if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink()) throw new SearchFailed("failed");

  for await (const entry of walkFiles(input.path, "", 1, state)) {
    if (!checkActive(state)) return;
    if (input.searchType === "filename") {
      if (entry.relativePath.includes(input.pattern)) {
        state.results += 1;
        yield { path: entry.relativePath };
        if (state.results >= MAX_RESULTS) {
          state.truncated = true;
          return;
        }
      }
    } else if (entry.file) {
      yield* contentMatches(entry.fullPath, entry.relativePath, input.pattern, state);
    }
  }
}

export class SearchSessions {
  private readonly sessions = new Map<string, SearchSession>();
  private readonly sessionTtlMs: number;

  constructor(sessionTtlMs = SEARCH_SESSION_TTL_MS) {
    this.sessionTtlMs = Number.isFinite(sessionTtlMs) && sessionTtlMs > 0 ? sessionTtlMs : SEARCH_SESSION_TTL_MS;
  }

  async start(input: LocalSearch, requestSignal?: AbortSignal): Promise<SearchPage> {
    if (requestSignal?.aborted) throw new SearchFailed("failed");
    if (this.sessions.size >= MAX_ACTIVE_SEARCHES) throw new SearchFailed("conflict");
    const controller = new AbortController();
    const state: SearchState = {
      startedAt: Date.now(),
      entries: 0,
      results: 0,
      bytes: 0,
      truncated: false,
      signal: controller.signal,
    };
    const id = randomUUID();
    const timer = setTimeout(() => void this.stop(id), this.sessionTtlMs);
    timer.unref?.();
    const session: SearchSession = {
      id,
      iterator: searchMatches(input, state),
      state,
      controller,
      timer,
      busy: false,
    };
    this.sessions.set(id, session);
    const stopWatching = this.cancelOnAbort(session, requestSignal);
    try {
      const page = await this.page(session);
      if (requestSignal?.aborted) throw new SearchFailed("failed");
      if (!page.has_more) await this.dispose(session, false);
      return { ...page, ...(page.has_more ? { session_id: id } : {}) };
    } catch (error) {
      await this.dispose(session, true);
      throw error;
    } finally {
      stopWatching();
    }
  }

  async more(sessionId: string, requestSignal?: AbortSignal): Promise<SearchPage> {
    if (requestSignal?.aborted) throw new SearchFailed("failed");
    const session = this.sessions.get(sessionId);
    if (!session) throw new SearchFailed("not_found");
    if (session.busy) throw new SearchFailed("conflict");
    if (Date.now() - session.state.startedAt >= this.sessionTtlMs) {
      await this.dispose(session, true);
      throw new SearchFailed("not_found");
    }
    const stopWatching = this.cancelOnAbort(session, requestSignal);
    try {
      const page = await this.page(session);
      if (requestSignal?.aborted) throw new SearchFailed("failed");
      if (!page.has_more) await this.dispose(session, false);
      return { ...page, ...(page.has_more ? { session_id: sessionId } : {}) };
    } catch (error) {
      await this.dispose(session, true);
      throw error;
    } finally {
      stopWatching();
    }
  }

  async stop(sessionId: string): Promise<SearchPage> {
    const session = this.sessions.get(sessionId);
    if (!session) throw new SearchFailed("not_found");
    await this.dispose(session, true);
    return { results: [], has_more: false, truncated: false, status: "stopped" };
  }

  async close(): Promise<void> {
    await Promise.all([...this.sessions.values()].map((session) => this.dispose(session, true)));
  }

  private cancelOnAbort(session: SearchSession, signal?: AbortSignal): () => void {
    if (!signal) return () => undefined;
    const cancel = () => void this.dispose(session, true);
    signal.addEventListener("abort", cancel, { once: true });
    if (signal.aborted) cancel();
    return () => signal.removeEventListener("abort", cancel);
  }

  private async page(session: SearchSession): Promise<SearchPage> {
    if (session.busy) throw new SearchFailed("conflict");
    session.busy = true;
    try {
      const results: SearchResult[] = [];
      if (session.pending) {
        results.push(session.pending);
        delete session.pending;
      }
      while (results.length < PAGE_SIZE) {
        if (!checkActive(session.state)) break;
        const next = await session.iterator.next();
        if (next.done) break;
        results.push(next.value);
      }
      if (results.length === PAGE_SIZE && !session.state.signal.aborted && checkActive(session.state)) {
        const next = await session.iterator.next();
        if (!next.done) session.pending = next.value;
      }
      const hasMore = session.pending !== undefined;
      return {
        results,
        has_more: hasMore,
        truncated: session.state.truncated,
        status: hasMore ? "running" : "complete",
      };
    } finally {
      session.busy = false;
    }
  }

  private async dispose(session: SearchSession, abort: boolean): Promise<void> {
    if (this.sessions.get(session.id) === session) this.sessions.delete(session.id);
    clearTimeout(session.timer);
    if (abort) session.controller.abort();
    try {
      await session.iterator.return(undefined);
    } catch {
      // The iterator can already be completing after an abort.
    }
  }
}
