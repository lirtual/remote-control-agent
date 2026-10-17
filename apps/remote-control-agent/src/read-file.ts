import { constants } from "node:fs";
import { open, type FileHandle } from "node:fs/promises";
import type { LocalRead } from "./local-read.ts";

/** Returned text cap. Above this, the read fails instead of returning a partial secret. */
export const MAX_RESULT_CHARS = 200_000;
/** Bytes read from the start of a file while seeking a line window. */
export const MAX_SCAN_BYTES = 1_048_576;

const DEFAULT_LINE_COUNT = 1000;
const CHUNK_BYTES = 64 * 1024;

export class ReadFailed extends Error {
  constructor() {
    super("The file read failed.");
    this.name = "ReadFailed";
  }
}

function isExpectedFsError(error: unknown): boolean {
  if (!(error instanceof Error) || !("code" in error)) return false;
  const code = (error as NodeJS.ErrnoException).code;
  return (
    code === "ENOENT" ||
    code === "EACCES" ||
    code === "EPERM" ||
    code === "EISDIR" ||
    code === "ENOTDIR" ||
    code === "ELOOP" ||
    code === "ENAMETOOLONG" ||
    code === "EINVAL" ||
    code === "EIO" ||
    code === "EBUSY" ||
    code === "ETXTBSY" ||
    code === "EAGAIN"
  );
}

function fail(error: unknown): never {
  if (error instanceof ReadFailed) throw error;
  if (isExpectedFsError(error)) throw new ReadFailed();
  throw error;
}

function cappedJoin(lines: string[]): string {
  let chars = 0;
  for (const line of lines) {
    const extra = line.length + (chars > 0 ? 1 : 0);
    if (line.length > MAX_RESULT_CHARS || chars + extra > MAX_RESULT_CHARS) throw new ReadFailed();
    chars += extra;
  }
  return lines.join("\n");
}

/**
 * Take one line. A trailing CR stays buffered so a following LF can complete CRLF.
 * Returns null when the buffer has no complete line yet.
 */
function takeLine(pending: string): { line: string; rest: string } | null {
  const newline = pending.indexOf("\n");
  const carriage = pending.indexOf("\r");
  if (newline === -1 && carriage === -1) return null;
  if (carriage !== -1 && (newline === -1 || carriage < newline)) {
    if (carriage === pending.length - 1) return null;
    const restStart = pending.charAt(carriage + 1) === "\n" ? carriage + 2 : carriage + 1;
    return { line: pending.slice(0, carriage), rest: pending.slice(restStart) };
  }
  let line = pending.slice(0, newline);
  if (line.endsWith("\r")) line = line.slice(0, -1);
  return { line, rest: pending.slice(newline + 1) };
}

async function forEachLine(
  handle: FileHandle,
  onLine: (line: string) => "continue" | "stop",
): Promise<void> {
  const decoder = new TextDecoder("utf-8");
  const buffer = Buffer.alloc(CHUNK_BYTES);
  let pending = "";
  let scanned = 0;
  let position = 0;

  const emitPendingLines = (): "continue" | "stop" => {
    let next = takeLine(pending);
    while (next) {
      pending = next.rest;
      if (onLine(next.line) === "stop") return "stop";
      next = takeLine(pending);
    }
    if (pending.length > MAX_RESULT_CHARS) throw new ReadFailed();
    return "continue";
  };

  for (;;) {
    let bytesRead = 0;
    try {
      const result = await handle.read(buffer, 0, buffer.length, position);
      bytesRead = result.bytesRead;
    } catch (error) {
      fail(error);
    }
    if (bytesRead === 0) break;
    position += bytesRead;
    scanned += bytesRead;
    if (scanned > MAX_SCAN_BYTES) throw new ReadFailed();
    pending += decoder.decode(buffer.subarray(0, bytesRead), { stream: true });
    if (emitPendingLines() === "stop") return;
  }

  pending += decoder.decode();
  if (emitPendingLines() === "stop") return;
  if (pending.endsWith("\r")) pending = pending.slice(0, -1);
  if (pending.length > 0) onLine(pending);
}

async function readForward(handle: FileHandle, offset: number, lineCount: number): Promise<string> {
  const selected: string[] = [];
  let index = 0;
  await forEachLine(handle, (line) => {
    const current = index;
    index += 1;
    if (current < offset) return "continue";
    if (selected.length >= lineCount) return "stop";
    selected.push(line);
    return selected.length >= lineCount ? "stop" : "continue";
  });
  return cappedJoin(selected);
}

async function readFromEnd(handle: FileHandle, offset: number, lineCount: number): Promise<string> {
  const info = await handle.stat();
  if (info.size > MAX_SCAN_BYTES) throw new ReadFailed();
  const lines: string[] = [];
  await forEachLine(handle, (line) => {
    lines.push(line);
    return "continue";
  });
  const start = Math.max(0, lines.length + offset);
  return cappedJoin(lines.slice(start, start + lineCount));
}

export async function readLocalFile(read: LocalRead): Promise<string> {
  let handle: FileHandle;
  try {
    handle = await open(read.path, constants.O_RDONLY | constants.O_NONBLOCK);
  } catch (error) {
    fail(error);
  }

  try {
    const info = await handle.stat();
    if (!info.isFile()) throw new ReadFailed();
    const offset = read.offset ?? 0;
    const lineCount = read.length ?? DEFAULT_LINE_COUNT;
    if (offset < 0) return await readFromEnd(handle, offset, lineCount);
    return await readForward(handle, offset, lineCount);
  } catch (error) {
    fail(error);
  } finally {
    await handle.close().catch(() => undefined);
  }
}
