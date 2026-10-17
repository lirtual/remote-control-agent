/**
 * Internal read-only/search execution seam shared by the v1 authenticated
 * loopback adapter and the future v2 Agent adapter.
 *
 * This does not authenticate callers: do NOT expose it directly over a socket.
 * The transport must authorize the specific device, operation and capability
 * before invoking this executor. Mutations/Shell remain in the existing v1
 * engine until their receipt-safe seam is separately extracted.
 */
import { listLocalDirectory, readLocalFileInfo, readMultipleLocalFiles, BrowseFailed } from "./browse.ts";
import {
  parseFileInfo, parseListDirectory, parseLocalRead, parseReadMultiple,
  parseSearchSessionId, parseSearchStart,
} from "./local-read.ts";
import { readLocalFile, ReadFailed } from "./read-file.ts";
import { SearchFailed, SearchSessions } from "./search.ts";

export type ReadToolOutcome =
  | { kind: "rejected"; message: string }
  | {
      kind: "failed";
      event: "read_failed" | "list_failed" | "info_failed" | "search_failed";
      code: "bad_request" | "failed" | "not_found" | "conflict";
      message: string;
    }
  | { kind: "unavailable" }
  | {
      kind: "completed";
      event: "read_completed" | "list_completed" | "info_completed" | "search_completed" | "search_stopped";
      text: string;
    };

export async function executeReadTool(
  tool: unknown,
  args: unknown,
  searches: SearchSessions,
  requestSignal: AbortSignal,
  onSearchStart?: () => void,
): Promise<ReadToolOutcome> {
  try {
    if (tool === "read_file") {
      const read = parseLocalRead(args);
      if (!read) return { kind: "rejected", message: "The requested tool call was rejected." };
      return { kind: "completed", event: "read_completed", text: await readLocalFile(read) };
    }
    if (tool === "read_multiple_files") {
      const read = parseReadMultiple(args);
      if (!read) return { kind: "rejected", message: "The requested tool call was rejected." };
      return { kind: "completed", event: "read_completed", text: await readMultipleLocalFiles(read) };
    }
    if (tool === "list_directory") {
      const list = parseListDirectory(args);
      if (!list) return { kind: "rejected", message: "The requested tool call was rejected." };
      return { kind: "completed", event: "list_completed", text: await listLocalDirectory(list) };
    }
    if (tool === "get_file_info") {
      const info = parseFileInfo(args);
      if (!info) return { kind: "rejected", message: "The requested tool call was rejected." };
      return { kind: "completed", event: "info_completed", text: await readLocalFileInfo(info) };
    }
    if (tool === "start_search") {
      const search = parseSearchStart(args);
      if (!search) return { kind: "rejected", message: "The requested tool call was rejected." };
      onSearchStart?.();
      return {
        kind: "completed",
        event: "search_completed",
        text: JSON.stringify(await searches.start(search, requestSignal)),
      };
    }
    if (tool === "get_more_search_results" || tool === "stop_search") {
      const session = parseSearchSessionId(args);
      if (!session) return { kind: "rejected", message: "The requested tool call was rejected." };
      const result =
        tool === "get_more_search_results"
          ? await searches.more(session.sessionId, requestSignal)
          : await searches.stop(session.sessionId);
      return {
        kind: "completed",
        event: tool === "stop_search" ? "search_stopped" : "search_completed",
        text: JSON.stringify(result),
      };
    }
    return { kind: "rejected", message: "The requested tool is not available." };
  } catch (error) {
    if (error instanceof ReadFailed) {
      return { kind: "failed", event: "read_failed", code: "bad_request", message: "The file read failed." };
    }
    if (error instanceof BrowseFailed) {
      const event = error.message.startsWith("The directory")
        ? "list_failed"
        : error.message.startsWith("The file info")
          ? "info_failed"
          : "read_failed";
      return { kind: "failed", event, code: "bad_request", message: error.message };
    }
    if (error instanceof SearchFailed) {
      return {
        kind: "failed",
        event: "search_failed",
        code: error.code,
        message: "The local search request could not be completed.",
      };
    }
    return { kind: "unavailable" };
  }
}
