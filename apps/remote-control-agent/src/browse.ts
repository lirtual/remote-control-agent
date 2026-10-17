import { lstat, readdir, realpath } from "node:fs/promises";
import path from "node:path";
import { MAX_DIRECTORY_ENTRIES } from "./local-read.ts";
import type { LocalFileInfo, LocalListDirectory, LocalReadMultiple } from "./local-read.ts";
import { MAX_RESULT_CHARS, readLocalFile, ReadFailed } from "./read-file.ts";

export class BrowseFailed extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BrowseFailed";
  }
}

function isExpectedFsError(error: unknown): boolean {
  if (!(error instanceof Error) || !("code" in error)) return false;
  const code = (error as NodeJS.ErrnoException).code;
  return (
    code === "ENOENT" ||
    code === "EACCES" ||
    code === "EPERM" ||
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

function fail(error: unknown, message: string): never {
  if (error instanceof BrowseFailed) throw error;
  if (isExpectedFsError(error)) throw new BrowseFailed(message);
  throw error;
}

function kindOf(entry: { isSymbolicLink: () => boolean; isDirectory: () => boolean; isFile: () => boolean }): string {
  if (entry.isSymbolicLink()) return "symlink";
  if (entry.isDirectory()) return "directory";
  if (entry.isFile()) return "file";
  return "other";
}

export async function listLocalDirectory(request: LocalListDirectory): Promise<string> {
  const lines: string[] = [];
  let truncated = false;
  const seen = new Set<string>();

  const visit = async (directory: string, relative: string, depthLeft: number): Promise<void> => {
    let identity: string;
    try {
      identity = await realpath(directory);
    } catch (error) {
      fail(error, "The directory list failed.");
    }
    if (seen.has(identity)) return;
    seen.add(identity);

    let entries;
    try {
      entries = await readdir(directory, { withFileTypes: true });
    } catch (error) {
      fail(error, "The directory list failed.");
    }
    entries.sort((left, right) => (left.name < right.name ? -1 : left.name > right.name ? 1 : 0));

    for (const entry of entries) {
      if (lines.length >= MAX_DIRECTORY_ENTRIES) {
        truncated = true;
        return;
      }
      const relativePath = relative.length === 0 ? entry.name : `${relative}/${entry.name}`;
      const kind = kindOf(entry);
      lines.push(`${kind} ${relativePath}`);
      if (kind === "directory" && depthLeft > 1) {
        await visit(path.join(directory, entry.name), relativePath, depthLeft - 1);
        if (truncated) return;
      }
    }
  };

  try {
    const info = await lstat(request.path);
    if (!info.isDirectory() || info.isSymbolicLink()) throw new BrowseFailed("The directory list failed.");
    await visit(request.path, "", request.depth);
  } catch (error) {
    fail(error, "The directory list failed.");
  }

  return `depth: ${request.depth}\ntruncated: ${truncated}\n${lines.join("\n")}`;
}

export async function readLocalFileInfo(request: LocalFileInfo): Promise<string> {
  try {
    const info = await lstat(request.path);
    const kind = info.isSymbolicLink()
      ? "symlink"
      : info.isDirectory()
        ? "directory"
        : info.isFile()
          ? "file"
          : "other";
    const mode = (info.mode & 0o777).toString(8).padStart(3, "0");
    return `type: ${kind}\nsize: ${info.size}\nmode: ${mode}\nmtime_ms: ${Math.trunc(info.mtimeMs)}`;
  } catch (error) {
    fail(error, "The file info request failed.");
  }
}

export async function readMultipleLocalFiles(request: LocalReadMultiple): Promise<string> {
  const blocks: string[] = [];
  let chars = 0;
  let truncated = false;

  for (let index = 0; index < request.paths.length; index += 1) {
    let body: string;
    try {
      body = `status: ok\n${await readLocalFile({ path: request.paths[index] ?? "" })}`;
    } catch (error) {
      if (error instanceof ReadFailed) {
        body = "status: failed\nmessage: The file read failed.";
      } else {
        throw error;
      }
    }
    const block = `# file ${index + 1}\n${body}`;
    if (chars + block.length + 1 > MAX_RESULT_CHARS) {
      truncated = true;
      break;
    }
    blocks.push(block);
    chars += block.length + 1;
  }

  return `${blocks.join("\n")}\ntruncated: ${truncated}`;
}
