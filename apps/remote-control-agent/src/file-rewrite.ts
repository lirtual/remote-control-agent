import { randomUUID } from "node:crypto";
import { constants } from "node:fs";
import {
  access, link, lstat, open, readFile, realpath, statfs, unlink,
} from "node:fs/promises";
import path from "node:path";

/** Provably no target modification, not an inferred OS errno after a commit. */
export class NoTargetEffectError extends Error {}

// Only locally verified Linux ext filesystems; all others keep the old path.
const ATOMIC_FILESYSTEMS = new Set([0xef53]);

async function canStageNewFile(target: string): Promise<boolean> {
  if (process.platform !== "linux" || process.getuid?.() !== process.geteuid?.() ||
      process.getgid?.() !== process.getegid?.()) return false;
  const directory = path.dirname(target);
  if (Buffer.byteLength(path.basename(target), "utf8") > 200) return false;
  try {
    const parent = await lstat(directory);
    // A private, ordinary parent avoids exposing a staged file before chmod.
    if (!parent.isDirectory() || parent.uid !== process.geteuid?.() ||
        (parent.mode & 0o3077) !== 0 ||
        await realpath(directory) !== path.resolve(directory)) return false;
    if (!ATOMIC_FILESYSTEMS.has((await statfs(directory)).type)) return false;
    await access(directory, constants.W_OK | constants.X_OK);
    // Existing-file rename changes inode, ACL/xattrs, and external handles.
    // Node built-ins cannot establish those compatibility conditions; use
    // the original in-place rewrite for every existing target.
    try { await lstat(target); return false; }
    catch (error) { return (error as NodeJS.ErrnoException).code === "ENOENT"; }
  } catch { return false; }
}

export interface FileRewriteOptions {
  expectedOriginal?: Buffer;
  /** Local integration-test probes only, never passed over MCP. */
  fileStageForTests?: (stage: "staged" | "precommit", target: string) => Promise<void>;
}

async function sourceUnchanged(target: string, expectedOriginal: Buffer): Promise<boolean> {
  try { return Buffer.from(await readFile(target)).equals(expectedOriginal); }
  catch { return false; }
}

/** Stage only compatible new files; legacy rewrites preserve existing inodes. */
export async function rewriteFile(
  target: string, content: string, options: FileRewriteOptions = {},
): Promise<void> {
  if (!(await canStageNewFile(target))) {
    // Revalidate immediately before the legacy open; this remains best effort,
    // not compare-and-swap against external writers.
    if (options.expectedOriginal) {
      await options.fileStageForTests?.("precommit", target);
      if (!(await sourceUnchanged(target, options.expectedOriginal)))
        throw new NoTargetEffectError("Source changed before edit.");
    }
    let handle: Awaited<ReturnType<typeof open>>;
    try { handle = await open(target, "w"); }
    catch (error) {
      if (["EACCES", "EPERM", "ENOENT", "ENOTDIR", "EISDIR", "ELOOP", "EROFS"].includes(
        (error as NodeJS.ErrnoException).code ?? "",
      )) throw new NoTargetEffectError("Could not open target for writing.");
      throw error;
    }
    try { await handle.writeFile(content, "utf8"); }
    finally { await handle.close(); }
    return;
  }

  const temp = path.join(path.dirname(target), `.${path.basename(target)}.rca-${randomUUID()}.tmp`);
  let owned: { dev: number; ino: number } | undefined;
  let commitStarted = false;
  try {
    const handle = await open(temp, "wx", 0o600);
    try {
      owned = await handle.stat();
      await handle.writeFile(content, "utf8");
      // The test seam observes a fully written, still-private temporary file.
      await options.fileStageForTests?.("staged", target);
      await handle.chmod(0o666 & ~process.umask());
    } finally { await handle.close(); }
    // The exclusive link is the final authority if another process created
    // the destination after our check. Never retry a failed link as overwrite.
    try {
      await lstat(target);
      throw new NoTargetEffectError("Destination appeared before commit.");
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    commitStarted = true;
    await link(temp, target);
  } catch (error) {
    if (commitStarted) throw error; // Link outcome might be unknown.
    if (error instanceof NoTargetEffectError) throw error;
    throw new NoTargetEffectError("File staging failed before commit.");
  } finally {
    // Only the temporary inode created by this operation may be removed.
    if (owned) {
      try {
        const current = await lstat(temp);
        if (current.dev === owned.dev && current.ino === owned.ino)
          await unlink(temp);
      } catch { /* Cleanup is distinct from target commit certainty. */ }
    }
  }
}
