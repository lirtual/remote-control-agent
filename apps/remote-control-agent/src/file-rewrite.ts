import { randomUUID } from "node:crypto";
import { constants } from "node:fs";
import {
  access, link, lstat, open, readFile, readdir, realpath, rename, stat,
  statfs, unlink,
} from "node:fs/promises";
import path from "node:path";

/**
 * A definite no-target-effect failure. Filesystem commit uncertainty is never
 * represented by this type (even when an OS errno looks recoverable).
 */
export class NoTargetEffectError extends Error {}

type Snapshot = { dev: number; ino: number; ctimeMs: number; mtimeMs: number; size: number };
function sameSnapshot(a: Snapshot, b: Snapshot): boolean {
  return a.dev === b.dev && a.ino === b.ino &&
    a.ctimeMs === b.ctimeMs && a.mtimeMs === b.mtimeMs && a.size === b.size;
}

type Eligibility = "create" | "replace" | "legacy";
// Only the locally verified Linux ext filesystem; all others keep the old path.
const ATOMIC_FILESYSTEMS = new Set([0xef53]);

async function agentHasOpenDescriptor(info: Snapshot): Promise<boolean> {
  // A conservative, local-process check, not a system-wide open-handle proof.
  const fds = await readdir("/proc/self/fd");
  for (const fd of fds) {
    try {
      const current = await stat("/proc/self/fd/" + fd);
      if (current.dev === info.dev && current.ino === info.ino) return true;
    } catch { /* FD closed between readdir and stat. */ }
  }
  return false;
}

async function eligibility(target: string): Promise<Eligibility> {
  if (process.platform !== "linux" || process.getuid?.() !== process.geteuid?.() ||
      process.getgid?.() !== process.getegid?.()) return "legacy";
  const directory = path.dirname(target);
  if (Buffer.byteLength(path.basename(target), "utf8") > 200) return "legacy";
  try {
    const parent = await lstat(directory);
    // setgid/sticky directories can change the new inode's ownership or
    // replacement semantics, so retain the original write path there.
    if (!parent.isDirectory() || parent.uid !== process.geteuid?.() ||
        (parent.mode & 0o3022) !== 0 || await realpath(directory) !== path.resolve(directory)) return "legacy";
    if (!ATOMIC_FILESYSTEMS.has((await statfs(directory)).type)) return "legacy";
    await access(directory, constants.W_OK | constants.X_OK);
    let existing: Awaited<ReturnType<typeof lstat>>;
    try { existing = await lstat(target); }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") return "legacy";
      // A private directory keeps the staged file inaccessible while its
      // mode is prepared to match ordinary new-file writeFile semantics.
      return (parent.mode & 0o077) === 0 ? "create" : "legacy";
    }
    // Replacing a path changes the inode. Preserve legacy semantics for
    // links, special files, non-private ACL/metadata and unsupported owners.
    if (!existing.isFile() || existing.nlink !== 1 || (existing.mode & 0o7777) !== 0o600 ||
        existing.uid !== process.geteuid?.() || existing.gid !== process.getegid?.() ||
        parent.mode & 0o1000 || await agentHasOpenDescriptor(existing)) return "legacy";
    await access(target, constants.W_OK);
    return "replace";
  } catch { return "legacy"; }
}

export interface FileRewriteOptions {
  expectedOriginal?: Buffer;
  /** Local-only integration-test injection; never passed over the wire. */
  fileStageForTests?: (stage: "staged", target: string) => Promise<void>;
}

async function sourceUnchanged(target: string, expectedOriginal: Buffer, original?: Snapshot): Promise<boolean> {
  try {
    const current = await lstat(target);
    if (original && !sameSnapshot(original, current)) return false;
    return Buffer.from(await readFile(target)).equals(expectedOriginal);
  } catch { return false; }
}

/**
 * Compatible private regular files: stage then rename. New paths: stage then
 * link exclusively, so a concurrently created destination is not clobbered.
 * Everything else follows the original writeFile route, without staging.
 */
export async function rewriteFile(
  target: string, content: string, options: FileRewriteOptions = {},
): Promise<void> {
  const route = await eligibility(target);
  if (route === "legacy") {
    if (options.expectedOriginal && !(await sourceUnchanged(target, options.expectedOriginal))) {
      throw new NoTargetEffectError("Source changed before edit.");
    }
    // The legacy route retains truncate-and-write semantics. Open failures
    // known to occur before truncation are definite no-effect failures;
    // anything after a successful O_TRUNC open may have changed the target.
    let handle: Awaited<ReturnType<typeof open>>;
    try {
      handle = await open(target, "w");
    } catch (error) {
      if (["EACCES", "EPERM", "ENOENT", "ENOTDIR", "EISDIR", "ELOOP", "EROFS"].includes(
        (error as NodeJS.ErrnoException).code ?? "",
      )) throw new NoTargetEffectError("Could not open target for writing.");
      throw error;
    }
    try { await handle.writeFile(content, "utf8"); }
    finally { await handle.close(); }
    return;
  }

  let original: Snapshot | undefined;
  if (route === "replace") {
    try {
      const current = await lstat(target);
      if (!current.isFile() || current.nlink !== 1 ||
          (current.mode & 0o7777) !== 0o600 ||
          current.uid !== process.geteuid?.() || current.gid !== process.getegid?.()) {
        throw new NoTargetEffectError("Target changed before staging.");
      }
      original = current;
    } catch {
      throw new NoTargetEffectError("Target changed before staging.");
    }
  }

  const temp = path.join(path.dirname(target), `.${path.basename(target)}.rca-${randomUUID()}.tmp`);
  let owned: Snapshot | undefined;
  let commitStarted = false;
  let committed = false;
  try {
    const handle = await open(temp, "wx", 0o600);
    try {
      owned = await handle.stat();
      await handle.writeFile(content, "utf8");
      if (route === "create") await handle.chmod(0o666 & ~process.umask());
      else await handle.chmod(0o600);
    } finally {
      await handle.close();
    }
    await options.fileStageForTests?.("staged", target);
    if (route === "replace") {
      let now: Awaited<ReturnType<typeof lstat>>;
      try { now = await lstat(target); }
      catch { throw new NoTargetEffectError("Target changed before commit."); }
      if (!original || !sameSnapshot(original, now)) throw new NoTargetEffectError("Target changed before commit.");
    } else {
      try {
        await lstat(target);
        throw new NoTargetEffectError("Destination appeared before commit.");
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      }
    }
    if (options.expectedOriginal && !(await sourceUnchanged(target, options.expectedOriginal, original))) {
      throw new NoTargetEffectError("Source changed before edit commit.");
    }
    commitStarted = true;
    if (route === "create") await link(temp, target);
    else await rename(temp, target);
    committed = true;
  } catch (error) {
    if (commitStarted) throw error; // May have committed: receipt must stay Unknown.
    if (error instanceof NoTargetEffectError) throw error;
    throw new NoTargetEffectError("File staging failed before commit.");
  } finally {
    // Clean up only the inode created by this operation. No blind sweeping of
    // other files, even after commit or a failed cleanup.
    if (owned) {
      try {
        const current = await lstat(temp);
        if (current.dev === owned.dev && current.ino === owned.ino) await unlink(temp);
      } catch { /* Cleanup outcome is distinct from target commit outcome. */ }
    }
  }
  if (!committed) throw Error("File commit outcome unknown.");
}
