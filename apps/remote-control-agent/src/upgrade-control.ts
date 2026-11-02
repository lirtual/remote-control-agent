/**
 * Owner-local v2 upgrade handshake. No TCP listener, key, token or remote
 * tool: Unix socket is under owner-private state; Windows uses an owner-only
 * named pipe. The pipe never takes a remote-provided command or path.
 */
import { createConnection, createServer, type Server } from "node:net";
import { createHash } from "node:crypto";
import { chmod, lstat, mkdir, unlink } from "node:fs/promises";
import path from "node:path";
import type { AgentExecutionEngine } from "./execution.ts";

export function upgradeSocketPath(keyPath: string): string {
  if (process.platform === "win32") {
    // Flat pipe namespace: derive a fixed collision-resistant same-user name
    // from the installed *path*, never an arbitrary remote argument.
    // Hash the same locally assembled identity spelling as the PowerShell
    // installer. Win32 GetFullPath can expand/rewrite CI temporary paths
    // differently from Node normalize(), yielding two different pipe names.
    const identity = keyPath.replaceAll("/", "\\").toLowerCase();
    const digest = createHash("sha256").update(identity, "utf8").digest("hex").slice(0, 32);
    return String.raw`\\.\pipe\rca-upgrade-` + digest;
  }
  return path.join(path.dirname(keyPath), "upgrade.sock");
}

async function clearOnlyStaleOwnedSocket(file: string): Promise<void> {
  let stat;
  try { stat = await lstat(file); }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    throw error;
  }
  if (!stat.isSocket() || stat.uid !== process.getuid?.()) {
    throw new Error("Unsafe upgrade socket; refusing to replace it.");
  }
  const state = await new Promise<"live" | "stale" | "unsafe">((resolve) => {
    const connection = createConnection(file);
    connection.once("connect", () => { connection.destroy(); resolve("live"); });
    connection.once("error", (error: NodeJS.ErrnoException) => {
      resolve(error.code === "ECONNREFUSED" ? "stale" : "unsafe");
    });
  });
  if (state !== "stale") throw new Error("An Agent upgrade socket is already owned or unavailable.");
  await unlink(file);
}

export async function startUpgradeControl(execution: AgentExecutionEngine, keyPath: string):
  Promise<{ close(): Promise<void> }> {
  const socketPath = upgradeSocketPath(keyPath);
  const windows = process.platform === "win32";
  if (!windows) {
    const directory = path.dirname(socketPath);
    await mkdir(directory, { recursive: true, mode: 0o700 });
    const stat = await lstat(directory);
    if (!stat.isDirectory() || stat.isSymbolicLink() ||
        stat.uid !== process.getuid?.() || (stat.mode & 0o077) !== 0)
      throw new Error("Unsafe Agent upgrade control directory.");
    await clearOnlyStaleOwnedSocket(socketPath);
  }
  const server: Server = createServer(socket => {
    socket.setTimeout(2000, () => socket.destroy());
    let buffer = "";
    socket.on("data", chunk => {
      buffer += Buffer.from(chunk).toString("utf8");
      if (buffer.length > 32) { socket.destroy(); return; }
      if (!buffer.includes("\n")) return;
      if (buffer === "freeze\n") {
        socket.end(execution.freezeForUpgrade() ? "ready\n" : "busy\n");
      } else if (buffer === "verify-frozen\n") {
        // Read-only check: the remote owner admission must already have
        // frozen the original Agent before the one-shot watchdog switches.
        socket.end(execution.verifyUpgradeFreeze() ? "ready\n" : "busy\n");
      } else if (buffer === "release\n") {
        execution.releaseUpgradeFreeze();
        socket.end("released\n");
      } else {
        socket.destroy();
      }
    });
  });
  try {
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen({path:socketPath,readableAll:false,writableAll:false}, () => {
        server.off("error", reject);
        resolve();
      });
    });
    if (!windows) await chmod(socketPath, 0o600);
  } catch (error) {
    server.close();
    if (!windows) {
      try { await unlink(socketPath); } catch { /* Do not mask original failure */ }
    }
    throw error;
  }
  return {
    close: async () => {
      await new Promise<void>(resolve => server.close(() => resolve()));
      if (windows) return; // Windows named pipes disappear when closed.
      try {
        const current = await lstat(socketPath);
        if (current.isSocket() && current.uid === process.getuid?.())
          await unlink(socketPath);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      }
    },
  };
}
