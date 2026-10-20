/**
 * Owner-local v2 upgrade handshake. No TCP listener, key, token or remote
 * tool: socket exists only under the Agent user's mode-0700 state directory.
 */
import { createConnection, createServer, type Server } from "node:net";
import { chmod, lstat, mkdir, unlink } from "node:fs/promises";
import path from "node:path";
import type { AgentExecutionEngine } from "./execution.ts";

export function upgradeSocketPath(keyPath: string): string {
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
  const directory = path.dirname(socketPath);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const stat = await lstat(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink() ||
      stat.uid !== process.getuid?.() || (stat.mode & 0o077) !== 0)
    throw new Error("Unsafe Agent upgrade control directory.");
  await clearOnlyStaleOwnedSocket(socketPath);
  const server: Server = createServer(socket => {
    socket.setTimeout(2000, () => socket.destroy());
    let buffer = "";
    socket.on("data", chunk => {
      buffer += chunk.toString("utf8");
      if (buffer.length > 32) { socket.destroy(); return; }
      if (!buffer.includes("\n")) return;
      if (buffer === "freeze\n") {
        socket.end(execution.freezeForUpgrade() ? "ready\n" : "busy\n");
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
      server.listen(socketPath, () => {
        server.off("error", reject);
        resolve();
      });
    });
    await chmod(socketPath, 0o600);
  } catch (error) {
    server.close();
    try { await unlink(socketPath); } catch { /* Do not mask original failure */ }
    throw error;
  }
  return {
    close: async () => {
      await new Promise<void>(resolve => server.close(() => resolve()));
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
