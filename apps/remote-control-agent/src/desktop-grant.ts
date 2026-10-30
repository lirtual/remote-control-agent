/**
 * Local Computer Use authority. A Stop tombstone is independent from the
 * grant file: even an overlapping local enable cannot erase a newer Stop.
 * No network path can enable the grant, and no desktop content is stored.
 */
import { randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { lstat, open, readFile, rename, unlink } from "node:fs/promises";
import path from "node:path";

export type DesktopGrant = {
  state: "enabled" | "stopped";
  generation: string | null;
};
const UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
type GrantRecord = { schema: 1; generation: string; acknowledged_stop: string | null };
type StopRecord = { schema: 1; generation: string };
const unavailable = () => Error("desktop_grant_unavailable");
function isUuid(x: unknown): x is string {
  return typeof x === "string" && UUID.test(x);
}

async function checkedFile(directory: string, basename: string): Promise<string> {
  const dir = await lstat(directory).catch(() => { throw unavailable(); });
  if (!dir.isDirectory() || dir.isSymbolicLink() ||
      (process.platform !== "win32" &&
       (dir.uid !== process.getuid?.() || (dir.mode & 0o022) !== 0))) throw unavailable();
  const file = path.join(directory, basename);
  try {
    const st = await lstat(file);
    if (!st.isFile() || st.isSymbolicLink() || st.size > 256 ||
        (process.platform !== "win32" &&
          (st.uid !== process.getuid?.() || (st.mode & 0o077) !== 0))) {
      throw unavailable();
    }
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw unavailable();
  }
  return file;
}

async function readRecord(directory: string, basename: string): Promise<unknown | null> {
  const filename = await checkedFile(directory, basename);
  try {
    return JSON.parse(await readFile(filename, "utf8")) as unknown;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw unavailable();
  }
}
async function stopGeneration(directory: string): Promise<string | null> {
  const record = await readRecord(directory, "desktop-stop.json");
  if (record === null) return null;
  if (!record || typeof record !== "object" || Array.isArray(record)) throw unavailable();
  const o = record as Record<string, unknown>;
  if (Object.keys(o).sort().join(",") !== "generation,schema" ||
      o.schema !== 1 || !isUuid(o.generation)) throw unavailable();
  return o.generation;
}
async function grantRecord(directory: string): Promise<GrantRecord | null> {
  const record = await readRecord(directory, "desktop-grant.json");
  if (record === null) return null;
  if (!record || typeof record !== "object" || Array.isArray(record)) throw unavailable();
  const o = record as Record<string, unknown>;
  if (Object.keys(o).sort().join(",") !== "acknowledged_stop,generation,schema" ||
      o.schema !== 1 || !isUuid(o.generation) ||
      (o.acknowledged_stop !== null && !isUuid(o.acknowledged_stop))) {
    throw unavailable();
  }
  return o as GrantRecord;
}
async function atomicRecord(directory: string, basename: string,
  record: GrantRecord | StopRecord): Promise<void> {
  const filename = await checkedFile(directory, basename);
  const tmp = path.join(directory, "." + basename + "-" + randomUUID());
  const handle = await open(tmp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600);
  try {
    await handle.writeFile(JSON.stringify(record) + "\n");
    await handle.sync();
  } finally { await handle.close(); }
  try {
    await checkedFile(directory, basename);
    await rename(tmp, filename);
  } catch (error) {
    await unlink(tmp).catch(() => {});
    throw error;
  }
}

/** A marker change during read always denies; a missing grant is stopped. */
export async function readDesktopGrant(directory: string): Promise<DesktopGrant> {
  const firstStop = await stopGeneration(directory);
  const grant = await grantRecord(directory);
  const currentStop = await stopGeneration(directory);
  if (!grant || firstStop !== currentStop ||
      grant.acknowledged_stop !== currentStop) {
    return { state: "stopped", generation: currentStop };
  }
  return { state: "enabled", generation: grant.generation };
}

/** The only enable entrypoint: foreground, owner-local approval outside this module. */
export async function enableDesktopGrantLocally(directory: string): Promise<DesktopGrant> {
  const priorStop = await stopGeneration(directory);
  await grantRecord(directory); // malformed or linked state cannot be overridden
  const generation = randomUUID();
  await atomicRecord(directory, "desktop-grant.json", {
    schema: 1, generation, acknowledged_stop: priorStop,
  });
  const result = await readDesktopGrant(directory);
  if (result.state !== "enabled" || result.generation !== generation) {
    throw Error("desktop_stopped"); // a concurrent Stop won
  }
  return result;
}

/** Stop commits only a tombstone; it never has to overwrite a stale grant. */
export async function stopDesktopGrant(directory: string): Promise<DesktopGrant> {
  const generation = randomUUID();
  await atomicRecord(directory, "desktop-stop.json", { schema: 1, generation });
  return { state: "stopped", generation };
}

/** A caller rechecks immediately before GUI input; old grants cannot dispatch. */
export async function assertDesktopGrantGeneration(directory: string, expected: unknown): Promise<void> {
  const grant = await readDesktopGrant(directory);
  if (grant.state !== "enabled") throw Error("desktop_stopped");
  if (!isUuid(expected) || grant.generation !== expected) throw Error("stale_target");
}
