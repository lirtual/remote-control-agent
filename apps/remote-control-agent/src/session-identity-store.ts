/** Linux GitHub Runner job-private identity; no installation or permanent store. */
import { open, link, unlink, mkdir, lstat, readFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import path from 'node:path';
import { assertSessionPhysicalAttempt, newSessionDeviceIdentity,
  validateSessionDeviceIdentity, type SessionDeviceIdentity, type SessionPhysicalAttempt } from './session-device-identity.ts';

const FILE='identity.json';
async function safeDirectory(directory: string, privateMode = false): Promise<void> {
  const value=await lstat(directory);
  if (!value.isDirectory() || value.isSymbolicLink()) throw Error('Unsafe Session directory.');
  if (privateMode && (value.uid !== process.getuid?.() || (value.mode & 0o077)!==0)) {
    throw Error('Session identity directory must be private.');
  }
}
async function rejectLinkedAncestors(directory: string): Promise<void> {
  let current=path.resolve(directory);
  while (true) {
    await safeDirectory(current);
    const parent=path.dirname(current);
    if (parent===current) break;
    current=parent;
  }
}
async function readVerified(file: string, attempt: SessionPhysicalAttempt): Promise<SessionDeviceIdentity> {
  const meta=await lstat(file);
  if (!meta.isFile() || meta.isSymbolicLink() || meta.nlink!==1 ||
      meta.uid!==process.getuid?.() || (meta.mode & 0o077)!==0 || meta.size>4096) {
    throw Error('Unsafe Session identity file.');
  }
  const data=JSON.parse(await readFile(file,'utf8')) as SessionDeviceIdentity;
  validateSessionDeviceIdentity(data,attempt);
  return data;
}

/** Atomic no-overwrite publication makes same-Attempt concurrent retries recover one key. */
export async function loadOrCreateLinuxSessionIdentity(
  runnerTemp: string, attempt: SessionPhysicalAttempt,
): Promise<{ file: string; identity: SessionDeviceIdentity }> {
  if (process.platform!=='linux' || typeof process.getuid!=='function') throw Error('Linux Runner required.');
  assertSessionPhysicalAttempt(attempt);
  if (!runnerTemp || !path.isAbsolute(runnerTemp)) throw Error('Absolute RUNNER_TEMP required.');
  await rejectLinkedAncestors(runnerTemp);
  const parent=await lstat(runnerTemp);
  if (parent.uid!==process.getuid() || (parent.mode & 0o022)!==0) {
    throw Error('Untrusted Runner temporary directory.');
  }
  const directory=path.join(runnerTemp,'session-rca');
  try { await mkdir(directory,{mode:0o700}); }
  catch (error) { if ((error as NodeJS.ErrnoException).code!=='EEXIST') throw error; }
  await safeDirectory(directory,true);
  const file=path.join(directory,FILE);
  try {
    return { file, identity:await readVerified(file,attempt) };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code!=='ENOENT') throw error;
  }
  const identity=newSessionDeviceIdentity(attempt);
  const temporary=path.join(directory,'identity-'+randomUUID()+'.tmp');
  const fd=await open(temporary,'wx',0o600);
  try { await fd.writeFile(JSON.stringify(identity),'utf8'); await fd.sync(); }
  finally { await fd.close(); }
  try {
    try { await link(temporary,file); }
    catch (error) { if ((error as NodeJS.ErrnoException).code!=='EEXIST') throw error; }
  } finally { await unlink(temporary); }
  // A peer may have won the first publication: always load that verified identity.
  return { file, identity:await readVerified(file,attempt) };
}
