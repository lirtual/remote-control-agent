import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile, rm, chmod, rename, symlink, link } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { DatabaseSync } from "node:sqlite";
import { ReceiptStore } from "../src/operations.ts";
import { assertSafePortableUpgrade, renderV2Service } from "../scripts/install-v2.mjs";

const profile = {name:"remote-control-agent", artifact_schema:1,
  device_protocol:2,receipt_schema:1,upgrade_profile:"read-only-no-shell-v1"};
const safeEntry='export const policy = { readOnly: true, writeFile: false, shell: false, };';
const fullProfile={...profile,upgrade_profile:"paired-full-v1"};
const fullEntry='export const V2_RUNTIME_PROFILE = "paired-full-v1";';
async function prepareVersion(dir,{schema=profile,entry=safeEntry}={}) {
  await mkdir(path.join(dir,"apps/remote-control-agent/src"),{recursive:true,mode:0o700});
  await chmod(dir,0o700);
  await writeFile(path.join(dir,"bundle.json"),JSON.stringify(schema),{mode:0o600});
  await writeFile(path.join(dir,"apps/remote-control-agent/src/v2-main.js"),entry,{mode:0o600});
}
async function createReceiptDatabase(home, version = 1, mode = 0o600) {
  const directory = path.join(home, ".local", "state", "mcp-workers", "remote-control-agent");
  await mkdir(directory, {recursive:true, mode:0o700});
  await chmod(directory, 0o700);
  const file = path.join(directory, "operation-receipts.sqlite");
  await rm(file, {force:true});
  const store = new ReceiptStore(directory);
  await store.open();
  await store.close();
  if (version !== 1) {
    const db = new DatabaseSync(file);
    db.exec("PRAGMA user_version = " + version);
    db.close();
  }
  await chmod(file, mode);
  return file;
}
test("#77 reviewed full-tools upgrade requires authoritative in-process freeze",async()=>{
  const home=await mkdtemp(path.join(os.tmpdir(),"rc-t08-manual-"));
  const programs=path.join(home,".local/share/mcp-workers/remote-control/programs");
  const oldRoot=path.join(programs,"v0.1.0-linux-x64-glibc");
  const newRoot=path.join(programs,"v0.2.0-linux-x64-glibc");
  try {
    await prepareVersion(oldRoot);
    await prepareVersion(newRoot,{schema:fullProfile,entry:fullEntry});
    const unit=renderV2Service({home,repoRoot:oldRoot,node:oldRoot+"/bin/node",
      endpoint:"https://rc.example.org/", keyPath:home+"/.local/share/mcp-workers/remote-control/v2-identity.pem",entryExt:"js"});
    const receiptFile = await createReceiptDatabase(home, 1);
    const result=await assertSafePortableUpgrade(unit,home,newRoot+"/bundle.json");
    assert.equal(result.oldProgram,oldRoot);
    assert.equal(result.newProgram,newRoot);
    assert.equal(result.needsFreeze,false);
    await assert.rejects(assertSafePortableUpgrade(unit,home,oldRoot+"/bundle.json"),/Already running/);
    await assert.rejects(assertSafePortableUpgrade(null,home,newRoot+"/bundle.json"),/owned/);

    // The live ReceiptStore accepts user_version 0 (uninitialized) and 1;
    // unsupported versions, missing files, malformed headers and unsafe modes fail closed.
    await createReceiptDatabase(home, 0);
    await assert.doesNotReject(assertSafePortableUpgrade(unit,home,newRoot+"/bundle.json"));
    await createReceiptDatabase(home, 1);
    await assert.doesNotReject(assertSafePortableUpgrade(unit,home,newRoot+"/bundle.json"));
    await createReceiptDatabase(home, 2);
    await assert.rejects(assertSafePortableUpgrade(unit,home,newRoot+"/bundle.json"),/schema is incompatible/);
    await writeFile(receiptFile, "not a SQLite database", {mode:0o600});
    await assert.rejects(assertSafePortableUpgrade(unit,home,newRoot+"/bundle.json"),/valid SQLite/);
    await rm(receiptFile, {force:true});
    // Fresh read-only v2 installs may have no receipt state at all.
    await assert.doesNotReject(assertSafePortableUpgrade(unit,home,newRoot+"/bundle.json"));
    const legacyFile = path.join(path.dirname(receiptFile), "operation-receipts.json");
    await writeFile(legacyFile, JSON.stringify({version:1,receipts:[]}), {mode:0o600});
    await assert.rejects(assertSafePortableUpgrade(unit,home,newRoot+"/bundle.json"),/Legacy receipt data exists/);
    await rm(legacyFile, {force:true});
    await createReceiptDatabase(home, 1, 0o644);
    await assert.rejects(assertSafePortableUpgrade(unit,home,newRoot+"/bundle.json"),/ownership or permissions/);
    await createReceiptDatabase(home, 1);
    const symlinkTarget = receiptFile + ".target";
    await rename(receiptFile, symlinkTarget);
    await symlink(symlinkTarget, receiptFile);
    await assert.rejects(assertSafePortableUpgrade(unit,home,newRoot+"/bundle.json"),/cannot be opened safely/);
    await rm(receiptFile, {force:true});
    await rename(symlinkTarget, receiptFile);
    const hardlink = receiptFile + ".link";
    await link(receiptFile, hardlink);
    await assert.rejects(assertSafePortableUpgrade(unit,home,newRoot+"/bundle.json"),/ownership or permissions/);
    await rm(hardlink, {force:true});
    await rm(path.dirname(receiptFile), {recursive:true,force:true});
    await assert.doesNotReject(assertSafePortableUpgrade(unit,home,newRoot+"/bundle.json"));
    await createReceiptDatabase(home, 1);
    await assert.rejects(assertSafePortableUpgrade(unit.replace("Managed by mcp-workers","Managed by someone else"),home,newRoot+"/bundle.json"),/owned/);
    await writeFile(newRoot+"/bundle.json",JSON.stringify({...profile,upgrade_profile:"shell-enabled"}),{mode:0o600});
    await assert.rejects(assertSafePortableUpgrade(unit,home,newRoot+"/bundle.json"),/profile|quiescence/);
    await writeFile(newRoot+"/bundle.json",JSON.stringify({...profile,receipt_schema:2}),{mode:0o600});
    await assert.rejects(assertSafePortableUpgrade(unit,home,newRoot+"/bundle.json"),/profile|quiescence/);
    await writeFile(newRoot+"/bundle.json",JSON.stringify(fullProfile),{mode:0o600});
    await writeFile(newRoot+"/apps/remote-control-agent/src/v2-main.js","export const policy = { readOnly: true, writeFile: false, shell: true, };",{mode:0o600});
    await assert.rejects(assertSafePortableUpgrade(unit,home,newRoot+"/bundle.json"),/Shell ownership/);
    await writeFile(newRoot+"/apps/remote-control-agent/src/v2-main.js",fullEntry,{mode:0o600});
    // A full-tools predecessor passes manifest validation but must still
    // obtain a live in-process freeze before the installer changes the unit.
    const nextRoot=path.join(programs,"v0.3.0-linux-x64-glibc");
    await prepareVersion(nextRoot,{schema:fullProfile,entry:fullEntry});
    const fullUnit=renderV2Service({home,repoRoot:newRoot,node:newRoot+"/bin/node",
      endpoint:"https://rc.example.org/", keyPath:home+"/.local/share/mcp-workers/remote-control/v2-identity.pem",entryExt:"js"});
    const gated=await assertSafePortableUpgrade(fullUnit,home,nextRoot+"/bundle.json");
    assert.equal(gated.needsFreeze,true);
    await chmod(newRoot,0o755);
    await assert.rejects(assertSafePortableUpgrade(unit,home,newRoot+"/bundle.json"),/Unowned Agent/);
  } finally {await rm(home,{recursive:true,force:true});}
});
