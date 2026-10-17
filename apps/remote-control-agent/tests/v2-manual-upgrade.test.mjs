import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile, rm, chmod } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { assertSafePortableUpgrade, renderV2Service } from "../scripts/install-v2.mjs";

const profile = {name:"remote-control-agent", artifact_schema:1,
  device_protocol:2,receipt_schema:1,upgrade_profile:"read-only-no-shell-v1"};
const safeEntry='export const policy = { readOnly: true, writeFile: false, shell: false, };';
async function prepareVersion(dir,{schema=profile,entry=safeEntry}={}) {
  await mkdir(path.join(dir,"apps/remote-control-agent/src"),{recursive:true,mode:0o700});
  await chmod(dir,0o700);
  await writeFile(path.join(dir,"bundle.json"),JSON.stringify(schema),{mode:0o600});
  await writeFile(path.join(dir,"apps/remote-control-agent/src/v2-main.js"),entry,{mode:0o600});
}
test("#77 only owned versioned signed-read-only runtimes can change a v2 service program path",async()=>{
  const home=await mkdtemp(path.join(os.tmpdir(),"rc-t08-manual-"));
  const programs=path.join(home,".local/share/mcp-workers/remote-control/programs");
  const oldRoot=path.join(programs,"v0.1.0-linux-x64-glibc");
  const newRoot=path.join(programs,"v0.2.0-linux-x64-glibc");
  try {
    await prepareVersion(oldRoot);
    await prepareVersion(newRoot);
    const unit=renderV2Service({home,repoRoot:oldRoot,node:oldRoot+"/bin/node",
      endpoint:"https://rc.example.org/", keyPath:home+"/.local/share/mcp-workers/remote-control/v2-identity.pem",entryExt:"js"});
    const result=await assertSafePortableUpgrade(unit,home,newRoot+"/bundle.json");
    assert.equal(result.oldProgram,oldRoot);
    assert.equal(result.newProgram,newRoot);
    await assert.rejects(assertSafePortableUpgrade(unit,home,oldRoot+"/bundle.json"),/Already running/);
    await assert.rejects(assertSafePortableUpgrade(null,home,newRoot+"/bundle.json"),/owned/);
    await assert.rejects(assertSafePortableUpgrade(unit.replace("Managed by mcp-workers","Managed by someone else"),home,newRoot+"/bundle.json"),/owned/);
    await writeFile(newRoot+"/bundle.json",JSON.stringify({...profile,upgrade_profile:"shell-enabled"}),{mode:0o600});
    await assert.rejects(assertSafePortableUpgrade(unit,home,newRoot+"/bundle.json"),/quiescence/);
    await writeFile(newRoot+"/bundle.json",JSON.stringify({...profile,receipt_schema:2}),{mode:0o600});
    await assert.rejects(assertSafePortableUpgrade(unit,home,newRoot+"/bundle.json"),/quiescence/);
    await writeFile(newRoot+"/bundle.json",JSON.stringify(profile),{mode:0o600});
    await writeFile(newRoot+"/apps/remote-control-agent/src/v2-main.js","export const policy = { readOnly: true, writeFile: false, shell: true, };",{mode:0o600});
    await assert.rejects(assertSafePortableUpgrade(unit,home,newRoot+"/bundle.json"),/Shell ownership/);
    await writeFile(newRoot+"/apps/remote-control-agent/src/v2-main.js",safeEntry,{mode:0o600});
    await chmod(newRoot,0o755);
    await assert.rejects(assertSafePortableUpgrade(unit,home,newRoot+"/bundle.json"),/Unowned Agent/);
  } finally {await rm(home,{recursive:true,force:true});}
});
