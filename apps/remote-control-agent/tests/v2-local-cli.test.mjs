import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmod, lstat, mkdir, mkdtemp, readFile, readlink, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { installManagerLauncher } from "../scripts/install-v2.mjs";

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");

async function fixture() {
  const home=await mkdtemp(path.join(os.tmpdir(),"rc-cli-lab-"));
  const programs=path.join(home,".local/share/mcp-workers/remote-control/programs");
  const program=path.join(programs,"v0.1.1-linux-x64-glibc");
  const script=path.join(program,"apps/remote-control-agent/scripts");
  await mkdir(script,{recursive:true,mode:0o700});
  await writeFile(path.join(script,"manage-v2.py"),"#!/usr/bin/env python3\n",{mode:0o700});
  await chmod(path.join(script,"manage-v2.py"),0o700);
  await writeFile(path.join(home,".bashrc"),"# existing commands\n",{mode:0o600});
  return {home,program,script};
}

test("user-local Agent launcher is installed idempotently and PATH is appended only once",async()=>{
  const f=await fixture();
  try {
    const link=await installManagerLauncher(f.home,f.program);
    assert.equal(link,path.join(f.home,".local/bin/remote-control-agent"));
    assert.equal(await readlink(link),path.join(f.script,"manage-v2.py"));
    assert.equal((await readFile(path.join(f.home,".bashrc"),"utf8")).match(/# remote-control-agent local CLI/g)?.length,1);
    await installManagerLauncher(f.home,f.program);
    assert.equal((await readFile(path.join(f.home,".bashrc"),"utf8")).match(/# remote-control-agent local CLI/g)?.length,1);
  } finally { await rm(f.home,{recursive:true,force:true}); }
});

test("foreign real executable or unrelated symlink is never replaced",async()=>{
  const f=await fixture();
  try {
    const bin=path.join(f.home,".local/bin");
    await mkdir(bin,{recursive:true});
    const link=path.join(bin,"remote-control-agent");
    await writeFile(link,"foreign",{mode:0o700});
    await assert.rejects(installManagerLauncher(f.home,f.program),/foreign/);
    assert.equal(await readFile(link,"utf8"),"foreign");
    await rm(link);
    await symlink("/tmp/definitely-not-our-agent.py",link);
    await assert.rejects(installManagerLauncher(f.home,f.program),/not owned/);
    assert.equal(await readlink(link),"/tmp/definitely-not-our-agent.py");
  } finally { await rm(f.home,{recursive:true,force:true}); }
});

test("untrusted user-local bin symlink blocks new launcher",async()=>{
  const f=await fixture();
  try {
    const bin=path.join(f.home,".local/bin");
    await symlink("/tmp",bin);
    await assert.rejects(installManagerLauncher(f.home,f.program),/Untrusted/);
    assert.ok((await lstat(bin)).isSymbolicLink());
  } finally { await rm(f.home,{recursive:true,force:true}); }
});

test("short prerelease shell bootstrap syntax and noninteractive fail-closed before GitHub",()=>{
  const sh=path.join(root,"install.sh");
  const parsed=spawnSync("sh",["-n",sh],{encoding:"utf8",timeout:3000});
  assert.equal(parsed.status,0,parsed.stderr);
  const result=spawnSync("sh",[sh],{encoding:"utf8",input:"",timeout:3000});
  assert.notEqual(result.status,0);
  assert.match(result.stderr,/interactive/);
});
