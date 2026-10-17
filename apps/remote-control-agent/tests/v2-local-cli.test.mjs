import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmod, link, lstat, mkdir, mkdtemp, readFile, readlink, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { installManagerLauncher, preflightManagerLauncher } from "../scripts/install-v2.mjs";

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
    assert.equal(link,path.join(f.home,".local/bin/rca"));
    assert.equal(await readlink(link),path.join(f.script,"manage-v2.py"));
    assert.equal((await readFile(path.join(f.home,".bashrc"),"utf8")).match(/# rca local CLI/g)?.length,1);
    await installManagerLauncher(f.home,f.program);
    assert.equal((await readFile(path.join(f.home,".bashrc"),"utf8")).match(/# rca local CLI/g)?.length,1);
  } finally { await rm(f.home,{recursive:true,force:true}); }
});

test("optional PATH customization skips hardlinks and unsafe Bash rc modes",async()=>{
  const f=await fixture();
  const rc=path.join(f.home,".bashrc");
  try {
    await rm(rc);
    const unrelated=path.join(f.home,"unrelated-private-text");
    await writeFile(unrelated,"# unrelated\\n",{mode:0o600});
    await link(unrelated,rc);
    await installManagerLauncher(f.home,f.program);
    assert.equal(await readFile(unrelated,"utf8"),"# unrelated\\n");
    assert.equal(await readFile(rc,"utf8"),"# unrelated\\n");
    await rm(rc);
    await writeFile(rc,"# read only\\n",{mode:0o400});
    await installManagerLauncher(f.home,f.program);
    assert.equal(await readFile(rc,"utf8"),"# read only\\n");
    await rm(rc);
    await writeFile(rc,"# group writable\\n",{mode:0o620});
    await installManagerLauncher(f.home,f.program);
    assert.equal(await readFile(rc,"utf8"),"# group writable\\n");
    assert.equal(await readlink(path.join(f.home,".local/bin/rca")),
      path.join(f.script,"manage-v2.py"));
  } finally { await rm(f.home,{recursive:true,force:true}); }
});

test("foreign real executable or unrelated symlink is never replaced",async()=>{
  const f=await fixture();
  try {
    const bin=path.join(f.home,".local/bin");
    await mkdir(bin,{recursive:true});
    const link=path.join(bin,"rca");
    await writeFile(link,"foreign",{mode:0o700});
    await assert.rejects(installManagerLauncher(f.home,f.program),/foreign/);
    assert.equal(await readFile(link,"utf8"),"foreign");
    await rm(link);
    await symlink("/tmp/definitely-not-our-agent.py",link);
    await assert.rejects(installManagerLauncher(f.home,f.program),/not owned/);
    assert.equal(await readlink(link),"/tmp/definitely-not-our-agent.py");
  } finally { await rm(f.home,{recursive:true,force:true}); }
});

test("read-only launcher preflight rejects collisions before any pairing state exists",async()=>{
  const f=await fixture();
  try {
    const bin=path.join(f.home,".local/bin");
    assert.equal(await preflightManagerLauncher(f.home,f.program),undefined);
    await assert.rejects(lstat(bin),/ENOENT/);
    await mkdir(bin,{recursive:true,mode:0o700});
    const link=path.join(bin,"rca");
    await writeFile(link,"foreign-owned-by-user",{mode:0o700});
    await assert.rejects(preflightManagerLauncher(f.home,f.program),/foreign rca/);
    assert.equal(await readFile(link,"utf8"),"foreign-owned-by-user");
    await rm(link);
    await symlink("/tmp/other-command",link);
    await assert.rejects(preflightManagerLauncher(f.home,f.program),/not owned/);
    assert.equal(await readlink(link),"/tmp/other-command");
    const identity=path.join(f.home,".local/share/mcp-workers/remote-control/v2-identity.pem");
    await assert.rejects(lstat(identity),/ENOENT/);
    assert.equal(await readFile(path.join(f.home,".bashrc"),"utf8"),"# existing commands\n");
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
