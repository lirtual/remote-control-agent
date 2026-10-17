import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmod, link, lstat, mkdir, mkdtemp, readFile, readlink, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { installManagerLauncher, preflightManagerLauncher, assertRepeatInstallSameVersion } from "../scripts/install-v2.mjs";

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");

async function fixture() {
  const home=await mkdtemp(path.join(os.tmpdir(),"rc-cli-lab-"));
  const programs=path.join(home,".local/share/mcp-workers/remote-control/programs");
  const program=path.join(programs,"v0.1.1-linux-x64-glibc");
  const script=path.join(program,"apps/remote-control-agent/scripts");
  await mkdir(script,{recursive:true,mode:0o700});
  await writeFile(path.join(script,"manage-v2.py"),"#!/usr/bin/env python3\n",{mode:0o700});
  await chmod(path.join(script,"manage-v2.py"),0o700);
  await writeFile(path.join(script,"rca.sh"),"#!/bin/sh\nexit 0\n",{mode:0o700});
  await chmod(path.join(script,"rca.sh"),0o700);
  await writeFile(path.join(home,".bashrc"),"# existing commands\n",{mode:0o600});
  return {home,program,script};
}

test("repeat installer reuses only the exact running program, never silently switches CLI versions",()=>{
  const old="/home/test/.local/share/mcp-workers/remote-control/programs/v0.1.1-linux-x64-glibc";
  const next="/home/test/.local/share/mcp-workers/remote-control/programs/v0.1.2-linux-x64-glibc";
  const unit="# Managed by mcp-workers v2 Linux installer; NOT the v1 Agent.\n[Service]\n"+
    "ExecStart="+old+"/bin/node "+old+"/apps/remote-control-agent/src/v2-main.js\n";
  assert.equal(assertRepeatInstallSameVersion(unit,old),undefined);
  assert.throws(()=>assertRepeatInstallSameVersion(unit,next),/use reviewed rca upgrade/);
  assert.throws(()=>assertRepeatInstallSameVersion(unit.replace("ExecStart=","ExecStart=/bin/sh -c foreign #"),old));
  assert.throws(()=>assertRepeatInstallSameVersion(unit+"ExecStart=/bin/sh\n",old));
});

test("user-local Agent launcher is installed idempotently and PATH is appended only once",async()=>{
  const f=await fixture();
  try {
    const link=await installManagerLauncher(f.home,f.program);
    assert.equal(link,path.join(f.home,".local/bin/rca"));
    assert.equal(await readlink(link),path.join(f.script,"rca.sh"));
    assert.equal((await readFile(path.join(f.home,".bashrc"),"utf8")).match(/# rca local CLI/g)?.length,1);
    await installManagerLauncher(f.home,f.program);
    assert.equal((await readFile(path.join(f.home,".bashrc"),"utf8")).match(/# rca local CLI/g)?.length,1);
  } finally { await rm(f.home,{recursive:true,force:true}); }
});

test("previous owned Python launcher migrates to bundled Node shim",async()=>{
  const f=await fixture();
  try {
    await mkdir(path.join(f.home,".local/bin"),{recursive:true,mode:0o700});
    const link=path.join(f.home,".local/bin/rca");
    await symlink(path.join(f.script,"manage-v2.py"),link);
    await preflightManagerLauncher(f.home,f.program);
    await installManagerLauncher(f.home,f.program);
    assert.equal(await readlink(link),path.join(f.script,"rca.sh"));
  } finally {await rm(f.home,{recursive:true,force:true});}
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
    // CI umask may strip group write bits at create-time: set the actual mode.
    await chmod(rc,0o620);
    assert.notEqual((await lstat(rc)).mode & 0o020,0);
    await installManagerLauncher(f.home,f.program);
    assert.equal(await readFile(rc,"utf8"),"# group writable\\n");
    assert.equal(await readlink(path.join(f.home,".local/bin/rca")),
      path.join(f.script,"rca.sh"));
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

test("#76 interrupted verified-download staging cleanup preserves identities and refuses hostile entries",()=>{
  const bootstrap=path.join(root,"apps/remote-control-agent/scripts/bootstrap-v2.py");
  const source=String.raw`import importlib.util,pathlib,tempfile,stat,sys
spec=importlib.util.spec_from_file_location("bootstrap_v2_recovery",sys.argv[1])
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
with tempfile.TemporaryDirectory(prefix="rc-recovery-isolated-") as tmp:
    root=pathlib.Path(tmp)
    home=root/"private";home.mkdir(mode=0o700)
    programs=home/"programs";programs.mkdir(mode=0o700)
    identity=home/"v2-identity.pem";identity.write_bytes(b"original-owner-identity")
    receipts=home/"operation-receipts.sqlite";receipts.write_bytes(b"unknown-receipt")
    interrupted=programs/".unverified-interrupted";interrupted.mkdir(mode=0o700)
    nested=interrupted/"bin";nested.mkdir(mode=0o700)
    (nested/"node").write_bytes(b"not-a-verified-executable")
    partial=programs/".download-incomplete";partial.write_bytes(b"partial-github-download");partial.chmod(0o600)
    untouched=programs/"foreign-file";untouched.write_bytes(b"never-remove")
    # A real killed child leaves partially extracted bytes on disk; only
    # the next invocation's bounded staging cleanup may remove them.
    import os,signal
    pid=os.fork()
    if pid == 0:
        crashed=programs/".unverified-sigkill"
        crashed.mkdir(mode=0o700)
        (crashed/"node").write_bytes(b"never-execute-partial")
        os.kill(os.getpid(),signal.SIGKILL)
        os._exit(7)
    _,status=os.waitpid(pid,0)
    assert os.WIFSIGNALED(status) and os.WTERMSIG(status)==signal.SIGKILL
    assert (programs/".unverified-sigkill/node").read_bytes()==b"never-execute-partial"
    module.clean_orphaned_staging(programs)
    assert not (programs/".unverified-sigkill").exists()
    assert not interrupted.exists() and not partial.exists()
    assert identity.read_bytes()==b"original-owner-identity"
    assert receipts.read_bytes()==b"unknown-receipt"
    assert untouched.read_bytes()==b"never-remove"
    hostile=programs/".unverified-symlink";hostile.symlink_to(identity)
    try: module.clean_orphaned_staging(programs)
    except ValueError: pass
    else: raise AssertionError("refused symlink staging expected")
    assert hostile.is_symlink() and identity.read_bytes()==b"original-owner-identity"
    hostile.unlink()
    wrong_mode=programs/".download-untrusted";wrong_mode.write_bytes(b"untouched")
    wrong_mode.chmod(0o666)
    try: module.clean_orphaned_staging(programs)
    except ValueError: pass
    else: raise AssertionError("refused unsafe staging permissions expected")
    assert wrong_mode.read_bytes()==b"untouched"
    assert receipts.read_bytes()==b"unknown-receipt"
`;
  const result=spawnSync("python3",["-B","-c",source,bootstrap],{
    encoding:"utf8",timeout:10000
  });
  assert.equal(result.status,0,result.stderr);
});

test("rca status does not create __pycache__ inside its versioned program",async()=>{
  const f=await fixture();
  try {
    const src=path.join(root,"apps/remote-control-agent/scripts");
    for(const name of ["manage-v2.py","bootstrap-v2.py"])
      await writeFile(path.join(f.script,name),await readFile(path.join(src,name)),{mode:0o600});
    await chmod(path.join(f.script,"manage-v2.py"),0o700);
    await writeFile(path.join(f.program,"bundle.json"),JSON.stringify({
      version:"v0.1.1",target:"linux-x64-glibc",artifact_schema:1,
      device_protocol:2,receipt_schema:1,upgrade_profile:"read-only-no-shell-v1"
    }),{mode:0o600});
    const env={...process.env,HOME:f.home};
    delete env.PYTHONDONTWRITEBYTECODE;
    delete env.PYTHONPYCACHEPREFIX;
    for(let n=0;n<2;n++){
      const result=spawnSync("python3",[path.join(f.script,"manage-v2.py"),"status"],
        {encoding:"utf8",env,timeout:10000});
      assert.equal(result.status,0,result.stderr);
      assert.match(result.stdout,/"cli_version": "v0.1.1"/);
      await assert.rejects(lstat(path.join(f.script,"__pycache__")),{code:"ENOENT"});
    }
  } finally {await rm(f.home,{recursive:true,force:true});}
});

test("portable installer exits cleanly without reopening local manager twice",async()=>{
  const source=await readFile(path.join(root,"apps/remote-control-agent/scripts/install-v2.mjs"),"utf8");
  assert.doesNotMatch(source,/Open Agent manager now/);
  assert.match(source,/Open the Agent manager now:/);
  assert.match(source,/To use rca in this terminal:/);
  assert.match(source,/New Bash terminals can use rca if/);
  // A shell child cannot change its parent Bash PATH: show the explicit fix.
  assert.match(source,/export PATH=/);
});

test("short prerelease shell bootstrap syntax and noninteractive fail-closed before GitHub",()=>{
  const sh=path.join(root,"install.sh");
  const parsed=spawnSync("sh",["-n",sh],{encoding:"utf8",timeout:3000});
  assert.equal(parsed.status,0,parsed.stderr);
  const result=spawnSync("sh",[sh],{encoding:"utf8",input:"",timeout:3000});
  assert.notEqual(result.status,0);
  assert.match(result.stderr,/interactive/);
});
