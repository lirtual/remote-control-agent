import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { existsSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const script = path.join(root, "scripts/bootstrap-v2.py");
const PY = String.raw`import importlib.util, json, pathlib, sys, tempfile, shutil, tarfile, io
spec=importlib.util.spec_from_file_location("bootstrap",sys.argv[1])
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
tag="v0.1.0"; target="linux-x64-glibc"; commit="a"*40
assert m.safe_member("bin/node",False)=="bin/node"
for unsafe in ["../../.ssh/id_rsa","/tmp/evil","bin/../evil","apps/remote-control-agent/tests/evil.js"]:
    try: m.safe_member(unsafe,False); raise AssertionError(unsafe)
    except ValueError: pass
for url in ["http://github.com/file","https://evil.example/file","https://github.com.evil.test/file"]:
    assert not m.https_origin(url),url
assert m.https_origin("https://github.com/lirtual/remote-control-agent/releases/download/v0.1.0/agent.tgz")
try: m.resolve_pinned("latest",commit,target); raise AssertionError("latest accepted")
except ValueError: pass
print("PYTHON_BOOTSTRAP_FAIL_CLOSED_OK")
`;
function python(args,{input,env}={}) {
  return spawnSync("python3",args,{input,encoding:"utf8",timeout:15000,env:{...process.env,...env}});
}

test("#74 version-pinned bootstrap validates inputs and prevents unsafe redirects",()=>{
  const result=python(["-c",PY,script]);
  assert.equal(result.status,0,result.stderr);
  assert.match(result.stdout,/PYTHON_BOOTSTRAP_FAIL_CLOSED_OK/);
});

test("#74 standalone bootstrap fails without real TTY, before network or identity change",async()=>{
  const home=await mkdtemp(path.join(os.tmpdir(),"rc-bootstrap-tty-"));
  try {
    const r=python([script,"--tag","v0.1.0","--commit","a".repeat(40),
      "--endpoint","https://rc.example.org/"],{input:"",env:{HOME:home}});
    assert.equal(r.status,1,r.stderr);
    assert.match(r.stderr,/real interactive terminal/);
    assert.equal(existsSync(path.join(home,".local","share","mcp-workers")),false);
  } finally {await rm(home,{recursive:true,force:true});}
});

test("#74 public immutable Release metadata and exact tag SHA are necessary",()=>{
  const body=String.raw`import importlib.util,sys
spec=importlib.util.spec_from_file_location("bootstrap",sys.argv[1])
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
tag="v0.1.0";c="a"*40;t="linux-x64-glibc"
name="remote-control-agent-"+tag+"-"+t+".tar.gz"
asset={"name":name,"state":"uploaded","id":42,"size":50000,"digest":"sha256:"+"b"*64,
       "url":m.API+"/releases/assets/42",
       "browser_download_url":"https://github.com/lirtual/remote-control-agent/releases/download/"+tag+"/"+name}
calls=[]
def response(url):
    calls.append(url)
    if "/releases/tags/" in url:return {"immutable":True,"draft":False,"tag_name":tag,"id":1,"assets":[asset]}
    return {"ref":"refs/tags/"+tag,"object":{"type":"commit","sha":c}}
m.json_api=response
info=m.resolve_pinned(tag,c,t)
assert info["digest"]=="b"*64
assert len(calls)==2
assert all("/immutable-releases" not in p for p in calls)
asset["digest"]=None
try:m.resolve_pinned(tag,c,t);raise AssertionError("missing digest accepted")
except ValueError:pass
asset["digest"]="sha256:"+"b"*64
old=response
def bad(url):
    x=old(url)
    if "/releases/tags/" in url: x=dict(x,immutable=False)
    return x
m.json_api=bad
try:m.resolve_pinned(tag,c,t);raise AssertionError("mutable release accepted")
except ValueError:pass
print("PINNED_RELEASE_API_OK")
`;
  const r=python(["-c",body,script]);
  assert.equal(r.status,0,r.stderr);
  assert.match(r.stdout,/PINNED_RELEASE_API_OK/);
});

test("#74 bootstrap rejects archive symlink/traversal and safely inspects the real unpublished x64 test archive",()=>{
  const body=String.raw`import importlib.util,sys,tarfile,tempfile,pathlib,io,os
spec=importlib.util.spec_from_file_location("bootstrap",sys.argv[1])
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
with tempfile.TemporaryDirectory() as d:
    f=pathlib.Path(d)/"bad.tar.gz"
    with tarfile.open(f,"w:gz") as tf:
        ti=tarfile.TarInfo("apps/remote-control-agent/src/backdoor.js")
        ti.type=tarfile.SYMTYPE;ti.linkname="/tmp/evil";tf.addfile(ti)
    try:m.inspect_archive(f,"v0.1.0","linux-x64-glibc");raise AssertionError("link accepted")
    except ValueError:pass
archive=sys.argv[2] if len(sys.argv)>2 else ""
if archive:
    entries=m.inspect_archive(archive,"v0.1.0","linux-x64-glibc")
    assert len(entries)>20
    with tempfile.TemporaryDirectory() as d:
        dest=pathlib.Path(d)/"installed"
        m.unpack_verified(archive,dest,entries,"v0.1.0","linux-x64-glibc")
        assert (dest/"bin/node").is_file()
        assert os.stat(dest/"bin/node").st_mode&0o777 ==0o700
        try:m.unpack_verified(archive,dest,entries,"v0.1.0","linux-x64-glibc");raise AssertionError("overwrote install")
        except ValueError:pass
print("PYTHON_TAR_SAFETY_OK")
`;
  const archive=process.env.RC_V2_PACKAGE_SMOKE;
  const r=python(["-c",body,script,...(archive?[archive]:[])]);
  assert.equal(r.status,0,r.stderr);
  assert.match(r.stdout,/PYTHON_TAR_SAFETY_OK/);
});

test("#76 same verified archive reuses installed program; tampering never overwrites it",()=>{
  const validation=String.raw`import importlib.util,sys,tarfile,tempfile,pathlib,os
spec=importlib.util.spec_from_file_location("b",sys.argv[1]);b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
archive=sys.argv[2]
with tempfile.TemporaryDirectory() as d:
    root=pathlib.Path(d);dest=root/"v0.1.0"
    records=b.inspect_archive(archive,"v0.1.0","linux-x64-glibc")
    b.unpack_verified(archive,dest,records,"v0.1.0","linux-x64-glibc")
    assert b.verify_existing_program(archive,dest,records)
    target=dest/"apps/remote-control-agent/src/v2-main.js"
    with target.open("ab") as f:f.write(b"malicious extension")
    try:b.verify_existing_program(archive,dest,records);raise AssertionError("modified program accepted")
    except ValueError:pass
    assert target.read_bytes().endswith(b"malicious extension")
    orphan=root/".download-historical"
    orphan.write_bytes(b"partial");orphan.chmod(0o600)
    b.clean_orphaned_staging(root)
    assert not orphan.exists()
    foreign=root/".download-unsafe"
    foreign.symlink_to(dest)
    try:b.clean_orphaned_staging(root);raise AssertionError("staging symlink deleted")
    except ValueError:pass
    assert foreign.is_symlink()
print("SAME_ARCHIVE_SAFE_RETRY_OK")
`;
  const archive=process.env.RC_V2_PACKAGE_SMOKE;
  if (!archive) return;
  const r=python(["-c",validation,script,archive]);
  assert.equal(r.status,0,r.stderr);
  assert.match(r.stdout,/SAME_ARCHIVE_SAFE_RETRY_OK/);
});

test("#73 clean-host bootstrap rejects a release whose real glibc ABI exceeds host",()=>{
  const archive=process.env.RC_V2_PACKAGE_SMOKE;
  if(!archive) return;
  const code=String.raw`import importlib.util,sys
spec=importlib.util.spec_from_file_location("b",sys.argv[1])
b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
archive=sys.argv[2]
records=b.inspect_archive(archive,"v0.1.0","linux-x64-glibc")
assert len(records)>20
original=b.platform.libc_ver
b.platform.libc_ver=lambda:("glibc","2.28")
try:
    b.inspect_archive(archive,"v0.1.0","linux-x64-glibc")
    raise AssertionError("ABI mismatch accepted")
except ValueError as e:
    assert "newer glibc ABI" in str(e)
finally:
    b.platform.libc_ver=original
print("GLIBC_ABI_FAILS_BEFORE_UNPACK_OR_EXECUTE")
`;
  const r=python(["-c",code,script,archive]);
  assert.equal(r.status,0,r.stderr);
  assert.match(r.stdout,/GLIBC_ABI_FAILS_BEFORE_UNPACK_OR_EXECUTE/);
});
