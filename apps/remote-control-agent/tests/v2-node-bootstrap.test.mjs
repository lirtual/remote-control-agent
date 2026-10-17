import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, mkdirSync, chmodSync, writeFileSync, rmSync, symlinkSync, lstatSync, readFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";
import { gzipSync } from "node:zlib";
import { inspectPinnedArchiveBytes, stagePinnedProgram, stageOrVerifyPinnedProgram } from "../scripts/bootstrap-node.mjs";

const APP="apps/remote-control-agent";
const manifest={name:"remote-control-agent",artifact_schema:1,version:"v0.1.2",
  target:"linux-x64-glibc",node:"v24.21.0",glibc_min:"2.34",device_protocol:2,
  receipt_schema:1,upgrade_profile:"read-only-no-shell-v1"};
function ELF(machine=62){const b=Buffer.alloc(64);b.writeUInt32LE(0x464c457f,0);b[4]=2;b[5]=1;b.writeUInt16LE(machine,18);return b;}
function fixture({corrupt=false,symlink=false,pax=false}={}){
  const dir=mkdtempSync(path.join(tmpdir(),"rca-node-unit-"));
  mkdirSync(path.join(dir,"bin"),{recursive:true,mode:0o700});
  for(const p of [APP,APP+"/src",APP+"/scripts",APP+"/.build"])
    mkdirSync(path.join(dir,p),{recursive:true,mode:0o700});
  for(const [name,contents,mode] of [
    ["bin/node",ELF(),0o700],
    ["bundle.json",JSON.stringify(manifest),0o600],
    [APP+"/package.json","{}",0o600],
    [APP+"/.build/session-supervisor",ELF(),0o700],
    [APP+"/scripts/bootstrap-node.mjs","export const candidate = true;\n",0o600],
    [APP+"/scripts/manage-v2.mjs","export const candidate = true;\n",0o600],
    [APP+"/scripts/install-v2.mjs","export const candidate = true;\n",0o600],
    [APP+"/src/v2-main.js","export const candidate = true;\n",0o600],
  ]){
    writeFileSync(path.join(dir,name),contents,{mode});chmodSync(path.join(dir,name),mode);
  }
  if(symlink)symlinkSync("/etc/passwd",path.join(dir,APP,"scripts","bad.js"));
  const options=["--format="+(pax?"pax":"ustar"),"--owner=0","--group=0",
    "--numeric-owner","--mode=u+rwX,go-rwx","-cf","-","bin","apps","bundle.json"];
  const tar=spawnSync("tar",options,{cwd:dir,maxBuffer:2048*1024});
  assert.equal(tar.status,0,tar.stderr.toString());
  const bytes=gzipSync(tar.stdout);
  const expectedSha256=createHash("sha256").update(bytes).digest("hex");
  return {dir,bytes,sha:expectedSha256};
}
const params=(x)=>({expectedSha256:x.sha,tag:"v0.1.2",target:"linux-x64-glibc"});
test("uncompleted Node installer refuses direct execution instead of reporting success",()=>{
  const exe=path.join(path.dirname(new URL(import.meta.url).pathname),"../scripts/bootstrap-node.mjs");
  const result=spawnSync(process.execPath,[exe,"--archive","/tmp/no-such-archive"],{
    encoding:"utf8",timeout:3000,
  });
  assert.equal(result.status,1);
  assert.match(result.stderr,/not enabled in this Draft/);
});
test("pinned original USTAR archive is inspected without Python, tar extraction or side effects",()=>{
  const x=fixture();
  try{
    const result=inspectPinnedArchiveBytes(x.bytes,params(x));
    assert.equal(result.manifest.version,"v0.1.2");
    assert.ok(result.records.has("bin/node"));
    assert.ok(result.records.has(APP+"/scripts/manage-v2.mjs"));
  }finally{rmSync(x.dir,{recursive:true,force:true});}
});
test("wrong checksum and wrong version fail before unpacking",()=>{
  const x=fixture();
  try {
    assert.throws(()=>inspectPinnedArchiveBytes(x.bytes,{...params(x),expectedSha256:"0".repeat(64)}),/SHA mismatch/);
    assert.throws(()=>inspectPinnedArchiveBytes(x.bytes,{...params(x),tag:"v0.1.3"}),/manifest/);
  }finally{rmSync(x.dir,{recursive:true,force:true});}
});
test("archive symlink and PAX/extended entry fail closed",()=>{
  for(const shape of [{symlink:true},{pax:true}]){
    const x=fixture(shape);
    try{
      assert.throws(()=>inspectPinnedArchiveBytes(x.bytes,params(x)),/link|PAX|special type|canonical USTAR/);
    }finally{rmSync(x.dir,{recursive:true,force:true});}
  }
});
test("corrupt tar data with self-consistent outer sha still fails inner header verification",()=>{
  const x=fixture();
  try {
    const bad=Buffer.from(x.bytes);
    bad[bad.length-8]^=1;
    const digest=createHash("sha256").update(bad).digest("hex");
    assert.throws(()=>inspectPinnedArchiveBytes(bad,{...params(x),expectedSha256:digest}));
  }finally{rmSync(x.dir,{recursive:true,force:true});}
});

test("verified Node archive stages atomically with private files and no Python",()=>{
  const x=fixture();
  const parent=mkdtempSync(path.join(tmpdir(),"rca-node-programs-"));
  try {
    chmodSync(parent,0o700);
    const dst=stagePinnedProgram(x.bytes,params(x),parent,"v0.1.2-linux-x64-glibc");
    assert.equal(readFileSync(path.join(dst,"bundle.json"),"utf8"),JSON.stringify(manifest));
    assert.ok(lstatSync(path.join(dst,"bin/node")).isFile());
    assert.equal(lstatSync(dst).mode&0o777,0o700);
    assert.equal(lstatSync(path.join(dst,"bin/node")).mode&0o777,0o700);
    assert.equal(lstatSync(path.join(dst,"bundle.json")).mode&0o777,0o600);
    assert.deepEqual(readdirSync(parent),["v0.1.2-linux-x64-glibc"]);
    assert.throws(()=>stagePinnedProgram(x.bytes,params(x),parent,"v0.1.2-linux-x64-glibc"),/already exists/);
    assert.equal(readFileSync(path.join(dst,"bundle.json"),"utf8"),JSON.stringify(manifest));
  }finally{
    rmSync(x.dir,{recursive:true,force:true});
    rmSync(parent,{recursive:true,force:true});
  }
});

test("atomic staging refuses wrong digest and preserves foreign destination",()=>{
  const x=fixture(),parent=mkdtempSync(path.join(tmpdir(),"rca-node-programs-"));
  try{
    chmodSync(parent,0o700);
    const dst=path.join(parent,"v0.1.2-linux-x64-glibc");
    writeFileSync(dst,"FOREIGN NO CLOBBER",{mode:0o600});
    assert.throws(()=>stagePinnedProgram(x.bytes,params(x),parent,"v0.1.2-linux-x64-glibc"),/already exists/);
    assert.equal(readFileSync(dst,"utf8"),"FOREIGN NO CLOBBER");
    assert.throws(()=>stagePinnedProgram(x.bytes,{...params(x),expectedSha256:"0".repeat(64)},parent,"v0.1.2-linux-x64-glibc"),/SHA mismatch/);
    assert.deepEqual(readdirSync(parent),["v0.1.2-linux-x64-glibc"]);
  }finally{rmSync(x.dir,{recursive:true,force:true});rmSync(parent,{recursive:true,force:true});}
});

test("staging never overwrites a dangling symlink version destination",()=>{
  const x=fixture(),parent=mkdtempSync(path.join(tmpdir(),"rca-node-programs-"));
  try{
    chmodSync(parent,0o700);
    const dst=path.join(parent,"v0.1.2-linux-x64-glibc");
    symlinkSync(path.join(parent,"does-not-exist"),dst);
    assert.throws(()=>stagePinnedProgram(x.bytes,params(x),parent,"v0.1.2-linux-x64-glibc"),/already exists/);
    assert.ok(lstatSync(dst).isSymbolicLink());
    assert.deepEqual(readdirSync(parent),["v0.1.2-linux-x64-glibc"]);
  }finally{rmSync(x.dir,{recursive:true,force:true});rmSync(parent,{recursive:true,force:true});}
});
test("staging refuses symlinked/untrusted parents and version-label mismatch",()=>{
  const x=fixture(),root=mkdtempSync(path.join(tmpdir(),"rca-node-parent-"));
  try{
    const safe=path.join(root,"private");
    mkdirSync(safe,{mode:0o700});chmodSync(safe,0o700);
    const alias=path.join(root,"redirect");
    symlinkSync(safe,alias);
    assert.throws(()=>stagePinnedProgram(x.bytes,params(x),alias,"v0.1.2-linux-x64-glibc"),/Untrusted private/);
    assert.throws(()=>stagePinnedProgram(x.bytes,params(x),safe,"v0.1.3-linux-x64-glibc"),/Versioned destination/);
    chmodSync(safe,0o755);
    assert.throws(()=>stagePinnedProgram(x.bytes,params(x),safe,"v0.1.2-linux-x64-glibc"),/Untrusted private/);
    assert.deepEqual(readdirSync(safe),[]);
  }finally{rmSync(x.dir,{recursive:true,force:true});rmSync(root,{recursive:true,force:true});}
});

test("repeat-install verifies exact immutable Node files with no mutation",()=>{
  const x=fixture(),p=mkdtempSync(path.join(tmpdir(),"rca-node-repeat-"));
  try{
    chmodSync(p,0o700);
    const dst=stageOrVerifyPinnedProgram(x.bytes,params(x),p,"v0.1.2-linux-x64-glibc");
    const before=readFileSync(path.join(dst,"bundle.json"));
    const again=stageOrVerifyPinnedProgram(x.bytes,params(x),p,"v0.1.2-linux-x64-glibc");
    assert.equal(again,dst);
    assert.ok(readFileSync(path.join(dst,"bundle.json")).equals(before));
    assert.deepEqual(readdirSync(p),["v0.1.2-linux-x64-glibc"]);
  }finally{rmSync(x.dir,{recursive:true,force:true});rmSync(p,{recursive:true,force:true});}
});
test("repeat-install rejects injected Python cache, modified file and mode drift",()=>{
  const x=fixture(),p=mkdtempSync(path.join(tmpdir(),"rca-node-tamper-"));
  try{
    chmodSync(p,0o700);
    const dst=stageOrVerifyPinnedProgram(x.bytes,params(x),p,"v0.1.2-linux-x64-glibc");
    const scripts=path.join(dst,APP,"scripts");
    mkdirSync(path.join(scripts,"__pycache__"),{mode:0o700});
    assert.throws(()=>stageOrVerifyPinnedProgram(x.bytes,params(x),p,"v0.1.2-linux-x64-glibc"),/differs/);
    rmSync(path.join(scripts,"__pycache__"),{recursive:true});
    const file=path.join(dst,"bundle.json");
    writeFileSync(file,"TAMPERED");
    assert.throws(()=>stageOrVerifyPinnedProgram(x.bytes,params(x),p,"v0.1.2-linux-x64-glibc"),/Modified/);
    writeFileSync(file,JSON.stringify(manifest));chmodSync(file,0o644);
    assert.throws(()=>stageOrVerifyPinnedProgram(x.bytes,params(x),p,"v0.1.2-linux-x64-glibc"),/Unexpected|differs/);
  }finally{rmSync(x.dir,{recursive:true,force:true});rmSync(p,{recursive:true,force:true});}
});
test("repeat-install rejects symlink member and dangling symlink root",()=>{
  const x=fixture(),p=mkdtempSync(path.join(tmpdir(),"rca-node-links-"));
  try{
    chmodSync(p,0o700);
    const dst=stageOrVerifyPinnedProgram(x.bytes,params(x),p,"v0.1.2-linux-x64-glibc");
    const member=path.join(dst,"bundle.json");
    rmSync(member);symlinkSync("/etc/passwd",member);
    assert.throws(()=>stageOrVerifyPinnedProgram(x.bytes,params(x),p,"v0.1.2-linux-x64-glibc"),/Unexpected/);
    rmSync(dst,{recursive:true});
    symlinkSync(path.join(p,"missing"),dst);
    assert.throws(()=>stageOrVerifyPinnedProgram(x.bytes,params(x),p,"v0.1.2-linux-x64-glibc"));
  }finally{rmSync(x.dir,{recursive:true,force:true});rmSync(p,{recursive:true,force:true});}
});
