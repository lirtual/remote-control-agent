import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, mkdirSync, chmodSync, writeFileSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";
import { gzipSync } from "node:zlib";
import { inspectPinnedArchiveBytes } from "../scripts/bootstrap-node.mjs";

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
