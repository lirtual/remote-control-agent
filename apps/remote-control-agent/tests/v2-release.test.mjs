import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { gzipSync } from "node:zlib";
import test from "node:test";
import { parseArgs, runtimeSources, ensureNativeTarget, requiredGlibcVersion } from "../scripts/build-v2-release.mjs";
import { resolvePinnedRelease, downloadPinnedAsset, inspectTarGzip, extractVerifiedAsset, releaseAssetName } from "../scripts/verify-v2-release.mjs";

const tag="v0.1.0",target="linux-x64-glibc",commit="1".repeat(40);
const sha=b=>createHash("sha256").update(b).digest("hex");
function elf(machine) {
  const b=Buffer.alloc(80); b.writeUInt32BE(0x7f454c46,0);
  b[4]=2; b[5]=1; b.writeUInt16LE(machine,18);
  return b;
}
function tar(entries) {
  const chunks=[];
  for(const {name,data=Buffer.alloc(0),type="0"} of entries) {
    const header=Buffer.alloc(512);
    header.write(name,0,"ascii");
    function writeOct(value,start,width){
      const v=value.toString(8).padStart(width-1,"0")+"\0";
      header.write(v,start,width,"ascii");
    }
    writeOct(0o600,100,8);writeOct(0,108,8);writeOct(0,116,8);
    writeOct(data.length,124,12);writeOct(0,136,12);
    header.fill(32,148,156);header.write(type,156,"ascii");
    header.write("ustar\0",257,"ascii");
    const sum=header.reduce((a,b)=>a+b,0);
    writeOct(sum,148,8);
    chunks.push(header,data,Buffer.alloc(Math.ceil(data.length/512)*512-data.length));
  }
  chunks.push(Buffer.alloc(1024));
  return gzipSync(Buffer.concat(chunks),{mtime:0});
}
function fixture(extra=[],opts={}) {
  const manifest=Buffer.from(JSON.stringify({name:"remote-control-agent",artifact_schema:1,version:tag,target,node:"v24.21.0",modules:["v2-main.ts"]}));
  return tar([
    {name:"bin/node",data:elf(62)},
    {name:"bundle.json",data:manifest},
    {name:"apps/remote-control-agent/package.json",data:Buffer.from('{"type":"module"}')},
    {name:"apps/remote-control-agent/src/v2-main.js",data:Buffer.from("console.log('ok')")},
    {name:"apps/remote-control-agent/scripts/install-v2.mjs",data:Buffer.from("export {}")},
    {name:"apps/remote-control-agent/.build/session-supervisor",data:elf(62)},
    ...extra,
  ]);
}
const api="https://api.github.com/repos/lirtual/remote-control-agent";
function mockGithub(buffer,{immutable=true,digest="sha256:"+sha(buffer),actualCommit=commit,assetSize=buffer.length,
  routeRedirect=null,repoEnabled=true}={}) {
  const assetName=releaseAssetName(tag,target);
  const seen=[];
  async function send(url,init) {
    seen.push({url,init});
    const u=new URL(url);
    if(u.href===api+"/immutable-releases") return Response.json({enabled:repoEnabled});
    if(u.href===api+"/releases/tags/"+tag) return Response.json({
      id:71,tag_name:tag,draft:false,immutable,assets:[
        {name:assetName,id:903,state:"uploaded",size:assetSize,
          digest,url:api+"/releases/assets/903"}]});
    if(u.href===api+"/git/ref/tags/"+tag) return Response.json({
      ref:"refs/tags/"+tag,object:{type:"commit",sha:actualCommit}});
    if(u.href===api+"/releases/assets/903") {
      if(routeRedirect) return new Response(null,{status:302,headers:{location:routeRedirect}});
      return new Response(buffer,{status:200,headers:{"content-type":"application/octet-stream"}});
    }
    if (u.hostname==="release-assets.githubusercontent.com") return new Response(buffer,{status:200});
    throw new Error("Unexpected URL "+url);
  }
  return {send,seen};
}

test("#73 release package build rejects unverified architectures and unpinned targets",()=>{
  assert.deepEqual(parseArgs(["--version",tag,"--target",target,
    "--node-bin","/opt/node","--native","/opt/supervisor","--out","/tmp/archive",
    "--node-sha256","f".repeat(64),"--native-sha256","e".repeat(64)]),{
      version:tag,target,nodeBin:"/opt/node",native:"/opt/supervisor",out:"/tmp/archive",
      nodeSha256:"f".repeat(64),nativeSha256:"e".repeat(64)});
  for(const args of [
    ["--version","latest","--target",target,"--node-bin","/n","--native","/b","--out","/tmp/o"],
    ["--version",tag,"--target","linux-x64-musl","--node-bin","/n","--native","/b","--out","/tmp/o"],
    ["--version",tag,"--target",target,"--node-bin","node","--native","/b","--out","/tmp/o"],
  ]) assert.throws(()=>parseArgs(args));
  assert.ok(runtimeSources().includes("v2-main.ts"));
  assert.ok(!runtimeSources().includes("main.ts"));
  assert.ok(!runtimeSources().includes("server.ts"));
  const mismatchedArch = process.arch === "arm64" ? "linux-x64-glibc" : "linux-arm64-glibc";
  assert.throws(()=>ensureNativeTarget({target:mismatchedArch,nodeBin:"/missing",native:"/missing"}),/architecture/);
});

test("#73 verifies immutable setting, tag commit, exact asset id and official digest",async()=>{
  const payload=Buffer.alloc(2048,0x52);
  const {send,seen}=mockGithub(payload);
  const info=await resolvePinnedRelease({tag,commit,target,send});
  assert.equal(info.assetId,903);
  assert.equal(info.bytes,payload.length);
  assert.equal(info.digest,sha(payload));
  const bytes=await downloadPinnedAsset(info,send);
  assert.deepEqual(bytes, payload);
  assert.equal(seen.some(x=>x.url.endsWith("/latest")),false);
  assert.ok(seen.every(x=>x.init.redirect==="manual"));
  assert.equal(seen.some(x=>x.url.endsWith("/immutable-releases")),false,
    "A public installer must not need GitHub admin credentials.");
  for(const options of [
    {immutable:false},{actualCommit:"2".repeat(40)},
    {digest:null},{digest:"sha256:"+"a".repeat(63)},
    {assetSize:MAX_NEGATIVE},
  ]) {
    await assert.rejects(resolvePinnedRelease({tag,commit,target,send:mockGithub(payload,options).send}));
  }
});
const MAX_NEGATIVE=250_000_000;

test("#73 refuses tampered bytes and redirects outside official GitHub HTTPS",async()=>{
  const payload=Buffer.alloc(2048,0x52);
  const tamper=mockGithub(payload,{digest:"sha256:"+"f".repeat(64)});
  const pinned=await resolvePinnedRelease({tag,commit,target,send:tamper.send});
  await assert.rejects(downloadPinnedAsset(pinned,tamper.send),/digest mismatch/);
  for(const url of ["http://release-assets.githubusercontent.com/artifact",
    "https://not-github.example/fake","file:///tmp/payload",
    "https://github.com.evil.invalid/file"]) {
    const m=mockGithub(payload,{routeRedirect:url});
    const info=await resolvePinnedRelease({tag,commit,target,send:m.send});
    await assert.rejects(downloadPinnedAsset(info,m.send),/outside GitHub HTTPS/);
  }
  const good=mockGithub(payload,{routeRedirect:"https://release-assets.githubusercontent.com/asset"});
  const info=await resolvePinnedRelease({tag,commit,target,send:good.send});
  assert.deepEqual(await downloadPinnedAsset(info,good.send),payload);
});

test("#73 rejects malicious archive entries, wrong CPU, version, duplicates and corruption before writing",()=>{
  const badEntries=[
    {name:"../../.ssh/id_rsa",data:Buffer.from("pwn")},
    {name:"/tmp/exploit",data:Buffer.from("bad")},
    {name:"apps/remote-control-agent/src/evil.js",type:"2"},
    {name:"apps/remote-control-agent/src/v2-main.js",data:Buffer.from("duplicate")},
    {name:"apps/remote-control-agent/tests/private.js",data:Buffer.from("oops")},
    {name:"apps/remote-control-agent/src/back\\slash.js",data:Buffer.from("oops")},
  ];
  assert.equal(inspectTarGzip(fixture(),{tag,target}).size,6);
  for (const bad of badEntries) {
    assert.throws(()=>inspectTarGzip(fixture([bad]),{tag,target}));
  }
  assert.throws(()=>inspectTarGzip(fixture(),{tag:"v0.2.0",target}));
  assert.throws(()=>inspectTarGzip(fixture(),{tag,target:"linux-arm64-glibc"}));
  assert.throws(()=>inspectTarGzip(Buffer.from("invalid gzip"),{tag,target}));
  assert.throws(()=>inspectTarGzip(fixture().subarray(0,25),{tag,target}));
});

test("#73 verified local staging is owner-only, leaves unrelated active version untouched",async()=>{
  const dir=await mkdtemp(path.join(os.tmpdir(),"rc-release-safe-"));
  const dst=path.join(dir,"program");
  const archive=fixture();
  const meta={tag,target,digest:sha(archive)};
  try {
    await assert.rejects(extractVerifiedAsset({...meta,digest:"0".repeat(64)},archive,dst),/digest/);
    assert.deepEqual(await readdir(dir),[]);
    const result=await extractVerifiedAsset(meta,archive,dst);
    assert.equal(result.files,6);
    assert.equal((await readFile(path.join(dst,"bundle.json"),"utf8")).includes(tag),true);
    await assert.rejects(extractVerifiedAsset(meta,archive,dst));
    assert.equal((await readFile(path.join(dst,"bundle.json"),"utf8")).includes(tag),true);
  } finally {await rm(dir,{recursive:true,force:true});}
});

test("#73 builder selects maximum actual glibc version across ELF requirements",()=>{
  const probe = (_binary,args,opts) => ({status:0,stdout:
    "Version needs section: Name: GLIBC_2.28; Name: GLIBC_2.34; Name: GLIBC_2.2.5",
  });
  assert.equal(requiredGlibcVersion("/fake/supervisor",probe),"2.34");
  assert.throws(()=>requiredGlibcVersion("/fake/musl",()=>({status:0,stdout:""})),
    /no verifiable glibc/);
  assert.throws(()=>requiredGlibcVersion("/fake/readelf-fail",()=>({status:1,stdout:""})),
    /Cannot determine/);
});
