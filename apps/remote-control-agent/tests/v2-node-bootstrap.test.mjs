import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, mkdirSync, chmodSync, writeFileSync, rmSync, symlinkSync, lstatSync, readFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";
import { gzipSync, gunzipSync } from "node:zlib";
import { inspectPinnedArchiveBytes, stagePinnedProgram, stageOrVerifyPinnedProgram, parseNodeBootstrapArgs, prepareNodeBootstrap, executeNodeBootstrap, ensurePrivatePrograms, removeSafeOrphanStages, hasLegacySignedService } from "../scripts/bootstrap-node.mjs";

const APP="apps/remote-control-agent";
const manifest={name:"remote-control-agent",artifact_schema:1,version:"v0.1.2",
  target:"linux-x64-glibc",node:"v24.21.0",glibc_min:"2.34",device_protocol:2,
  receipt_schema:1,upgrade_profile:"read-only-no-shell-v1"};
function ELF(machine=62){const b=Buffer.alloc(64);b.writeUInt32LE(0x464c457f,0);b[4]=2;b[5]=1;b.writeUInt16LE(machine,18);return b;}
function fixture({corrupt=false,symlink=false,pax=false,duplicate=false,profile="read-only-no-shell-v1"}={}){
  const dir=mkdtempSync(path.join(tmpdir(),"rca-node-unit-"));
  mkdirSync(path.join(dir,"bin"),{recursive:true,mode:0o700});
  for(const p of [APP,APP+"/src",APP+"/scripts",APP+"/.build"])
    mkdirSync(path.join(dir,p),{recursive:true,mode:0o700});
  for(const [name,contents,mode] of [
    ["bin/node",ELF(),0o700],
    ["bundle.json",JSON.stringify({...manifest,upgrade_profile:profile}),0o600],
    [APP+"/package.json","{}",0o600],
    [APP+"/.build/session-supervisor",ELF(),0o700],
    [APP+"/scripts/bootstrap-node.mjs","export const candidate = true;\n",0o600],
    [APP+"/scripts/manage-v2.mjs","export const candidate = true;\n",0o600],
    [APP+"/scripts/lifecycle-v2.mjs","export const candidate = true;\n",0o600],
    [APP+"/scripts/upgrade-v2.mjs","export const candidate = true;\n",0o600],
    [APP+"/scripts/upgrade-existing-service.mjs","export const candidate = true;\n",0o600],
    [APP+"/scripts/verify-v2-release.mjs","export const candidate = true;\n",0o600],
    [APP+"/scripts/rca.sh","#!/bin/sh\n",0o700],
    [APP+"/scripts/install-v2.mjs","export const candidate = true;\n",0o600],
    [APP+"/src/v2-main.js","export const candidate = true;\n",0o600],
  ]){
    writeFileSync(path.join(dir,name),contents,{mode});chmodSync(path.join(dir,name),mode);
  }
  if(symlink)symlinkSync("/etc/passwd",path.join(dir,APP,"scripts","bad.js"));
  const options=["--format="+(pax?"pax":"ustar"),"--owner=0","--group=0",
    "--numeric-owner","--mode=u+rwX,go-rwx",...(duplicate?["--hard-dereference"]:[]),
    "-cf","-","bin","apps","bundle.json",...(duplicate?["bundle.json"]:[])];
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
  assert.match(result.stderr,/Pinned Node installation refused/);
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
test("immutable bootstrap accepts reviewed paired-full profile without changing target or identity",()=>{
  const f=fixture({profile:"paired-full-v1"});
  try{
    const inspected=inspectPinnedArchiveBytes(f.bytes,params(f));
    assert.equal(inspected.manifest.upgrade_profile,"paired-full-v1");
    assert.equal(inspected.manifest.version,"v0.1.2");
    assert.ok(inspected.records.has(APP+"/src/v2-main.js"));
  }finally{rmSync(f.dir,{recursive:true,force:true});}
});
test("immutable bootstrap refuses an unreviewed release profile before unpacking",()=>{
  const f=fixture({profile:"shell-enabled-unreviewed"});
  try{
    assert.throws(()=>inspectPinnedArchiveBytes(f.bytes,params(f)),/Unsupported Agent manifest/);
  }finally{rmSync(f.dir,{recursive:true,force:true});}
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
test("duplicate tar members fail even with a matching outer archive SHA",()=>{
  const x=fixture({duplicate:true});
  try{
    assert.throws(()=>inspectPinnedArchiveBytes(x.bytes,params(x)),/duplicate tar entries/);
  }finally{rmSync(x.dir,{recursive:true,force:true});}
});

test("malformed archive name, mode and size fail even with a matching outer archive SHA",()=>{
  const x=fixture();
  try{
    const original=gunzipSync(x.bytes);
    const start=original.indexOf(Buffer.from("bundle.json"));
    assert.ok(start>=0 && start%512===0,"bundle.json must be a USTAR header");
    const variants=[
      {name:"traversal",edit:(h)=>{h.fill(0,0,100);h.write("../escape",0,"ascii");},error:/Unsafe tar path/},
      {name:"world-writable",edit:(h)=>{h.fill(0,100,108);h.write("0000666",100,"ascii");},error:/Invalid tar entry size or mode/},
      {name:"oversized member",edit:(h)=>{h.fill(0,124,136);h.write("77777777777",124,"ascii");},error:/oversized or truncated/},
    ];
    for(const scenario of variants){
      const tar=Buffer.from(original),header=tar.subarray(start,start+512);
      scenario.edit(header);
      header.fill(32,148,156);
      let sum=0;
      for(const v of header)sum+=v;
      header.write(sum.toString(8).padStart(6,"0"),148,"ascii");
      header[154]=0;header[155]=32;
      const bytes=gzipSync(tar);
      const digest=createHash("sha256").update(bytes).digest("hex");
      assert.throws(
        ()=>inspectPinnedArchiveBytes(bytes,{...params(x),expectedSha256:digest}),
        scenario.error,scenario.name,
      );
    }
  }finally{rmSync(x.dir,{recursive:true,force:true});}
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

const nativeTarget=process.arch==="arm64"?"linux-arm64-glibc":"linux-x64-glibc";
function nativeFixture(){
  const x=fixture();
  if(process.arch==="arm64"){
    const newManifest={...manifest,target:nativeTarget};
    writeFileSync(path.join(x.dir,"bundle.json"),JSON.stringify(newManifest));
    for(const name of ["bin/node",APP+"/.build/session-supervisor"])
      writeFileSync(path.join(x.dir,name),ELF(183));
    const tar=spawnSync("tar",["--format=ustar","--owner=0","--group=0",
      "--numeric-owner","--mode=u+rwX,go-rwx","-cf","-","bin","apps","bundle.json"],
      {cwd:x.dir,maxBuffer:2048*1024});
    assert.equal(tar.status,0,tar.stderr.toString());
    x.bytes=gzipSync(tar.stdout);
    x.sha=createHash("sha256").update(x.bytes).digest("hex");
  }
  return x;
}
function localBootstrapFixture(){
  const x=nativeFixture();
  const home=mkdtempSync(path.join(tmpdir(),"rca-install-target-"));
  chmodSync(home,0o700);
  const archive=path.join(home,"verified-archive.tar.gz");
  writeFileSync(archive,x.bytes,{mode:0o600});
  chmodSync(archive,0o600);
  const opts={archive,tag:"v0.1.2",commit:"a".repeat(40),
    sha256:x.sha,endpoint:"https://remote-control-v2-preview.aiyaya.workers.dev/",
    target:nativeTarget,locked:false};
  return {x,home,archive,opts,cleanup(){
    rmSync(x.dir,{recursive:true,force:true});
    rmSync(home,{recursive:true,force:true});
  }};
}
test("Node bootstrap pins only clean Worker origin and strict version+commit",()=>{
  const f=localBootstrapFixture();
  try{
    const argv=["--archive",f.archive,"--tag","v0.1.2","--commit","a".repeat(40),
      "--sha256",f.x.sha,"--endpoint",f.opts.endpoint];
    assert.equal(parseNodeBootstrapArgs(argv).target,nativeTarget);
    assert.equal(parseNodeBootstrapArgs(argv).upgrade,false);
    assert.equal(parseNodeBootstrapArgs([...argv,"--upgrade"]).upgrade,true);
    assert.throws(()=>parseNodeBootstrapArgs([...argv,"--upgrade","--upgrade"]),/Duplicate/);
    assert.throws(()=>parseNodeBootstrapArgs([...argv,"--upgrade=true"]));
    for(const evil of [
      argv.concat("--endpoint","https://evil.example/"),
      argv.slice(0,-1).concat("https://evil.example/?x=1"),
      argv.slice(0,-1).concat("http://remote-control-v2-preview.aiyaya.workers.dev/"),
      argv.slice(0,3).concat("latest",argv.slice(4)),
    ])assert.throws(()=>parseNodeBootstrapArgs(evil));
  }finally{f.cleanup();}
});
test("invalid archive and missing TTY fail before creating installation state",()=>{
  const f=localBootstrapFixture();
  try{
    let calls=0;
    assert.throws(()=>executeNodeBootstrap(f.opts,{home:f.home,
      stdin:{isTTY:false},stdout:{isTTY:true},invoke:()=>{calls++;}}),/real local terminal/);
    assert.equal(calls,0);
    assert.equal(readdirSync(f.home).length,1);
    assert.throws(()=>prepareNodeBootstrap({...f.opts,sha256:"f".repeat(64)},
      {home:f.home,runtimeLibc:"2.41"}),/SHA mismatch/);
    assert.equal(readdirSync(f.home).length,1);
  }finally{f.cleanup();}
});
test("unlocked bootstrap takes ONE shared flock before package staging",()=>{
  const f=localBootstrapFixture();
  try{
    const staged=path.join(f.home,"bootstrap.mjs");
    writeFileSync(staged,"safe local bootstrap",{mode:0o600});
    let call;
    const rv=executeNodeBootstrap(f.opts,{home:f.home,
      stdin:{isTTY:true},stdout:{isTTY:true},bootstrap:staged,
      invoke:(cmd,args,opts)=>{call={cmd,args,opts};return {status:0};}});
    assert.equal(rv,0);
    assert.equal(call.cmd,"flock");
    assert.ok(call.args.includes("--lock-held"));
    assert.equal(call.args.at(-2),f.opts.endpoint);
    assert.equal(call.opts.env.NODE_OPTIONS,"");
    const programs=path.join(f.home,".local/share/mcp-workers/remote-control/programs");
    assert.deepEqual(readdirSync(programs),[]);
  }finally{f.cleanup();}
});
test("locked bootstrap stages once, reuses identical archive, and passes single authority to existing installer",()=>{
  const f=localBootstrapFixture();
  try{
    const locked={...f.opts,locked:true};
    const events=[];
    for(let n=0;n<2;n++){
      assert.equal(executeNodeBootstrap(locked,{home:f.home,
        stdin:{isTTY:true},stdout:{isTTY:true},
        invoke:(cmd,args,opts)=>{events.push({cmd,args,opts});return {status:0};}}),0);
    }
    assert.equal(events.length,2);
    assert.ok(events[0].cmd.endsWith("/bin/node"));
    assert.ok(events[0].args[0].endsWith("/scripts/install-v2.mjs"));
    assert.deepEqual(events[0].args.slice(1),["--endpoint",f.opts.endpoint]);
    assert.equal(events[0].opts.env.RC_V2_INSTALL_FLOCKED,"1");
    const programs=path.join(f.home,".local/share/mcp-workers/remote-control/programs");
    assert.deepEqual(readdirSync(programs),["v0.1.2-"+nativeTarget]);
  }finally{f.cleanup();}
});

test("only an explicit upgrade flag passes through the single existing flock and installer",()=>{
  const f=localBootstrapFixture();
  try{
    const upgraded={...f.opts,upgrade:true};
    const staged=path.join(f.home,"bootstrap.mjs");
    writeFileSync(staged,"safe local bootstrap",{mode:0o600});
    const invocations=[];
    assert.equal(executeNodeBootstrap(upgraded,{home:f.home,
      stdin:{isTTY:true},stdout:{isTTY:true},bootstrap:staged,
      invoke:(cmd,args,opts)=>{invocations.push({cmd,args,opts});return {status:0};}}),0);
    assert.ok(invocations[0].args.includes("--lock-held"));
    assert.deepEqual(invocations[0].args.slice(-2),["--lock-held","--upgrade"]);
    assert.equal(executeNodeBootstrap({...upgraded,locked:true},{home:f.home,
      stdin:{isTTY:true},stdout:{isTTY:true},
      invoke:(cmd,args,opts)=>{invocations.push({cmd,args,opts});return {status:0};}}),0);
    assert.deepEqual(invocations[1].args.slice(-3),["--endpoint",f.opts.endpoint,"--upgrade"]);
    assert.equal(invocations[1].opts.env.RC_V2_INSTALL_FLOCKED,"1");
  }finally{f.cleanup();}
});

test("orphaned partial stage cleanup is bounded to installer-owned paths",()=>{
  const f=localBootstrapFixture();
  try{
    const programs=ensurePrivatePrograms(f.home);
    const orphan=mkdtempSync(path.join(programs,".unverified-node-"));
    chmodSync(orphan,0o700);
    const bin=path.join(orphan,"bin");
    mkdirSync(bin,{mode:0o700});
    writeFileSync(path.join(bin,"node"),"PARTIAL",{mode:0o600});
    removeSafeOrphanStages(programs);
    assert.deepEqual(readdirSync(programs),[]);
    const foreign=mkdtempSync(path.join(programs,".unverified-node-"));
    chmodSync(foreign,0o700);
    symlinkSync("/etc/passwd",path.join(foreign,"bundle.json"));
    assert.throws(()=>removeSafeOrphanStages(programs),/Untrusted|orphan/);
    assert.ok(lstatSync(foreign).isDirectory());
    assert.ok(lstatSync(path.join(foreign,"bundle.json")).isSymbolicLink());
  }finally{f.cleanup();}
});
test("bad glibc or a world-readable download is refused before any Agent directory",()=>{
  const f=localBootstrapFixture();
  try{
    assert.throws(()=>prepareNodeBootstrap(f.opts,{home:f.home,
      runtimeLibc:"2.31"}),/glibc ABI/);
    assert.deepEqual(readdirSync(f.home),["verified-archive.tar.gz"]);
    chmodSync(f.archive,0o644);
    assert.throws(()=>prepareNodeBootstrap(f.opts,{home:f.home,
      runtimeLibc:"2.41"}),/owner-local path/);
    assert.deepEqual(readdirSync(f.home),["verified-archive.tar.gz"]);
  }finally{f.cleanup();}
});
test("failed installer activation preserves prior local keys and does not report success",()=>{
  const f=localBootstrapFixture();
  try{
    const marker=path.join(f.home,"unrelated-identity.keep");
    writeFileSync(marker,"KEEP",{mode:0o600});
    const opts={...f.opts,locked:true};
    assert.throws(()=>executeNodeBootstrap(opts,{home:f.home,
      stdin:{isTTY:true},stdout:{isTTY:true},
      invoke:()=>({status:1})}),/activation incomplete/);
    assert.equal(readFileSync(marker,"utf8"),"KEEP");
    assert.ok(readdirSync(path.join(f.home,".local/share/mcp-workers/remote-control/programs"))
      .includes("v0.1.2-"+nativeTarget));
  }finally{f.cleanup();}
});

test("explicit upgrade uses the exact new direct-service helper, not a three-service migration",()=>{
  const f=localBootstrapFixture();
  try{
    const unitDir=path.join(f.home,".config/systemd/user");
    mkdirSync(unitDir,{recursive:true});
    writeFileSync(path.join(unitDir,"remote-control-v2-agent.service"),"legacy", {mode:0o600});
    const calls=[];
    assert.equal(executeNodeBootstrap({...f.opts,locked:true,upgrade:true},{
      home:f.home,stdin:{isTTY:true},stdout:{isTTY:true},
      invoke:(cmd,args,env)=>{calls.push({cmd,args,env});return {status:0};}
    }),0);
    assert.equal(calls.length,1);
    assert.ok(calls[0].args[0].endsWith("/scripts/upgrade-existing-service.mjs"));
    assert.deepEqual(calls[0].args.slice(2),[f.opts.endpoint]);
    assert.ok(!calls[0].args.some(arg=>String(arg).includes("migrate")));
  }finally{f.cleanup();}
});
test("ordinary installation cannot duplicate an existing signed device as a second service",()=>{
  const f=localBootstrapFixture();
  try{
    const unitDir=path.join(f.home,".config/systemd/user");
    mkdirSync(unitDir,{recursive:true});
    writeFileSync(path.join(unitDir,"remote-control-v2-agent.service"),"legacy",{mode:0o600});
    let invoked=0;
    assert.throws(()=>executeNodeBootstrap({...f.opts,locked:true},{
      home:f.home,stdin:{isTTY:true},stdout:{isTTY:true},
      invoke:()=>{invoked++;return {status:0};}
    }),/requires explicit --upgrade/);
    assert.equal(invoked,0);
  }finally{f.cleanup();}
});
test("signed service discovery is independent of retired loopback and Tunnel units",()=>{
  const home=mkdtempSync(path.join(tmpdir(),"rca-signed-discovery-"));
  const unitDir=path.join(home,".config/systemd/user");
  mkdirSync(unitDir,{recursive:true});
  const signed=path.join(unitDir,"remote-control-v2-agent.service");
  const canonical=path.join(unitDir,"remote-control-agent.service");
  try{
    assert.equal(hasLegacySignedService(home),false);
    writeFileSync(signed,"test", {mode:0o600});
    assert.equal(hasLegacySignedService(home),true);
    writeFileSync(canonical,"other",{mode:0o600});
    assert.throws(()=>hasLegacySignedService(home),/Conflicting/);
    rmSync(canonical);
    rmSync(signed);
    symlinkSync("/etc/passwd",signed);
    assert.throws(()=>hasLegacySignedService(home),/Untrusted/);
  }finally{rmSync(home,{recursive:true,force:true});}
});
