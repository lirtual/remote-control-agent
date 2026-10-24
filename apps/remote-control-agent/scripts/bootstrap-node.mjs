/**
 * Strict immutable Release USTAR inspector for the bundled-Node bootstrap.
 * No Python, third-party tar package, runtime installation, or network side effects.
 *
 * This module is staged only on Draft PR #2; not part of immutable v0.1.1.
 */
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import os from "node:os";
import { readFileSync, lstatSync, mkdtempSync, chmodSync, mkdirSync, openSync, writeSync, fsyncSync, fchmodSync, closeSync, renameSync, rmSync, readdirSync, constants } from "node:fs";
import { fileURLToPath } from "node:url";
import { gunzipSync } from "node:zlib";
import { join, dirname, isAbsolute, normalize } from "node:path";

const APP="apps/remote-control-agent";
const DIRS=new Set(["bin","apps",APP,APP+"/src",APP+"/scripts",APP+"/.build"]);
const FILES=new Set([
  "bin/node","bundle.json",APP+"/package.json",
  APP+"/scripts/install-v2.mjs",APP+"/scripts/bootstrap-node.mjs",
  APP+"/scripts/manage-v2.mjs",APP+"/scripts/lifecycle-v2.mjs",
  APP+"/scripts/upgrade-v2.mjs",APP+"/scripts/upgrade-existing-service.mjs",APP+"/scripts/verify-v2-release.mjs",
  APP+"/scripts/rca.sh",APP+"/.build/session-supervisor",
]);
const MAX_ARCHIVE=180*1024*1024, MAX_UNCOMPRESSED=240*1024*1024, MAX_FILES=80;
const SHA=/^[a-f0-9]{64}$/;
const TAG=/^v[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9.-]+)?$/;

function numeric(header,offset,length){
  const raw=header.subarray(offset,offset+length).toString("ascii");
  if(!/^[ 0-7]*\0* *$/.test(raw))throw Error("Untrusted tar number");
  const trimmed=raw.replace(/\0.*$/,"").trim();
  return trimmed?parseInt(trimmed,8):0;
}
function field(header,offset,length){
  const b=header.subarray(offset,offset+length);
  const end=b.indexOf(0);
  const used=end<0?b:b.subarray(0,end);
  const name=used.toString("ascii");
  if(!Buffer.from(name,"ascii").equals(used))throw Error("Untrusted tar pathname encoding");
  return name;
}
function checkedName(raw,directory){
  const name=directory&&raw.endsWith("/")?raw.slice(0,-1):raw;
  if(!name||name.length>160||name.startsWith("/")||name.includes("\\")||
      name.split("/").some(p=>!p||p==="."||p==="..")||
      !/^[A-Za-z0-9._/-]+$/.test(name))throw Error("Unsafe tar path");
  if(directory){
    if(!DIRS.has(name))throw Error("Unexpected directory");
  }else if(!FILES.has(name)&&!new RegExp("^"+APP+"/src/[a-z0-9-]+\\.js$").test(name)){
    throw Error("Unexpected program file");
  }
  return name;
}
export function inspectPinnedArchiveBytes(bytes,{expectedSha256,tag,target}){
  if(!SHA.test(expectedSha256)||!TAG.test(tag)||
      !["linux-x64-glibc","linux-arm64-glibc"].includes(target)||
      bytes.length<128||bytes.length>MAX_ARCHIVE)throw Error("Untrusted release parameters");
  if(createHash("sha256").update(bytes).digest("hex")!==expectedSha256)
    throw Error("Immutable archive SHA mismatch");
  const tar=gunzipSync(bytes,{maxOutputLength:MAX_UNCOMPRESSED});
  const records=new Map();
  let offset=0,total=0,ended=false;
  while(offset+512<=tar.length){
    const header=tar.subarray(offset,offset+512);offset+=512;
    if(header.every(b=>b===0)){ended=true;break;}
    const checksum=numeric(header,148,8);
    let computed=0;
    for(let j=0;j<512;j++)computed+=(j>=148&&j<156)?32:header[j];
    if(checksum!==computed)throw Error("Tar header checksum mismatch");
    const type=header[156];
    if(type!==0&&type!==48&&type!==53)throw Error("Archive contains link, PAX or special type");
    if(field(header,157,100))throw Error("Archive contains a link target");
    if(field(header,345,155))throw Error("Archive uses unexpected USTAR prefix");
    if(field(header,257,6)!=="ustar")throw Error("Archive must be canonical USTAR");
    const isDir=type===53;
    const rawName=field(header,0,100);
    const name=checkedName(rawName,isDir);
    if(records.size>=MAX_FILES||records.has(name))throw Error("Too many or duplicate tar entries");
    const size=numeric(header,124,12);
    const mode=numeric(header,100,8)&0o777;
    if((isDir&&size!==0)||(!isDir&&size<0)||
       (isDir&&mode!==0o700)||
       (!isDir&&mode!==0o600&&mode!==0o700))throw Error("Invalid tar entry size or mode");
    total+=size;if(total>MAX_UNCOMPRESSED||offset+size>tar.length)
      throw Error("Archive member is oversized or truncated");
    const body=tar.subarray(offset,offset+size);
    records.set(name,{directory:isDir,data:body,mode});
    offset+=Math.ceil(size/512)*512;
  }
  if(!ended||tar.subarray(offset).some(b=>b!==0))throw Error("Unexpected tar trailer");
  for(const required of ["bin/node","bundle.json",APP+"/.build/session-supervisor",
    APP+"/scripts/bootstrap-node.mjs",APP+"/scripts/manage-v2.mjs",
    APP+"/scripts/install-v2.mjs",APP+"/scripts/lifecycle-v2.mjs",
    APP+"/scripts/upgrade-v2.mjs",APP+"/scripts/verify-v2-release.mjs",
    APP+"/scripts/rca.sh",APP+"/src/v2-main.js"]){
    if(!records.has(required)||records.get(required).directory)throw Error("Required Node program missing");
  }
  let manifest;
  try{manifest=JSON.parse(records.get("bundle.json").data.toString("utf8"));}
  catch{throw Error("Invalid runtime manifest");}
  if(manifest.artifact_schema!==1||manifest.version!==tag||manifest.target!==target||
    !/^v24\.[0-9]+\.[0-9]+$/.test(manifest.node||"")||
    !/^[0-9]+\.[0-9]+$/.test(manifest.glibc_min||"")||
    manifest.device_protocol!==2||manifest.receipt_schema!==1||
    !["read-only-no-shell-v1","paired-full-v1"].includes(manifest.upgrade_profile))
    throw Error("Unsupported Agent manifest / ABI / protocol");
  const elfMachine=target==="linux-x64-glibc"?62:183;
  for(const entry of ["bin/node",APP+"/.build/session-supervisor"]){
    const elf=records.get(entry).data;
    if(elf.length<64||elf.subarray(0,4).toString("hex")!=="7f454c46"||
      elf[4]!==2||elf[5]!==1||elf.readUInt16LE(18)!==elfMachine)
      throw Error("Untrusted bundled ELF architecture");
  }
  return {records,manifest};
}
export function inspectPinnedArchiveFile(filename,expected){
  const st=lstatSync(filename);
  if(!st.isFile()||st.isSymbolicLink()||st.uid!==process.getuid()||
     (st.mode&0o077)!==0||st.size>MAX_ARCHIVE)
    throw Error("Untrusted downloaded archive path");
  return inspectPinnedArchiveBytes(readFileSync(filename),expected);
}



/**
 * Atomically promote an already verified archive into a private versioned
 * program directory. Does not write identity, systemd, or operation receipts.
 * Caller is responsible for holding the existing per-user installer flock.
 */
function pathPresentNoFollow(filename){
  try{ lstatSync(filename);return true; }
  catch(error){ if(error.code==="ENOENT")return false;throw error; }
}
export function stagePinnedProgram(bytes,expected,parent,versionName){
  const {records}=inspectPinnedArchiveBytes(bytes,expected);
  if(versionName!==expected.tag+"-"+expected.target)
    throw Error("Versioned destination mismatch");
  const parentInfo=lstatSync(parent);
  if(!parentInfo.isDirectory()||parentInfo.isSymbolicLink()||
     parentInfo.uid!==process.getuid()||(parentInfo.mode&0o077)!==0)
    throw Error("Untrusted private installation parent");
  const destination=join(parent,versionName);
  if(pathPresentNoFollow(destination))throw Error("Installed program already exists; refuse replacement");
  const stage=mkdtempSync(join(parent,".unverified-node-"));
  let promoted=false;
  try{
    chmodSync(stage,0o700);
    for(const [name,entry] of records){
      const target=join(stage,...name.split("/"));
      if(entry.directory){
        mkdirSync(target,{recursive:true,mode:0o700});
        chmodSync(target,0o700);
      }else{
        mkdirSync(dirname(target),{recursive:true,mode:0o700});
        const fd=openSync(target,constants.O_WRONLY|constants.O_CREAT|constants.O_EXCL|constants.O_NOFOLLOW,entry.mode);
        try{
          let written=0;
          while(written<entry.data.length){
            const n=writeSync(fd,entry.data,written,entry.data.length-written);
            if(n<=0)throw Error("Incomplete program file write");
            written+=n;
          }
          fsyncSync(fd);
          fchmodSync(fd,entry.mode);
        }finally{closeSync(fd);}
      }
    }
    if(pathPresentNoFollow(destination))throw Error("Version installed while staging");
    renameSync(stage,destination);
    promoted=true;
    return destination;
  }finally{
    if(!promoted)rmSync(stage,{recursive:true,force:true});
  }
}

/** Repeat-install may reuse only an exact, owner-protected release tree.
 * Any extra file (including __pycache__), missing file, modified bytes,
 * hardlink, symlink, or permissions drift is refused with no mutation.
 */
export function verifyExistingPinnedProgram(bytes,expected,parent,versionName){
  const {records}=inspectPinnedArchiveBytes(bytes,expected);
  if(versionName!==expected.tag+"-"+expected.target)
    throw Error("Versioned destination mismatch");
  const parentInfo=lstatSync(parent);
  if(!parentInfo.isDirectory()||parentInfo.isSymbolicLink()||
     parentInfo.uid!==process.getuid()||(parentInfo.mode&0o077)!==0)
    throw Error("Untrusted private installation parent");
  const root=join(parent,versionName);
  const rootInfo=lstatSync(root);
  if(!rootInfo.isDirectory()||rootInfo.isSymbolicLink()||
    rootInfo.uid!==process.getuid()||(rootInfo.mode&0o077)!==0)
    throw Error("Untrusted installed version root");
  const actual=new Set();
  function walk(dir,rel=""){
    for(const de of readdirSync(dir,{withFileTypes:true})){
      const member=rel?rel+"/"+de.name:de.name;
      const full=join(dir,de.name);
      const meta=lstatSync(full);
      if(meta.uid!==process.getuid()||(meta.mode&0o077)!==0 ||
          (meta.nlink!==1&&!meta.isDirectory())||
          (!meta.isDirectory()&&!meta.isFile()) ||
          meta.isSymbolicLink())throw Error("Unexpected installed program entry");
      const record=records.get(member);
      if(!record||record.directory!==meta.isDirectory()||
          (meta.mode&0o777)!==record.mode)
        throw Error("Installed program differs from verified archive");
      if(meta.isFile() &&
        !readFileSync(full).equals(record.data))
        throw Error("Modified installed program file");
      actual.add(member);
      if(meta.isDirectory())walk(full,member);
    }
  }
  walk(root);
  if(actual.size!==records.size ||
    [...records.keys()].some(member=>!actual.has(member)))
    throw Error("Missing installed program file");
  return root;
}
export function stageOrVerifyPinnedProgram(bytes,expected,parent,versionName){
  const destination=join(parent,versionName);
  return pathPresentNoFollow(destination)
    ?verifyExistingPinnedProgram(bytes,expected,parent,versionName)
    :stagePinnedProgram(bytes,expected,parent,versionName);
}

/** Preserve an existing signed-WSS service name during direct upgrades.
 * Reject collisions and links; exact template validation happens in the
 * offline-staged upgrader before it touches systemd.
 */
export function hasLegacySignedService(home){
  const dir=join(home,".config/systemd/user");
  const old=join(dir,"remote-control-v2-agent.service");
  let stat;
  try{stat=lstatSync(old);}
  catch(e){if(e.code==="ENOENT")return false;throw e;}
  if(!stat.isFile()||stat.isSymbolicLink()||stat.uid!==process.getuid()||
    (stat.mode&0o777)!==0o600)throw Error("Untrusted installed signed service");
  const canonical=join(dir,"remote-control-agent.service");
  try{lstatSync(canonical);throw Error("Conflicting canonical Agent service");}
  catch(e){if(e.code!=="ENOENT")throw e;}
  return true;
}

/** Immutable Worker-origin CLI handoff. Never mutates identity itself. */
export function parseNodeBootstrapArgs(args){
  const result={locked:false,upgrade:false};
  const flags=new Set(["--archive","--tag","--commit","--sha256","--endpoint"]);
  for(let i=0;i<args.length;i++){
    const flag=args[i];
    if(flag==="--lock-held"){
      if(result.locked)throw Error("Duplicate lock marker");
      result.locked=true;continue;
    }
    if(flag==="--upgrade"){
      if(result.upgrade)throw Error("Duplicate explicit upgrade mode");
      result.upgrade=true;continue;
    }
    if(!flags.has(flag)||!args[i+1]||result[flag.slice(2)]!==undefined)
      throw Error("Missing or duplicate immutable installer parameter");
    result[flag.slice(2)]=args[++i];
  }
  const {archive,tag,commit,sha256,endpoint}=result;
  if(!isAbsolute(archive||"")||!TAG.test(tag||"")||
      !/^[a-f0-9]{40}$/.test(commit||"")||!SHA.test(sha256||""))
    throw Error("Untrusted Release pins");
  const u=new URL(endpoint);
  if(u.protocol!=="https:"||u.username||u.password||u.search||u.hash||
      u.pathname!=="/"||u.port||u.origin+"/"!==endpoint||
      !/^[a-z0-9.-]+$/i.test(u.hostname))
    throw Error("Untrusted Worker origin");
  const target=process.platform==="linux" ?
    (process.arch==="x64"?"linux-x64-glibc":
      process.arch==="arm64"?"linux-arm64-glibc":null):null;
  if(!target||process.getuid()===0)throw Error("Unsupported host or root user");
  return Object.freeze({archive,tag,commit,sha256,endpoint,target,locked:result.locked,upgrade:result.upgrade});
}
function verifyOwnedPath(p,{directory=false,relaxed=false}={}){
  const st=lstatSync(p);
  if(st.uid!==process.getuid()||st.isSymbolicLink()||
    (directory?!st.isDirectory():!st.isFile())||
    (st.mode&(relaxed?0o022:0o077))!==0||
    (!directory&&st.nlink!==1))
    throw Error("Untrusted owner-local path");
  return st;
}
export function ensurePrivatePrograms(home){
  if(!isAbsolute(home)||normalize(home)!==home)throw Error("Invalid HOME");
  verifyOwnedPath(home,{directory:true,relaxed:true});
  const parts=[
    [".local",true],[".local/share",true],
    [".local/share/mcp-workers",false],
    [".local/share/mcp-workers/remote-control",false],
    [".local/share/mcp-workers/remote-control/programs",false]
  ];
  for(const [relative,relaxed] of parts){
    const next=join(home,relative);
    try{mkdirSync(next,{mode:0o700});}
    catch(e){if(e.code!=="EEXIST")throw e;}
    verifyOwnedPath(next,{directory:true,relaxed});
  }
  return join(home,".local/share/mcp-workers/remote-control/programs");
}
function supportedGlibc(actual,minimum){
  if(!/^\d+\.\d+$/.test(actual||"")||!/^\d+\.\d+$/.test(minimum||""))
    return false;
  const [am,an]=actual.split(".").map(Number);
  const [bm,bn]=minimum.split(".").map(Number);
  return am>bm||(am===bm&&an>=bn);
}
function validateOrphan(directory,relative="",counter={n:0}){
  for(const name of readdirSync(directory)){
    if(++counter.n>MAX_FILES)throw Error("Untrusted orphan stage size");
    const member=relative?relative+"/"+name:name;
    const full=join(directory,name);
    const st=lstatSync(full);
    verifyOwnedPath(full,{directory:st.isDirectory()});
    if(st.isDirectory()){
      if(!DIRS.has(member))throw Error("Foreign orphan directory");
      validateOrphan(full,member,counter);
    }else checkedName(member,false);
  }
}
export function removeSafeOrphanStages(programs){
  verifyOwnedPath(programs,{directory:true});
  for(const name of readdirSync(programs)){
    if(!/^\.unverified-node-[A-Za-z0-9]{6}$/.test(name))continue;
    const p=join(programs,name);
    verifyOwnedPath(p,{directory:true});
    validateOrphan(p);
    rmSync(p,{recursive:true,force:false,maxRetries:0});
  }
}

export function prepareNodeBootstrap(options,{
  home=os.homedir(),
  runtimeLibc=process.report?.getReport?.().header?.glibcVersionRuntime,
}={}){
  const meta=verifyOwnedPath(options.archive);
  if(meta.size<128||meta.size>MAX_ARCHIVE)
    throw Error("Untrusted downloaded Agent archive");
  const expected={tag:options.tag,target:options.target,
    expectedSha256:options.sha256};
  const bytes=readFileSync(options.archive);
  const {manifest}=inspectPinnedArchiveBytes(bytes,expected);
  if(!supportedGlibc(runtimeLibc,manifest.glibc_min))
    throw Error("Bundled Agent glibc ABI is unsupported");
  const programs=ensurePrivatePrograms(home);
  if(!options.locked)return {programs,expected};
  removeSafeOrphanStages(programs);
  const version=options.tag+"-"+options.target;
  const root=stageOrVerifyPinnedProgram(bytes,expected,programs,version);
  const bin=join(root,"bin/node");
  const install=join(root,APP,"scripts/install-v2.mjs");
  const shim=join(root,APP,"scripts/rca.sh");
  for(const [p,mode] of [[bin,0o700],[install,0o600],[shim,0o700]]){
    const stat=verifyOwnedPath(p);
    if((stat.mode&0o777)!==mode)throw Error("Untrusted installed Agent mode");
  }
  return {programs,expected,root,bin,install};
}
export function executeNodeBootstrap(options,{
  home=os.homedir(),invoke=spawnSync,
  stdin=process.stdin,stdout=process.stdout,
  bootstrap=fileURLToPath(import.meta.url),
}={}){
  if(!stdin.isTTY||!stdout.isTTY)
    throw Error("Owner-approved pairing requires a real local terminal");
  const prepared=prepareNodeBootstrap(options,{home});
  if(!options.locked){
    verifyOwnedPath(bootstrap);
    const lock=join(dirname(prepared.programs),"v2-installer.lock");
    try{
      const fd=openSync(lock,constants.O_WRONLY|constants.O_CREAT|
        constants.O_EXCL|constants.O_NOFOLLOW,0o600);
      closeSync(fd);
    }catch(e){if(e.code!=="EEXIST")throw e;}
    if((verifyOwnedPath(lock).mode&0o777)!==0o600)
      throw Error("Untrusted Agent installer lock");
    const processResult=invoke("flock",[
      "-n","-E","75","-F",lock,process.execPath,bootstrap,
      "--archive",options.archive,"--tag",options.tag,
      "--commit",options.commit,"--sha256",options.sha256,
      "--endpoint",options.endpoint,"--lock-held",
      ...(options.upgrade?["--upgrade"]:[])
    ],{stdio:"inherit",env:{...process.env,NODE_OPTIONS:"",NODE_PATH:""}});
    if(processResult.error||processResult.signal||processResult.status!==0)
      throw Error("Exclusive Agent installation could not complete");
    return 0;
  }
  // Existing signed WSS Agents upgrade in place; never require the retired
  // loopback/Tunnel pair or a second, migration-specific confirmation.
  const existingSigned=hasLegacySignedService(home);
  if(existingSigned && !options.upgrade)
    throw Error("Installed signed Agent requires explicit --upgrade");
  if(existingSigned){
    const upgrader=join(prepared.root,APP,"scripts/upgrade-existing-service.mjs");
    verifyOwnedPath(upgrader);
    const changed=invoke(prepared.bin,[upgrader,prepared.root,options.endpoint],{
      stdio:"inherit",env:{...process.env,NODE_OPTIONS:"",NODE_PATH:""},
    });
    if(changed.error||changed.signal||changed.status!==0)
      throw Error("Reviewed direct Agent upgrade failed; existing identity retained");
    return 0;
  }
  // install-v2.mjs handles the existing lifetime selection, owner challenge,
  // permission gates, signed device registration and systemd rollback.
  // RC_V2_INSTALL_FLOCKED prevents relocking the SAME already-held kernel flock.
  const child=invoke(prepared.bin,[prepared.install,
    "--endpoint",options.endpoint,...(options.upgrade?["--upgrade"]:[])],{stdio:"inherit",env:{
    ...process.env,RC_V2_INSTALL_FLOCKED:"1",RC_AGENT_NO_POST_START:"1",
    NODE_OPTIONS:"",NODE_PATH:"",
  }});
  if(child.error||child.signal||child.status!==0)
    throw Error("Local pairing or service activation incomplete; identity preserved");
  return 0;
}
if(process.argv[1]===fileURLToPath(import.meta.url)){
  try{
    process.exitCode=executeNodeBootstrap(
      parseNodeBootstrapArgs(process.argv.slice(2)));
  }catch{
    console.error("Pinned Node installation refused; prior identity retained.");
    process.exitCode=1;
  }
}
