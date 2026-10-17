/**
 * Strict immutable Release USTAR inspector for the bundled-Node bootstrap.
 * No Python, third-party tar package, runtime installation, or network side effects.
 *
 * This module is staged only on Draft PR #2; not part of immutable v0.1.1.
 */
import { createHash } from "node:crypto";
import { readFileSync, lstatSync, mkdtempSync, chmodSync, mkdirSync, openSync, writeSync, fsyncSync, fchmodSync, closeSync, renameSync, rmSync, readdirSync, constants } from "node:fs";
import { fileURLToPath } from "node:url";
import { gunzipSync } from "node:zlib";
import { join, dirname } from "node:path";

const APP="apps/remote-control-agent";
const DIRS=new Set(["bin","apps",APP,APP+"/src",APP+"/scripts",APP+"/.build"]);
const FILES=new Set([
  "bin/node","bundle.json",APP+"/package.json",
  APP+"/scripts/install-v2.mjs",APP+"/scripts/bootstrap-node.mjs",
  APP+"/scripts/manage-v2.mjs",APP+"/.build/session-supervisor",
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
    APP+"/scripts/install-v2.mjs",APP+"/src/v2-main.js"]){
    if(!records.has(required)||records.get(required).directory)throw Error("Required Node program missing");
  }
  let manifest;
  try{manifest=JSON.parse(records.get("bundle.json").data.toString("utf8"));}
  catch{throw Error("Invalid runtime manifest");}
  if(manifest.artifact_schema!==1||manifest.version!==tag||manifest.target!==target||
    !/^v24\.[0-9]+\.[0-9]+$/.test(manifest.node||"")||
    !/^[0-9]+\.[0-9]+$/.test(manifest.glibc_min||"")||
    manifest.device_protocol!==2||manifest.receipt_schema!==1||
    manifest.upgrade_profile!=="read-only-no-shell-v1")
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


// This first Draft only supplies the bounded archive inspector. Do not treat
// it as a runnable installer until secure staging, lifecycle and JS rca are
// implemented and exercised on both architectures. No success-shaped no-op.
if (process.argv[1] && process.argv[1] === fileURLToPath(import.meta.url)) {
  console.error("Python-free Agent installer is not enabled in this Draft build.");
  process.exitCode = 1;
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
