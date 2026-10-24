import test from "node:test";
import assert from "node:assert/strict";
import {createHash,randomBytes} from "node:crypto";
import {spawnSync} from "node:child_process";
import {mkdtempSync,mkdirSync,writeFileSync,readFileSync,rmSync,unlinkSync} from "node:fs";
import path from "node:path";
import os from "node:os";
import {comparePinnedWindowsZipToInstalled} from "../src/upgrade-windows-zip-provenance.ts";

const windows=process.platform==="win32"&&process.arch==="x64"?test:test.skip;
function runPS(script:string):void {
 const exe=path.win32.join(process.env.SystemRoot!,"System32","WindowsPowerShell","v1.0","powershell.exe");
 const result=spawnSync(exe,["-NoProfile","-NonInteractive","-EncodedCommand",
   Buffer.from(script,"utf16le").toString("base64")],
   {encoding:"utf8",timeout:20000,windowsHide:true});
 assert.equal(result.status,0,result.stderr||result.stdout);
}
function fixture() {
 const base=mkdtempSync(path.join(os.tmpdir(),"rca-zip-proof-"));
 const installed=path.join(base,"programs","v0.1.23-windows-x64");
 const archive=path.join(base,"candidate.zip");
 for(let i=0;i<10;i++) {
  const parent=i%2===0?"bin":"apps/remote-control-agent/src";
  const file=path.join(installed,parent,"member"+i+".bin");
  mkdirSync(path.dirname(file),{recursive:true});
  writeFileSync(file,i===0?randomBytes(130000):Buffer.from("member"+i));
 }
 const ps="Add-Type -AssemblyName System.IO.Compression.FileSystem;"+
  "[IO.Compression.ZipFile]::CreateFromDirectory('"+
  installed.replace(/'/g,"''")+"','"+archive.replace(/'/g,"''")+"')";
 runPS(ps);
 const sha=createHash("sha256").update(readFileSync(archive)).digest("hex");
 assert.ok(readFileSync(archive).length>=100000);
 return {base,installed,archive,sha,close:()=>rmSync(base,{recursive:true,force:true})};
}
windows("approved Windows ZIP is compared byte-for-byte against every installed member",()=>{
 const f=fixture();
 try{
  const proof=comparePinnedWindowsZipToInstalled(f.archive,f.installed,f.sha);
  assert.equal(proof.memberCount,10);
  assert.equal(proof.approvedSha256,f.sha);
 }finally{f.close();}
});
windows("modified, missing, and extra installed Windows program members are refused",()=>{
 const f=fixture();
 try{
  const member=path.join(f.installed,"bin","member0.bin");
  const original=readFileSync(member);
  writeFileSync(member,"changed");
  assert.throws(()=>comparePinnedWindowsZipToInstalled(f.archive,f.installed,f.sha),/differs/);
  writeFileSync(member,original);
  writeFileSync(path.join(f.installed,"bin","extra.bin"),"extra");
  assert.throws(()=>comparePinnedWindowsZipToInstalled(f.archive,f.installed,f.sha),/differs/);
  unlinkSync(path.join(f.installed,"bin","extra.bin"));
  unlinkSync(member);
  assert.throws(()=>comparePinnedWindowsZipToInstalled(f.archive,f.installed,f.sha),/Missing/);
 }finally{f.close();}
});
windows("mismatched SHA-256 and altered ZIP bytes cannot pass verification",()=>{
 const f=fixture();
 try{
  assert.throws(()=>comparePinnedWindowsZipToInstalled(f.archive,f.installed,"f".repeat(64)),/SHA-256 mismatch/);
  const bad=readFileSync(f.archive);bad[bad.length-1]^=1;writeFileSync(f.archive,bad);
  assert.throws(()=>comparePinnedWindowsZipToInstalled(f.archive,f.installed,f.sha),/SHA-256 mismatch/);
 }finally{f.close();}
});
test("non-Windows cannot assert Windows ZIP provenance",()=>{
 if(process.platform==="win32")return;
 assert.throws(()=>comparePinnedWindowsZipToInstalled("/tmp/no.zip","/tmp/nonexistent","a".repeat(64)),/Unsupported/);
});
