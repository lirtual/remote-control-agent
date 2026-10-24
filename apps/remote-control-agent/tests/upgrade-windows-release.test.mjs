import test from "node:test";
import assert from "node:assert/strict";
import {createHash} from "node:crypto";
import {fetchApprovedWindowsRelease} from "../scripts/verify-windows-release.mjs";
import {resolvePinnedRelease,releaseAssetName} from "../scripts/verify-v2-release.mjs";

const tag="v0.1.23",commit="a".repeat(40),api="https://api.github.com/repos/lirtual/remote-control-agent";
const content=Buffer.alloc(110_000,0x5b);
const digest=createHash("sha256").update(content).digest("hex");
const assetName="remote-control-agent-"+tag+"-windows-x64.zip";
const context={tag,commit,sha256:digest};
function server({immutable=true,actualCommit=commit,assetDigest=digest,actualContent=content,
  changedUrl=false,duplicate=false,redirectUrl=null,assetSize=content.length}={}) {
 const seen=[];
 async function send(url,options){
   seen.push({url,options});
   if(url===api+"/releases/tags/"+tag) return Response.json({
     id:77,immutable,draft:false,tag_name:tag,assets:[
       {name:assetName,id:903,state:"uploaded",size:assetSize,digest:"sha256:"+assetDigest,
        url:changedUrl?"https://attacker.example/zip":api+"/releases/assets/903"},
       ...(duplicate?[{name:assetName,id:904,state:"uploaded",size:assetSize,digest:"sha256:"+assetDigest,
         url:api+"/releases/assets/904"}]:[]),
     ],
   });
   if(url===api+"/git/ref/tags/"+tag)
     return Response.json({ref:"refs/tags/"+tag,object:{type:"commit",sha:actualCommit}});
   if(url===api+"/releases/assets/903") {
     if(redirectUrl) return new Response(null,{status:302,headers:{location:redirectUrl}});
     return new Response(actualContent,{status:200,headers:{"content-type":"application/octet-stream"}});
   }
   if(url.startsWith("https://release-assets.githubusercontent.com/"))
     return new Response(actualContent,{status:200,headers:{"content-type":"application/octet-stream"}});
   throw Error("Unreviewed GitHub API access: "+url);
 }
 return {send,seen};
}
test("Windows pinned ZIP asset name uses shared canonical immutable Release resolver",async()=>{
 assert.equal(releaseAssetName(tag,"windows-x64"),assetName);
 const {send,seen}=server();
 const pinned=await resolvePinnedRelease({tag,commit,target:"windows-x64",send});
 assert.equal(pinned.name,assetName);
 assert.equal(pinned.digest,digest);
 const output=await fetchApprovedWindowsRelease({...context,send});
 assert.deepEqual(output.archive,content);
 assert.equal(output.commit,commit);
 assert.equal(output.sha256,digest);
 assert.ok(seen.every(call=>call.options.redirect==="manual"));
});
test("rejects local or unreviewed target inputs before any network",async()=>{
 const {send,seen}=server();
 for(const inputs of [
  {...context,tag:"latest"},
  {...context,tag:"v0.1.23-rc.1"},
  {...context,commit:"b".repeat(39)},
  {...context,sha256:"b".repeat(63)},
 ])await assert.rejects(fetchApprovedWindowsRelease({...inputs,send}),/Stable approved/);
 assert.equal(seen.length,0);
});
test("mutable or duplicate Release metadata, different Git commit, and altered asset source are denied",async()=>{
 for(const fail of [{immutable:false},{actualCommit:"b".repeat(40)},
   {changedUrl:true},{duplicate:true},{assetSize:100}]){
   await assert.rejects(fetchApprovedWindowsRelease({...context,send:server(fail).send}));
 }
});
test("untrusted digest and tampered returned Windows ZIP cannot be accepted",async()=>{
 await assert.rejects(fetchApprovedWindowsRelease({
   ...context,sha256:"d".repeat(64),send:server().send,
 }),/differs/);
 await assert.rejects(fetchApprovedWindowsRelease({
   ...context,send:server({actualContent:Buffer.alloc(content.length,0x41)}).send,
 }),/digest mismatch/);
});
test("rejects private HTTP redirect but permits an approved GitHub asset host",async()=>{
 await assert.rejects(fetchApprovedWindowsRelease({
   ...context,send:server({redirectUrl:"http://127.0.0.1/metadata"}).send,
 }),/outside GitHub HTTPS/);
 const result=await fetchApprovedWindowsRelease({
   ...context,send:server({redirectUrl:"https://release-assets.githubusercontent.com/approved"}).send,
 });
 assert.equal(result.archive.length,content.length);
});
