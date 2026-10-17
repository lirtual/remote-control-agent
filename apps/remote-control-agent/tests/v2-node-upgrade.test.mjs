import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import {
  validateManualUpgrade,prepareManualUpgrade,activateManualUpgrade
} from "../scripts/upgrade-v2.mjs";
import { runInteractiveLocalManager } from "../scripts/manage-v2.mjs";

const APP="apps/remote-control-agent";
const ID="ea3b5d4f-e35c-4425-84d1-fa16d25e2efe";
const ENDPOINT="https://remote-control-v2-preview.aiyaya.workers.dev/";
const tag="v0.1.3",commit="a".repeat(40);
const TARGET=process.arch==="arm64"?"linux-arm64-glibc":"linux-x64-glibc";
const MAIN="const caps = {readOnly: true, writeFile: false, shell: false,};\n";
const manifest=()=>({name:"remote-control-agent",artifact_schema:1,
  version:tag,target:TARGET,node:"v24.21.0",glibc_min:"2.34",
  device_protocol:2,receipt_schema:1,upgrade_profile:"read-only-no-shell-v1"});
function elf(){
  const b=Buffer.alloc(72);b.writeUInt32LE(0x464c457f,0);
  b[4]=2;b[5]=1;b.writeUInt16LE(process.arch==="arm64"?183:62,18);return b;
}
function fixture({newSource=MAIN}={}){
  const home=mkdtempSync(path.join(os.tmpdir(),"rca-upgrade-local-"));chmodSync(home,0o700);
  const programs=path.join(home,".local/share/mcp-workers/remote-control/programs");
  mkdirSync(programs,{recursive:true,mode:0o700});chmodSync(programs,0o700);
  const oldRoot=path.join(programs,"v0.1.2-"+TARGET);
  const oldSrc=path.join(oldRoot,APP,"src");
  mkdirSync(oldSrc,{recursive:true,mode:0o700});
  writeFileSync(path.join(oldSrc,"v2-main.js"),MAIN,{mode:0o600});
  const ids=path.join(home,".local/share/mcp-workers/remote-control/v2-identity.pem.device-id");
  writeFileSync(ids,ID,{mode:0o600});
  const receipt=path.join(home,".local/share/mcp-workers/remote-control/receipts.keep");
  writeFileSync(receipt,"PRESERVE_RECEIPT",{mode:0o600});
  const unit=[
    "# Managed by mcp-workers v2 Linux installer; NOT the v1 Agent.",
    "[Service]",
    "Environment=REMOTE_CONTROL_V2_ENDPOINT="+ENDPOINT,
    "WorkingDirectory="+path.join(oldRoot,APP),
    "ExecStart="+path.join(oldRoot,"bin/node")+" "+path.join(oldRoot,APP,"src/v2-main.js"),
    "",
  ].join("\n");
  const state={root:oldRoot,versions:[path.basename(oldRoot)],unit,
    ids:{permanent:ID},info:{version:"v0.1.2",target:TARGET}};
  const packageDir=path.join(home,"archive-fixture");
  const filePaths=[
    ["bin/node",elf(),0o700],
    ["bundle.json",JSON.stringify(manifest()),0o600],
    [APP+"/package.json",'{"type":"module"}\n',0o600],
    [APP+"/.build/session-supervisor",elf(),0o700],
    [APP+"/scripts/bootstrap-node.mjs","export const safe=true;\n",0o600],
    [APP+"/scripts/manage-v2.mjs","export const safe=true;\n",0o600],
    [APP+"/scripts/lifecycle-v2.mjs","export const safe=true;\n",0o600],
    [APP+"/scripts/upgrade-v2.mjs","export const safe=true;\n",0o600],
    [APP+"/scripts/verify-v2-release.mjs","export const safe=true;\n",0o600],
    [APP+"/scripts/rca.sh","#!/bin/sh\n",0o700],
    [APP+"/scripts/install-v2.mjs","export const safe=true;\n",0o600],
    [APP+"/src/v2-main.js",newSource,0o600],
  ];
  mkdirSync(packageDir,{mode:0o700});
  for(const [name,content,mode] of filePaths){
    const full=path.join(packageDir,name);
    mkdirSync(path.dirname(full),{recursive:true,mode:0o700});
    writeFileSync(full,content,{mode});chmodSync(full,mode);
  }
  const tar=spawnSync("tar",[
    "--format=ustar","--owner=0","--group=0","--numeric-owner",
    "--mode=u+rwX,go-rwx","-czf","-","bin","apps","bundle.json"
  ],{cwd:packageDir,timeout:10000,maxBuffer:1024*1024});
  assert.equal(tar.status,0,tar.stderr.toString());
  const archive=tar.stdout;
  const digest=createHash("sha256").update(archive).digest("hex");
  const release=Object.freeze({tag,commit,target:TARGET,digest});
  return {home,programs,oldRoot,state,ids,receipt,archive,digest,release};
}
const cleanup=f=>rmSync(f.home,{recursive:true,force:true});

test("retrying rca upgrade recovers an interrupted unit before inventory and release validation",async()=>{
  const calls=[];
  const home="/tmp/rca-recovery-order-test";
  const stdout={isTTY:true,write:()=>{}};
  const stdin={isTTY:true};
  const state={unit:"owned-unit",root:"old-root",info:{version:"v0.1.2"},ids:{permanent:ID}};
  const prepared={version:tag,program:"new-root"};
  const result=await runInteractiveLocalManager(["upgrade",tag,commit],{
    home,stdin,stdout,
    recoverInterruptedUpgrade:async options=>{calls.push("recover");assert.equal(options.home,home);},
    inventory:()=>{calls.push("inventory");return state;},
    prepareUpgrade:async()=>{calls.push("prepare");return prepared;},
    activateUpgrade:()=>{calls.push("activate");return prepared;},
  });
  assert.equal(result,0);
  assert.deepEqual(calls,["recover","inventory","prepare","activate"]);
});

test("preflight accepts explicit newer release and unchanged Worker endpoint",()=>{
  const f=fixture();
  try{
    const p=validateManualUpgrade(f.state,{home:f.home,tag,commit});
    assert.equal(p.targetDir,path.join(f.programs,tag+"-"+TARGET));
    assert.equal(p.endpoint,ENDPOINT);
    assert.equal(readFileSync(f.ids,"utf8"),ID);
  }finally{cleanup(f);}
});
test("preflight rejects downgrades, unreviewed release and Shell-enabled old agent",()=>{
  const f=fixture();
  try{
    for(const [t,c] of [["v0.1.2",commit],["v0.1.0",commit],["v0.1.3","z".repeat(40)],["latest",commit]]){
      assert.throws(()=>validateManualUpgrade(f.state,{home:f.home,tag:t,commit:c}));
    }
    writeFileSync(path.join(f.oldRoot,APP,"src/v2-main.js"),
      "const c={readOnly: true, writeFile: false, shell: true,};\n");
    assert.throws(()=>validateManualUpgrade(f.state,{home:f.home,tag,commit}),/mutable or Shell/);
  }finally{cleanup(f);}
});
test("verified immutable release stage is private, preserves old identity and receipts",async()=>{
  const f=fixture();
  try{
    const result=await prepareManualUpgrade(f.state,{tag,commit},{
      home:f.home,resolve:async()=>f.release,download:async()=>f.archive
    });
    assert.equal(result.program,path.join(f.programs,tag+"-"+TARGET));
    assert.equal(readFileSync(f.ids,"utf8"),ID);
    assert.equal(readFileSync(f.receipt,"utf8"),"PRESERVE_RECEIPT");
    assert.equal(readFileSync(path.join(f.oldRoot,APP,"src/v2-main.js"),"utf8"),MAIN);
    const calls=[];
    const activation=activateManualUpgrade(result,{invoke:(bin,args,options)=>{
      calls.push({bin,args,options});return {status:0};
    }});
    assert.equal(activation.version,tag);
    assert.equal(calls[0].bin,path.join(result.program,"bin/node"));
    assert.deepEqual(calls[0].args,[
      path.join(result.program,APP,"scripts/install-v2.mjs"),
      "--upgrade","--endpoint",ENDPOINT
    ]);
    assert.equal(calls[0].options.env.RC_AGENT_NO_POST_START,"1");
    assert.equal(readFileSync(f.receipt,"utf8"),"PRESERVE_RECEIPT");
  }finally{cleanup(f);}
});
test("wrong Release mapping or digest cannot create a new staged version",async()=>{
  const f=fixture();
  try{
    const versions=()=>readFileSync(f.receipt,"utf8");
    await assert.rejects(prepareManualUpgrade(f.state,{tag,commit},{
      home:f.home,resolve:async()=>({...f.release,commit:"b".repeat(40)}),
      download:async()=>f.archive
    }),/Release pin mismatch/);
    await assert.rejects(prepareManualUpgrade(f.state,{tag,commit},{
      home:f.home,resolve:async()=>({...f.release,digest:"0".repeat(64)}),
      download:async()=>f.archive
    }),/SHA mismatch/);
    assert.equal(versions(),"PRESERVE_RECEIPT");
    assert.equal(readFileSync(f.ids,"utf8"),ID);
  }finally{cleanup(f);}
});
test("new mutable agent is refused before any activation",async()=>{
  const f=fixture({newSource:"const c={readOnly: true, writeFile: false, shell: true,};\n"});
  try{
    await assert.rejects(prepareManualUpgrade(f.state,{tag,commit},{
      home:f.home,resolve:async()=>f.release,download:async()=>f.archive
    }),/Unproven Shell ownership/);
    assert.equal(readFileSync(f.ids,"utf8"),ID);
  }finally{cleanup(f);}
});
test("service activation rejection propagates without touching keys or receipt",async()=>{
  const f=fixture();
  try{
    const result=await prepareManualUpgrade(f.state,{tag,commit},{
      home:f.home,resolve:async()=>f.release,download:async()=>f.archive
    });
    assert.throws(()=>activateManualUpgrade(result,{invoke:()=>({status:1})}),
      /upgrade failed/);
    assert.equal(readFileSync(f.ids,"utf8"),ID);
    assert.equal(readFileSync(f.receipt,"utf8"),"PRESERVE_RECEIPT");
  }finally{cleanup(f);}
});
