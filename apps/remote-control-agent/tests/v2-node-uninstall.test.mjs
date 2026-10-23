import assert from "node:assert/strict";
import { test } from "node:test";
import { chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync,
  readlinkSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { renderV2Service } from "../scripts/install-v2.mjs";
import { executeLocalUninstall, planLocalUninstall, noOwnedAgentProcesses }
  from "../scripts/lifecycle-v2.mjs";

const DEVICE="ea3b5d4f-e35c-4425-84d1-fa16d25e2efe";
const APP="apps/remote-control-agent";
const VERSION="v0.1.2-linux-x64-glibc";
function testFixture({withUnit=true,withLauncher=true,profile="read-only-no-shell-v1"}={}){
  const home=mkdtempSync(path.join(tmpdir(),"rca-lifecycle-safe-"));
  chmodSync(home,0o700);
  function dir(relative){
    const full=path.join(home,relative);mkdirSync(full,{recursive:true,mode:0o700});
    chmodSync(full,0o700);return full;
  }
  const base=".local/share/mcp-workers/remote-control";
  const program=dir(base+"/programs/"+VERSION);
  dir(base+"/programs/"+VERSION+"/"+APP+"/src");
  dir(base+"/programs/"+VERSION+"/"+APP+"/scripts");
  writeFileSync(path.join(program,"bundle.json"),JSON.stringify({
    version:"v0.1.2",target:"linux-x64-glibc",artifact_schema:1,
    device_protocol:2,receipt_schema:1,upgrade_profile:profile
  }),{mode:0o600});
  writeFileSync(path.join(program,APP,"src/v2-main.js"),
    profile==="paired-full-v1" ? 'export const V2_RUNTIME_PROFILE = "paired-full-v1";\n' :
      "const caps = {readOnly: true, writeFile: false, shell: false,};\n",{mode:0o600});
  writeFileSync(path.join(program,APP,"scripts/manage-v2.mjs"),"export {};\n",{mode:0o600});
  const identity=path.join(dir(base),"v2-identity.pem.device-id");
  writeFileSync(identity,DEVICE,{mode:0o600});
  const receipts=path.join(dir(".local/state/mcp-workers/remote-control-agent"),"operation-receipts.sqlite");
  writeFileSync(receipts,"RECEIPTS_UNTOUCHED",{mode:0o600});
  const unitPath=path.join(dir(".config/systemd/user"),"remote-control-agent.service");
  const unit=withUnit?renderV2Service({
    node:path.join(program,"bin/node"),home,repoRoot:program,
    endpoint:"https://rc.example.org/",
    keyPath:path.join(home,base,"v2-identity.pem"),
    entryExt:"js",
  }):"";
  if(withUnit)writeFileSync(unitPath,unit,{mode:0o600});
  const launcher=path.join(dir(".local/bin"),"rca");
  if(withLauncher)symlinkSync(path.join(program,APP,"scripts/manage-v2.mjs"),launcher);
  const state={versions:[VERSION],unit:withUnit?unit:null,ids:{permanent:DEVICE}};
  return {home,program,unitPath,launcher,identity,receipts,state};
}
const cleanup=f=>rmSync(f.home,{recursive:true,force:true});
test("owner-confirmed uninstall stops only v2 service then keeps keys and SQLite",()=>{
  const f=testFixture();try{
    const calls=[];
    const p=planLocalUninstall(f.state,{home:f.home});
    const result=executeLocalUninstall(p,{
      confirm:true,scan:()=>true,
      invoke:(cmd,args)=>{
        calls.push([cmd,...args]);return {status:0};
      }
    });
    assert.deepEqual(calls,[
      ["systemctl","--user","disable","--now","remote-control-agent.service"],
      ["systemctl","--user","daemon-reload"]
    ]);
    assert.equal(result.cloud_revocation,"NOT_PERFORMED");
    assert.deepEqual(result.removed_versions,[VERSION]);
    assert.deepEqual(result.preserved_device_ids,{permanent:DEVICE});
    assert.equal(existsSync(f.unitPath),false);
    assert.equal(existsSync(f.launcher),false);
    assert.equal(existsSync(f.program),false);
    assert.equal(readFileSync(f.identity,"utf8"),DEVICE);
    assert.equal(readFileSync(f.receipts,"utf8"),"RECEIPTS_UNTOUCHED");
  }finally{cleanup(f);}
});
test("full-tools uninstall requires successful owned-service stop and preserves identity/receipts",()=>{
  const f=testFixture({profile:"paired-full-v1"});
  try{
    const plan=planLocalUninstall(f.state,{home:f.home});
    assert.throws(()=>executeLocalUninstall(plan,{
      confirm:true,scan:()=>false,invoke:()=>({status:0})
    }),/remains after service stop/);
    assert.ok(existsSync(f.program));
    const calls=[];
    const result=executeLocalUninstall(plan,{
      confirm:true,scan:()=>true,invoke:(name,args)=>{calls.push([name,...args]);return {status:0};}
    });
    assert.equal(result.cloud_revocation,"NOT_PERFORMED");
    assert.equal(existsSync(f.program),false);
    assert.equal(readFileSync(f.identity,"utf8"),DEVICE);
    assert.equal(readFileSync(f.receipts,"utf8"),"RECEIPTS_UNTOUCHED");
    assert.deepEqual(calls.map(x=>x[2]),["disable","daemon-reload"]);
  }finally{cleanup(f);}
});

test("unconfirmed uninstall refuses and preserves owned service/program",()=>{
  const f=testFixture();try{
    const plan=planLocalUninstall(f.state,{home:f.home});
    assert.throws(()=>executeLocalUninstall(plan,{confirm:false}),/confirmation/);
    assert.ok(existsSync(f.unitPath));
    assert.ok(existsSync(f.program));
    assert.equal(readFileSync(f.receipts,"utf8"),"RECEIPTS_UNTOUCHED");
  }finally{cleanup(f);}
});
test("systemd stop failure leaves service, keys and executable intact",()=>{
  const f=testFixture();try{
    const plan=planLocalUninstall(f.state,{home:f.home});
    assert.throws(()=>executeLocalUninstall(plan,{
      confirm:true,invoke:()=>({status:1}),scan:()=>true
    }),/Unable to change/);
    assert.ok(existsSync(f.unitPath));assert.ok(existsSync(f.program));
    assert.equal(readFileSync(f.identity,"utf8"),DEVICE);
  }finally{cleanup(f);}
});
test("still running process after stop blocks file deletion and preserves receipts",()=>{
  const f=testFixture();try{
    const plan=planLocalUninstall(f.state,{home:f.home});
    assert.throws(()=>executeLocalUninstall(plan,{
      confirm:true,invoke:()=>({status:0}),scan:()=>false
    }),/remains after service stop/);
    assert.ok(existsSync(f.unitPath));assert.ok(existsSync(f.program));
    assert.equal(readFileSync(f.receipts,"utf8"),"RECEIPTS_UNTOUCHED");
  }finally{cleanup(f);}
});
test("foreign launcher, symlink member or Shell-enabled source reject BEFORE stopping",()=>{
  for(const tamper of ["launcher","symlink","shell"]){
    const f=testFixture();
    try{
      if(tamper==="launcher"){
        rmSync(f.launcher);symlinkSync("/tmp/foreign-cli",f.launcher);
      }else if(tamper==="symlink"){
        const file=path.join(f.program,APP,"src/v2-main.js");
        rmSync(file);symlinkSync("/etc/passwd",file);
      }else{
        writeFileSync(path.join(f.program,APP,"src/v2-main.js"),
          "const caps={readOnly: true, writeFile: false, shell: true,};\n");
      }
      assert.throws(()=>planLocalUninstall(f.state,{home:f.home}),
        /Foreign|Untrusted|Shell ownership/);
      assert.ok(existsSync(f.unitPath));assert.equal(readFileSync(f.receipts,"utf8"),"RECEIPTS_UNTOUCHED");
    }finally{cleanup(f);}
  }
});
test("foreground-only uninstall refuses if a previous Agent process is active",()=>{
  const f=testFixture({withUnit:false});
  try{
    assert.throws(()=>planLocalUninstall(f.state,{
      home:f.home,scan:()=>false
    }),/Running or uncertain/);
    assert.ok(existsSync(f.program));
  }finally{cleanup(f);}
});
test("process scanner recognizes owned process path and ignores other user processes",()=>{
  const f=testFixture({withUnit:false});
  const proc=path.join(f.home,"proc");
  try{
    mkdirSync(path.join(proc,"1234"),{recursive:true,mode:0o700});
    const pid=path.join(proc,"1234");
    writeFileSync(path.join(pid,"status"),"Name:\tnode\nState:\tS (sleeping)\n");
    writeFileSync(path.join(pid,"cmdline"),path.join(f.program,"bin/node")+"\0");
    assert.equal(noOwnedAgentProcesses([f.program],proc,9999),false);
    writeFileSync(path.join(pid,"status"),"Name:\tnode\nState:\tZ (zombie)\n");
    assert.equal(noOwnedAgentProcesses([f.program],proc,9999),true);
  }finally{cleanup(f);}
});

test("extra file in managed version is rejected before any service mutation",()=>{
  const f=testFixture();
  try{
    writeFileSync(path.join(f.program,"unexpected.cache"),"unreviewed",{mode:0o600});
    assert.throws(()=>planLocalUninstall(f.state,{home:f.home}),/unexpected Agent program/);
    assert.ok(existsSync(f.unitPath));
    assert.ok(existsSync(f.program));
  }finally{cleanup(f);}
});
test("unit changed after reviewed plan cannot be stopped or unlinked",()=>{
  const f=testFixture();
  try{
    const plan=planLocalUninstall(f.state,{home:f.home});
    writeFileSync(f.unitPath,f.state.unit+"# external adjustment\n");
    let invoked=0;
    assert.throws(()=>executeLocalUninstall(plan,{confirm:true,
      invoke:()=>{invoked++;return {status:0};}
    }),/service changed/);
    assert.equal(invoked,0);
    assert.ok(existsSync(f.unitPath));
    assert.ok(existsSync(f.program));
  }finally{cleanup(f);}
});

test("#78 reject foreign systemd lifecycle directives BEFORE v2 uninstall stop",()=>{
  for(const directive of [
    "ExecStopPost=/usr/bin/touch /tmp/foreign-effect",
    "ExecStartPost=/usr/bin/true",
    "Environment=REMOTE_CONTROL_AGENT_KEY_PATH=/tmp/foreign.pem",
  ]){
    const f=testFixture();
    try{
      const injected=f.state.unit.replace("RestartSec=15s",directive+"\nRestartSec=15s");
      writeFileSync(f.unitPath,injected,{mode:0o600});
      const state={...f.state,unit:injected};
      assert.throws(()=>planLocalUninstall(state,{home:f.home}),
        /canonical installer template|ambiguous endpoint|identity/);
      assert.equal(readFileSync(f.unitPath,"utf8"),injected);
      assert.ok(existsSync(f.program));
      assert.equal(readFileSync(f.identity,"utf8"),DEVICE);
      assert.equal(readFileSync(f.receipts,"utf8"),"RECEIPTS_UNTOUCHED");
    }finally{cleanup(f);}
  }
});
