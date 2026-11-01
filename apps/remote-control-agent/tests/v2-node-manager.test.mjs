import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, copyFileSync, mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { dispatchLocalManager, localManagerInventory, localManagerStatus, runInteractiveLocalManager, safeManagerCliFailure } from "../scripts/manage-v2.mjs";

const source=fileURLToPath(new URL("../scripts/manage-v2.mjs",import.meta.url));
const UUID="ea3b5d4f-e35c-4425-84d1-fa16d25e2efe";
function fixture(){
  const home=mkdtempSync(path.join(os.tmpdir(),"rca-node-manager-"));chmodSync(home,0o700);
  function directory(relative){const p=path.join(home,relative);mkdirSync(p,{recursive:true,mode:0o700});chmodSync(p,0o700);return p;}
  const rel=".local/share/mcp-workers/remote-control";
  const root=directory(rel+"/programs/v0.1.2-linux-x64-glibc");
  const scripts=directory(rel+"/programs/v0.1.2-linux-x64-glibc/apps/remote-control-agent/scripts");
  const manager=path.join(scripts,"manage-v2.mjs");
  copyFileSync(source,manager);chmodSync(manager,0o600);
  for(const scriptName of ["lifecycle-v2.mjs","upgrade-v2.mjs",
    "verify-v2-release.mjs","bootstrap-node.mjs"]){
    const sourceFile=fileURLToPath(new URL("../scripts/"+scriptName,import.meta.url));
    copyFileSync(sourceFile,path.join(scripts,scriptName));
  }
  const info={version:"v0.1.2",target:"linux-x64-glibc",artifact_schema:1,
    device_protocol:2,receipt_schema:1,upgrade_profile:"read-only-no-shell-v1"};
  writeFileSync(path.join(root,"bundle.json"),JSON.stringify(info),{mode:0o600});
  const src=directory(rel+"/programs/v0.1.2-linux-x64-glibc/apps/remote-control-agent/src");
  writeFileSync(path.join(src,"v2-main.js"),"const caps={readOnly: true, writeFile: false, shell: false,};\n",{mode:0o600});
  const ids=directory(rel);
  writeFileSync(path.join(ids,"v2-identity.pem.device-id"),UUID,{mode:0o600});
  const units=directory(".config/systemd/user");
  const unit=path.join(units,"remote-control-agent.service");
  writeFileSync(unit,"# Managed by Remote Control Agent installer.\n[Service]\nEnvironment=REMOTE_CONTROL_AGENT_ENDPOINT=https://remote-control-v2-preview.aiyaya.workers.dev/\nWorkingDirectory="+path.join(root,"apps/remote-control-agent")+"\nExecStart="+path.join(root,"bin/node")+" "+path.join(root,"apps/remote-control-agent/src/v2-main.js")+"\n",{mode:0o600});
  mkdirSync(path.join(root,"bin"),{recursive:true,mode:0o700});
  writeFileSync(path.join(root,"bin/node"),"SYNTHETIC-DUMMY-NODE",{mode:0o700});
  writeFileSync(path.join(scripts,"install-v2.mjs"),"SYNTHETIC-DUMMY-INSTALLER",{mode:0o600});
  const receipts=path.join(directory(".local/state/mcp-workers/remote-control-agent"),"operation-receipts.sqlite");
  writeFileSync(receipts,"SIMULATED_RECEIPT_KEEP",{mode:0o600});
  return {home,manager,root,ids,unit,receipts,info};
}
function cleanup(f){rmSync(f.home,{recursive:true,force:true});}
test("Node-only rca status and version preserve identity and receipts",()=>{
  const f=fixture();
  try{
    const opts={home:f.home,source:f.manager};
    const inv=localManagerInventory(opts);
    assert.equal(inv.info.version,"v0.1.2");
    assert.equal(inv.ids.permanent,UUID);
    const status=localManagerStatus(opts,()=>({status:0,error:null}));
    assert.equal(status.local_permanent_service,"active");
    assert.equal(status.cloud_authorization,"unconfirmed");
    assert.equal(status.device_ids.permanent,UUID);
    assert.equal(status.cli_version,"v0.1.2");
    assert.equal(status.sqlite_receipts,"preserved");
    const stdout={text:"",write(value){this.text+=value;}};
    assert.equal(dispatchLocalManager(["--version"],{inventory:()=>inv,stdout}),0);
    assert.equal(stdout.text,"v0.1.2\n");
    assert.equal(readFileSync(f.receipts,"utf8"),"SIMULATED_RECEIPT_KEEP");
    assert.equal(readFileSync(path.join(f.ids,"v2-identity.pem.device-id"),"utf8"),UUID);
  }finally{cleanup(f);}
});
test("Node manager recognizes a retained historical signed unit without re-pairing",()=>{
  const f=fixture();
  try{
    const historic=path.join(path.dirname(f.unit),"remote-control-v2-agent.service");
    renameSync(f.unit,historic);
    const options={home:f.home,source:f.manager};
    const inventory=localManagerInventory(options);
    assert.equal(inventory.unitName,"remote-control-v2-agent.service");
    assert.equal(inventory.ids.permanent,UUID);
    const calls=[];
    const status=localManagerStatus(options,(bin,args)=>{
      calls.push([bin,...args]);return {status:0,error:null};
    });
    assert.equal(status.local_permanent_service,"active");
    assert.deepEqual(calls,[["systemctl","--user","is-active","--quiet",
      "remote-control-v2-agent.service"]]);
    const stdout={text:"",write(s){this.text+=s;}};
    assert.equal(dispatchLocalManager(["logs"],{
      inventory:()=>inventory,stdin:{isTTY:true},stdout:{
        isTTY:true,write(s){stdout.write(s);}
      },invoke:(bin,args)=>{calls.push([bin,...args]);return {status:0};}
    }),0);
    assert.equal(calls.at(-1)[0],"journalctl");
    assert.ok(calls.at(-1).includes("remote-control-v2-agent.service"));
    // A conflicting newer unit must fail closed, never select one by order.
    writeFileSync(f.unit,readFileSync(historic),{mode:0o600});
    assert.throws(()=>localManagerInventory(options),/Ambiguous installed Agent services/);
    assert.equal(readFileSync(f.receipts,"utf8"),"SIMULATED_RECEIPT_KEEP");
    assert.equal(readFileSync(path.join(f.ids,"v2-identity.pem.device-id"),"utf8"),UUID);
  }finally{cleanup(f);}
});

test("Node manager recognizes the immutable paired-full profile without optional switches",()=>{
  const f=fixture();
  try{
    writeFileSync(path.join(f.root,"bundle.json"),
      JSON.stringify({...f.info,upgrade_profile:"paired-full-v1"}),{mode:0o600});
    writeFileSync(path.join(f.root,"apps/remote-control-agent/src/v2-main.js"),
      'export const V2_RUNTIME_PROFILE = "paired-full-v1";\n',{mode:0o600});
    const inventory=localManagerInventory({home:f.home,source:f.manager});
    assert.equal(inventory.info.upgrade_profile,"paired-full-v1");
    assert.equal(inventory.ids.permanent,UUID);
    writeFileSync(path.join(f.root,"apps/remote-control-agent/src/v2-main.js"),
      'export const V2_RUNTIME_PROFILE = "unknown";\n',{mode:0o600});
    assert.throws(()=>localManagerInventory({home:f.home,source:f.manager}),/Untrusted Agent runtime/);
  }finally{cleanup(f);}
});

test("Node manager refuses foreign identities and does not read private keys",()=>{
  const f=fixture();
  try{
    const opts={home:f.home,source:f.manager};
    const identity=path.join(f.ids,"v2-identity.pem.device-id");
    rmSync(identity);symlinkSync("/etc/passwd",identity);
    assert.throws(()=>localManagerInventory(opts),/Untrusted/);
    rmSync(identity);writeFileSync(identity,"non-uuid",{mode:0o600});
    assert.throws(()=>localManagerInventory(opts),/Invalid local device/);
    assert.equal(readFileSync(f.receipts,"utf8"),"SIMULATED_RECEIPT_KEEP");
  }finally{cleanup(f);}
});
test("not-yet-reviewed mutations and noninteractive logs fail closed",()=>{
  const f=fixture();
  try{
    const opts={home:f.home,source:f.manager};
    const inv=()=>localManagerInventory(opts);
    for(const action of ["upgrade","uninstall","purge","bash"])
      assert.throws(()=>dispatchLocalManager([action],{inventory:inv}),/not yet implemented/);
    assert.throws(()=>dispatchLocalManager(["logs"],{
      inventory:inv,stdin:{isTTY:false},stdout:{isTTY:false,write(){}}
    }),/local terminal/);
    const result=spawnSync(process.execPath,[f.manager,"uninstall"],{
      env:{...process.env,HOME:f.home},encoding:"utf8",timeout:3000
    });
    assert.equal(result.status,1);
    assert.equal(readFileSync(f.receipts,"utf8"),"SIMULATED_RECEIPT_KEEP");
  }finally{cleanup(f);}
});
test("Node-only pair dispatch reuses owned installer and only bound endpoint with local TTY",()=>{
  const f=fixture();
  try{
    const state=localManagerInventory({home:f.home,source:f.manager});
    const actions=[];
    const invoke=(cmd,args,opts)=>{
      actions.push({cmd,args,opts});
      return {status:0};
    };
    const tty={isTTY:true,write(){}};
    assert.equal(dispatchLocalManager(["pair"],{
      inventory:()=>state,stdin:tty,stdout:tty,invoke
    }),0);
    assert.equal(actions.length,1);
    assert.equal(actions[0].cmd,path.join(f.root,"bin/node"));
    assert.deepEqual(actions[0].args,[
      path.join(f.root,"apps/remote-control-agent/scripts/install-v2.mjs"),
      "--endpoint","https://remote-control-v2-preview.aiyaya.workers.dev/"
    ]);
    assert.equal(actions[0].opts.env.RC_AGENT_NO_POST_START,"1");
    assert.throws(()=>dispatchLocalManager(["pair"],{
      inventory:()=>state,stdin:{isTTY:false},stdout:tty,invoke
    }),/real local terminal/);
    assert.throws(()=>dispatchLocalManager(["pair","https://evil.example/"],{
      inventory:()=>state,stdin:tty,stdout:tty,invoke
    }),/Cannot silently change/);
    assert.equal(actions.length,1);
    assert.equal(readFileSync(f.receipts,"utf8"),"SIMULATED_RECEIPT_KEEP");
  }finally{cleanup(f);}
});
test("Node manager rejects a systemd unit retargeted to an unrelated process",()=>{
  const f=fixture();
  try{
    const unit=readFileSync(f.unit,"utf8");
    writeFileSync(f.unit,unit.replace(/ExecStart=[^\n]+/,"ExecStart=/bin/sh -c something"));
    assert.throws(()=>localManagerInventory({home:f.home,source:f.manager}),/Service does not reference/);
    assert.equal(readFileSync(f.receipts,"utf8"),"SIMULATED_RECEIPT_KEEP");
  }finally{cleanup(f);}
});
test("Node manager creates no Python cache or program mutations",()=>{
  const f=fixture();
  try{
    const result=spawnSync(process.execPath,[f.manager,"status"],{
      env:{...process.env,HOME:f.home},encoding:"utf8",timeout:3000
    });
    assert.equal(result.status,0,result.stderr);
    assert.equal(JSON.parse(result.stdout.split("\nLocal service")[0]).cli_version,"v0.1.2");
    const programFiles=readFileSync(f.manager,"utf8");
    assert.doesNotMatch(programFiles,/python3|manage-v2\.py|exec python/i);
    assert.equal(readFileSync(f.receipts,"utf8"),"SIMULATED_RECEIPT_KEEP");
  }finally{cleanup(f);}
});

test("Node uninstall asks for explicit exact confirmation before any action",async()=>{
  const f=fixture();
  try{
    const output={text:"",isTTY:true,write(s){this.text+=s;}};
    const input={isTTY:true};
    const state=localManagerInventory({home:f.home,source:f.manager});
    const plan={home:f.home,versions:[f.root],unitPath:f.unit,
      preserved_device_ids:{permanent:UUID}};
    const events=[];
    const base={inventory:()=>state,home:f.home,stdin:input,stdout:output,
      plan:()=>{events.push("review");return plan;},
      execute:(p,options)=>{events.push("execute");assert.equal(p,plan);
        assert.equal(options.confirm,true);
        return {preserved_device_ids:{permanent:UUID},cloud_revocation:"NOT_PERFORMED"};}};
    await assert.rejects(runInteractiveLocalManager(["uninstall"],{
      ...base,ask:async()=>"no"
    }),/not confirmed/);
    assert.deepEqual(events,["review"]);
    assert.equal(await runInteractiveLocalManager(["uninstall"],{
      ...base,ask:async()=>"UNINSTALL"
    }),0);
    assert.deepEqual(events,["review","review","execute"]);
    assert.match(output.text,/does NOT revoke cloud grants/);
    assert.match(output.text,/SQLite receipts are preserved/);
    assert.equal(readFileSync(f.receipts,"utf8"),"SIMULATED_RECEIPT_KEEP");
    await assert.rejects(runInteractiveLocalManager(["uninstall"],{
      ...base,stdin:{isTTY:false},ask:async()=>"UNINSTALL"
    }),/interactive terminal/);
  }finally{cleanup(f);}
});

test("Node explicit upgrade requires local TTY and correctly paired tag + commit arguments",async()=>{
  const f=fixture();
  try{
    const state=localManagerInventory({home:f.home,source:f.manager});
    const calls=[];
    const tty={isTTY:true,write(){}};
    const pinned="a".repeat(40);
    const prepared={program:"/synthetic/owned/new-version"};
    const options={home:f.home,inventory:()=>state,
      stdin:tty,stdout:tty,
      prepareUpgrade:async(s,p,settings)=>{
        calls.push(["prepare",s,p,settings]);return prepared;
      },
      activateUpgrade:p=>{
        calls.push(["activate",p]);return {version:"v0.1.3"};
      }};
    await assert.rejects(runInteractiveLocalManager(["upgrade","v0.1.3"],options),/Use rca upgrade/);
    await assert.rejects(runInteractiveLocalManager(["upgrade","v0.1.3",pinned],{
      ...options,stdin:{isTTY:false}
    }),/local terminal/);
    assert.equal(calls.length,0);
    assert.equal(await runInteractiveLocalManager(["upgrade","v0.1.3",pinned],options),0);
    assert.deepEqual(calls.map(x=>x[0]),["prepare","activate"]);
    assert.deepEqual(calls[0][2],{tag:"v0.1.3",commit:pinned});
    assert.equal(calls[0][3].home,f.home);
    assert.equal(calls[1][1],prepared);
    assert.equal(readFileSync(f.receipts,"utf8"),"SIMULATED_RECEIPT_KEEP");
  }finally{cleanup(f);}
});
test("a rejected upgrade prepare cannot invoke a new binary",async()=>{
  const f=fixture();
  try{
    const state=localManagerInventory({home:f.home,source:f.manager});
    let invoked=0;
    await assert.rejects(runInteractiveLocalManager(["upgrade","v0.1.3","a".repeat(40)],{
      home:f.home,inventory:()=>state,
      stdin:{isTTY:true},stdout:{isTTY:true,write(){}},
      prepareUpgrade:async()=>{throw Error("untrusted pinned release");},
      activateUpgrade:()=>{invoked++;}
    }),/untrusted pinned release/);
    assert.equal(invoked,0);
    assert.equal(readFileSync(f.receipts,"utf8"),"SIMULATED_RECEIPT_KEEP");
  }finally{cleanup(f);}
});

test("failed manual upgrade activation reports safe actionable guidance",async()=>{
  const f=fixture();
  try{
    const state=localManagerInventory({home:f.home,source:f.manager});
    const message="Manual upgrade activation failed. Check `rca status` and `systemctl --user status remote-control-agent.service` before retrying; do not re-pair or replay operations.";
    await assert.rejects(runInteractiveLocalManager(["upgrade","v0.1.3","a".repeat(40)],{
      home:f.home,inventory:()=>state,
      stdin:{isTTY:true},stdout:{isTTY:true,write(){}},
      prepareUpgrade:async()=>({program:"/synthetic/owned/new-version"}),
      activateUpgrade:()=>{throw Error("Reviewed Agent upgrade failed; inspect local rollback and service");}
    }),error=>error.message===message);
    assert.equal(safeManagerCliFailure(new Error(message)),message);
    assert.equal(safeManagerCliFailure(new Error("secret-like exception")),
      "rca refused unsafe or unsupported local operation.");
    assert.equal(readFileSync(f.receipts,"utf8"),"SIMULATED_RECEIPT_KEEP");
  }finally{cleanup(f);}
});

test("installed rca shell shim executes the bundled Node, not a host Node",()=>{
  const f=fixture();
  try{
    const app=path.join(f.root,"apps/remote-control-agent/scripts");
    const shim=path.join(app,"rca.sh");
    copyFileSync(fileURLToPath(new URL("../scripts/rca.sh",import.meta.url)),shim);
    chmodSync(shim,0o700);
    const node=path.join(f.root,"bin/node");
    writeFileSync(node,'#!/bin/sh\nprintf "bundled:%s:node-options=%s\\n" "$2" "$'+'{NODE_OPTIONS:-unset}"\n');
    chmodSync(node,0o700);
    const localBin=path.join(f.home,".local/bin");
    mkdirSync(localBin,{recursive:true,mode:0o700});
    symlinkSync(shim,path.join(localBin,"rca"));
    const out=spawnSync(path.join(localBin,"rca"),["version"],{
      encoding:"utf8",timeout:3000,
      env:{...process.env,HOME:f.home,NODE_OPTIONS:"--require=/not-real"}
    });
    assert.equal(out.status,0,out.stderr);
    assert.equal(out.stdout.trim(),"bundled:version:node-options=unset");
    assert.equal(readFileSync(f.receipts,"utf8"),"SIMULATED_RECEIPT_KEEP");
  }finally{cleanup(f);}
});

test('Linux/WSL2 owner Stop survives offline cloud failure and Start reconciles signed intent without re-pair',async()=>{
 const f=fixture();
 try{
  writeFileSync(path.join(f.ids,'v2-identity.pem'),'key retained',{mode:0o600});
  const events=[],tty={isTTY:true,write(){}};
  let available=false;
  const opts={home:f.home,inventory:()=>localManagerInventory({home:f.home,source:f.manager}),
   stdin:tty,stdout:tty,
   invokeService:(_bin,args)=>{events.push(args[1]);return {status:0};},
   signedIntent:async(_origin,_key,action)=>{
    events.push('cloud:'+action);
    if(!available)throw Error('network unavailable');
    return action==='stop'?{status:'stopped',idle_expires_at:9999999999999}:
     {status:'resume_pending',idle_expires_at:9999999999999};
   }};
  const marker=path.join(f.ids,'v2-identity.pem.owner-stopped');
  assert.equal(await runInteractiveLocalManager(['stop'],opts),0);
  assert.deepEqual(events,['cloud:stop','stop']);
  assert.equal(readFileSync(marker,'utf8'),'stopped\n');
  assert.equal(readFileSync(f.receipts,'utf8'),'SIMULATED_RECEIPT_KEEP');
  await assert.rejects(runInteractiveLocalManager(['upgrade'],opts),/Owner STOP retained/);
  await assert.rejects(runInteractiveLocalManager(['start'],opts),/network unavailable/);
  assert.equal(readFileSync(marker,'utf8'),'stopped\n');
  available=true;
  assert.equal(await runInteractiveLocalManager(['start'],opts),0);
  assert.deepEqual(events.slice(-3),['cloud:stop','cloud:resume','start']);
  assert.equal(await import('node:fs').then(fs=>fs.existsSync(marker)),false);
  assert.equal(readFileSync(path.join(f.ids,'v2-identity.pem.device-id'),'utf8'),UUID);
  assert.equal(readFileSync(f.receipts,'utf8'),'SIMULATED_RECEIPT_KEEP');
 }finally{cleanup(f);}
});

test('owner STOP state rejects tampered symlink and no owner terminal',async()=>{
 const f=fixture();
 try{
  writeFileSync(path.join(f.ids,'v2-identity.pem'),'key',{mode:0o600});
  const tty={isTTY:true,write(){}};
  const opts={home:f.home,inventory:()=>localManagerInventory({home:f.home,source:f.manager}),
   stdin:tty,stdout:tty,signedIntent:async()=>{throw Error('cannot authorize');},
   invokeService:()=>({status:0})};
  await assert.rejects(runInteractiveLocalManager(['stop'],{...opts,stdin:{isTTY:false}}),/real terminal/);
  const marker=path.join(f.ids,'v2-identity.pem.owner-stopped');
  symlinkSync('/etc/passwd',marker);
  await assert.rejects(runInteractiveLocalManager(['start'],opts),/Untrusted local managed path/);
  assert.equal(readFileSync(f.receipts,'utf8'),'SIMULATED_RECEIPT_KEEP');
 }finally{cleanup(f);}
});
