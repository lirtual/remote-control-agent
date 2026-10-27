import assert from "node:assert/strict";
import {test} from "node:test";
import {mkdtempSync,mkdirSync,writeFileSync,readdirSync,readFileSync,rmSync} from "node:fs";
import {tmpdir} from "node:os";
import path from "node:path";
import {createHash} from "node:crypto";
import {launchDetachedLinuxUpgrade,oneShotLinuxUnit,ONE_SHOT_MAX_SECONDS}
  from "../scripts/linux-upgrade-detached.mjs";

const linux=process.platform==="linux"&&process.getuid?.()!==0?test:test.skip;
const DEVICE="af666663-b30c-4b3d-ad85-c8047dc3516b";
const OP="approved-linux-39";
const CURRENT="v0.1.22",TARGET="v0.1.23";
const ARCH=process.arch;

function fixture(){
  const home=mkdtempSync(path.join(tmpdir(),"rca-linux-detached-"));
  const base=path.join(home,".local/share/mcp-workers/remote-control");
  const program=path.join(base,"programs");
  const state=path.join(home,".local/state/mcp-workers/remote-control-agent");
  const identity=path.join(base,"v2-identity.pem");
  const current=path.join(program,CURRENT+"-linux-"+ARCH+"-glibc");
  const target=path.join(program,TARGET+"-linux-"+ARCH+"-glibc");
  mkdirSync(state,{recursive:true,mode:0o700});
  mkdirSync(base,{recursive:true,mode:0o700});
  writeFileSync(identity,"private fixture key",{mode:0o600});
  writeFileSync(identity+".device-id",DEVICE+"\n",{mode:0o600});
  for(const [root,version] of [[current,CURRENT],[target,TARGET]]){
    mkdirSync(path.join(root,"apps/remote-control-agent/scripts"),{
      recursive:true,mode:0o700});
    mkdirSync(path.join(root,"bin"),{recursive:true,mode:0o700});
    writeFileSync(path.join(root,"bundle.json"),JSON.stringify({
      name:"remote-control-agent",version,target:"linux-"+ARCH+"-glibc",
      upgrade_profile:"paired-full-v1",device_protocol:2,receipt_schema:1,
      upgrade_protocol:"owner-one-shot-v1",
    }),{mode:0o600});
  }
  // The script exists ONLY in the test fixture. This tests launcher admission,
  // never a real systemd-run or an actual Linux systemd service restart.
  writeFileSync(path.join(current,"apps/remote-control-agent/scripts",
    "linux-upgrade-watchdog.mjs"),"fixture",{mode:0o600});
  writeFileSync(path.join(current,"bin/node"),"fixture",{mode:0o700});
  const attempts=()=>readdirSync(state).filter(x=>x.startsWith("upgrade-run-"));
  const calls=[];
  const invoke=(binary,args)=>{
    calls.push({binary,args});
    return {status:0,stdout:"",stderr:""};
  };
  const options={home,operationId:OP,deviceId:DEVICE,
    currentVersion:CURRENT,targetVersion:TARGET,
    assertAdmission:async()=>true,verifyPinnedTarget:async()=>true,invoke};
  return {home,current,target,state,attempts,calls,options,cleanup:()=>rmSync(home,{force:true,recursive:true})};
}
linux("transient Linux user unit is a fixed hash, not caller-chosen service name",()=>{
  const expected=createHash("sha256").update(OP).digest("hex");
  assert.deepEqual(oneShotLinuxUnit(OP),{
    unit:"rca-upgrade-"+expected.slice(0,32),
    marker:"upgrade-run-"+expected+".json",
  });
  for(const id of ["","..","../bad","bad/name","bad\nname","x".repeat(129)]){
    assert.throws(()=>oneShotLinuxUnit(id),/Invalid one-shot/);
  }
});
linux("approved reviewed Linux upgrade creates durable guard then launches separate user service",async()=>{
  const f=fixture();
  try{
    let checks=0;
    const result=await launchDetachedLinuxUpgrade({...f.options,
      assertAdmission:async payload=>{
        checks++;assert.deepEqual(payload,{operationId:OP,deviceId:DEVICE,
          currentVersion:CURRENT,targetVersion:TARGET});
        return true;
      },
      verifyPinnedTarget:async payload=>{
        checks++;assert.equal(payload.targetRoot,f.target);
        assert.equal(f.attempts().length,0,
          "all source verification precedes any replay evidence");
        return true;
      },
      invoke:(binary,args)=>{
        assert.equal(checks,2,"cannot launch before both independent review gates");
        assert.equal(f.attempts().length,1,
          "attempt marker must be committed before any child can run");
        return f.options.invoke(binary,args);
      },
    });
    assert.deepEqual(result,{status:"launched",operationId:OP,
      unit:oneShotLinuxUnit(OP).unit});
    assert.equal(f.calls.length,1);
    assert.equal(f.calls[0].binary,"/usr/bin/systemd-run");
    const args=f.calls[0].args;
    assert.ok(args.includes("--user"));
    assert.ok(args.includes("--no-block"));
    assert.ok(args.includes("--collect"));
    assert.ok(args.includes("--service-type=exec"));
    assert.ok(args.includes("--property=RuntimeMaxSec="+ONE_SHOT_MAX_SECONDS));
    assert.ok(args.includes("--property=UMask=0077"));
    assert.ok(!args.includes("--scope"),"scope mode must not inherit Agent cgroup");
    assert.ok(!args.includes("--wait"),"launcher cannot wait for service restart");
    assert.deepEqual(args.slice(-4),[
      path.join(f.current,"bin/node"),
      path.join(f.current,"apps/remote-control-agent/scripts/linux-upgrade-watchdog.mjs"),
      "--operation-id",OP,
    ]);
    const marker=path.join(f.state,oneShotLinuxUnit(OP).marker);
    const json=JSON.parse(readFileSync(marker,"utf8"));
    assert.deepEqual(json,{operation_id:OP,device_id:DEVICE,
      current_version:CURRENT,target_version:TARGET});
    assert.equal(f.attempts().length,1);
    await assert.rejects(launchDetachedLinuxUpgrade(f.options),
      /EEXIST|file already exists/i,"same operation must never execute a second time");
    assert.equal(f.calls.length,1);
  }finally{f.cleanup();}
});
linux("denied local receipt or unverified pin causes zero systemd or filesystem effects",async()=>{
  for(const field of ["assertAdmission","verifyPinnedTarget"]){
    const f=fixture();
    try{
      await assert.rejects(launchDetachedLinuxUpgrade({...f.options,
        [field]:async()=>false,
      }),/No durable owner-approved|Unverified immutable/);
      assert.deepEqual(f.attempts(),[]);
      assert.deepEqual(f.calls,[]);
    }finally{f.cleanup();}
  }
});
linux("failure to spawn is uncertain and keeps the replay guard",async()=>{
  const f=fixture();
  try{
    let calls=0;
    const opts={...f.options,invoke:()=>{calls++;return {status:1};}};
    await assert.rejects(launchDetachedLinuxUpgrade(opts),/start uncertain/);
    assert.equal(f.attempts().length,1);
    await assert.rejects(launchDetachedLinuxUpgrade(opts),/EEXIST|already exists/i);
    assert.equal(calls,1,"a native startup error may have had effects");
  }finally{f.cleanup();}
});
linux("identity, version and unreviewed manifest failures never ask user systemd to start",async()=>{
  for(const mutation of ["id","downgrade","target-protocol","current-protocol","missing-runner","unsafe-home"]){
    const f=fixture();
    try{
      const options={...f.options};
      if(mutation==="id")options.deviceId="11111111-1111-4111-8111-111111111111";
      if(mutation==="downgrade")options.targetVersion=CURRENT;
      if(mutation==="unsafe-home")options.home=f.home+"/../untrusted";
      if(mutation==="target-protocol"||mutation==="current-protocol"){
        const root=mutation==="target-protocol"?f.target:f.current;
        const file=path.join(root,"bundle.json");
        const row=JSON.parse(readFileSync(file,"utf8"));
        delete row.upgrade_protocol;
        writeFileSync(file,JSON.stringify(row));
      }
      if(mutation==="missing-runner"){
        rmSync(path.join(f.current,"apps/remote-control-agent/scripts",
          "linux-upgrade-watchdog.mjs"));
      }
      await assert.rejects(launchDetachedLinuxUpgrade(options));
      assert.deepEqual(f.attempts(),[],mutation+" cannot consume approved operation");
      assert.deepEqual(f.calls,[],mutation+" cannot start a user service");
    }finally{f.cleanup();}
  }
});
