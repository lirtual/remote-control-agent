import assert from "node:assert/strict";
import { mkdtemp,mkdir,writeFile,readFile,lstat,rm,chmod } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { renderV2Service } from "../scripts/install-v2.mjs";
import { planServiceCutover,applyServiceCutover,rollbackServiceCutover,assertOffline } from "../scripts/migrate-linux-service.mjs";

const id="af666663-b30c-4b3d-ad85-c8047dc3516b";
const marker="# Managed by mcp-workers v2 Linux installer; NOT the v1 Agent.";
const legacy="# Installed from docs/remote-control/systemd/remote-control-agent.service.example\n"+
  "[Unit]\nDescription=Remote Control native Agent (loopback, user service)\n"+
  "[Service]\nExecStart=/home/fixture/bin/node src/main.ts\n";
const tunnel="# Installed from docs/remote-control/systemd/remote-control-tunnel.service.example\n"+
  "[Unit]\nDescription=Remote Control Cloudflare Tunnel (user service)\n"+
  "[Service]\nExecStart=/home/fixture/bin/cloudflared tunnel run\n";

async function fixture(){
  const home=await mkdtemp(path.join(os.tmpdir(),"rc-service-cutover-"));
  const unitDir=path.join(home,".config/systemd/user");
  const programs=path.join(home,".local/share/mcp-workers/remote-control/programs");
  const oldRoot=path.join(programs,"v0.1.12-linux-x64-glibc");
  const candidateRoot=path.join(programs,"v0.1.13-linux-x64-glibc");
  const key=path.join(home,".local/share/mcp-workers/remote-control/v2-identity.pem");
  await mkdir(unitDir,{recursive:true});
  await mkdir(path.dirname(key),{recursive:true,mode:0o700});
  await mkdir(oldRoot,{recursive:true,mode:0o700});
  await chmod(oldRoot,0o700);
  await mkdir(path.join(candidateRoot,"apps/remote-control-agent/src"),{recursive:true,mode:0o700});
  await chmod(candidateRoot,0o700);
  await writeFile(path.join(candidateRoot,"bundle.json"),JSON.stringify({
    name:"remote-control-agent",version:"v0.1.13",target:"linux-x64-glibc",
    upgrade_profile:"paired-full-v1",device_protocol:2,receipt_schema:1,
  }),{mode:0o600});
  await writeFile(path.join(candidateRoot,"apps/remote-control-agent/src/v2-main.js"),
    "export const V2_RUNTIME_PROFILE = 'paired-full-v1';\n",{mode:0o600});
  await writeFile(key,"dummy-private-key-for-test",{mode:0o600});
  await writeFile(key+".device-id",id+"\n",{mode:0o600});
  const signed=renderV2Service({home,repoRoot:oldRoot,
    node:path.join(oldRoot,"bin/node"),endpoint:"https://rc.example.org/",
    keyPath:key,entryExt:"js"})
    .replace("# Managed by Remote Control Agent installer.",marker)
    .replace("Description=Remote Control Agent (signed outbound WSS)",
      "Description=Remote Control v2 Agent (outbound WSS, independent of v1)")
    .replace("REMOTE_CONTROL_AGENT_ENDPOINT","REMOTE_CONTROL_V2_ENDPOINT")
    .replace("REMOTE_CONTROL_AGENT_KEY_PATH","REMOTE_CONTROL_V2_KEY_PATH");
  await writeFile(path.join(unitDir,"remote-control-agent.service"),legacy,{mode:0o644});
  await writeFile(path.join(unitDir,"remote-control-v2-agent.service"),signed,{mode:0o600});
  await writeFile(path.join(unitDir,"remote-control-tunnel.service"),tunnel,{mode:0o644});
  const plan=planServiceCutover({home,candidateRoot,legacyUnit:legacy,tunnelUnit:tunnel,
    signedUnit:signed,deviceId:id});
  return {home,key,plan,unitDir,legacy,signed,tunnel,
    dispose:async()=>rm(home,{recursive:true,force:true})};
}
function fakeSystemctl({active=false,failActivate=false}={}){
  const calls=[];
  const invoke=args=>{
    calls.push(args.join(" "));
    if(args[0]==="show")
      return active?"MainPID=10\nActiveState=active\nSubState=running":
        "MainPID=0\nActiveState=inactive\nSubState=dead";
    if(failActivate && args.join(" ")==="is-active --quiet remote-control-agent.service")
      throw Error("simulated activation failure");
    return "";
  };
  return {calls,invoke};
}

test("migration requires proof of both old runtimes, exact WSS template and fixed device",async()=>{
  const x=await fixture();
  try {
    assert.equal(x.plan.deviceId,id);
    assert.match(x.plan.canonical,/^# Managed by Remote Control Agent installer\./);
    assert.match(x.plan.canonical,/REMOTE_CONTROL_AGENT_ENDPOINT/);
    assert.doesNotMatch(x.plan.canonical,/REMOTE_CONTROL_V2_ENDPOINT/);
    const base={home:x.home,candidateRoot:x.plan.candidateRoot,legacyUnit:x.legacy,
      signedUnit:x.signed,tunnelUnit:x.tunnel,deviceId:id};
    assert.throws(()=>planServiceCutover({...base,legacyUnit:x.legacy.replace(
      "loopback, user service","unexpected")}),/historical/);
    assert.throws(()=>planServiceCutover({...base,tunnelUnit:x.tunnel.replace(
      "/cloudflared ","/untrusted ")}),/Tunnel/);
    assert.throws(()=>planServiceCutover({...base,signedUnit:x.signed.replace(
      "REMOTE_CONTROL_V2_KEY_PATH","FOREIGN_KEY_PATH")}),/Ambiguous/);
    assert.throws(()=>planServiceCutover({...base,deviceId:"not-a-device"}),/device ID/);
    assert.throws(()=>assertOffline(fakeSystemctl({active:true}).invoke),/stopped/);
  } finally {await x.dispose();}
});

test("owner-offline cutover switches to canonical unit, retaining old WSS and identity",async()=>{
  const x=await fixture();
  try{
    const system=fakeSystemctl();
    const result=await applyServiceCutover(x.plan,{systemctl:system.invoke});
    assert.equal(result.status,"locally_activated");
    assert.equal(result.signed_wss,"requires_independent_MCP_verification");
    assert.equal(await readFile(path.join(x.unitDir,"remote-control-agent.service"),"utf8"),
      x.plan.canonical);
    assert.equal(await readFile(path.join(x.unitDir,"remote-control-v2-agent.service"),"utf8"),
      x.signed);
    assert.equal(await readFile(x.key,"utf8"),"dummy-private-key-for-test");
    assert.equal((await readFile(x.key+".device-id","utf8")).trim(),id);
    assert.equal(await readFile(path.join(x.plan.backupDir,"remote-control-agent.service"),"utf8"),
      x.legacy);
    assert.ok(system.calls.includes("disable remote-control-tunnel.service"));
    assert.ok(system.calls.includes("disable remote-control-v2-agent.service"));
    assert.ok(system.calls.includes("enable --now remote-control-agent.service"));
    await assert.rejects(applyServiceCutover(x.plan,{systemctl:system.invoke}),
      /Unit changed|EEXIST|Untrusted/);
  } finally {await x.dispose();}
});

test("activation failure restores legacy service and restarts original signed-WSS Agent",async()=>{
  const x=await fixture();
  try{
    const system=fakeSystemctl({failActivate:true});
    await assert.rejects(applyServiceCutover(x.plan,{systemctl:system.invoke}),
      /simulated activation failure/);
    assert.equal(await readFile(path.join(x.unitDir,"remote-control-agent.service"),"utf8"),
      x.legacy);
    assert.equal((await readFile(x.key+".device-id","utf8")).trim(),id);
    assert.ok(system.calls.includes("enable --now remote-control-v2-agent.service"));
    assert.ok(system.calls.includes("enable --now remote-control-tunnel.service"));
    assert.equal((await lstat(path.join(x.plan.backupDir,"journal.json"))).mode&0o777,0o600);
  } finally {await x.dispose();}
});

test("owner-local rollback from inactive canonical unit restores exact previous unit",async()=>{
  const x=await fixture();
  try{
    const sys=fakeSystemctl();
    await applyServiceCutover(x.plan,{systemctl:sys.invoke});
    const done=await rollbackServiceCutover({home:x.home,systemctl:sys.invoke});
    assert.equal(done.status,"legacy_restored");
    assert.equal(await readFile(path.join(x.unitDir,"remote-control-agent.service"),"utf8"),x.legacy);
    assert.equal((await readFile(x.key+".device-id","utf8")).trim(),id);
    assert.ok(sys.calls.includes("enable --now remote-control-v2-agent.service"));
    assert.ok(sys.calls.includes("enable --now remote-control-tunnel.service"));
  }finally{await x.dispose();}
});

test("refuse rollback if canonical unit or private identity changed",async()=>{
  const x=await fixture();
  try{
    const sys=fakeSystemctl();
    await applyServiceCutover(x.plan,{systemctl:sys.invoke});
    const file=path.join(x.unitDir,"remote-control-agent.service");
    await writeFile(file,"[Service]\nExecStart=/untrusted\n",{mode:0o600});
    await assert.rejects(rollbackServiceCutover({home:x.home,systemctl:sys.invoke}),/unreviewed changes/);
    assert.equal(await readFile(file,"utf8"),"[Service]\nExecStart=/untrusted\n");
    await writeFile(file,x.plan.canonical,{mode:0o600});
    await writeFile(x.key,"tampered key",{mode:0o600});
    await assert.rejects(rollbackServiceCutover({home:x.home,systemctl:sys.invoke}),/identity changed/);
  }finally{await x.dispose();}
});
