import assert from "node:assert/strict";
import { mkdtemp,mkdir,writeFile,readFile,lstat,rm,chmod } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { renderV2Service } from "../scripts/install-v2.mjs";
import { planServiceCutover,applyServiceCutover,rollbackServiceCutover,assertOffline } from "../scripts/migrate-linux-service.mjs";

const id="af666663-b30c-4b3d-ad85-c8047dc3516b";
const marker="# Managed by mcp-workers v2 Linux installer; NOT the v1 Agent.";
const revision="d24ddda4051af58c2397229d6a047358dd1c6283";
function historicalLoopback(home){
  const root=path.join(home,".local/share/mcp-workers/remote-control-agent",revision);
  return [
    "# Installed from docs/remote-control/systemd/remote-control-agent.service.example",
    "# at "+revision+". Placeholders substituted on host.",
    "# Runtime pin: Node v24.21.0 and agent tree "+revision.slice(0,7)+". The live process is left running.",
    "[Unit]","Description=Remote Control native Agent (loopback, user service)",
    "StartLimitIntervalSec=0","",
    "[Service]","Type=simple",
    "WorkingDirectory="+path.join(root,"apps/remote-control-agent"),
    "Environment=REMOTE_CONTROL_AGENT_HOST=127.0.0.1",
    "Environment=REMOTE_CONTROL_AGENT_PORT=9477",
    "EnvironmentFile=%h/.config/mcp-workers/remote-control-agent.env",
    "UMask=0077",
    "ExecStartPre=/usr/bin/test -x "+path.join(root,"apps/remote-control-agent/.build/session-supervisor"),
    "ExecStart="+path.join(home,".local/share/mcp-workers/node/v24.21.0/bin/node")+" --experimental-strip-types src/main.ts",
    "Restart=always","RestartSec=15s","",
    "[Install]","WantedBy=default.target","",
  ].join("\n");
}
function historicalTunnel(home){
  return [
    "# Installed from docs/remote-control/systemd/remote-control-tunnel.service.example",
    "# at "+revision+". Placeholders substituted on host.",
    "[Unit]","Description=Remote Control Cloudflare Tunnel (user service)",
    "Wants=remote-control-agent.service","After=remote-control-agent.service",
    "StartLimitIntervalSec=0","",
    "[Service]","Type=simple","UMask=0077",
    "ExecStart="+path.join(home,".local/bin/cloudflared")+" tunnel --protocol http2 run --token-file "+
      path.join(home,".local/share/remote-control-t02/token"),
    "Restart=always","RestartSec=15s","",
    "[Install]","WantedBy=default.target","",
  ].join("\n");
}

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
  const legacy=historicalLoopback(home);
  const tunnel=historicalTunnel(home);
  await writeFile(path.join(unitDir,"remote-control-agent.service"),legacy,{mode:0o644});
  await chmod(path.join(unitDir,"remote-control-agent.service"),0o644);
  await writeFile(path.join(unitDir,"remote-control-v2-agent.service"),signed,{mode:0o600});
  await writeFile(path.join(unitDir,"remote-control-tunnel.service"),tunnel,{mode:0o644});
  await chmod(path.join(unitDir,"remote-control-tunnel.service"),0o644);
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
      "loopback, user service","unexpected")}),/historical|Historical/);
    assert.throws(()=>planServiceCutover({...base,tunnelUnit:x.tunnel.replace(
      "/cloudflared ","/untrusted ")}),/Tunnel/);
    assert.throws(()=>planServiceCutover({...base,legacyUnit:x.legacy.replace(
      "RestartSec=15s","RestartSec=15s\nExecStartPost=/bin/true")}),/template/);
    assert.throws(()=>planServiceCutover({...base,tunnelUnit:x.tunnel.replace(
      "RestartSec=15s","RestartSec=15s\nExecStop=/bin/true")}),/template/);
    assert.throws(()=>planServiceCutover({...base,signedUnit:x.signed.replace(
      "REMOTE_CONTROL_V2_KEY_PATH","FOREIGN_KEY_PATH")}),/Ambiguous/);
    assert.throws(()=>planServiceCutover({...base,deviceId:"not-a-device"}),/device ID/);
    assert.throws(()=>planServiceCutover({...base,candidateRoot:
      x.plan.candidateRoot.replace("v0.1.13","v0.1.11")}),/newer/);
    assert.throws(()=>planServiceCutover({...base,candidateRoot:
      x.plan.candidateRoot.replace("linux-x64-glibc","linux-arm64-glibc")}),/same CPU/);
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
    assert.ok(system.calls.includes("start remote-control-agent.service"));
    assert.ok(system.calls.includes("enable --now remote-control-v2-agent.service"));
    assert.ok(system.calls.includes("enable --now remote-control-tunnel.service"));
    assert.equal((await lstat(path.join(x.plan.backupDir,"journal.json"))).mode&0o777,0o600);
    await assert.rejects(lstat(path.join(x.unitDir,".remote-control-agent.restore.tmp")),{code:"ENOENT"});
  } finally {await x.dispose();}
});

test("failed automatic rollback never truncates the canonical service and permits journal recovery",async()=>{
  const x=await fixture();
  try{
    // Simulate an interrupted or unrelated owner-local rollback staging file.
    // The safe O_EXCL stage must fail rather than truncate this or the live unit.
    const stage=path.join(x.unitDir,".remote-control-agent.restore.tmp");
    await writeFile(stage,"INCOMPLETE", {mode:0o600});
    const sys=fakeSystemctl({failActivate:true});
    await assert.rejects(applyServiceCutover(x.plan,{systemctl:sys.invoke}),
      /rollback uncertain/);
    assert.equal(await readFile(stage,"utf8"),"INCOMPLETE");
    assert.equal(await readFile(path.join(x.unitDir,"remote-control-agent.service"),"utf8"),
      x.plan.canonical);
    assert.equal((await lstat(path.join(x.plan.backupDir,"journal.json"))).mode&0o777,0o600);
    // The explicit offline rollback uses its own staged atomic rename, so
    // backup and original identity remain independently recoverable.
    const recovered=await rollbackServiceCutover({home:x.home,systemctl:fakeSystemctl().invoke});
    assert.equal(recovered.status,"legacy_restored");
    assert.equal(await readFile(path.join(x.unitDir,"remote-control-agent.service"),"utf8"),
      x.legacy);
    assert.equal((await readFile(x.key+".device-id","utf8")).trim(),id);
  }finally{await x.dispose();}
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
    assert.ok(sys.calls.includes("start remote-control-agent.service"));
    assert.ok(!sys.calls.includes("enable remote-control-agent.service"));
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


test("interrupted partial backup preparation is safely retried before modifying units",async()=>{
  const x=await fixture();
  try{
    const pending=x.plan.backupDir+".preparing";
    await mkdir(pending,{mode:0o700});
    await chmod(pending,0o700);
    await writeFile(path.join(pending,"remote-control-agent.service"),
      x.legacy.slice(0,50),{mode:0o600});
    await chmod(path.join(pending,"remote-control-agent.service"),0o600);
    const system=fakeSystemctl();
    const result=await applyServiceCutover(x.plan,{systemctl:system.invoke});
    assert.equal(result.status,"locally_activated");
    await assert.rejects(lstat(pending),{code:"ENOENT"});
    assert.equal(await readFile(path.join(x.plan.backupDir,"remote-control-agent.service"),"utf8"),
      x.legacy);
  }finally{await x.dispose();}
});

test("foreign partial backup is never deleted or treated as a trusted snapshot",async()=>{
  const x=await fixture();
  try{
    const pending=x.plan.backupDir+".preparing";
    await mkdir(pending,{mode:0o700});
    await chmod(pending,0o700);
    const unknown=path.join(pending,"remote-control-agent.service");
    await writeFile(unknown,"UNTRUSTED",{mode:0o600});
    await chmod(unknown,0o600);
    const system=fakeSystemctl();
    await assert.rejects(applyServiceCutover(x.plan,{systemctl:system.invoke}),
      /Interrupted backup differs/);
    assert.equal(await readFile(unknown,"utf8"),"UNTRUSTED");
    assert.equal(await readFile(path.join(x.unitDir,"remote-control-agent.service"),"utf8"),
      x.legacy);
    assert.equal(system.calls.some(x=>x.startsWith("disable ")),false);
  }finally{await x.dispose();}
});