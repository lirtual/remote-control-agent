import assert from "node:assert/strict";
import {randomUUID} from "node:crypto";
import {chmod,cp,mkdir,mkdtemp,readFile,rm,symlink,writeFile} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {candidateName,checked,localMacAction,parsePlist,plistText,verifiedEndpoint} from
  "../scripts/macos-local.mjs";
import {parsePermanentMacArgs} from "../src/macos-permanent.ts";
const ID="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
const ENDPOINT="https://rca.example.test/";
const bundle=process.env.RCA_MACOS_BUNDLE_ROOT;

test("#660 permanent service accepts only exact approved existing grant and managed generation",()=>{
  const approved=parsePermanentMacArgs(["--service","--endpoint",ENDPOINT,"--generation",ID]);
  assert.equal(approved.service,true);
  assert.equal(approved.endpoint,ENDPOINT);
  for(const args of [
    ["--service","--endpoint",ENDPOINT],
    ["--service","--endpoint",ENDPOINT,"--retry-pairing","--generation",ID],
    ["--service","--endpoint",ENDPOINT,"--name","foreign","--generation",ID],
    ["--service","--endpoint",ENDPOINT,"--generation","bad"],
  ])assert.throws(()=>parsePermanentMacArgs(args));
  assert.throws(()=>verifiedEndpoint("http://rca.example.test/"));
  assert.throws(()=>verifiedEndpoint("https://example.test/path"));
});

test("#660 LaunchAgent plist is strictly owned, deterministic and rejects foreign mutations",()=>{
  const programs="/Users/test/.local/share/mcp-workers/remote-control/macos/programs";
  const root=path.join(programs,"v0.0.0-ci-darwin-arm64");
  const node=path.join(root,"bin/node");
  const entry=path.join(root,"apps/remote-control-agent/src/macos-permanent.js");
  const xml=plistText({node,entry,endpoint:ENDPOINT,generation:ID});
  assert.deepEqual(parsePlist(xml,programs,ENDPOINT),{root,generation:ID});
  for(const other of [
    xml.replace("/bin/node","/bin/sh"),
    xml.replace("KeepAlive</key><true/>","KeepAlive</key><false/>"),
    xml.replace("</dict>","<key>Disabled</key><true/></dict>"),
  ])assert.throws(()=>parsePlist(other,programs,ENDPOINT));
});

test("#660 candidate provenance requires exact pinned source and no change of protocol",()=>{
  const meta={version:"v0.0.0-ci",target:"darwin-arm64",source_commit:"a".repeat(40),
    artifact_schema:1,device_protocol:2,receipt_schema:1,
    candidate_profile:"darwin-permanent-local-v1",
    native_supervisor:"darwin-owned-group-v1",modules:["macos-permanent.ts"]};
  assert.equal(candidateName(meta,"a".repeat(40)),"v0.0.0-ci-darwin-arm64");
  assert.throws(()=>candidateName(meta,"b".repeat(40)));
  assert.throws(()=>candidateName({...meta,target:"linux-x64-glibc"},"a".repeat(40)));
  assert.throws(()=>candidateName({...meta,device_protocol:3},"a".repeat(40)));
});

const native=process.platform==="darwin"&&process.arch==="arm64"&&!!bundle;
async function fixture(t){
  const root=await mkdtemp(path.join(os.tmpdir(),"rca660-test-"));
  const home=path.join(root,"home");
  await mkdir(home,{mode:0o700});
  const identity=path.join(home,".local/share/mcp-workers/remote-control");
  await mkdir(identity,{recursive:true,mode:0o700});
  // The fixture is an already explicitly authorized permanent identity;
  // no remote pairing and NO real launchctl commands are performed by tests.
  const key=path.join(identity,"v2-identity.pem");
  await writeFile(key,"synthetic-private-key",{mode:0o600});
  await writeFile(key+".device-id",ID+"\n",{mode:0o600});
  const manifest=JSON.parse(await readFile(path.join(bundle,"bundle.json"),"utf8"));
  t.after(async()=>rm(root,{recursive:true,force:true,maxRetries:5,retryDelay:20}));
  return {root,home,identity,sourceSha:manifest.source_commit,version:manifest.version,
    commands:[],invoke:(command,args)=>{assert.equal(command,"/bin/launchctl");
      const entry=args.join(" ");return {status:0,stdout:entry};}};
}
test("#660 native offline install → stopped state → upgrade without restart",{
  skip:!native},async t=>{
  const f=await fixture(t);
  const opts={home:f.home,bundle,sourceSha:f.sourceSha,endpoint:ENDPOINT,
    invoke:f.invoke,ask:async()=>true,online:async()=>true,freezeAgent:async()=>{throw Error("Stopped service must not freeze");}};
  const first=await localMacAction("install",opts);
  assert.equal(first.status,"connected_observed");
  const state=await localMacAction("status",{home:f.home,invoke:f.invoke});
  assert.equal(state.installed,true);
  await localMacAction("stop",{...opts,invoke:(command,args)=>{
    f.commands.push(args[0]);return {status:0};}});
  const alt=path.join(f.root,"second");
  await cp(bundle,alt,{recursive:true});
  const manifestFile=path.join(alt,"bundle.json");
  const manifest=JSON.parse(await readFile(manifestFile,"utf8"));
  manifest.version="v0.0.1-ci";
  await writeFile(manifestFile,JSON.stringify(manifest)+"\n",{mode:0o600});
  f.commands.length=0;
  const result=await localMacAction("upgrade",{...opts,bundle:alt,
    invoke:(command,args)=>{f.commands.push(args[0]);
      return {status:args[0]==="print"?1:0};}});
  assert.equal(result.status,"stopped_preserved");
  assert.deepEqual(f.commands,["print"],
    "intentionally stopped service may only be checked, never auto-launched");
  assert.equal((await localMacAction("status",{home:f.home,invoke:f.invoke})).local_service,
    "stopped_requested_unverified");
  assert.equal((await readFile(path.join(f.identity,"v2-identity.pem.device-id"),"utf8")).trim(),ID);
});

test("#660 native upgrade busy/activation failure retains identity and rolls back",{
  skip:!native},async t=>{
  const f=await fixture(t);
  const base={home:f.home,bundle,sourceSha:f.sourceSha,endpoint:ENDPOINT,
    invoke:f.invoke,ask:async()=>true,online:async()=>true};
  await localMacAction("install",base);
  const alt=path.join(f.root,"update");
  await cp(bundle,alt,{recursive:true});
  const manifestFile=path.join(alt,"bundle.json");
  const m=JSON.parse(await readFile(manifestFile,"utf8"));
  m.version="v0.0.1-ci";
  await writeFile(manifestFile,JSON.stringify(m)+"\n",{mode:0o600});
  const opts={...base,bundle:alt,freezeAgent:async()=> "busy"};
  await assert.rejects(localMacAction("upgrade",opts),/Busy or uncertain/);
  assert.equal((await localMacAction("status",{home:f.home,invoke:f.invoke})).version,
    m.version.replace("0.1-ci","0.0-ci")+"-darwin-arm64");
  // Busy attempt safely staged the second version; explicit human inspection
  // is required before repeat, rather than overwriting it blindly.
  assert.equal((await readFile(path.join(f.identity,"v2-identity.pem.device-id"),"utf8")).trim(),ID);
});

test("#660 native refuses unsafe identity, LaunchAgent and file links",{
  skip:!native},async t=>{
  const f=await fixture(t);
  await chmod(path.join(f.identity,"v2-identity.pem"),0o644);
  const opts={home:f.home,bundle,sourceSha:f.sourceSha,endpoint:ENDPOINT,
    invoke:f.invoke,ask:async()=>true,online:async()=>true};
  await assert.rejects(localMacAction("install",opts),/Unsafe owner/);
});

test("#660 native activation failure restores prior reviewed LaunchAgent and identity",{
  skip:!native},async t=>{
  const f=await fixture(t);
  const actions=[];
  const mock=(command,args)=>{actions.push(args[0]);return {status:0};};
  const first={home:f.home,bundle,sourceSha:f.sourceSha,endpoint:ENDPOINT,
    invoke:mock,ask:async()=>true,online:async()=>true};
  await localMacAction("install",first);
  const plist=path.join(f.home,"Library/LaunchAgents/org.mcp-workers.remote-control-agent.plist");
  const before=await readFile(plist,"utf8");
  const alt=path.join(f.root,"rollback-candidate");
  await cp(bundle,alt,{recursive:true});
  const manifestFile=path.join(alt,"bundle.json");
  const meta=JSON.parse(await readFile(manifestFile,"utf8"));
  meta.version="v0.0.1-ci";
  await writeFile(manifestFile,JSON.stringify(meta)+"\n",{mode:0o600});
  let onlineCalls=0;
  await assert.rejects(localMacAction("upgrade",{
    ...first,bundle:alt,freezeAgent:async()=> "ready",
    online:async()=>++onlineCalls===2,
  }),/Upgrade blocked; previous service restored/);
  assert.match(actions.join(","),/bootout,bootstrap,bootout,bootstrap/);
  assert.equal(await readFile(plist,"utf8"),before);
  assert.equal((await readFile(path.join(f.identity,"v2-identity.pem.device-id"),"utf8")).trim(),ID);
  await assert.rejects(readFile(path.join(f.home,
    ".local/share/mcp-workers/remote-control/macos/switch.json")),{code:"ENOENT"});
});

test("#660 native suspicious LaunchAgent symlink refused before any mutation",{
  skip:!native},async t=>{
  const f=await fixture(t);
  const opts={home:f.home,bundle,sourceSha:f.sourceSha,endpoint:ENDPOINT,
    invoke:f.invoke,ask:async()=>true,online:async()=>true};
  await localMacAction("install",opts);
  const plist=path.join(f.home,"Library/LaunchAgents/org.mcp-workers.remote-control-agent.plist");
  await rm(plist);
  await symlink(path.join(f.identity,"v2-identity.pem"),plist);
  await assert.rejects(localMacAction("status",opts),/Unsafe owner/);
  assert.equal(await readFile(path.join(f.identity,"v2-identity.pem"),"utf8"),"synthetic-private-key");
});
