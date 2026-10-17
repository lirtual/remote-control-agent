import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, access } from "node:fs/promises";
import { existsSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { renderV2Service, choosePortableInstallMode, keyForInstallMode } from "../scripts/install-v2.mjs";
import { extractVerifiedAsset } from "../scripts/verify-v2-release.mjs";

const example={
  node:"/home/test/remote-control/programs/v0.1.0/bin/node",
  home:"/home/test",
  repoRoot:"/home/test/remote-control/programs/v0.1.0",
  endpoint:"https://rc.example.org/",
  keyPath:"/home/test/.local/share/mcp-workers/remote-control/v2-identity.pem",
};
test("#74 packaged systemd uses compiled JS + bundled Node, no TS checkout or compilation",()=>{
  const unit=renderV2Service({...example,entryExt:"js"});
  assert.match(unit,/ExecStart=\/home\/test\/remote-control\/programs\/v0\.1\.0\/bin\/node \/home\/test\/remote-control\/programs\/v0\.1\.0\/apps\/remote-control-agent\/src\/v2-main\.js/);
  assert.doesNotMatch(unit,/experimental-strip-types|src\/v2-main\.ts/);
  assert.match(unit,/session-supervisor/);
  assert.ok(!unit.includes("cloudflared"));
  assert.ok(!unit.includes("REMOTE_CONTROL_DEVICE_TOKEN"));
  assert.throws(()=>renderV2Service({...example,entryExt:"sh"}));
});

test("#74 portable installer requires a real local TTY and explicit permanent selection before pairing",async()=>{
  const src=await readFile(path.join(path.dirname(fileURLToPath(import.meta.url)),
    "..","scripts","install-v2.mjs"),"utf8");
  assert.match(src,/portable && options\.action === "install"/);
  assert.match(src,/if \(!stdin\.isTTY \|\| !stdout\.isTTY\)/);
  assert.match(src,/Choose Permanent or Temporary explicitly/);
  assert.match(src,/choice !== "1"/);
  assert.match(src,/options.grantType === "temporary"/);
  assert.match(src,/foreground only; cloud expires 24 hours/);
  assert.match(src,/Portable runtime mismatch; no pairing attempted/);
  assert.match(src,/assertNativeSupervisorProbe\(native\)/);
  assert.match(src,/entryExt: portable \? "js" : "ts"/);
});

test("#74 real staged x64 test package: no interactive TTY => fail before identity creation",async t=>{
  const artifact=process.env.RC_V2_PACKAGE_SMOKE;
  if (!artifact) { t.skip("Set RC_V2_PACKAGE_SMOKE to a locally built, unpublished x64 test archive."); return; }
  const dir=await mkdtemp(path.join(os.tmpdir(),"rc-standalone-t05-"));
  const root=path.join(dir,"release");
  const privateHome=path.join(dir,"home");
  const bytes=await readFile(artifact);
  const digest=createHash("sha256").update(bytes).digest("hex");
  try {
    await extractVerifiedAsset({tag:"v0.1.0",target:"linux-x64-glibc",digest},bytes,root);
    const binary=path.join(root,"bin/node");
    const script=path.join(root,"apps/remote-control-agent/scripts/install-v2.mjs");
    const out=spawnSync(binary,[script,"--endpoint","https://rc.example.org/"],{
      env:{...process.env,HOME:privateHome},input:"",encoding:"utf8",timeout:15000});
    assert.equal(out.status,1);
    assert.match(out.stderr,/installation\/upgrade\/removal failed/);
    assert.equal(existsSync(path.join(privateHome,".local/share/mcp-workers/remote-control/v2-identity.pem")),false);
  } finally {
    await rm(dir,{recursive:true,force:true});
  }
});
