/**
 * Reviewed manual upgrade orchestration for the owner-local Node manager.
 * Does not silently discover latest, change Worker, or mutate identity.
 * The actual systemd cut-over and rollback remain in install-v2.mjs.
 */
import { spawnSync } from "node:child_process";
import { readFileSync, lstatSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  resolvePinnedRelease, downloadPinnedAsset,
} from "./verify-v2-release.mjs";
import { inspectPinnedArchiveBytes, stageOrVerifyPinnedProgram }
  from "./bootstrap-node.mjs";

const SHA=/^[a-f0-9]{40}$/;
const VERSION=/^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
const APP="apps/remote-control-agent";

/**
 * Discover the immutable Release pin from this device's already-bound Worker.
 * Treat the installer as DATA only; never execute fetched shell text.
 * The existing GitHub release verifier still checks tag, commit and SHA-256.
 */
export async function resolveWorkerUpgradePin(endpoint,{request=fetch}={}){
  const origin=new URL(endpoint);
  if(origin.protocol!=="https:"||origin.username||origin.password||
     origin.port||origin.search||origin.hash||origin.pathname!=="/"||
     origin.origin+"/"!==endpoint)throw Error("Untrusted installed Worker endpoint");
  const url=origin.origin+"/install.sh";
  const response=await request(url,{
    method:"GET",redirect:"error",cache:"no-store",signal:AbortSignal.timeout(12000),
  });
  if(response.status!==200||!response.ok||response.url!==url)
    throw Error("Reviewed Worker installer is unavailable");
  const length=Number(response.headers.get("content-length")??"0");
  if(!Number.isFinite(length)||length<0||length>16384)
    throw Error("Unexpected Worker installer size");
  const script=await response.text();
  if(Buffer.byteLength(script,"utf8")>16384||
     !script.startsWith("#!/bin/sh\n# Worker-origin Agent installer: published immutable GitHub archive only\nset -eu\n")||
     !script.includes('sha256sum -c -')||
     !script.includes('case "$(uname -m)" in'))
    throw Error("Unrecognized reviewed Worker installer");
  const matches=[...script.matchAll(/--tag "(v[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9.-]+)?)" --commit "([a-f0-9]{40})" --sha256 "\$expected" --endpoint "(https:\/\/[^"\s]+\/)" "\$@" < \/dev\/tty/g)];
  if(matches.length!==1||matches[0][3]!==endpoint||
     !/x86_64\) target=linux-x64-glibc; expected=[a-f0-9]{64} ;;/.test(script)||
     !/aarch64\) target=linux-arm64-glibc; expected=[a-f0-9]{64} ;;/.test(script))
    throw Error("Worker installer has no unambiguous immutable Release pin");
  return Object.freeze({tag:matches[0][1],commit:matches[0][2]});
}

function ownedFile(p,mode){
  const st=lstatSync(p);
  if(!st.isFile()||st.isSymbolicLink()||st.uid!==process.getuid()||
     (st.mode&0o777)!==mode||st.nlink!==1)
    throw Error("Untrusted staged Agent executable");
  return p;
}
function sameOrOlder(candidate,current){
  const a=VERSION.exec(candidate),b=VERSION.exec(current);
  if(!a||!b)throw Error("Upgrade requires stable pinned semantic versions");
  for(let i=1;i<4;i++){
    const next=BigInt(a[i]),old=BigInt(b[i]);
    if(next!==old)return next<old;
  }
  return true;
}
function serviceEndpoint(unit){
  if(!unit)throw Error("Upgrade requires an installer-owned permanent service");
  const values=unit.split("\n")
    .filter(x=>x.startsWith("Environment=REMOTE_CONTROL_V2_ENDPOINT="));
  if(values.length!==1)throw Error("Missing or ambiguous approved Worker origin");
  const endpoint=values[0].slice("Environment=REMOTE_CONTROL_V2_ENDPOINT=".length);
  const url=new URL(endpoint);
  if(url.protocol!=="https:"||url.username||url.password||url.search||
     url.hash||url.pathname!=="/"||url.port||
     endpoint!==url.origin+"/")throw Error("Untrusted installed Worker endpoint");
  return endpoint;
}
export function validateManualUpgrade(state,{home=os.homedir(),tag,commit}){
  if(process.getuid()===0||!SHA.test(commit)||!VERSION.test(tag))
    throw Error("Manual upgrade requires reviewed tag and commit");
  if(!state?.unit||!state?.root||!state?.info||!state?.ids?.permanent)
    throw Error("Only an approved permanent installation can upgrade");
  if(sameOrOlder(tag,state.info.version))
    throw Error("Silent downgrade, prerelease, or same-version upgrade refused");
  const target=state.info.target;
  if(!["linux-x64-glibc","linux-arm64-glibc"].includes(target))
    throw Error("Unsupported upgrade architecture");
  if((target==="linux-x64-glibc"&&process.arch!=="x64")||
     (target==="linux-arm64-glibc"&&process.arch!=="arm64")||
     process.platform!=="linux")throw Error("Host CPU does not match Agent archive");
  const programs=path.join(home,".local/share/mcp-workers/remote-control/programs");
  if(path.dirname(state.root)!==programs||
    path.basename(state.root)!==state.info.version+"-"+target)
    throw Error("Untrusted currently managed program directory");
  const old=path.join(state.root,APP,"src/v2-main.js");
  ownedFile(old,0o600);
  const text=readFileSync(old,"utf8");
  if(!/readOnly:\s*true,\s*writeFile:\s*false,\s*shell:\s*false,/.test(text))
    throw Error("Existing Agent may have mutable or Shell sessions");
  // The old unit is already owned and path-checked by manager inventory.
  const endpoint=serviceEndpoint(state.unit);
  const targetDir=path.join(programs,tag+"-"+target);
  return Object.freeze({tag,commit,target,programs,targetDir,endpoint,oldRoot:state.root});
}
/**
 * Network fetch remains bounded to reviewed immutable GitHub origins by
 * existing verifier; the SHA is additionally checked by the native stage.
 * On error this function does not change unit, identity, or owner receipts.
 */
export async function prepareManualUpgrade(state,pins,{
  home=os.homedir(),
  resolve=resolvePinnedRelease,
  download=downloadPinnedAsset,
  stage=stageOrVerifyPinnedProgram,
}={}){
  const approved=validateManualUpgrade(state,{home,...pins});
  const release=await resolve({tag:approved.tag,commit:approved.commit,target:approved.target});
  if(release.tag!==approved.tag||release.commit!==approved.commit||
     release.target!==approved.target||!/^[a-f0-9]{64}$/.test(release.digest))
    throw Error("Release pin mismatch");
  const bytes=await download(release);
  const expected={tag:approved.tag,target:approved.target,expectedSha256:release.digest};
  inspectPinnedArchiveBytes(bytes,expected);
  const program=stage(bytes,expected,approved.programs,path.basename(approved.targetDir));
  if(program!==approved.targetDir)throw Error("Unexpected staged version directory");
  const runner=ownedFile(path.join(program,"bin/node"),0o700);
  const script=ownedFile(path.join(program,APP,"scripts/install-v2.mjs"),0o600);
  // Only an immutable paired-full target may replace a proven read-only
  // Agent. The currently installed runtime is verified separately above.
  const main=ownedFile(path.join(program,APP,"src/v2-main.js"),0o600);
  const manifest=ownedFile(path.join(program,"bundle.json"),0o600);
  const info=JSON.parse(readFileSync(manifest,"utf8"));
  const entry=readFileSync(main,"utf8");
  if(info.upgrade_profile!=="paired-full-v1" ||
     !/V2_RUNTIME_PROFILE\s*=\s*"paired-full-v1"/.test(entry) ||
     /(?:readOnly|writeFile|shell)\s*:/.test(entry))
    throw Error("Unproven paired full-tools upgrade target");
  return Object.freeze({...approved,program,runner,script});
}
export function activateManualUpgrade(prepared,{
  invoke=spawnSync,env=process.env,
}={}){
  const result=invoke(prepared.runner,[prepared.script,"--upgrade",
    "--endpoint",prepared.endpoint],{
    stdio:"inherit",env:{...env,RC_AGENT_NO_POST_START:"1"},
  });
  if(result.error||result.signal||result.status!==0)
    throw Error("Reviewed Agent upgrade failed; inspect local rollback and service");
  return {version:prepared.tag,program:prepared.program,endpoint:prepared.endpoint};
}
