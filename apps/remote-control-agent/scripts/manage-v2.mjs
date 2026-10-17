#!/usr/bin/env node
/** Local-only Python-free Agent manager; read-only command slice.
 * Lifecycle mutations remain blocked until their Node implementations pass
 * separate review. This file is Draft-only and is not an installable CLI yet.
 */
import { spawnSync } from "node:child_process";
import { createInterface } from "node:readline/promises";
import { planLocalUninstall, executeLocalUninstall } from "./lifecycle-v2.mjs";
import { prepareManualUpgrade, activateManualUpgrade } from "./upgrade-v2.mjs";
import { lstatSync, readFileSync, readdirSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const STORE=".local/share/mcp-workers/remote-control";
const UNIT="remote-control-v2-agent.service";
const MARKER="# Managed by mcp-workers v2 Linux installer; NOT the v1 Agent.";
const VERSION=/^v[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9.-]+)?-linux-(?:x64|arm64)-glibc$/;
const ID=/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
const MANUAL_UPGRADE_ACTIVATION_FAILURE = "Manual upgrade activation failed. Check `rca status` and `systemctl --user status remote-control-v2-agent.service` before retrying; do not re-pair or replay operations.";
const GENERIC_LOCAL_FAILURE = "rca refused unsafe or unsupported local operation.";
export function safeManagerCliFailure(error) {
  return error instanceof Error && error.message === MANUAL_UPGRADE_ACTIVATION_FAILURE
    ? MANUAL_UPGRADE_ACTIVATION_FAILURE
    : GENERIC_LOCAL_FAILURE;
}

function lstatSafe(filename){
  try { return lstatSync(filename); }
  catch(e){ if(e.code==="ENOENT")return null; throw e; }
}
function checkedPath(filename,{directory=false,mode=null,optional=false,privatePath=true}={}){
  const s=lstatSafe(filename);
  if(!s){ if(optional)return false; throw Error("Missing local managed path"); }
  if(s.isSymbolicLink()||s.uid!==process.getuid()||
      (s.mode&(privatePath?0o077:0o022))!==0 ||
      (directory?!s.isDirectory():!s.isFile())||
      (mode!==null&&(s.mode&0o777)!==mode) ||
      (!directory&&s.nlink!==1))
    throw Error("Untrusted local managed path");
  return true;
}
function readDeviceId(home,relative){
  const filename=path.join(home,STORE,relative+".device-id");
  if(!checkedPath(filename,{optional:true,mode:0o600}))return undefined;
  if(lstatSync(filename).size>128)throw Error("Oversized identity marker");
  const s=readFileSync(filename,"utf8").trim();
  if(!ID.test(s))throw Error("Invalid local device ID");
  return s;
}
export function localManagerInventory({home=os.homedir(),source=fileURLToPath(import.meta.url)}={}){
  if(process.getuid()===0)throw Error("Do not run rca as root");
  if(!path.isAbsolute(home)||path.normalize(home)!==home)throw Error("Untrusted home");
  checkedPath(home,{directory:true,privatePath:false});
  for(const part of [".local",".local/share",".local/share/mcp-workers",STORE,STORE+"/programs"]){
    checkedPath(path.join(home,part),{directory:true,privatePath:part===STORE||part===STORE+"/programs"});
  }
  checkedPath(source);
  const root=path.resolve(path.dirname(source),"../../..");
  const programs=path.join(home,STORE,"programs");
  if(path.dirname(root)!==programs||!VERSION.test(path.basename(root)))
    throw Error("Manager must run from its owned version directory");
  checkedPath(root,{directory:true});
  const manifestFile=path.join(root,"bundle.json");
  checkedPath(manifestFile,{mode:0o600});
  if(lstatSync(manifestFile).size>16384)throw Error("Oversized runtime manifest");
  const info=JSON.parse(readFileSync(manifestFile,"utf8"));
  if(info.artifact_schema!==1||info.device_protocol!==2||
      info.receipt_schema!==1||info.upgrade_profile!=="read-only-no-shell-v1"||
      path.basename(root)!==info.version+"-"+info.target)
    throw Error("Untrusted Agent runtime manifest");
  const versions=[];
  for(const name of readdirSync(programs)){
    if(name==="install.lock"||name.startsWith(".download-")||name.startsWith(".unverified-"))continue;
    if(!VERSION.test(name))throw Error("Foreign program-directory entry");
    checkedPath(path.join(programs,name),{directory:true});
    versions.push(name);
  }
  for(const part of [".config",".config/systemd",".config/systemd/user"]){
    checkedPath(path.join(home,part),{directory:true,optional:true,privatePath:false});
  }
  checkedPath(path.join(home,STORE,"temporary"),{directory:true,optional:true});
  const unitFile=path.join(home,".config/systemd/user",UNIT);
  const unit=checkedPath(unitFile,{optional:true})?readFileSync(unitFile,"utf8"):null;
  if(unit){
    if(!unit.startsWith(MARKER+"\n")||unit.length>16384)
      throw Error("Foreign user service");
    const fields=Object.fromEntries(["WorkingDirectory","ExecStart"].map(name=>{
      const values=unit.split("\n").filter(x=>x.startsWith(name+"="));
      if(values.length!==1)throw Error("Ambiguous managed service");
      return [name,values[0].slice(name.length+1)];
    }));
    const matched=versions.some(version=>{
      const base=path.join(programs,version);
      const app=path.join(base,"apps/remote-control-agent");
      return fields.WorkingDirectory===app &&
        fields.ExecStart===path.join(base,"bin/node")+" "+path.join(app,"src/v2-main.js");
    });
    if(!matched)throw Error("Service does not reference installer-owned Agent");
  }
  const permanent=readDeviceId(home,"v2-identity.pem");
  const temporary=readDeviceId(home,"temporary/v2-identity.pem");
  return {info,root,versions:versions.sort(),unit,ids:{...(permanent?{permanent}:{}),...(temporary?{temporary}:{})}};
}
export function localManagerStatus(options={},invoke=spawnSync){
  const {info,versions,unit,ids}=localManagerInventory(options);
  let service="not_installed";
  if(unit){
    const p=invoke("systemctl",["--user","is-active","--quiet",UNIT],
      {encoding:"utf8",timeout:5000,stdio:"ignore"});
    service=!p.error&&p.status===0?"active":"inactive_or_unconfirmed";
  }
  return {
    installed_versions:versions,local_permanent_service:service,device_ids:ids,
    cloud_authorization:"unconfirmed",signed_wss:"unconfirmed",
    read_only_access:"unconfirmed",cloud_revoke:"not_performed",
    temporary_expires_at:"server_authoritative_unconfirmed",
    sqlite_receipts:"preserved",cli_version:info.version,
  };
}
export function trustedInstalledEndpoint(unit){
  if(!unit)return null;
  const matches=unit.split("\n").filter(s=>s.startsWith("Environment=REMOTE_CONTROL_V2_ENDPOINT="));
  if(matches.length!==1)throw Error("Ambiguous managed Worker endpoint");
  const endpoint=matches[0].slice("Environment=REMOTE_CONTROL_V2_ENDPOINT=".length);
  const uri=new URL(endpoint);
  if(uri.protocol!=="https:"||uri.username||uri.password||uri.search||uri.hash||
    uri.pathname!=="/"||!uri.hostname||uri.port||endpoint!==uri.origin+"/")
    throw Error("Untrusted managed Worker endpoint");
  return endpoint;
}
export function dispatchLocalManager(args,{inventory=localManagerInventory,status=localManagerStatus,
  invoke=spawnSync,stdin=process.stdin,stdout=process.stdout,stderr=process.stderr}={}){
  const cmd=args[0]??"help";
  if(args.length>2)throw Error("Too many rca arguments");
  if(args.length>1&&cmd!=="pair")throw Error("Only documented rca subcommands are accepted");
  if(cmd==="help"||cmd==="--help"||cmd==="-h"){
    stdout.write("rca [status|version|logs|pair [HTTPS endpoint]|upgrade TAG COMMIT|uninstall] — Python-free Draft CLI\n");
    stdout.write("Manual upgrade: rca upgrade <reviewed-tag> <reviewed-40-char-commit>.\n");
    return 0;
  }
  if(cmd==="version"||cmd==="--version"){
    stdout.write(inventory().info.version+"\n");return 0;
  }
  if(cmd==="status"){
    stdout.write(JSON.stringify(status(),null,2)+"\n");
    stdout.write("Local service state is NOT proof of signed WSS, cloud approval or Shell rights.\n");
    return 0;
  }
  if(cmd==="pair"){
    if(!stdin.isTTY||!stdout.isTTY)throw Error("Device pairing requires a real local terminal");
    const state=inventory();
    const bound=trustedInstalledEndpoint(state.unit);
    const requested=args[1];
    if(requested&&requested!==new URL(requested).origin+"/")
      throw Error("Only a clean HTTPS Worker origin is accepted");
    if(requested&&(new URL(requested).protocol!=="https:" ||
        (bound&&requested!==bound)))throw Error("Cannot silently change an installed Worker endpoint");
    const endpoint=requested||bound;
    if(!endpoint)throw Error("A reviewed HTTPS endpoint is required for initial pairing");
    const installer=path.join(state.root,"apps/remote-control-agent/scripts/install-v2.mjs");
    checkedPath(installer,{mode:0o600});
    const executable=path.join(state.root,"bin/node");
    checkedPath(executable,{mode:0o700});
    const result=invoke(executable,[installer,"--endpoint",endpoint],{
      stdio:"inherit",env:{...process.env,RC_AGENT_NO_POST_START:"1"},
    });
    return result.error||result.signal||result.status!==0?1:0;
  }
  if(cmd==="logs"){
    const state=inventory();
    if(!state.unit){stdout.write("No managed v2 user service.\n");return 0;}
    if(!stdin.isTTY||!stdout.isTTY)throw Error("Logs require the local terminal");
    stdout.write("Local systemd logs may contain sensitive details; redact before sharing.\n");
    const result=invoke("journalctl",["--user","--unit",UNIT,"--no-pager",
      "--lines","40","--output","short-iso"],{stdio:"inherit",timeout:12000});
    return result.error||result.status!==0?1:0;
  }
  // Never fall back to a Python manager, arbitrary Node source or OS shell.
  throw Error("Lifecycle operation not yet implemented in reviewed Node CLI");
}
/** One explicit owner-terminal confirmation; cloud revoke remains independent. */
export async function runInteractiveLocalManager(args,{
  inventory=localManagerInventory,home=os.homedir(),
  stdin=process.stdin,stdout=process.stdout,
  ask=null,plan=planLocalUninstall,execute=executeLocalUninstall,
  ...rest
}={}){
  if(args.length===0){
    if(!stdin.isTTY||!stdout.isTTY)throw Error("Interactive Agent manager requires a local terminal");
    const rl=createInterface({input:stdin,output:stdout,terminal:true});
    try {
      for(;;){
        stdout.write("\nRemote Control Agent "+inventory().info.version+"\n");
        stdout.write("1. Status\n2. Pair / repair\n3. Logs\n");
        stdout.write("4. Upgrade\n5. Uninstall\n6. Exit\n");
        const choice=(await rl.question("Choose an option: ")).trim();
        if(choice==="6"||choice.toLowerCase()==="q")return 0;
        if(choice==="1"){
          dispatchLocalManager(["status"],{inventory,stdin,stdout,...rest});
          continue;
        }
        if(choice==="3"){
          dispatchLocalManager(["logs"],{inventory,stdin,stdout,...rest});
          continue;
        }
        if(choice==="4"){
          const pin=(await rl.question("Reviewed Release tag and Git commit: ")).trim().split(/\s+/);
          if(pin.length!==2)throw Error("Manual upgrade needs tag and commit");
          rl.close();
          return runInteractiveLocalManager(["upgrade",...pin],{
            inventory,home,stdin,stdout,ask,plan,execute,...rest,
          });
        }
        if(choice==="2"||choice==="5"){
          rl.close();
          return runInteractiveLocalManager([choice==="2"?"pair":"uninstall"],{
            inventory,home,stdin,stdout,ask,plan,execute,...rest,
          });
        }
        stdout.write("Choose 1–6.\n");
      }
    }finally{rl.close();}
  }
  if(args[0]==="upgrade"){
    if(args.length!==3)throw Error("Use rca upgrade <reviewed-tag> <reviewed-40-char-commit>");
    if(!stdin.isTTY||!stdout.isTTY)throw Error("Manual upgrade requires the local terminal");
    const upgrade=rest.prepareUpgrade??prepareManualUpgrade;
    const activate=rest.activateUpgrade??activateManualUpgrade;
    const state=inventory();
    const prepared=await upgrade(state,{tag:args[1],commit:args[2]},{home});
    let result;
    try { result=activate(prepared); }
    catch { throw new Error(MANUAL_UPGRADE_ACTIVATION_FAILURE); }
    stdout.write("Manual upgrade completed; independent cloud verification remains required.\n");
    stdout.write(JSON.stringify(result,null,2)+"\n");
    return 0;
  }
  if(args[0]!=="uninstall")
    return dispatchLocalManager(args,{inventory,stdin,stdout,...rest});
  if(args.length!==1)throw Error("Uninstall accepts no additional arguments");
  if(!stdin.isTTY||!stdout.isTTY)throw Error("Uninstall requires a local interactive terminal");
  const state=inventory();
  const reviewed=plan(state,{home});
  stdout.write("Owned Agent versions: "+reviewed.versions.map(version=>path.basename(version)).join(", ")+"\n");
  stdout.write("Device IDs: "+JSON.stringify(reviewed.preserved_device_ids)+"\n");
  stdout.write("Local uninstall does NOT revoke cloud grants. Revoke via authenticated MCP separately.\n");
  stdout.write("Private keys and SQLite receipts are preserved; prior effects are NOT undone.\n");
  let answer;
  if(ask){
    answer=await ask("Type UNINSTALL-V2 to confirm local removal: ");
  }else{
    const rl=createInterface({input:stdin,output:stdout,terminal:true});
    try{answer=await rl.question("Type UNINSTALL-V2 to confirm local removal: ");}
    finally{rl.close();}
  }
  if(answer?.trim()!=="UNINSTALL-V2")throw Error("Local uninstall was not confirmed");
  const result=execute(reviewed,{confirm:true});
  stdout.write(JSON.stringify(result,null,2)+"\n");
  return 0;
}
if(process.argv[1]===fileURLToPath(import.meta.url)){
  runInteractiveLocalManager(process.argv.slice(2)).then(
    code=>{process.exitCode=code;},
    error=>{console.error(safeManagerCliFailure(error));process.exitCode=1;}
  );
}
