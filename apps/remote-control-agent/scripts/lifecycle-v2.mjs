/**
 * Node-only, owner-scoped local v2 uninstall. No cloud revoke and no identity
 * or SQLite deletion. Call only from an interactive user-confirmed CLI.
 */
import { lstatSync, readFileSync, readlinkSync, readdirSync, rmSync, unlinkSync } from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

const APP="apps/remote-control-agent";
const UNIT="remote-control-v2-agent.service";
const V2MARKER="# Managed by mcp-workers v2 Linux installer; NOT the v1 Agent.";
const VERSION=/^v[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9.-]+)?-linux-(?:x64|arm64)-glibc$/;

function safeStat(p,dir=false) {
  const s=lstatSync(p);
  if(s.uid!==process.getuid()||(s.mode&0o077)!==0||
     (dir?!s.isDirectory():!s.isFile()) || s.isSymbolicLink() ||
     (!dir&&s.nlink!==1))throw Error("Untrusted owned Agent path");
  return s;
}
export function verifyOwnedProgram(version){
  if(!VERSION.test(path.basename(version)))throw Error("Unknown Agent version");
  safeStat(version,true);
  const manifestFile=path.join(version,"bundle.json");
  safeStat(manifestFile);
  const info=JSON.parse(readFileSync(manifestFile,"utf8"));
  const code=path.join(version,APP,"src/v2-main.js");
  safeStat(code);
  const source=readFileSync(code,"utf8");
  const approvedProfile =
    (info.upgrade_profile==="read-only-no-shell-v1" &&
      /readOnly:\s*true,\s*writeFile:\s*false,\s*shell:\s*false,/.test(source)) ||
    (info.upgrade_profile==="paired-full-v1" &&
      /V2_RUNTIME_PROFILE\s*=\s*"paired-full-v1"/.test(source) &&
      !/(?:readOnly|writeFile|shell)\s*:/.test(source));
  if(info.artifact_schema!==1||info.device_protocol!==2||
    info.receipt_schema!==1||!approvedProfile||
    info.version+"-"+info.target!==path.basename(version))
    throw Error("Untrusted Agent profile or Shell ownership; uninstall blocked");
  const allowedDirs=new Set(["bin","apps",APP,APP+"/src",APP+"/scripts",APP+"/.build"]);
  const allowedFiles=new Set(["bundle.json","bin/node",APP+"/package.json",
    APP+"/.build/session-supervisor",APP+"/src/v2-main.js",
    APP+"/scripts/install-v2.mjs",APP+"/scripts/verify-v2-release.mjs",
    APP+"/scripts/bootstrap-v2.py",APP+"/scripts/manage-v2.py",
    APP+"/scripts/bootstrap-node.mjs",APP+"/scripts/manage-v2.mjs",
    APP+"/scripts/lifecycle-v2.mjs",APP+"/scripts/upgrade-v2.mjs",
    APP+"/scripts/verify-v2-release.mjs",APP+"/scripts/rca.sh"]);
  if(Array.isArray(info.modules)){
    if(info.modules.length>80)throw Error("Unexpected Agent module inventory");
    for(const name of info.modules){
      if(typeof name!=="string"||!/^[a-z0-9-]+\.ts$/.test(name))
        throw Error("Untrusted module name in manifest");
      allowedFiles.add(APP+"/src/"+name.slice(0,-3)+".js");
    }
  }
  function walk(dir,relative=""){
    for(const name of readdirSync(dir)){
      const member=relative?relative+"/"+name:name;
      const child=path.join(dir,name);
      const meta=lstatSync(child);
      if(meta.uid!==process.getuid()||(meta.mode&0o077)!==0||
        meta.isSymbolicLink() || (!meta.isDirectory()&&!meta.isFile()) ||
        (meta.isFile()&&meta.nlink!==1)||
        (meta.isDirectory()?!allowedDirs.has(member):!allowedFiles.has(member)))
        throw Error("Untrusted or unexpected Agent program contents");
      if(meta.isDirectory())walk(child,member);
    }
  }
  walk(version);
}
export function verifyOwnedLauncher(home,versions){
  const bin=path.join(home,".local/bin");
  let entry;
  try{entry=lstatSync(path.join(bin,"rca"));}
  catch(e){if(e.code==="ENOENT")return null;throw e;}
  const launcher=path.join(bin,"rca");
  if(!entry.isSymbolicLink()||entry.uid!==process.getuid())
    throw Error("Foreign rca launcher");
  const target=readlinkSync(launcher);
  if(!versions.some(version=>["manage-v2.py","manage-v2.mjs","rca.sh"].some(m=>
      target===path.join(version,APP,"scripts",m))))
    throw Error("Foreign rca symlink destination");
  return launcher;
}
/** A targeted /proc check fails closed on uncertain owned sessions. */
export function noOwnedAgentProcesses(versions,proc="/proc",self=process.pid){
  const prefixes=versions.map(v=>v+path.sep);
  for(const name of readdirSync(proc)){
    if(!/^[0-9]+$/.test(name)||Number(name)===self)continue;
    const pidDir=path.join(proc,name);
    try{
      if(lstatSync(pidDir).uid!==process.getuid())continue;
      const status=readFileSync(path.join(pidDir,"status"),"utf8");
      if(/^State:\s*Z\b/m.test(status))continue;
      const cmd=readFileSync(path.join(pidDir,"cmdline")).toString("utf8").split("\0");
      if(cmd.some(arg=>prefixes.some(prefix=>arg.startsWith(prefix))))
        return false;
      // The user session manager does not execute the Agent runtime.
      if(/^Name:\s*systemd$/m.test(status)&&
         cmd[0]==="/usr/lib/systemd/systemd")continue;
      if(/^Name:\s*\(sd-pam\)$/m.test(status)&&cmd[0]==="(sd-pam)")continue;
      for(const link of ["exe","cwd"]){
        const resolved=readlinkSync(path.join(pidDir,link));
        if(prefixes.some(prefix=>resolved.startsWith(prefix)))return false;
      }
    }catch(e){
      if(e.code==="ENOENT"||e.code==="ESRCH"){
        try{lstatSync(pidDir);}catch(g){if(g.code==="ENOENT")continue;}
      }
      return false;
    }
  }
  return true;
}
/** Compare against the exact installer-owned portable unit before STOP.
 * Deliberately standalone: the shipped CLI must not import the installer,
 * whose source-only TypeScript dependencies are excluded from native assets.
 */
export function assertSafeUninstallUnit(unit,home,versions){
  const lines=unit.split("\n");
  const get=(name)=>{
    const values=lines.filter(line=>line.startsWith(name+"="));
    if(values.length!==1)throw Error("Ambiguous managed service field");
    return values[0].slice(name.length+1);
  };
  const working=get("WorkingDirectory");
  const version=versions.find(v=>working===path.join(v,APP));
  if(!version)throw Error("Foreign managed service program");
  const endpoint=get("Environment=REMOTE_CONTROL_V2_ENDPOINT");
  let url;
  try{url=new URL(endpoint);}catch{throw Error("Invalid managed endpoint");}
  if(url.protocol!=="https:"||endpoint!==url.origin+"/"||url.username||
     url.password||url.search||url.hash||url.port)throw Error("Invalid managed endpoint");
  const key=path.join(home,".local/share/mcp-workers/remote-control/v2-identity.pem");
  const expected=[
    V2MARKER,"[Unit]",
    "Description=Remote Control v2 Agent (outbound WSS, independent of v1)",
    "StartLimitIntervalSec=0","",
    "[Service]","Type=simple",
    "WorkingDirectory="+path.join(version,APP),
    "Environment=REMOTE_CONTROL_V2_ENDPOINT="+endpoint,
    "Environment=REMOTE_CONTROL_V2_KEY_PATH="+key,
    "UMask=0077",
    "ExecStartPre=/usr/bin/test -r "+key,
    "ExecStartPre=/usr/bin/test -r "+key+".device-id",
    "ExecStartPre=/usr/bin/test -x "+path.join(version,APP,".build/session-supervisor"),
    "ExecStart="+path.join(version,"bin/node")+" "+path.join(version,APP,"src/v2-main.js"),
    "Restart=on-failure","RestartSec=15s","TimeoutStopSec=15s","",
    "[Install]","WantedBy=default.target","",
  ].join("\n");
  if(unit!==expected)throw Error("Managed service differs from canonical installer template");
}

export function planLocalUninstall(state,{home,scan=noOwnedAgentProcesses}={}){
  if(process.getuid()===0)throw Error("Root cannot uninstall this Agent");
  if(!home||!path.isAbsolute(home))throw Error("Missing trusted home");
  const base=path.join(home,".local/share/mcp-workers/remote-control/programs");
  const versions=state.versions.map(v=>path.join(base,v));
  if(versions.some((v,i)=>!VERSION.test(state.versions[i])||
      path.dirname(v)!==base))throw Error("Untrusted Agent inventory");
  for(const version of versions)verifyOwnedProgram(version);
  const launcher=verifyOwnedLauncher(home,versions);
  // Inventory already validated exact WorkingDirectory and ExecStart.
  if(state.unit){
    // Uninstall must use the SAME exact installer-owned unit validation as
    // interrupted-upgrade recovery. A matching marker and ExecStart alone do
    // not exclude foreign ExecStopPost/ExecStartPost or identity overrides.
    assertSafeUninstallUnit(state.unit,home,versions);
  }
  if(!state.unit&&!scan(versions))throw Error("Running or uncertain Agent process");
  const unitPath=state.unit?path.join(home,".config/systemd/user",UNIT):null;
  if(unitPath){
    safeStat(unitPath);
    if(readFileSync(unitPath,"utf8")!==state.unit)throw Error("Managed unit changed during review");
  }
  return Object.freeze({home,versions,launcher,unitPath,unitContents:state.unit,
    preserved_device_ids:{...state.ids},preserved_keys_and_sqlite:true});
}
export function executeLocalUninstall(plan,{scan=noOwnedAgentProcesses,
  invoke=spawnSync,confirm=false}={}){
  if(!confirm||process.getuid()===0)throw Error("Explicit uninstall confirmation required");
  // Revalidate ownership again before any stop/removal.
  for(const version of plan.versions)verifyOwnedProgram(version);
  if(plan.launcher!==verifyOwnedLauncher(plan.home,plan.versions))
    throw Error("Local launcher changed during confirmation");
  if(!plan.unitPath&&!scan(plan.versions))throw Error("Agent still active; no deletion");
  function systemctl(args){
    const r=invoke("systemctl",["--user",...args],{
      timeout:15000,stdio:"ignore",encoding:"utf8"});
    if(r.error||r.signal||r.status!==0)
      throw Error("Unable to change installer-owned v2 service");
  }
  if(plan.unitPath){
    safeStat(plan.unitPath);
    if(readFileSync(plan.unitPath,"utf8")!==plan.unitContents)
      throw Error("Managed service changed during confirmation");
    systemctl(["disable","--now",UNIT]);
    if(!scan(plan.versions))throw Error("Agent process remains after service stop");
    safeStat(plan.unitPath);
    if(readFileSync(plan.unitPath,"utf8")!==plan.unitContents)
      throw Error("Managed service changed after stop");
    unlinkSync(plan.unitPath);
    systemctl(["daemon-reload"]);
  }
  for(const version of plan.versions){
    verifyOwnedProgram(version);
    rmSync(version,{recursive:true,force:false,maxRetries:0});
  }
  if(plan.launcher){
    if(plan.launcher!==verifyOwnedLauncher(plan.home,plan.versions))
      throw Error("Foreign launcher appeared");
    unlinkSync(plan.launcher);
  }
  return {removed_versions:plan.versions.map(version=>path.basename(version)),
    removed_owned_v2_service:!!plan.unitPath,
    preserved_device_ids:plan.preserved_device_ids,
    preserved_keys_and_sqlite:true,cloud_revocation:"NOT_PERFORMED"};
}
