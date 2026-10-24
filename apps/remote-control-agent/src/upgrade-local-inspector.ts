/** Owner-local, read-only Linux upgrade inspector. No release provenance is inferred. */
import {spawnSync} from "node:child_process";
import {createHash} from "node:crypto";
import {constants} from "node:fs";
import {lstat,readFile,open} from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import type {UpgradeRequest} from "./upgrade-authorization.ts";

const HISTORICAL="remote-control-v2-agent.service";
const CANONICAL="remote-control-agent.service";
const UUID=/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/;
type UnitName=typeof HISTORICAL|typeof CANONICAL;
export interface LocalUpgradeInspection {
  readonly deviceId:string;
  readonly identitySha256:string;
  readonly runningVersion:string;
  readonly platform:string;
  readonly serviceActive:boolean;
  /** Service process, entrypoint and unit layout only; NOT verified archive bytes. */
  readonly servicePathsMatch:boolean;
  /** SQLite file header only; NOT a successful history query. */
  readonly receiptHeaderCompatible:boolean;
}
export interface LinuxRuntimeInspectionContext {
  /** From the authenticated Agent configuration, never the unit being inspected. */
  expectedEndpoint:string;
  home?:string; keyPath?:string; executable?:string; entrypoint?:string; pid?:number;
  /** Test seam; the real Agent always invokes fixed systemctl --user show. */
  serviceShow?: (name:UnitName)=>string;
}
function showService(name:UnitName):string{
  const r=spawnSync("systemctl",["--user","show",name,
    "-p","ActiveState","-p","SubState","-p","MainPID",
    "-p","FragmentPath","-p","DropInPaths"],
    {encoding:"utf8",timeout:5000,maxBuffer:4096});
  if(r.error||r.signal||r.status!==0)throw Error("Unable to read user service");
  return r.stdout;
}
export function parseUpgradeServiceState(value:string):Readonly<Record<string,string>>{
  if(typeof value!=="string"||value.length>4096)throw Error("Invalid service state");
  const required=["ActiveState","SubState","MainPID","FragmentPath","DropInPaths"];
  const lines=value.trimEnd().split("\n");
  if(lines.length!==5)throw Error("Ambiguous service state");
  const out:Record<string,string>={};
  for(const line of lines){
    const n=line.indexOf("="),name=line.slice(0,n),data=line.slice(n+1);
    if(n<=0||!required.includes(name)||Object.hasOwn(out,name)||
       data.includes("\r")||data.includes("\0"))throw Error("Ambiguous service field");
    out[name]=data;
  }
  if(required.some(key=>!Object.hasOwn(out,key)))throw Error("Missing service field");
  return Object.freeze(out);
}
async function owned(file:string,kind:"file"|"directory"):Promise<void>{
  const s=await lstat(file);
  if(s.uid!==process.getuid?.()||s.isSymbolicLink()||(s.mode&0o077)!==0||
    (kind==="file"?(!s.isFile()||s.nlink!==1):!s.isDirectory()))
    throw Error("Untrusted installed Agent file");
}
function expectedUnit(unit:string,root:string,key:string,endpoint:string):boolean{
  try {
    const url=new URL(endpoint);
    if(url.protocol!=="https:"||url.username||url.password||url.hash||url.search||
      url.port||url.pathname!=="/"||endpoint!==url.origin+"/"||
      !/^[a-z0-9.-]+$/i.test(url.hostname))return false;
  }catch{return false;}
  const app=path.join(root,"apps/remote-control-agent");
  return unit===[
    "# Managed by Remote Control Agent installer.",
    "[Unit]","Description=Remote Control Agent (signed outbound WSS)",
    "StartLimitIntervalSec=0","",
    "[Service]","Type=simple",
    "WorkingDirectory="+app,
    "Environment=REMOTE_CONTROL_AGENT_ENDPOINT="+endpoint,
    "Environment=REMOTE_CONTROL_AGENT_KEY_PATH="+key,
    "UMask=0077",
    "ExecStartPre=/usr/bin/test -r "+key,
    "ExecStartPre=/usr/bin/test -r "+key+".device-id",
    "ExecStartPre=/usr/bin/test -x "+path.join(app,".build/session-supervisor"),
    "ExecStart="+path.join(root,"bin/node")+" "+path.join(app,"src/v2-main.js"),
    "Restart=on-failure","RestartSec=15s","TimeoutStopSec=15s","",
    "[Install]","WantedBy=default.target","",
  ].join("\n");
}
async function validReceiptHeader(file:string):Promise<boolean>{
  try{
    await owned(file,"file");
    const handle=await open(file,constants.O_RDONLY|constants.O_NOFOLLOW);
    try{
      const data=Buffer.alloc(100);
      if((await handle.read(data,0,100,0)).bytesRead!==100)return false;
      return data.subarray(0,16).equals(Buffer.from("SQLite format 3\0","ascii")) &&
        [0,1].includes(data.readUInt32BE(60));
    }finally{await handle.close();}
  }catch{return false;}
}
export async function inspectLinuxLocalUpgrade(
  request:Readonly<UpgradeRequest>,
  options:LinuxRuntimeInspectionContext,
):Promise<Readonly<LocalUpgradeInspection>>{
  const result={
    deviceId:"",identitySha256:"",runningVersion:"",platform:"",
    serviceActive:false,servicePathsMatch:false,receiptHeaderCompatible:false,
  };
  if(process.platform!=="linux"||process.getuid?.()===0)return result;
  const home=options.home??os.homedir();
  const key=options.keyPath??path.join(home,".local/share/mcp-workers/remote-control/v2-identity.pem");
  const pid=options.pid??process.pid;
  const executable=options.executable??process.execPath;
  const entrypoint=options.entrypoint??process.argv[1]??"";
  if(!path.isAbsolute(home)||home!==path.normalize(home)||
     key!==path.join(home,".local/share/mcp-workers/remote-control/v2-identity.pem")||
     !Number.isSafeInteger(pid)||pid<=0)return result;
  try{
    await owned(key,"file");await owned(key+".device-id","file");
    const deviceId=(await readFile(key+".device-id","utf8")).trim();
    if(!UUID.test(deviceId)||deviceId!==request.device_id)return result;
    result.deviceId=deviceId;
    result.identitySha256=createHash("sha256").update(await readFile(key)).digest("hex");
  }catch{return result;}
  const target="linux-"+process.arch+"-glibc";
  if(target!==request.target_platform)return result;
  const root=path.join(home,".local/share/mcp-workers/remote-control/programs",
    request.target_version+"-"+target);
  const bin=path.join(root,"bin/node");
  const entry=path.join(root,"apps/remote-control-agent/src/v2-main.js");
  if(executable!==bin||entrypoint!==entry)return result;
  try{
    await owned(root,"directory");
    for(const p of [bin,entry,path.join(root,"bundle.json")])await owned(p,"file");
    const manifest=JSON.parse(await readFile(path.join(root,"bundle.json"),"utf8")) as Record<string,unknown>;
    if(manifest.name!=="remote-control-agent"||manifest.version!==request.target_version||
       manifest.target!==target||manifest.artifact_schema!==1||manifest.device_protocol!==2||
       manifest.receipt_schema!==1||manifest.upgrade_profile!=="paired-full-v1")return result;
    result.runningVersion=request.target_version;
    result.platform=target;
  }catch{return result;}
  result.receiptHeaderCompatible=await validReceiptHeader(
    path.join(home,".local/state/mcp-workers/remote-control-agent/operation-receipts.sqlite"));
  for(const name of [HISTORICAL,CANONICAL] as const){
    try{
      const unitFile=path.join(home,".config/systemd/user",name);
      await owned(unitFile,"file");
      const unit=await readFile(unitFile,"utf8");
      // Canonical service uses a different installer template, so remain
      // fail-closed pending exact-template review.
      if(name!==HISTORICAL||!expectedUnit(unit,root,key,options.expectedEndpoint))continue;
      const state=parseUpgradeServiceState((options.serviceShow??showService)(name));
      if(state.ActiveState!=="active"||state.SubState!=="running"||
        state.MainPID!==String(pid)||state.FragmentPath!==unitFile||state.DropInPaths!=="")continue;
      result.serviceActive=true;result.servicePathsMatch=true;break;
    }catch{/* Missing, foreign or inactive unit: never infer success. */}
  }
  return Object.freeze(result);
}
