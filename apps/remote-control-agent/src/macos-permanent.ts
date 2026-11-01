/**
 * #660–#661 native macOS 15+ non-root login-scoped Agent candidate.
 * Pair only in a real local terminal; LaunchAgent can only resume a
 * previously explicitly approved permanent key and signed WSS identity.
 */
import { lstat, rename, writeFile } from "node:fs/promises";
import { realpathSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";
import { beginDeviceEnrollment } from "./pair-device.ts";
import { requireNativeMac, privateDirectory, privateFileIfPresent,
  awaitTemporaryApproval, parseTemporaryMacArgs } from "./macos-temporary.ts";
import { selectDeviceLabel } from "./v2-enrollment.ts";
import { recoverDeviceId } from "./v2-session-client.ts";
import { maintainAuthenticatedDeviceSession } from "./v2-connection-lifecycle.ts";

export function parsePermanentMacArgs(argv: string[]): {
  endpoint:string; name?:string; service:boolean; retryPairing:boolean; generation?:string;
} {
  let service=false, enroll=false, retryPairing=false, generation:string|undefined;
  const rest:string[]=[];
  for(let i=0;i<argv.length;i++){
    if(argv[i]==="--service" && !service)service=true;
    else if(argv[i]==="--enroll" && !service && !enroll) enroll=true;
    else if(argv[i]==="--generation" && !generation && argv[i+1])generation=argv[++i];
    else if(argv[i]==="--retry-pairing" && !retryPairing)retryPairing=true;
    else rest.push(argv[i]!);
  }
  if(service && (enroll || retryPairing || !generation || rest.includes("--name")))
    throw Error("LaunchAgent may only resume its existing permanent identity.");
  if(!service && generation)throw Error("Generation is reserved for the managed LaunchAgent.");
  if(generation && !/^[a-f0-9-]{36}$/.test(generation))throw Error("Invalid service generation.");
  const opts=parseTemporaryMacArgs(rest);
  if(opts.resume || opts.retryPairing)throw Error("Invalid permanent grant options.");
  return {endpoint:opts.endpoint,name:opts.name,service,retryPairing,generation};
}
export async function runPermanentMac(argv=process.argv.slice(2)):Promise<void>{
  requireNativeMac();
  const {endpoint,name,service,retryPairing,generation}=parsePermanentMacArgs(argv);
  if(!service && (!process.stdin.isTTY || !process.stdout.isTTY))
    throw Error("Permanent enrollment requires a real owner terminal.");
  process.umask(0o077);
  const controller=new AbortController();
  const abort=()=>controller.abort();
  process.once("SIGTERM",abort);process.once("SIGINT",abort);
  try{
    const home=os.homedir();
    const identity=await privateDirectory(home,[".local","share","mcp-workers","remote-control"]);
    const receipts=await privateDirectory(home,[".local","state","mcp-workers","remote-control-agent"]);
    await privateFileIfPresent(path.join(receipts,"operation-receipts.sqlite"));
    const key=path.join(identity,"v2-identity.pem");
    const hasKey=await privateFileIfPresent(key), hasId=await privateFileIfPresent(key+".device-id");
    if(hasId&&!hasKey)throw Error("Orphaned permanent device ID; operator inspection required.");
    if(!service){
      if(hasId){
        if(retryPairing)throw Error("Approved permanent identity cannot be re-enrolled.");
        await recoverDeviceId(endpoint,key,fetch,controller.signal);
        process.stdout.write("Existing approved permanent identity preserved.\n");
        return;
      }
      if(hasKey&&!retryPairing)throw Error("Pending key exists; use explicit --retry-pairing.");
      if(!hasKey&&retryPairing)throw Error("No pending permanent key to retry.");
      const enrolled=await beginDeviceEnrollment(selectDeviceLabel(name??"",os.hostname()),
        endpoint,key,fetch,retryPairing,"permanent");
      process.stdout.write("Permanent pairing code (10 min): "+enrolled.code+"\n");
      process.stdout.write("Fingerprint: "+enrolled.fingerprint+"\n");
      process.stdout.write("Approve this exact permanent identity in authenticated MCP.\n");
      await awaitTemporaryApproval(endpoint,key,controller.signal,enrolled.expiresAt);
      if(!await privateFileIfPresent(key+".device-id"))throw Error("Approval not persisted.");
      return;
    }
    if(!hasKey||!hasId)throw Error("LaunchAgent cannot enroll or renew an unapproved identity.");
    const marker=path.join(identity,"macos-connection.json");
    const record=async(state:"connected"|"disconnected"|"rejected")=>{
      // Owner-private directory, exclusive temporary file, atomic replace; no secrets.
      const temp=path.join(identity,".connection-"+randomUUID());
      await writeFile(temp,JSON.stringify({generation,version:process.env.RCA_CANDIDATE_VERSION??"candidate",
        pid:process.pid,state,at:new Date().toISOString()})+"\n",{flag:"wx",mode:0o600});
      try {
        if(await privateFileIfPresent(marker)) {
          const st=await lstat(marker);
          if(st.nlink!==1)throw Error("Unsafe connection marker links.");
        }
        await rename(temp,marker);
      }catch(error){try{const {unlink}=await import("node:fs/promises");await unlink(temp);}catch{}throw error;}
    };
    await record("disconnected");
    await maintainAuthenticatedDeviceSession(endpoint,key,controller.signal,{
      receiptDirectory:receipts,enableLocalUpgrade:true,
      onState: state=>{void record(state).catch(()=>controller.abort());},
    });
  }finally{
    process.off("SIGTERM",abort);process.off("SIGINT",abort);
  }
}
if(process.argv[1] && realpathSync(process.argv[1])===fileURLToPath(import.meta.url)){
  try{await runPermanentMac();}
  catch(error){
    process.stderr.write("macOS permanent Agent blocked: "+
      (error instanceof Error?error.message:"unknown")+".\n");
    process.exitCode=1;
  }
}
