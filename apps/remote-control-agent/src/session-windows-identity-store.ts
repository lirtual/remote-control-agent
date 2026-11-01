/** Job-scoped Windows identity with explicit native ACL; no personal Agent state. */
import {spawnSync} from 'node:child_process';
import {open,readFile,lstat,mkdir} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {newSessionDeviceIdentity,validateSessionDeviceIdentity,
  assertSessionPhysicalAttempt,type SessionPhysicalAttempt,type SessionDeviceIdentity}
  from './session-device-identity.ts';
const SCRIPT=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..','scripts','windows-session-private-store.ps1');
export type SessionFileName='identity.json'|'v2-identity.pem'|'v2-identity.pem.device-id'|'receipts'|'transport-stage';

/** Never print native errors; command arguments contain paths, not private keys. */
export function checkWindowsSessionAcl(action:'Init'|'Check'|'Seal',directory:string,file?:SessionFileName):void{
 if(process.platform!=='win32'||!process.env.SystemRoot)throw Error('Native Windows required.');
 const ps=path.win32.join(process.env.SystemRoot,'System32','WindowsPowerShell','v1.0','powershell.exe');
 // The ACL helper accepts only command-line arguments and its raw output must
 // never be surfaced. No pipe handles are needed; avoid nested Windows pipe
 // lifetime issues when the OIDC-bearing parent has already exited.
 const result=spawnSync(ps,['-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass',
   '-File',SCRIPT,'-Action',action,'-Directory',directory,...(file?['-FileName',file]:[])],
   {windowsHide:true,timeout:12000,stdio:'ignore'});
 if((result.error as NodeJS.ErrnoException|undefined)?.code==='ETIMEDOUT')
   throw Error('Session ACL helper timed out.');
 if(result.error||result.status!==0)throw Error('Session job-private ACL check refused.');
}
export async function verifiedWindowsSessionFile(dir:string,name:SessionFileName,expected:string):Promise<void>{
 const filename=path.win32.join(dir,name);
 let created=false;
 try{
  const handle=await open(filename,'wx');created=true;
  try{await handle.writeFile(expected,'utf8');await handle.sync();}finally{await handle.close();}
 }catch(e){if((e as NodeJS.ErrnoException).code!=='EEXIST')throw e;}
 if(created)checkWindowsSessionAcl('Seal',dir,name);
 else checkWindowsSessionAcl('Check',dir);
 const st=await lstat(filename);
 if(!st.isFile()||st.isSymbolicLink()||st.nlink!==1||st.size>4096||
   (await readFile(filename,'utf8'))!==expected)throw Error('Unexpected Windows Session identity file.');
}
export async function loadOrCreateWindowsSessionIdentity(
 runnerTemp:string,attempt:SessionPhysicalAttempt,
):Promise<{dir:string;identity:SessionDeviceIdentity}>{
 if(process.platform!=='win32'||process.env.GITHUB_ACTIONS!=='true'||
   process.env.RUNNER_ENVIRONMENT!=='github-hosted')throw Error('Windows GitHub Runner required.');
 assertSessionPhysicalAttempt(attempt);
 if(!path.win32.isAbsolute(runnerTemp)||runnerTemp.startsWith('\\\\'))
   throw Error('Invalid Windows Runner Temp.');
 const dir=path.win32.join(runnerTemp,'session-rca');
 checkWindowsSessionAcl('Init',dir);
 const file=path.win32.join(dir,'identity.json');
 let identity:SessionDeviceIdentity;
 try{
  checkWindowsSessionAcl('Check',dir);
  identity=JSON.parse(await readFile(file,'utf8')) as SessionDeviceIdentity;
 }catch(error){
  if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;
  identity=newSessionDeviceIdentity(attempt);
  // Write-once identity; existing file is never replaced or silently re-keyed.
  await verifiedWindowsSessionFile(dir,'identity.json',JSON.stringify(identity));
  identity=JSON.parse(await readFile(file,'utf8')) as SessionDeviceIdentity;
 }
 checkWindowsSessionAcl('Check',dir);
 validateSessionDeviceIdentity(identity,attempt);
 return {dir,identity};
}
export async function ensureWindowsSessionReceipts(dir:string):Promise<string>{
 const target=path.win32.join(dir,'receipts');
 let created=false;
 try{await mkdir(target);created=true;}catch(e){if((e as NodeJS.ErrnoException).code!=='EEXIST')throw e;}
 checkWindowsSessionAcl(created?'Seal':'Check',dir,created?'receipts':undefined);
 return target;
}
