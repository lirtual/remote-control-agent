/** Native Windows GitHub-hosted Session Agent, foreground and job-private only. */
import {lstat} from 'node:fs/promises';
import {pathToFileURL} from 'node:url';
import path from 'node:path';
import {loadOrCreateWindowsSessionIdentity,verifiedWindowsSessionFile,
  ensureWindowsSessionReceipts,checkWindowsSessionAcl} from './session-windows-identity-store.ts';
import {runnerOidcToken} from './session-runner-oidc.ts';
import {registerSessionRcaDevice} from './session-rca-client.ts';
import {recoverDeviceId} from './v2-session-client.ts';
import {maintainAuthenticatedDeviceSession} from './v2-connection-lifecycle.ts';
import type {SessionPhysicalAttempt} from './session-device-identity.ts';
const ENDPOINT='https://rca.lirtual.dpdns.org/';

export function windowsRunnerSessionEnvironment(env:NodeJS.ProcessEnv,platform=process.platform){
 if(platform!=='win32'||env.GITHUB_ACTIONS!=='true'||env.RUNNER_ENVIRONMENT!=='github-hosted'||
    env.GITHUB_WORKFLOW!=='windows')throw Error('Unreviewed Windows Runner context.');
 const run=Number(env.GITHUB_RUN_ID),attempt=Number(env.GITHUB_RUN_ATTEMPT);
 if(!env.ATTEMPT_ID||!env.RUNNER_TEMP||!env.WORKFLOW_ACTION_OIDC_AUDIENCE||
   !env.ACTIONS_ID_TOKEN_REQUEST_URL||!env.ACTIONS_ID_TOKEN_REQUEST_TOKEN||
   !Number.isSafeInteger(run)||run<=0||!Number.isSafeInteger(attempt)||attempt<=0)
   throw Error('Missing Windows Session proof.');
 const physical:SessionPhysicalAttempt={attempt_id:env.ATTEMPT_ID,github_run_id:run,
   github_run_attempt:attempt,workflow_name:'windows'};
 return {physical,runnerTemp:env.RUNNER_TEMP,audience:env.WORKFLOW_ACTION_OIDC_AUDIENCE,
   oidcUrl:env.ACTIONS_ID_TOKEN_REQUEST_URL,oidcToken:env.ACTIONS_ID_TOKEN_REQUEST_TOKEN};
}

/** No user task, service or personal store is created or modified. */
export async function runWindowsSessionRca(env:NodeJS.ProcessEnv=process.env):Promise<void>{
 const e=windowsRunnerSessionEnvironment(env);
 const {dir,identity}=await loadOrCreateWindowsSessionIdentity(e.runnerTemp,e.physical);
 const jwt=await runnerOidcToken(e.oidcUrl,e.oidcToken,e.audience);
 const result=await registerSessionRcaDevice(identity,jwt);
 const keyPath=path.win32.join(dir,'v2-identity.pem');
 await verifiedWindowsSessionFile(dir,'v2-identity.pem',identity.private_key_pem);
 let idExists=false;
 try{await lstat(keyPath+'.device-id');idExists=true;}
 catch(error){if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;}
 if(idExists)checkWindowsSessionAcl('Check',dir);
 const recovered=await recoverDeviceId(ENDPOINT,keyPath);
 if(!idExists)checkWindowsSessionAcl('Seal',dir,'v2-identity.pem.device-id');
 checkWindowsSessionAcl('Check',dir);
 if(recovered!==result.device_id)throw Error('Windows Session recovered a mismatched identity.');
 const receipts=await ensureWindowsSessionReceipts(dir);
 const controller=new AbortController();
 const stop=()=>controller.abort();
 process.on('SIGINT',stop);process.on('SIGTERM',stop);
 const remaining=result.expires_at-Date.now();
 if(remaining<=0)throw Error('Expired Windows Session grant.');
 const deadline=setTimeout(stop,remaining);deadline.unref();
 try{
   await maintainAuthenticatedDeviceSession(ENDPOINT,keyPath,controller.signal,{
     receiptDirectory:receipts,
     onState:state=>{if(state==='rejected')controller.abort();},
   });
 }finally{
   clearTimeout(deadline);process.off('SIGINT',stop);process.off('SIGTERM',stop);
 }
}

if(process.argv[1]&&import.meta.url===pathToFileURL(path.resolve(process.argv[1])).href){
 try{await runWindowsSessionRca();}
 catch{process.stderr.write('Session RCA unavailable; SSH/RDP remain unaffected.\n');process.exitCode=1;}
}
