/** GitHub-hosted Ubuntu Session foreground Agent only; never personal onboarding. */
import {open,lstat,readFile} from 'node:fs/promises';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {loadOrCreateLinuxSessionIdentity} from './session-identity-store.ts';
import {runnerOidcToken} from './session-runner-oidc.ts';
import {registerSessionRcaDevice} from './session-rca-client.ts';
import {recoverDeviceId} from './v2-session-client.ts';
import {maintainAuthenticatedDeviceSession} from './v2-connection-lifecycle.ts';
import type {SessionPhysicalAttempt} from './session-device-identity.ts';
const ENDPOINT='https://rca.lirtual.dpdns.org/';

export function runnerSessionEnvironment(env:NodeJS.ProcessEnv,platform=process.platform){
 if(platform!=='linux'||env.GITHUB_ACTIONS!=='true'||env.RUNNER_ENVIRONMENT!=='github-hosted'||
     env.GITHUB_WORKFLOW!=='ubuntu')throw Error('Unreviewed Session Runner context.');
 const run=Number(env.GITHUB_RUN_ID),attempt=Number(env.GITHUB_RUN_ATTEMPT);
 if(!env.ATTEMPT_ID||!env.RUNNER_TEMP||!env.WORKFLOW_ACTION_OIDC_AUDIENCE||
   !env.ACTIONS_ID_TOKEN_REQUEST_URL||!env.ACTIONS_ID_TOKEN_REQUEST_TOKEN||
   !Number.isSafeInteger(run)||run<=0||!Number.isSafeInteger(attempt)||attempt<=0)
   throw Error('Missing Session Runner proof.');
 const physical:SessionPhysicalAttempt={attempt_id:env.ATTEMPT_ID,github_run_id:run,
   github_run_attempt:attempt,workflow_name:'ubuntu'};
 return {physical,runnerTemp:env.RUNNER_TEMP,audience:env.WORKFLOW_ACTION_OIDC_AUDIENCE,
   oidcUrl:env.ACTIONS_ID_TOKEN_REQUEST_URL,oidcToken:env.ACTIONS_ID_TOKEN_REQUEST_TOKEN};
}

async function ensurePrivateFile(filename:string,content:string):Promise<void>{
 try{
   const f=await open(filename,'wx',0o600);
   try{await f.writeFile(content,'utf8');await f.sync();}
   finally{await f.close();}
 }catch(error){if((error as NodeJS.ErrnoException).code!=='EEXIST')throw error;}
 const st=await lstat(filename);
 if(!st.isFile()||st.isSymbolicLink()||st.nlink!==1||st.uid!==process.getuid?.()||
    (st.mode&0o077)!==0||(await readFile(filename,'utf8'))!==content)
   throw Error('Session identity file mismatch.');
}

/** Foreground until expiry, GitHub cancellation or SIGTERM; no cron or service. */
export async function runUbuntuSessionRca(env:NodeJS.ProcessEnv=process.env):Promise<void>{
 const e=runnerSessionEnvironment(env);
 const {file,identity}=await loadOrCreateLinuxSessionIdentity(e.runnerTemp,e.physical);
 const jwt=await runnerOidcToken(e.oidcUrl,e.oidcToken,e.audience);
 const result=await registerSessionRcaDevice(identity,jwt);
 const keyPath=path.join(path.dirname(file),'v2-identity.pem');
 await ensurePrivateFile(keyPath,identity.private_key_pem);
 // Server-side signed nonce and device-ID recovery must agree with registration.
 const recovered=await recoverDeviceId(ENDPOINT,keyPath);
 if(recovered!==result.device_id)throw Error('Session recovered a mismatched device identity.');
 const controller=new AbortController();
 const stop=()=>controller.abort();
 process.on('SIGINT',stop);process.on('SIGTERM',stop);
 const remaining=result.expires_at-Date.now();
 if(remaining<=0)throw Error('Expired Session grant.');
 const deadline=setTimeout(stop,remaining);deadline.unref();
 try{
   await maintainAuthenticatedDeviceSession(ENDPOINT,keyPath,controller.signal,{
     receiptDirectory:path.join(path.dirname(file),'receipts'),
     onState:state=>{if(state==='rejected')controller.abort();},
   });
 }finally{
   clearTimeout(deadline);process.off('SIGINT',stop);process.off('SIGTERM',stop);
 }
}

if(process.argv[1]&&import.meta.url===pathToFileURL(path.resolve(process.argv[1])).href){
 try{await runUbuntuSessionRca();}
 catch{process.stderr.write('Session RCA unavailable; SSH/RDP remain unaffected.\n');process.exitCode=1;}
}
