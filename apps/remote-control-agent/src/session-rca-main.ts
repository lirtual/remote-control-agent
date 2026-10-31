/** GitHub-hosted Ubuntu Session foreground Agent only; never personal onboarding. */
import {open,lstat,readFile} from 'node:fs/promises';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {loadOrCreateLinuxSessionIdentity} from './session-identity-store.ts';
import {runnerOidcToken} from './session-runner-oidc.ts';
import {registerSessionRcaDevice,spawnSessionTransport} from './session-rca-client.ts';
import {recoverDeviceId} from './v2-session-client.ts';
import {maintainAuthenticatedDeviceSession} from './v2-connection-lifecycle.ts';
import type {SessionPhysicalAttempt} from './session-device-identity.ts';
const ENDPOINT='https://rca.lirtual.dpdns.org/';

export function runnerTransportEnvironment(env:NodeJS.ProcessEnv,platform=process.platform){
 if(platform!=='linux'||env.GITHUB_ACTIONS!=='true'||env.RUNNER_ENVIRONMENT!=='github-hosted'||
     env.GITHUB_WORKFLOW!=='ubuntu')throw Error('Unreviewed Session Runner context.');
 const run=Number(env.GITHUB_RUN_ID),attempt=Number(env.GITHUB_RUN_ATTEMPT);
 if(!env.ATTEMPT_ID||!env.RUNNER_TEMP||
   !Number.isSafeInteger(run)||run<=0||!Number.isSafeInteger(attempt)||attempt<=0)
   throw Error('Missing Session Runner proof.');
 const physical:SessionPhysicalAttempt={attempt_id:env.ATTEMPT_ID,github_run_id:run,
   github_run_attempt:attempt,workflow_name:'ubuntu'};
 return {physical,runnerTemp:env.RUNNER_TEMP};
}

export function runnerSessionEnvironment(env:NodeJS.ProcessEnv,platform=process.platform){
 const physical=runnerTransportEnvironment(env,platform);
 if(!env.WORKFLOW_ACTION_OIDC_AUDIENCE||
   !env.ACTIONS_ID_TOKEN_REQUEST_URL||!env.ACTIONS_ID_TOKEN_REQUEST_TOKEN)
   throw Error('Missing one-shot Session OIDC context.');
 return {...physical,audience:env.WORKFLOW_ACTION_OIDC_AUDIENCE,
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
 const transport=process.argv[2]==='--session-transport';
 if(process.argv.length>2&&!transport)throw Error('Unsupported Session entrypoint mode.');
 const e=transport?runnerTransportEnvironment(env):runnerSessionEnvironment(env);
 const {file,identity}=await loadOrCreateLinuxSessionIdentity(e.runnerTemp,e.physical);
 const keyPath=path.join(path.dirname(file),'v2-identity.pem');
 await ensurePrivateFile(keyPath,identity.private_key_pem);
 if(!transport){
   const registration=runnerSessionEnvironment(env);
   const jwt=await runnerOidcToken(registration.oidcUrl,registration.oidcToken,registration.audience);
   const result=await registerSessionRcaDevice(identity,jwt);
   if(await recoverDeviceId(ENDPOINT,keyPath)!==result.device_id)
     throw Error('Session recovered a mismatched device identity.');
   await spawnSessionTransport(process.argv[1]!,result.device_id,result.expires_at,env);
   return; // Token-bearing one-shot registration must never become the long-lived Agent.
 }
 const result={device_id:process.argv[3],expires_at:Number(process.argv[4])};
 if(!result.device_id||!Number.isSafeInteger(result.expires_at)||
   result.expires_at<=Date.now()||result.expires_at>Date.now()+300*60_000||
   await recoverDeviceId(ENDPOINT,keyPath)!==result.device_id)
   throw Error('Session transport identity or deadline mismatch.');
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
