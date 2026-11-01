/** No installer/pairing prompt: registration request for a reviewed physical Runner only. */
import {randomBytes} from 'node:crypto';
import {spawn} from 'node:child_process';
import {signSessionEnrollmentNonce, validateSessionDeviceIdentity,
  type SessionDeviceIdentity} from './session-device-identity.ts';

const UUID=/^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/;
const ORIGIN='https://rca.lirtual.dpdns.org';
const postPath='/agent/pair/start';
export interface RegisteredSessionDevice{device_id:string;expires_at:number;}

/** Only the trusted RCA origin is allowed; never forward GitHub OIDC to a caller URL. */
export async function registerSessionRcaDevice(
 identity:SessionDeviceIdentity,oidcJwt:string,
 http:(request:Request)=>Promise<Response>=fetch,
):Promise<RegisteredSessionDevice>{
 validateSessionDeviceIdentity(identity,identity.attempt);
 if(typeof oidcJwt!=='string'||oidcJwt.length<32||oidcJwt.length>8192||
    !/^[-A-Za-z0-9_.]+$/.test(oidcJwt))throw Error('Invalid GitHub OIDC proof.');
 const nonce=Buffer.from(randomBytes(18)).toString('base64url');
 const proof=signSessionEnrollmentNonce(identity,nonce);
 const request=new Request(ORIGIN+postPath,{
   method:'POST',redirect:'manual',signal:AbortSignal.timeout(8000),
   headers:{'content-type':'application/json','cache-control':'no-store'},
   body:JSON.stringify({kind:'github_session',attempt_id:identity.attempt.attempt_id,
     oidc_jwt:oidcJwt,public_key:identity.public_key,nonce,proof}),
 });
 const response=await http(request);
 if((response.status!==200&&response.status!==201)||
   Number(response.headers.get('content-length'))>1024)throw Error('Session enrollment unavailable.');
 const body=await response.text();
 if(body.length>1024)throw Error('Unbounded enrollment response.');
 let data:unknown;
 try{data=JSON.parse(body);}catch{throw Error('Malformed enrollment response.');}
 if(!data||typeof data!=='object'||Array.isArray(data))throw Error('Malformed enrollment response.');
 const result=data as Record<string,unknown>;
 if(typeof result.device_id!=='string'||!UUID.test(result.device_id)||
   !Number.isSafeInteger(result.expires_at)||Number(result.expires_at)<=Date.now()||
   !['registered','already_registered'].includes(String(result.status)))
   throw Error('Invalid Session enrollment result.');
 return {device_id:result.device_id,expires_at:result.expires_at as number};
}

// The OIDC-enabled registration process exits immediately after spawning one
// credential-free transport process. Never carry the Runner token/request URL,
// arbitrary repository variables, or secrets into a long-lived Shell-capable Agent.
const SESSION_TRANSPORT_ENV = [
  'GITHUB_ACTIONS', 'RUNNER_ENVIRONMENT', 'GITHUB_WORKFLOW', 'GITHUB_RUN_ID',
  'GITHUB_RUN_ATTEMPT', 'GITHUB_REPOSITORY', 'ATTEMPT_ID', 'RUNNER_TEMP',
  'RUNNER_TRACKING_ID', 'PATH', 'HOME', 'USER', 'LOGNAME', 'SHELL',
  'LANG', 'LC_ALL', 'TMPDIR', 'TMP', 'TEMP',
  'SystemRoot', 'WINDIR', 'COMSPEC', 'PATHEXT', 'HOMEDRIVE', 'HOMEPATH',
  'USERPROFILE', 'APPDATA', 'LOCALAPPDATA', 'PROGRAMDATA',
  'ProgramFiles', 'ProgramFiles(x86)', 'PROCESSOR_ARCHITECTURE',
  'NUMBER_OF_PROCESSORS',
] as const;

export function sessionTransportEnvironment(source:NodeJS.ProcessEnv):NodeJS.ProcessEnv {
  const clean:NodeJS.ProcessEnv={};
  // Windows env keys are case-insensitive, but spreading process.env into a
  // plain object loses that property (e.g. SYSTEMROOT instead of SystemRoot).
  // Only resolve aliases for reviewed allowlist keys, never forward others.
  const entries=Object.entries(source);
  for (const key of SESSION_TRANSPORT_ENV) {
    const exact=source[key];
    const value=typeof exact==='string'?exact:
      entries.find(([name])=>name.toLowerCase()===key.toLowerCase())?.[1];
    if (typeof value==='string') clean[key]=value;
  }
  return clean;
}

export async function spawnSessionTransport(
 entry:string,deviceId:string,expiresAt:number,source:NodeJS.ProcessEnv,
):Promise<void>{
 if(!entry||!UUID.test(deviceId)||!Number.isSafeInteger(expiresAt)||
   expiresAt<=Date.now()||expiresAt>Date.now()+300*60_000)
   throw Error('Invalid credential-free transport launch.');
 const child=spawn(process.execPath,[entry,'--session-transport',deviceId,String(expiresAt)],{
   cwd:process.cwd(),env:sessionTransportEnvironment(source),
   // Windows needs an independent process group after one-shot OIDC parent exits.
   // RUNNER_TRACKING_ID remains inherited so job cleanup still owns this child.
   detached:true,stdio:'ignore',windowsHide:true,
 });
 await new Promise<void>((resolve,reject)=>{
   child.once('spawn',()=>resolve());
   child.once('error',reject);
 });
 child.unref();
}
