/** No installer/pairing prompt: registration request for a reviewed physical Runner only. */
import {randomBytes} from 'node:crypto';
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
