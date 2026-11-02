import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {randomUUID,createPublicKey,createPrivateKey,verify} from 'node:crypto';
import {newEnrollment} from '../src/v2-enrollment.ts';
import {sendSignedOwnerIntent,signedOwnerIntentProof,verifyPermanentOwnerStopChallenge} from '../src/v2-session-client.ts';

test('explicit local owner Stop/Resume uses distinct fresh Ed25519 domain, not WSS proof',async()=>{
 const directory=await mkdtemp(path.join(tmpdir(),'rca666-signed-'));
 try{
  const id=randomUUID(),identity=newEnrollment('owner');
  const key=path.join(directory,'id.pem');
  await writeFile(key,identity.privateKeyPem,{mode:0o600});
  await writeFile(key+'.device-id',id,{mode:0o600});
  const generation=2,nonce='A'.repeat(24),calls:string[]=[];
  const mock=async(input:string|URL|Request,init?:RequestInit)=>{
   const route=new URL(String(input)).pathname;
   calls.push(route);
   const body=JSON.parse(String(init?.body));
   if(route==='/agent/owner/intent/challenge'){
    assert.deepEqual(body,{action:'stop',device_id:id});
    return Response.json({device_id:id,action:'stop',nonce,generation});
   }
   assert.equal(route,'/agent/owner/intent');
   assert.deepEqual(Object.keys(body).sort(),['action','device_id','generation','nonce','proof']);
   const publicKey=createPublicKey(createPrivateKey(identity.privateKeyPem));
   const message=`remote-control:v2:owner-intent:v1:stop:${id}:${generation}:${nonce}:${identity.request.public_key}`;
   assert.equal(verify(null,Buffer.from(message),publicKey,Buffer.from(body.proof,'base64url')),true);
   assert.notEqual(body.proof,signedOwnerIntentProof(identity.privateKeyPem,'resume',id,nonce,generation));
   return Response.json({device_id:id,status:'stopped',idle_expires_at:Date.now()+14*86_400_000});
  };
  const result=await sendSignedOwnerIntent('https://rca.example.test/',key,'stop',mock as typeof fetch);
  assert.equal(result.status,'stopped');
  assert.deepEqual(calls,['/agent/owner/intent/challenge','/agent/owner/intent']);
  await assert.rejects(sendSignedOwnerIntent('http://evil.example/',key,'stop',mock as typeof fetch));
 }finally{await rm(directory,{recursive:true,force:true});}
});


test("legacy mode verifies permanent-only challenge without signed Stop/Resume mutation",async()=>{
  const id=randomUUID(),origin="https://rca.example.test/";
  const accepted={device_id:id,action:"stop",nonce:"A".repeat(24),generation:1};
  let calls=0;
  const mock=async(input:string|URL|Request,init?:RequestInit)=>{
    assert.equal(new URL(String(input)).pathname,"/agent/owner/intent/challenge");
    assert.deepEqual(JSON.parse(String(init?.body)),{action:"stop",device_id:id});
    assert.equal(init?.redirect,"error");
    calls++;
    return Response.json(accepted);
  };
  await verifyPermanentOwnerStopChallenge(origin,id,mock as typeof fetch);
  assert.equal(calls,1);
  for(const response of [
    {status:404,body:{error:"not_found"}},
    {status:503,body:{error:"unavailable"}},
    {status:200,body:{...accepted,device_id:randomUUID()}},
    {status:200,body:{...accepted,action:"resume"}},
    {status:200,body:{...accepted,nonce:"not-a-nonce"}},
    {status:200,body:{...accepted,generation:-1}},
  ]){
    const stub=async()=>Response.json(response.body,{status:response.status});
    await assert.rejects(verifyPermanentOwnerStopChallenge(origin,id,stub as typeof fetch));
  }
  await assert.rejects(verifyPermanentOwnerStopChallenge("https://evil.test/path",id,mock as typeof fetch));
  await assert.rejects(verifyPermanentOwnerStopChallenge(origin,"bad-id",mock as typeof fetch));
});
