import test from 'node:test';
import assert from 'node:assert/strict';
import { createPublicKey, verify } from 'node:crypto';
import { mkdtemp, rm, symlink, chmod, stat, readFile } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { newSessionDeviceIdentity, signSessionEnrollmentNonce, validateSessionDeviceIdentity,
  type SessionPhysicalAttempt } from '../src/session-device-identity.ts';
import { loadOrCreateLinuxSessionIdentity } from '../src/session-identity-store.ts';

const attempt:SessionPhysicalAttempt={attempt_id:'123e4567-e89b-42d3-a456-426614174004',
  github_run_id:1234,github_run_attempt:2,workflow_name:'ubuntu'};

test('fresh identity and nonce proof are scoped to exact physical Attempt',()=>{
  const one=newSessionDeviceIdentity(attempt);
  const two=newSessionDeviceIdentity({...attempt,github_run_attempt:3});
  assert.notEqual(one.public_key,two.public_key);
  validateSessionDeviceIdentity(one,attempt);
  assert.throws(()=>validateSessionDeviceIdentity(one,{...attempt,github_run_attempt:3}));
  assert.throws(()=>validateSessionDeviceIdentity({...one,public_key:two.public_key},attempt));
  assert.throws(()=>newSessionDeviceIdentity({...attempt,github_run_id:0}));
  const nonce='dummy_nonce_AAAAAAAAAAAAAAAAAA';
  const signature=Buffer.from(signSessionEnrollmentNonce(one,nonce),'base64');
  const signed=['remote-control:github-session-enrollment:v1:',
    [attempt.attempt_id,attempt.github_run_id,attempt.github_run_attempt,
      attempt.workflow_name,one.public_key,nonce].join(':')].join('');
  const key=createPublicKey({key:Buffer.from(one.public_key,'base64'),type:'spki',format:'der'});
  assert.equal(verify(null,Buffer.from(signed),key,signature),true);
  assert.equal(verify(null,Buffer.from(signed+'changed'),key,signature),false);
  assert.throws(()=>signSessionEnrollmentNonce(one,'bad'));
});

test('Linux Runner identity is private, concurrent and same-Attempt recoverable',
  {skip:process.platform!=='linux'},async()=>{
    const root=await mkdtemp(path.join(os.tmpdir(),'spec62-agent-'));
    try{
      const results=await Promise.all(Array.from({length:12},()=>loadOrCreateLinuxSessionIdentity(root,attempt)));
      assert.equal(new Set(results.map(x=>x.identity.public_key)).size,1);
      const {file,identity}=results[0]!;
      const st=await stat(file);
      assert.equal(st.mode&0o077,0);
      assert.equal((await stat(path.dirname(file))).mode&0o077,0);
      assert.equal(JSON.parse(await readFile(file,'utf8')).public_key,identity.public_key);
      await assert.rejects(loadOrCreateLinuxSessionIdentity(root,{...attempt,github_run_attempt:3}),
        /another Attempt/);
    }finally{await rm(root,{recursive:true,force:true});}
  });

test('Linux path symlinks and insecure directories fail closed',
  {skip:process.platform!=='linux'},async()=>{
    const root=await mkdtemp(path.join(os.tmpdir(),'spec62-agent-'));
    const alias=root+'-alias';
    try{
      await symlink(root,alias);
      await assert.rejects(loadOrCreateLinuxSessionIdentity(alias,attempt),/Unsafe Session directory/);
      await chmod(root,0o777);
      await assert.rejects(loadOrCreateLinuxSessionIdentity(root,attempt),/Untrusted Runner/);
    }finally{await rm(alias,{force:true});await rm(root,{recursive:true,force:true});}
  });
