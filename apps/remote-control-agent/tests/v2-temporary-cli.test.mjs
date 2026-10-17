import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { choosePortableInstallMode, keyForInstallMode, renderV2Service } from '../scripts/install-v2.mjs';
import { newEnrollment } from '../src/v2-enrollment.ts';

const home='/home/nonprivileged';
test('#75 mode is mandatory, temporary uses foreground, permanent uses systemd',()=>{
  assert.deepEqual({...choosePortableInstallMode('1')},{grantType:'permanent',foreground:false});
  assert.deepEqual({...choosePortableInstallMode('2')},{grantType:'temporary',foreground:true});
  assert.throws(()=>choosePortableInstallMode(''),/explicitly/);
  assert.throws(()=>choosePortableInstallMode('3'),/explicitly/);
  assert.throws(()=>choosePortableInstallMode('1',['--foreground']),/Permanent installation/);
});
test('#75 temporary identity never aliases permanent private key or device ID',()=>{
  const permanent=keyForInstallMode(home,'permanent');
  const temporary=keyForInstallMode(home,'temporary');
  assert.notEqual(permanent,temporary);
  assert.ok(temporary.startsWith(home+'/'));
  assert.match(temporary,/\/temporary\/v2-identity\.pem$/);
  assert.throws(()=>keyForInstallMode(home,'bad'));
});
test('#75 temporary request grant mode is signed into pending enrollment',()=>{
  const permanent=newEnrollment('host');
  const temporary=newEnrollment('host',undefined,'temporary');
  assert.equal(permanent.request.grant_type,undefined);
  assert.equal(temporary.request.grant_type,'temporary');
  assert.notEqual(temporary.privateKeyPem,permanent.privateKeyPem);
});
test('#75 no temporary service, no new cloud cleanup timer, frontend reuses signed WSS',async()=>{
  const file=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../scripts/install-v2.mjs');
  const script=await readFile(file,'utf8');
  assert.match(script,/options\.foreground = choice === "2"|Object\.assign\(options, choosePortableInstallMode/);
  assert.match(script,/if \(options\.foreground\) \{[\s\S]*?await startForeground\([\s\S]*?return;/);
  assert.match(script,/options\.grantType \?\? "permanent"/);
  assert.match(script,/options\.grantType !== "temporary"/);
  assert.match(script,/options\.grantType \?\? "permanent"\)/);
  assert.match(script,/grantType.*"temporary"/);
  assert.match(script,/import\(portable \? "\.\.\/src\/v2-main\.js"/);
  assert.ok(!script.includes('setInterval('));
});
