import test from 'node:test';
import assert from 'node:assert/strict';
import {windowsRunnerSessionEnvironment,windowsRunnerTransportEnvironment,writeTransportStage} from '../src/session-rca-windows.ts';

const runner={
 GITHUB_ACTIONS:'true',RUNNER_ENVIRONMENT:'github-hosted',GITHUB_WORKFLOW:'windows',
 GITHUB_RUN_ID:'1234',GITHUB_RUN_ATTEMPT:'2',
 ATTEMPT_ID:'123e4567-e89b-42d3-a456-426614174004',
 RUNNER_TEMP:'C:\\a\\_temp',WORKFLOW_ACTION_OIDC_AUDIENCE:'workflow-approved-audience',
 ACTIONS_ID_TOKEN_REQUEST_URL:'https://pipelines.actions.githubusercontent.com/request',
 ACTIONS_ID_TOKEN_REQUEST_TOKEN:'github-runner-action-oidc-token-of-sufficient-length',
};

test('Windows Session entry requires exact GitHub-hosted physical Runner evidence',()=>{
 const parsed=windowsRunnerSessionEnvironment(runner,'win32');
 assert.deepEqual(parsed.physical,{
  attempt_id:runner.ATTEMPT_ID,github_run_id:1234,
  github_run_attempt:2,workflow_name:'windows',
 });
 for(const override of [
  {GITHUB_ACTIONS:'false'},{RUNNER_ENVIRONMENT:'self-hosted'},
  {GITHUB_WORKFLOW:'ubuntu'},{GITHUB_RUN_ID:'invalid'},
  {GITHUB_RUN_ATTEMPT:'0'},{ATTEMPT_ID:''},{RUNNER_TEMP:''},
  {WORKFLOW_ACTION_OIDC_AUDIENCE:''},{ACTIONS_ID_TOKEN_REQUEST_URL:''},
  {ACTIONS_ID_TOKEN_REQUEST_TOKEN:''},
 ])assert.throws(()=>windowsRunnerSessionEnvironment({...runner,...override},'win32'));
 assert.throws(()=>windowsRunnerSessionEnvironment(runner,'linux'));
});

test('Windows credential-free transport verifies Runner context without OIDC',()=>{
 const safe={GITHUB_ACTIONS:'true',RUNNER_ENVIRONMENT:'github-hosted',
   GITHUB_WORKFLOW:'windows',GITHUB_RUN_ID:'1234',GITHUB_RUN_ATTEMPT:'1',
   ATTEMPT_ID:'123e4567-e89b-42d3-a456-426614174004',RUNNER_TEMP:'C:\\Temp'};
 assert.equal(windowsRunnerTransportEnvironment(safe,'win32').physical.github_run_id,1234);
 assert.throws(()=>windowsRunnerSessionEnvironment(safe,'win32'));
 assert.throws(()=>windowsRunnerTransportEnvironment({...safe,GITHUB_RUN_ATTEMPT:'0'},'win32'));
});


test('native Windows transport stage stays in the sealed job-private file',
 {skip:process.platform!=='win32'}, async()=>{
 const {spawnSync}=await import('node:child_process');
 const {mkdtemp,rm,readFile,writeFile}=await import('node:fs/promises');
 const os=await import('node:os');
 const path=await import('node:path');
 const root=await mkdtemp(path.join(os.tmpdir(),'rca-session-stage-'));
 try{
  const env:NodeJS.ProcessEnv={...process.env,GITHUB_ACTIONS:'true',RUNNER_ENVIRONMENT:'github-hosted',RUNNER_TEMP:root};
  const powershell=path.win32.join(env.SystemRoot!,'System32','WindowsPowerShell','v1.0','powershell.exe');
  const script=path.resolve('scripts/windows-session-private-store.ps1');
  const dir=path.join(root,'session-rca');
  const native=(action:'Init'|'Check'|'Seal',file?:string)=>{
    const process=spawnSync(powershell,['-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass',
      '-File',script,'-Action',action,'-Directory',dir,...(file?['-FileName',file]:[])],
      {env,windowsHide:true,encoding:'utf8',timeout:15000});
    assert.equal(process.error,undefined);
    assert.equal(process.status,0,'exact private ACL action '+action);
  };
  native('Init');
  const checkpoint=path.join(dir,'transport-stage');
  await writeFile(checkpoint,'pending\n',{flag:'wx'});
  native('Seal','transport-stage');
  native('Check');
  await writeTransportStage(dir,'challenge_ok');
  assert.equal(await readFile(checkpoint,'utf8'),'challenge_ok\n');
  native('Check');
 }finally{await rm(root,{recursive:true,force:true});}
});

test('fixed credential-free connection stages identify WSS handshake and policy denial',async()=>{
 const {mkdtemp,rm,writeFile}=await import('node:fs/promises');
 const {tmpdir}=await import('node:os');
 const path=await import('node:path');
 const {generateKeyPairSync}=await import('node:crypto');
 const {openAuthenticatedDeviceSocket,DeviceSessionRejectedError}=await import('../src/v2-session-client.ts');
 const dir=await mkdtemp(path.join(tmpdir(),'rca-session-stage-'));
 const id='123e4567-e89b-42d3-a456-426614174004';
 try{
  const {privateKey}=generateKeyPairSync('ed25519');
  const key=path.join(dir,'v2-identity.pem');
  await writeFile(key,privateKey.export({type:'pkcs8',format:'pem'}).toString());
  await writeFile(key+'.device-id',id+'\n');
  const stages:string[]=[];
  const send=async()=>new Response(JSON.stringify({device_id:id,nonce:'A'.repeat(24)}),
    {status:200,headers:{'content-type':'application/json'}});
  const fake=new EventTarget() as EventTarget & {
    protocol:string;readyState:number;close:()=>void;
  };
  fake.protocol='rc-v2';fake.readyState=WebSocket.OPEN;fake.close=()=>{};
  const connected=await openAuthenticatedDeviceSocket('https://rca.example.test/',key,
    send as typeof fetch,()=>fake as WebSocket,undefined,stage=>stages.push(stage));
  assert.equal(connected.device_id,id);
  assert.deepEqual(stages,['challenge_start','challenge_ok','wss_start','wss_open']);
  const denied:string[]=[];
  const reject=async()=>new Response('',{status:403});
  await assert.rejects(
    openAuthenticatedDeviceSocket('https://rca.example.test/',key,reject as typeof fetch,
      undefined,undefined,stage=>denied.push(stage)),DeviceSessionRejectedError);
  assert.deepEqual(denied,['challenge_start','challenge_rejected']);
 }finally{await rm(dir,{recursive:true,force:true});}
});


// Regression: the previous fixture tested ACL operations in isolation using
// the entire CI environment. Exercise the complete identity/PEM/sidecar path
// through separate native Windows processes, using the actual OIDC-stripped
// transport allowlist and no network or real GitHub credentials.
test('native Windows Session identity recovers in the exact no-OIDC child environment',
 {skip:process.platform!=='win32'}, async()=>{
 const {spawnSync}=await import('node:child_process');
 const {mkdtemp,rm}=await import('node:fs/promises');
 const {tmpdir}=await import('node:os');
 const path=await import('node:path');
 const {pathToFileURL}=await import('node:url');
 const {sessionTransportEnvironment}=await import('../src/session-rca-client.ts');
 const root=await mkdtemp(path.join(tmpdir(),'rca-session-child-native-'));
 const attempt='123e4567-e89b-42d3-a456-426614174004';
 const source:NodeJS.ProcessEnv={...process.env,
  GITHUB_ACTIONS:'true',RUNNER_ENVIRONMENT:'github-hosted',
  GITHUB_WORKFLOW:'windows',GITHUB_RUN_ID:'1234',GITHUB_RUN_ATTEMPT:'2',
  ATTEMPT_ID:attempt,RUNNER_TEMP:root,
  ACTIONS_ID_TOKEN_REQUEST_URL:'https://example.test/synthetic-no-network',
  ACTIONS_ID_TOKEN_REQUEST_TOKEN:'SYNTHETIC_DO_NOT_FORWARD',
 };
 const childEnv=sessionTransportEnvironment(source);
 assert.equal(childEnv.ACTIONS_ID_TOKEN_REQUEST_URL,undefined);
 assert.equal(childEnv.ACTIONS_ID_TOKEN_REQUEST_TOKEN,undefined);
 const url=pathToFileURL(path.resolve('src/session-windows-identity-store.ts')).href;
 const program=`
  import {loadOrCreateWindowsSessionIdentity,verifiedWindowsSessionFile,
   checkWindowsSessionAcl} from ${JSON.stringify(url)};
  const physical={attempt_id:process.env.ATTEMPT_ID,
   github_run_id:Number(process.env.GITHUB_RUN_ID),
   github_run_attempt:Number(process.env.GITHUB_RUN_ATTEMPT),workflow_name:'windows'};
  const {dir,identity}=await loadOrCreateWindowsSessionIdentity(
   process.env.RUNNER_TEMP,physical);
  await verifiedWindowsSessionFile(dir,'v2-identity.pem',identity.private_key_pem);
  await verifiedWindowsSessionFile(dir,'v2-identity.pem.device-id',
    '123e4567-e89b-42d3-a456-426614174005'+String.fromCharCode(10));
  await verifiedWindowsSessionFile(dir,'transport-stage',
    'pending'+String.fromCharCode(10));
  checkWindowsSessionAcl('Check',dir);
  process.stdout.write('identity_ready');
 `;
 const invoke=(env:NodeJS.ProcessEnv)=>spawnSync(process.execPath,
  ['--experimental-strip-types','--input-type=module','--eval',program],
  {cwd:process.cwd(),env,encoding:'utf8',windowsHide:true,timeout:45000});
 try{
  const parent=invoke(source);
  assert.equal(parent.error,undefined);
  assert.equal(parent.status,0,'isolated native parent setup');
  assert.equal(parent.stdout,'identity_ready');
  const child=invoke(childEnv);
  assert.equal(child.error,undefined);
  assert.equal(child.status,0,'OIDC-stripped native child recovery');
  assert.equal(child.stdout,'identity_ready');
 }finally{await rm(root,{recursive:true,force:true});}
});
