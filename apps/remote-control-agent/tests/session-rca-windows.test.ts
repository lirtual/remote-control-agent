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
  await writeTransportStage(dir,'store_ready');
  assert.equal(await readFile(checkpoint,'utf8'),'store_ready\n');
  await writeTransportStage(dir,'pem_ready');
  assert.equal(await readFile(checkpoint,'utf8'),'pem_ready\n');
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
test('Windows Session child inherits only the reviewed identity/ACL environment',async()=>{
 const {sessionTransportEnvironment}=await import('../src/session-rca-client.ts');
 const source:NodeJS.ProcessEnv={...runner,SystemRoot:'C:\\Windows',
  PATH:'C:\\Windows\\System32',USERPROFILE:'C:\\Users\\runneradmin',
  TEMP:'C:\\a\\_temp',GITHUB_TOKEN:'synthetic-never-forwarded',
  ACTIONS_RUNTIME_TOKEN:'synthetic-never-forwarded',
 };
 const child=sessionTransportEnvironment(source);
 for(const key of ['GITHUB_ACTIONS','RUNNER_ENVIRONMENT','GITHUB_WORKFLOW',
  'GITHUB_RUN_ID','GITHUB_RUN_ATTEMPT','ATTEMPT_ID','RUNNER_TEMP',
  'SystemRoot','PATH','USERPROFILE','TEMP'])
  assert.equal(child[key],source[key],key);
 for(const key of ['ACTIONS_ID_TOKEN_REQUEST_URL','ACTIONS_ID_TOKEN_REQUEST_TOKEN',
  'WORKFLOW_ACTION_OIDC_AUDIENCE','GITHUB_TOKEN','ACTIONS_RUNTIME_TOKEN'])
  assert.equal(child[key],undefined,key);
 assert.equal(windowsRunnerTransportEnvironment(child,'win32').physical.attempt_id,
  runner.ATTEMPT_ID);
});

test('Windows child allowlist preserves host keys after a case-changing env copy',async()=>{
 const {sessionTransportEnvironment}=await import('../src/session-rca-client.ts');
 const source:NodeJS.ProcessEnv={...runner,
  SYSTEMROOT:'C:\\Windows',Path:'C:\\Windows\\System32',
  GITHUB_TOKEN:'synthetic-not-forwarded',
  actions_id_token_request_token:'synthetic-not-forwarded'};
 const env=sessionTransportEnvironment(source);
 assert.equal(env.SystemRoot,source.SYSTEMROOT);
 assert.equal(env.PATH,source.Path);
 assert.equal(env.GITHUB_ACTIONS,source.GITHUB_ACTIONS);
 assert.equal(env.GITHUB_TOKEN,undefined);
 assert.equal(env.actions_id_token_request_token,undefined);
 assert.equal(env.ACTIONS_ID_TOKEN_REQUEST_TOKEN,undefined);
});

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
  PSModulePath:'Z:\\no-untrusted-WindowsPowerShell-modules',
 };
 const childEnv=sessionTransportEnvironment(source);
 assert.equal(childEnv.SystemRoot,process.env.SystemRoot,
  'Windows SystemRoot preserved through a copied environment');
 assert.equal(childEnv.PATH,process.env.PATH,
  'Windows PATH preserved through a copied environment');
 assert.equal(childEnv.ACTIONS_ID_TOKEN_REQUEST_URL,undefined);
 assert.equal(childEnv.ACTIONS_ID_TOKEN_REQUEST_TOKEN,undefined);
 assert.equal(childEnv.PSModulePath,undefined);
 const url=pathToFileURL(path.resolve('src/session-windows-identity-store.ts')).href;
 const program=`
  import {spawnSync as launchNative} from 'node:child_process';
  import path from 'node:path';
  import {loadOrCreateWindowsSessionIdentity,verifiedWindowsSessionFile,
   checkWindowsSessionAcl} from ${JSON.stringify(url)};
  const physical={attempt_id:process.env.ATTEMPT_ID,
   github_run_id:Number(process.env.GITHUB_RUN_ID),
   github_run_attempt:Number(process.env.GITHUB_RUN_ATTEMPT),workflow_name:'windows'};
  let phase='store';
  try{
  const {dir,identity}=await loadOrCreateWindowsSessionIdentity(
   process.env.RUNNER_TEMP,physical);
  phase='pem';
  await verifiedWindowsSessionFile(dir,'v2-identity.pem',identity.private_key_pem);
  phase='sidecar';
  await verifiedWindowsSessionFile(dir,'v2-identity.pem.device-id',
    '123e4567-e89b-42d3-a456-426614174005'+String.fromCharCode(10));
  phase='checkpoint';
  await verifiedWindowsSessionFile(dir,'transport-stage',
    'pending'+String.fromCharCode(10));
  phase='final_acl';
  checkWindowsSessionAcl('Check',dir);
  process.stdout.write('identity_ready');
  }catch(e){
   const message=e instanceof Error?e.message:'';
   const cause=message==='Session ACL helper timed out.'?'acl_timeout':
    message==='Session job-private ACL check refused.'?'acl_refused':'other';
   // A fixed, no-script native startup probe distinguishes an unresponsive
   // PowerShell process from the ACL script itself. Never print raw errors.
   const ps=path.win32.join(process.env.SystemRoot,
     'System32','WindowsPowerShell','v1.0','powershell.exe');
   const probe=launchNative(ps,['-NoProfile','-NonInteractive','-Command','exit 0'],
     {windowsHide:true,timeout:5000,stdio:'ignore'});
   const start=probe.error?.code==='ETIMEDOUT'?'startup_timeout':
     probe.status===0?'startup_ok':'startup_other';
   process.stdout.write('failed_'+phase+'_'+cause+'_'+start);process.exitCode=1;
  }
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
  const safePhase=/^failed_(store|pem|sidecar|checkpoint|final_acl)_(acl_timeout|acl_refused|other)_(startup_timeout|startup_ok|startup_other)$/.test(child.stdout)?
    child.stdout:'unknown';
  assert.equal(child.status,0,'OIDC-stripped native child recovery: '+safePhase);
  assert.equal(child.stdout,'identity_ready');
 }finally{await rm(root,{recursive:true,force:true});}
});


// Synthetic physical Attempt, no network, real detached/stdio:ignore/unref launcher.
// Proves that a fresh credential-free Windows child can still perform ACL
// identity recovery after its one-shot registration parent exits.
test('native detached credential-free child recovers after parent exit',
 {skip:process.platform!=='win32'}, async()=>{
 const {spawnSync}=await import('node:child_process');
 const {mkdtemp,writeFile,readFile,rm}=await import('node:fs/promises');
 const {tmpdir}=await import('node:os');
 const path=await import('node:path');
 const {pathToFileURL}=await import('node:url');
 const root=await mkdtemp(path.join(tmpdir(),'rca-detached-native-fixture-'));
 const store=pathToFileURL(path.resolve('src/session-windows-identity-store.ts')).href;
 const client=pathToFileURL(path.resolve('src/session-rca-client.ts')).href;
 const windows=pathToFileURL(path.resolve('src/session-rca-windows.ts')).href;
 const deviceId='123e4567-e89b-42d3-a456-426614174005';
 const entry=path.join(root,'synthetic-child.mjs');
 const childCode=[
  "import path from 'node:path';",
  "import {lstat,writeFile} from 'node:fs/promises';",
  "import {loadOrCreateWindowsSessionIdentity,verifiedWindowsSessionFile,checkWindowsSessionAcl} from "+JSON.stringify(store)+";",
  "import {writeTransportStage,windowsRunnerTransportEnvironment} from "+JSON.stringify(windows)+";",
  "const e=windowsRunnerTransportEnvironment(process.env,'win32');",
  "const checkpoint=path.win32.join(e.runnerTemp,'session-rca');",
  "await writeTransportStage(checkpoint,'entered');",
  "let phase='store';try{",
  "const {dir,identity}=await loadOrCreateWindowsSessionIdentity(e.runnerTemp,e.physical);",
  "phase='pem';",
  "await writeTransportStage(dir,'store_ready');",
  "const key=path.win32.join(dir,'v2-identity.pem');",
  "await verifiedWindowsSessionFile(dir,'v2-identity.pem',identity.private_key_pem);",
  "await writeTransportStage(dir,'pem_ready');phase='sidecar';",
  "await lstat(key+'.device-id');",
  "checkWindowsSessionAcl('Check',dir);",
  "await writeTransportStage(dir,'identity_ready');",
  "}catch(e){",
  "const message=e instanceof Error?e.message:'';",
  "const cause=message==='Session ACL helper timed out.'?'acl_timeout':message==='Session job-private ACL check refused.'?'acl_refused':'other';",
  "await writeFile(path.win32.join(e.runnerTemp,'synthetic-child-failure'),'failed_'+phase+'_'+cause,'utf8');",
  "}",
 ].join(String.fromCharCode(10));
 const parentCode=[
  "import {loadOrCreateWindowsSessionIdentity,verifiedWindowsSessionFile} from "+JSON.stringify(store)+";",
  "import {spawnSessionTransport} from "+JSON.stringify(client)+";",
  "const physical={attempt_id:process.env.ATTEMPT_ID,github_run_id:Number(process.env.GITHUB_RUN_ID),github_run_attempt:Number(process.env.GITHUB_RUN_ATTEMPT),workflow_name:'windows'};",
  "const {dir,identity}=await loadOrCreateWindowsSessionIdentity(process.env.RUNNER_TEMP,physical);",
  "await verifiedWindowsSessionFile(dir,'v2-identity.pem',identity.private_key_pem);",
  "await verifiedWindowsSessionFile(dir,'v2-identity.pem.device-id',"+JSON.stringify(deviceId+'\n')+");",
  "await verifiedWindowsSessionFile(dir,'transport-stage','pending'+String.fromCharCode(10));",
  "await spawnSessionTransport("+JSON.stringify(entry)+","+JSON.stringify(deviceId)+",Date.now()+90000,process.env);",
 ].join(String.fromCharCode(10));
 const env:NodeJS.ProcessEnv={...process.env,
  GITHUB_ACTIONS:'true',RUNNER_ENVIRONMENT:'github-hosted',GITHUB_WORKFLOW:'windows',
  GITHUB_RUN_ID:'1234',GITHUB_RUN_ATTEMPT:'2',
  ATTEMPT_ID:'123e4567-e89b-42d3-a456-426614174004',
  RUNNER_TEMP:root,RUNNER_TRACKING_ID:'synthetic-detached-child',
  ACTIONS_ID_TOKEN_REQUEST_URL:'https://example.test/never-requested',
  ACTIONS_ID_TOKEN_REQUEST_TOKEN:'SYNTHETIC_NEVER_FORWARDED',
 };
 try{
  await writeFile(entry,childCode,'utf8');
  const parent=spawnSync(process.execPath,
   ['--experimental-strip-types','--input-type=module','--eval',parentCode],
   {cwd:process.cwd(),env,windowsHide:true,encoding:'utf8',timeout:45000});
  assert.equal(parent.error,undefined);
  assert.equal(parent.status,0,'one-shot native parent did not exit');
  let stage='';
  const until=Date.now()+25000;
  while(Date.now()<until){
   try{stage=await readFile(path.join(root,'session-rca','transport-stage'),'utf8');}
   catch{}
   if(stage==='identity_ready\n')break;
   await new Promise(resolve=>setTimeout(resolve,200));
  }
  let safeFailure='unknown';
  try{
   const value=await readFile(path.join(root,'synthetic-child-failure'),'utf8');
   if(/^failed_(store|pem|sidecar)_(acl_timeout|acl_refused|other)$/.test(value))safeFailure=value;
  }catch{}
  assert.equal(stage,'identity_ready\n',
   'real detached child did not recover identity after parent exited: '+safeFailure);
 }finally{
  await rm(root,{recursive:true,force:true});
 }
});
