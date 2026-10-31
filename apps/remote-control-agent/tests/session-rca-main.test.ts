import test from 'node:test';
import assert from 'node:assert/strict';
import {runnerSessionEnvironment,runnerOidcToken} from '../src/session-rca-main.ts';

const base={GITHUB_ACTIONS:'true',RUNNER_ENVIRONMENT:'github-hosted',GITHUB_WORKFLOW:'ubuntu',
  GITHUB_RUN_ID:'1234',GITHUB_RUN_ATTEMPT:'2',ATTEMPT_ID:'123e4567-e89b-42d3-a456-426614174004',
  RUNNER_TEMP:'/tmp/runner-temp',WORKFLOW_ACTION_OIDC_AUDIENCE:'workflow-approved-audience',
  ACTIONS_ID_TOKEN_REQUEST_URL:'https://pipelines.actions.githubusercontent.com/request',
  ACTIONS_ID_TOKEN_REQUEST_TOKEN:'github-runner-action-oidc-token-of-sufficient-length'};

test('only GitHub-hosted Ubuntu physical Session may start foreground RCA',()=>{
 const result=runnerSessionEnvironment(base,'linux');
 assert.equal(result.physical.github_run_id,1234);
 assert.equal(result.physical.github_run_attempt,2);
 for(const change of [
   {GITHUB_ACTIONS:'false'}, {RUNNER_ENVIRONMENT:'self-hosted'},
   {GITHUB_WORKFLOW:'windows'}, {GITHUB_RUN_ATTEMPT:'0'},
   {GITHUB_RUN_ID:'invalid'}, {ACTIONS_ID_TOKEN_REQUEST_TOKEN:''},
 ])assert.throws(()=>runnerSessionEnvironment({...base,...change},'linux'));
 assert.throws(()=>runnerSessionEnvironment(base,'win32'));
});

test('OIDC is obtained only by bounded nonredirecting HTTPS request',async()=>{
 const proof=await runnerOidcToken(base.ACTIONS_ID_TOKEN_REQUEST_URL,base.ACTIONS_ID_TOKEN_REQUEST_TOKEN,
   base.WORKFLOW_ACTION_OIDC_AUDIENCE,async req=>{
     assert.equal(req.redirect,'manual');
     assert.equal(new URL(req.url).searchParams.get('audience'),base.WORKFLOW_ACTION_OIDC_AUDIENCE);
     assert.ok(req.headers.get('authorization')?.startsWith('Bearer '));
     return Response.json({value:'header.payload.signature'});
   });
 assert.equal(proof,'header.payload.signature');
 await assert.rejects(runnerOidcToken('http://malicious.test/token',base.ACTIONS_ID_TOKEN_REQUEST_TOKEN,
   base.WORKFLOW_ACTION_OIDC_AUDIENCE,async()=>{throw Error('must not send')}));
 await assert.rejects(runnerOidcToken(base.ACTIONS_ID_TOKEN_REQUEST_URL,base.ACTIONS_ID_TOKEN_REQUEST_TOKEN,
   base.WORKFLOW_ACTION_OIDC_AUDIENCE,async()=>new Response(null,{status:302})));
});
