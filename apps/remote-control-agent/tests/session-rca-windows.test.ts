import test from 'node:test';
import assert from 'node:assert/strict';
import {windowsRunnerSessionEnvironment,windowsRunnerTransportEnvironment} from '../src/session-rca-windows.ts';

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
