import assert from 'node:assert/strict';
import { test } from 'node:test';
import { PassThrough } from 'node:stream';
import { promptInstallMode } from '../src/install-mode.ts';

async function choose(keys) {
  const input = new PassThrough(); input.isTTY = true; input.isRaw = false;
  const modes=[]; input.setRawMode = (v) => { input.isRaw = v; modes.push(v); };
  let pauses=0; const originalPause=input.pause.bind(input);
  input.pause=()=>{pauses++;return originalPause();};
  const output = new PassThrough(); output.isTTY = true;
  let text=''; output.on('data', chunk => { text+=chunk.toString(); });
  const promise=promptInstallMode(input,output);
  for (const key of keys) input.write(key);
  let value;
  try { value=await promise; } catch(e) {value=e;}
  return {value,modes,text,pauses};
}

test('mode selection begins on permanent but requires Enter, with arrow wrap and numeric shortcuts',async()=>{
  const a=await choose(['\r']); assert.equal(a.value,'permanent');
  const b=await choose(['\x1b[A','\r']); assert.equal(b.value,'temporary');
  const c=await choose(['\x1b[B','\r']); assert.equal(c.value,'temporary');
  const d=await choose(['2']); assert.equal(d.value,'temporary');
  const e=await choose(['1']); assert.equal(e.value,'permanent');
  assert.match(a.text,/❯ 1\. 永久/);
  assert.doesNotMatch(a.text,/推荐/);
  assert.deepEqual(b.modes,[true,false]);
  assert.equal(a.pauses,1,'completed prompt must pause TTY to release the Node event loop');
  assert.equal(d.pauses,1);
});

test('Escape and Ctrl+C cancel and always restore terminal mode',async()=>{
  for(const key of ['\x1b','\x03']) {
    const result=await choose([key]);
    assert.match(result.value.message,/cancel/i);
    assert.deepEqual(result.modes,[true,false]);
    assert.equal(result.pauses,1,'cancelled prompt must pause TTY');
  }
});

test('noninteractive input is rejected before showing an enrollment menu',async()=>{
  await assert.rejects(promptInstallMode(new PassThrough(),new PassThrough()),/interactive|TTY/i);
});


test('unexpected TTY EOF cancels promptly and restores the original raw mode', async()=>{
  const input=new PassThrough();input.isTTY=true;input.isRaw=false;
  const changes=[];input.setRawMode=v=>{input.isRaw=v;changes.push(v);};
  const output=new PassThrough();output.isTTY=true;
  const selected=promptInstallMode(input,output);
  input.end();
  await assert.rejects(selected,/closed|cancel/i);
  assert.deepEqual(changes,[true,false]);
});
