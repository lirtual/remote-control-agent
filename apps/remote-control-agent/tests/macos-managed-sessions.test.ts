import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { access, mkdtemp, readFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { ManagedSessions } from "../src/sessions.ts";
import { createAgentExecutionEngine } from "../src/execution.ts";

const native = process.platform==="darwin" && (process.arch==="arm64" || process.arch==="x64");
const sleep=(ms:number)=>new Promise<void>(resolve=>setTimeout(resolve,ms));
const alive=(pid:number)=>{try{process.kill(pid,0);return true;}catch{return false;}};

test("#659 Darwin native owned session starts, prints bounded output, accepts input and stops group children",
  {skip:!native}, async()=>{
  const sessions=new ManagedSessions("/bin/sh");
  const outsider=spawn("/bin/sleep",["30"],{detached:true,stdio:"ignore"});
  try {
    const s=await sessions.start("read input; echo REPLY:$input; sleep 30 & echo CHILD:$!; wait",100);
    assert.equal(s.state,"running");
    assert.equal(await sessions.writeInput(s.session_id,"hello\n"),"completed");
    let output="", pid=0;
    for(let i=0;i<35;i++){
      output=sessions.read(s.session_id,0,16384)?.output??"";
      pid=Number(/CHILD:(\d+)/.exec(output)?.[1]??0);
      if(pid)break;
      await sleep(30);
    }
    assert.match(output,/REPLY:hello/);
    assert.ok(pid>0 && alive(pid),"owned grandchild was present before stop");
    assert.equal(await sessions.terminate(s.session_id),"completed");
    for(let i=0;i<40 && alive(pid);i++)await sleep(25);
    assert.equal(alive(pid),false,"owned grandchild must be terminated");
    assert.equal(alive(outsider.pid!),true,"unrelated process must never be signalled");
    assert.equal(sessions.isQuiescentForUpgrade(),true);
  }finally{await sessions.close();outsider.kill("SIGKILL");}
});

test("#659 Darwin native normal shell exit, own group cleanup and non-replay Receipt",
  {skip:!native},async()=>{
  const root=await mkdtemp(path.join(os.tmpdir(),"rca659-"));
  const marker=path.join(root,"effect.txt");
  const id=randomUUID(), args={command:"echo once >> "+JSON.stringify(marker),timeout_ms:500};
  let engine=createAgentExecutionEngine({receiptDirectory:path.join(root,"db")});
  try {
    const a=await engine.executeTool({tool:"start_process",arguments:args,operation_id:id},new AbortController().signal);
    assert.equal(a?.status,200);
    await sleep(250);
    await engine.close();
    engine=createAgentExecutionEngine({receiptDirectory:path.join(root,"db")});
    const b=await engine.executeTool({tool:"start_process",arguments:args,operation_id:id},new AbortController().signal);
    assert.equal(b?.status,200);
    assert.equal((await readFile(marker,"utf8")).trim(),"once","same operation id cannot start again");
  }finally{await engine.close();await rm(root,{recursive:true,force:true,maxRetries:5,retryDelay:20});}
});

test("#659 Darwin owned deadline uses existing absolute timeout and closes the session",
  {skip:!native},async()=>{
  const sessions=new ManagedSessions("/bin/sh",160);
  try {
    const s=await sessions.start("trap '' TERM; while :; do sleep 2; done",50);
    assert.equal(s.state,"running");
    let state=sessions.get(s.session_id);
    for(let i=0;i<150 && state?.state==="running";i++){await sleep(50);state=sessions.get(s.session_id);}
    assert.equal(state?.state,"failed");
    assert.equal(state?.termination_reason,"deadline_exceeded");
    assert.equal(sessions.isQuiescentForUpgrade(),true);
  }finally{await sessions.close();}
});

test("#659 Darwin revocation fences further admissions and kills only owned group",
  {skip:!native},async()=>{
  const sessions=new ManagedSessions("/bin/sh");
  try {
    const first=await sessions.start("sleep 30",30);
    assert.equal(first.state,"running");
    assert.equal(sessions.isQuiescentForUpgrade(),false);
    assert.equal(await sessions.stopOwnedForRevocation(),"confirmed");
    await assert.rejects(sessions.start("echo never",100),/closed to new starts/);
  }finally{await sessions.close();}
});

test("#659 Darwin helper denies non-owned calls and cannot claim success when control breaks",
  {skip:!native},async()=>{
  const helper=path.resolve(path.dirname(new URL(import.meta.url).pathname),"../.build/darwin-session-supervisor");
  await access(helper);
  const invalid=spawn(helper,["/usr/bin/env","echo unauthorized"],
    {detached:true,stdio:"ignore"});
  assert.equal(await new Promise<number|null>(resolve=>invalid.on("exit",code=>resolve(code))),125);
  // The agent may lose its monitor, but never obtains a stale numeric-PID
  // kill permission. Its control pipe closing triggers the in-group anchor.
  const child=spawn(helper,["/bin/sh","sleep 30"],{detached:true,
    stdio:["pipe","pipe","pipe","pipe","pipe"]});
  const ready=await new Promise<string>((resolve,reject)=>{
    const timeout=setTimeout(()=>reject(Error("helper never proved ownership")),2000);
    child.stdio[4]!.once("data",data=>{clearTimeout(timeout);resolve(String(data));});
  });
  assert.equal(ready,"R");
  child.stdio[3]!.destroy();
  await new Promise<void>((resolve,reject)=>{
    const t=setTimeout(()=>reject(Error("control closure failed to stop monitor")),3000);
    child.on("close",()=>{clearTimeout(t);resolve();});
  });
  assert.notEqual(child.exitCode,0,"loss of control may never look like success");
});

test("#659 Darwin monitor SIGKILL must not leave its anchored group running an effect",
  {skip:!native},async()=>{
  const root=await mkdtemp(path.join(os.tmpdir(),"rca659-crash-"));
  const marker=path.join(root,"must-not-exist");
  const helper=path.resolve(path.dirname(new URL(import.meta.url).pathname),
    "../.build/darwin-session-supervisor");
  const command="sleep 2; echo unguarded > "+JSON.stringify(marker);
  const child=spawn(helper,["/bin/sh",command],{detached:true,
    stdio:["pipe","pipe","pipe","pipe","pipe"]});
  try {
    const ready=await new Promise<string>((resolve,reject)=>{
      const timeout=setTimeout(()=>reject(Error("monitor did not prove ownership")),2000);
      child.stdio[4]!.once("data",data=>{clearTimeout(timeout);resolve(String(data));});
    });
    assert.equal(ready,"R");
    // This kills ONLY our directly spawned monitor. The anchor must notice
    // its owned control pipe's EOF and kill the group before the effect.
    assert.equal(child.kill("SIGKILL"),true);
    await new Promise<void>((resolve,reject)=>{
      const timeout=setTimeout(()=>reject(Error("monitor did not exit")),2000);
      child.once("exit",()=>{clearTimeout(timeout);resolve();});
    });
    await sleep(2400);
    await assert.rejects(access(marker),{code:"ENOENT"},
      "a surviving shell would have performed an unauthorized later effect");
  }finally{
    child.stdio[3]!.destroy();
    if(child.exitCode===null && child.signalCode===null)child.kill("SIGKILL");
    await rm(root,{recursive:true,force:true,maxRetries:5,retryDelay:20});
  }
});
