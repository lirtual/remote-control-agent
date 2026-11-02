import assert from "node:assert/strict";
import {spawn} from "node:child_process";
import {createConnection} from "node:net";
import {mkdtemp,readFile,rm} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import {fileURLToPath} from "node:url";
import {test} from "node:test";
import {createAgentExecutionEngine} from "../src/execution.ts";
import {startUpgradeControl,upgradeSocketPath} from "../src/upgrade-control.ts";

const windows=process.platform==="win32"?test:test.skip;
function requestPipe(pipe,action){
  return new Promise((resolve,reject)=>{
    const socket=createConnection(pipe);
    let text="";
    socket.setTimeout(2000,()=>{socket.destroy();reject(Error("pipe timeout"));});
    socket.on("error",reject);
    socket.on("connect",()=>socket.write(action+"\n"));
    socket.on("data",data=>{
      text+=data.toString();
      if(text.endsWith("\n")){socket.end();resolve(text.trim());}
    });
  });
}
async function requestPowershell(key,action,fromTask=false){
  const target=fromTask?"../scripts/windows-user-task.ps1":"../../../install.ps1";
  const source=await readFile(fileURLToPath(new URL(target,import.meta.url)),"utf8");
  const functionText=source.split("function Invoke-AgentUpgradeFreeze(")[1]
    ?.split(fromTask?"if ($Action -eq 'Switch')":"# A Remote Control Shell may schedule")[0];
  assert(functionText,"reviewed Windows PowerShell freeze function missing");
  const command="function Invoke-AgentUpgradeFreeze("+functionText+
    "\nInvoke-AgentUpgradeFreeze '"+key.replaceAll("'","''")+"' '"+action+"'";
  const child=spawn("powershell.exe",["-NoProfile","-NonInteractive","-Command",command],
    {windowsHide:true,stdio:["ignore","pipe","pipe"]});
  let output="",errors="";
  child.stdout.on("data",x=>output+=x);
  child.stderr.on("data",x=>errors+=x);
  const exit=await new Promise((resolve,reject)=>{
    child.once("error",reject);
    child.once("close",resolve);
  });
  return {exit,output,errors};
}
windows("Windows same-user private pipe freezes all admissions; native PowerShell interoperates",async()=>{
  const dir=await mkdtemp(path.join(os.tmpdir(),"rca-pipe-ci-"));
  const key=path.join(dir,"v2-identity.pem");
  const execution=createAgentExecutionEngine({receiptDirectory:path.join(dir,"receipts")});
  let control;
  try {
    assert(upgradeSocketPath(key).startsWith(String.raw`\\.\pipe\rca-upgrade-`));
    control=await startUpgradeControl(execution,key);
    assert.equal(await requestPipe(upgradeSocketPath(key),"freeze"),"ready");
    assert.equal(await requestPipe(upgradeSocketPath(key),"freeze"),"busy");
    assert.equal(await requestPipe(upgradeSocketPath(key),"verify-frozen"),"ready");
    const verified=await requestPowershell(key,"verify-frozen");
    assert.equal(verified.errors,"","Windows PowerShell verification must not emit errors");
    assert.equal(verified.exit,0);
    const taskVerified=await requestPowershell(key,"verify-frozen",true);
    assert.equal(taskVerified.errors,"");
    assert.equal(taskVerified.exit,0);
    const denied=await execution.executeTool({tool:"get_file_info",arguments:{path:dir}},
      new AbortController().signal);
    assert.equal(denied?.status,503);
    const released=await requestPowershell(key,"release");
    assert.equal(released.errors,"","Windows PowerShell release must not emit errors");
    assert.equal(released.exit,0);
    assert.equal(execution.verifyUpgradeFreeze(),false);
    assert.equal(execution.freezeForUpgrade(),true,"owner release restores freeze admission");
    assert.equal(await requestPipe(upgradeSocketPath(key),"release"),"released");
    assert.equal((await requestPowershell(key,"verify-frozen")).exit!==0,true,
      "unfrozen Agent must not satisfy a new Task switch");
  }finally{
    await control?.close();
    await execution.close();
    await rm(dir,{recursive:true,force:true});
  }
});
