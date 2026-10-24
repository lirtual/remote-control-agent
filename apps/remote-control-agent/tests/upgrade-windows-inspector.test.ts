import test from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import {
  inspectWindowsTaskStructure,inspectWindowsLocalUpgradeTask,
  type WindowsTaskSnapshot,
} from "../src/upgrade-windows-inspector.ts";
import type {UpgradeRequest} from "../src/upgrade-authorization.ts";

const sid="S-1-5-21-704629843-1123557057-3086105933-1001";
const root="C:\\Users\\0\\AppData\\Local\\mcp-workers\\remote-control\\programs\\v0.1.23-windows-x64";
const endpoint="https://rca.lirtual.dpdns.org/";
const entry=path.win32.join(root,"apps/remote-control-agent/src/windows-v2.js");
const task:WindowsTaskSnapshot={
  taskName:"RCA-Remote-Control-v2-"+sid.replace(/-/g,"_"),
  state:4,sid,principal:sid,actionCount:1,
  execute:path.win32.join(root,"bin/rca-background.exe"),
  arguments:'"'+entry+'" run --endpoint "'+endpoint+'"',
  workingDirectory:path.win32.dirname(entry),
};
test("exact owner task, executable, entrypoint and endpoint return structural evidence only",()=>{
  const result=inspectWindowsTaskStructure(task,root,sid,endpoint);
  assert.deepEqual(result,{
    taskRunning:true,taskActionMatches:true,bundleManifestMatches:false,
  });
});
test("stopped task is never reported as running",()=>{
  const result=inspectWindowsTaskStructure({...task,state:3},root,sid,endpoint);
  assert.equal(result.taskRunning,false);
  assert.equal(result.taskActionMatches,true);
});
test("different principal, SID, task name or extra action fails closed",()=>{
  for(const patch of [
    {principal:"S-1-5-21-1-2-3-4"},
    {sid:"S-1-5-21-1-2-3-4"},
    {taskName:"Some-Other-Task"},
    {actionCount:2},
  ])assert.equal(inspectWindowsTaskStructure({...task,...patch},root,sid,endpoint).taskActionMatches,false);
});
test("an alternate executable, version, entrypoint, argument or working directory is refused",()=>{
  for(const patch of [
    {execute:"C:\\Windows\\System32\\cmd.exe"},
    {arguments:task.arguments.replace("v0.1.23","v0.1.22")},
    {arguments:task.arguments+" --extra"},
    {workingDirectory:"C:\\Users\\Public"},
  ])assert.equal(inspectWindowsTaskStructure({...task,...patch},root,sid,endpoint).taskActionMatches,false);
  assert.equal(inspectWindowsTaskStructure(task,root.replace("v0.1.23","v0.1.24"),sid,endpoint).taskActionMatches,false);
});
test("unapproved endpoint redirects, URL credentials and unsafe URL components are refused",()=>{
  for(const url of ["http://rca.lirtual.dpdns.org/","https://user:pass@rca.example/",
    "https://rca.example/path","https://rca.example/?x=1",
    "https://rca.example/#fragment"]){
    const alt={...task,arguments:'"'+entry+'" run --endpoint "'+url+'"'};
    assert.equal(inspectWindowsTaskStructure(alt,root,sid,url).taskActionMatches,false);
  }
  assert.equal(inspectWindowsTaskStructure(task,root,sid,"https://different.example/").taskActionMatches,false);
  // A well-formed but attacker-controlled URL is not the trusted endpoint.
  const altered={...task,arguments:task.arguments.replace(endpoint,"https://attacker.example/")};
  assert.equal(inspectWindowsTaskStructure(altered,root,sid,endpoint).taskActionMatches,false);
});
test("native Windows inspection never claims executable or key provenance from a task alone",async()=>{
  const req:UpgradeRequest={
    operation_id:"windows-structural-only",device_id:"2a83dae6-600c-49cc-b643-ab0d5ec7e0c8",
    source_version:"v0.1.22",target_version:"v0.1.23",
    target_commit:"a".repeat(40),target_sha256:"b".repeat(64),
    target_platform:"windows-x64",identity_sha256:"c".repeat(64),
    authorized_until:1792845120000,
  };
  if(process.platform!=="win32") {
    assert.deepEqual(await inspectWindowsLocalUpgradeTask(req,endpoint),{
      taskRunning:false,taskActionMatches:false,bundleManifestMatches:false,
    });
  }
});
