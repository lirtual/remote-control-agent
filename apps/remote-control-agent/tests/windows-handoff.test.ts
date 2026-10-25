/** Real Windows Job Object acceptance, with a disposable executable and no network. */
import assert from "node:assert/strict";
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import test from "node:test";
import { windowsTunnelLauncher } from "../src/protected-tunnel.ts";

test("native job: owner crash, supervisor crash, absolute expiry and unverified binary",{
  skip:process.platform!=="win32",timeout:150_000,
},async()=>{
  const directory=await mkdtemp(path.join(os.tmpdir(),"handoff-job-"));
  const launcher=windowsTunnelLauncher();
  const ps=(script:string,input:unknown)=>{
    const result=spawnSync(launcher.executable,["-NoProfile","-NonInteractive","-Command",script],{
      input:JSON.stringify(input),encoding:"utf8",timeout:30_000,windowsHide:true});
    assert.equal(result.status,0,result.stderr);
    return result.stdout.trim();
  };
  const identity=(pid:number)=>JSON.parse(ps(
    '$x=[Console]::In.ReadToEnd()|ConvertFrom-Json; $p=Get-Process -Id $x.pid; @{pid=$p.Id;started=$p.StartTime.ToUniversalTime().Ticks.ToString();executable=$p.MainModule.FileName}|ConvertTo-Json -Compress',{pid}));
  const gone=(id:{pid:number;started:string})=>ps(
    '$x=[Console]::In.ReadToEnd()|ConvertFrom-Json; $p=Get-Process -Id $x.pid -ErrorAction SilentlyContinue; if($p -and $p.StartTime.ToUniversalTime().Ticks.ToString() -ceq $x.started){"alive"}else{"gone"}',id)==="gone";
  const wait=async(predicate:()=>Promise<boolean>)=>{
    const deadline=Date.now()+10_000;
    while(!await predicate()) {if(Date.now()>deadline)throw Error("native job did not settle");await new Promise(r=>setTimeout(r,100));}
  };
  const executable=path.join(directory,"cloudflared-fixture.exe");
  let owner:ChildProcess|undefined,supervisor:ChildProcess|undefined;
  try {
    ps("$x=[Console]::In.ReadToEnd()|ConvertFrom-Json; Add-Type -TypeDefinition 'public class Fixture { public static void Main() { System.Console.WriteLine(12345); System.Threading.Thread.Sleep(60000); } }' -OutputAssembly $x.executable -OutputType ConsoleApplication",{executable});
    const config={email:"owner@example.com",cloudflared_path:executable,
      cloudflared_sha256:createHash("sha256").update(await readFile(executable)).digest("hex")};
    await writeFile(path.join(directory,"browser-handoff-config.json"),JSON.stringify(config));
    await writeFile(path.join(directory,"browser-handoff-tunnel.yml"),"{}\n");
    for(const mode of ["owner","supervisor","expiry","bad-sha"]){
      owner=spawn(process.execPath,["-e","setInterval(()=>{},1000)"],{windowsHide:true,stdio:"ignore"});
      const ownerId=identity(owner.pid!);
      const marker=path.join(directory,"browser-handoff-child.json");
      await writeFile(marker,JSON.stringify({version:1,owner:ownerId,supervisor:null}));
      supervisor=spawn(launcher.executable,launcher.args,{windowsHide:true,stdio:["pipe","pipe","pipe"]});
      let stdout="";supervisor.stdout!.on("data",b=>{stdout+=String(b);});
      let stderr="";supervisor.stderr!.on("data",b=>{stderr+=String(b);});
      const exited=new Promise<number|null>(resolve=>supervisor!.once("exit",resolve));
      const passedConfig=mode==="bad-sha"?{...config,cloudflared_sha256:"0".repeat(64)}:config;
      supervisor.stdin!.end(JSON.stringify({directory,config_directory:directory,marker,config:passedConfig,port:3456,
        owner_pid:ownerId.pid,owner_started:ownerId.started,expires_at:Date.now()+(mode==="expiry"?8000:30_000)}));
      if(mode==="bad-sha"){
        assert.equal(await exited,1);
        assert.equal(JSON.parse(await readFile(marker,"utf8")).child,undefined);
      }else{
        let child!: {pid:number;started:string};
        await wait(async()=>{
          if (supervisor?.exitCode !== null && supervisor?.exitCode !== undefined)
            throw Error(`Supervisor exited before child start: code=${supervisor.exitCode}, ${stderr.slice(0,300)}`);
          try {child=JSON.parse(await readFile(marker,"utf8")).child;return !!child;}catch{return false;}
        });
        if(mode==="owner")owner.kill();
        if(mode==="supervisor")supervisor.kill();
        await exited;
        if(mode==="expiry")assert.match(stdout,/12345/,"child log pipe inherited by native launcher");
        await wait(async()=>gone(child));
        assert.equal(gone(child),true,stderr);
        owner.kill();
        await wait(async()=>gone(ownerId));
        const recovered=spawnSync(launcher.executable,[...launcher.args,"-Action","Recover"],{
          input:JSON.stringify({marker}),encoding:"utf8",timeout:15_000,windowsHide:true});
        assert.equal(recovered.status,0,recovered.stderr);
        assert.equal(recovered.stdout.trim(),"confirmed");
      }
      owner.kill();supervisor.kill();
    }
    owner=spawn(process.execPath,["-e","setInterval(()=>{},1000)"],{windowsHide:true,stdio:"ignore"});
    const live=identity(owner.pid!);
    const marker=path.join(directory,"browser-handoff-child.json");
    const reused={...live,started:"100000000000000000"};
    const recover=()=>spawnSync(launcher.executable,[...launcher.args,"-Action","Recover"],{
      input:JSON.stringify({marker}),encoding:"utf8",timeout:15_000,windowsHide:true});
    await writeFile(marker,JSON.stringify({version:1,owner:reused,
      supervisor:{...live,executable:"C:\\unrecognized-supervisor.exe"},child:reused}));
    assert.equal(recover().status,1,"matching PID/start but unknown executable must remain blocked");
    assert.equal(gone(live),false,"ambiguous identity must never kill an unrelated process");
    await writeFile(marker,JSON.stringify({version:1,owner:reused,supervisor:reused,child:reused}));
    assert.equal(recover().status,0,"reused PID is proof the original process exited");
    assert.equal(gone(live),false,"reused PID must never be killed");
  }finally{
    owner?.kill();supervisor?.kill();
    await rm(directory,{recursive:true,force:true});
  }
});
