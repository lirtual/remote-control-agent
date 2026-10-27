import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { acknowledgeAuthenticatedUpgrade, readNativeUpgradeOutcome } from "../src/windows-upgrade-executor.ts";

const VERSION="v0.1.32-rc.1";
const OPERATION="approved:one-shot-39";
const key=createHash("sha256").update(OPERATION).digest("hex");
async function fixture(fn:(directory:string)=>Promise<void>) {
  const dir=await mkdtemp(path.join(os.tmpdir(),"rca-one-shot-"));
  try { await fn(dir); }
  finally { await rm(dir,{recursive:true,force:true}); }
}
test("only matching signed reconnect plus local receipt creates the exact one-time proof",{
  skip:process.platform!=="win32",
},async()=>{
  await fixture(async dir=>{
    const pending=path.win32.join(dir,"upgrade-pending-"+key+".json");
    await writeFile(pending,JSON.stringify({operation_id:OPERATION,target_version:VERSION}));
    assert.equal(await acknowledgeAuthenticatedUpgrade(dir,"v0.1.31-rc.1",async()=>true),0);
    assert.equal(await acknowledgeAuthenticatedUpgrade(dir,VERSION,async()=>false),0);
    assert.equal((await readdir(dir)).length,1);
    assert.equal(await acknowledgeAuthenticatedUpgrade(dir,VERSION,async id=>id===OPERATION),1);
    const proof=JSON.parse(await readFile(path.win32.join(dir,"upgrade-auth-"+key+".json"),"utf8"));
    assert.deepEqual(proof,{operation_id:OPERATION,target_version:VERSION,status:"authenticated_wss"});
    // Reconnect retries cannot overwrite or mint a new authorization.
    assert.equal(await acknowledgeAuthenticatedUpgrade(dir,VERSION,async()=>true),0);
    assert.equal((await readdir(dir)).length,2);
  });
});
test("malformed, renamed and unsupported pending records never authorize reconnect",{
  skip:process.platform!=="win32",
},async()=>{
  await fixture(async dir=>{
    const spoof="upgrade-pending-"+"f".repeat(64)+".json";
    await writeFile(path.win32.join(dir,spoof),JSON.stringify({
      operation_id:OPERATION,target_version:VERSION}));
    await writeFile(path.win32.join(dir,"upgrade-pending-"+key+".json"),JSON.stringify({
      operation_id:"../bad",target_version:VERSION}));
    assert.equal(await acknowledgeAuthenticatedUpgrade(dir,VERSION,async()=>true),0);
    assert.equal((await readdir(dir)).length,2);
  });
});
test("reviewed WMI watchdog has valid native PowerShell syntax without running Task",{
  skip:process.platform!=="win32",
},()=>{
  const source=fileURLToPath(new URL("../scripts/windows-upgrade-once.ps1",import.meta.url));
  const powershell=path.win32.join(process.env.SystemRoot??"C:\\Windows",
    "System32","WindowsPowerShell","v1.0","powershell.exe");
  const script="$tokens=$null;$errors=$null;[Management.Automation.Language.Parser]::ParseFile('"+
    source.replaceAll("'","''")+"',[ref]$tokens,[ref]$errors)|Out-Null;"+
    "if($errors.Count -gt 0){$errors|Select-Object -First 3|ForEach-Object {Write-Error $_.Message};exit 1}";
  const result=spawnSync(powershell,["-NoProfile","-NonInteractive","-Command",script],{
    encoding:"utf8",windowsHide:true,timeout:10000,maxBuffer:4096});
  assert.equal(result.status,0,"Native watchdog must parse without executing any Task command: "+(result.stderr??"").slice(0,800));
});

test("completed native outcome requires new-version WSS proof and exact operation",{
  skip:process.platform!=="win32",
},async()=>{
  await fixture(async dir=>{
    const outcome=path.win32.join(dir,"upgrade-outcome-"+key+".json");
    const row={operation_id:OPERATION,original_version:"v0.1.31-rc.1",
      target_version:VERSION,status:"completed"};
    await writeFile(outcome,JSON.stringify(row));
    assert.equal(await readNativeUpgradeOutcome(dir,OPERATION,VERSION),null,
      "local switch output cannot bypass signed WSS proof");
    const proof=path.win32.join(dir,"upgrade-auth-"+key+".json");
    await writeFile(proof,JSON.stringify({operation_id:OPERATION,
      target_version:VERSION,status:"authenticated_wss"}));
    assert.equal(await readNativeUpgradeOutcome(dir,OPERATION,"v0.1.31-rc.1"),null);
    assert.equal(await readNativeUpgradeOutcome(dir,OPERATION,VERSION),"completed");
    assert.equal(await readNativeUpgradeOutcome(dir,"other:operation",VERSION),null);
    await writeFile(outcome,JSON.stringify({...row,operation_id:"different"}));
    assert.equal(await readNativeUpgradeOutcome(dir,OPERATION,VERSION),null,
      "mismatching durable result cannot complete operation");
  });
});
test("confirmed rollback is not silently treated as upgrade success",{
  skip:process.platform!=="win32",
},async()=>{
  await fixture(async dir=>{
    await writeFile(path.win32.join(dir,"upgrade-outcome-"+key+".json"),
      JSON.stringify({operation_id:OPERATION,original_version:"v0.1.31-rc.1",
        target_version:VERSION,status:"rolled_back"}));
    assert.equal(await readNativeUpgradeOutcome(dir,OPERATION,VERSION),null);
    assert.equal(await readNativeUpgradeOutcome(dir,OPERATION,"v0.1.31-rc.1"),"rolled_back");
  });
});
