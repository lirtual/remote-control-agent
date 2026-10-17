import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile, chmod, mkdir } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { inspectInstallIdentity, persistRecoveredDeviceId } from "../scripts/install-v2.mjs";

const id="e11d9c70-16fe-4d47-aafc-d01db72750fd";
test("#76 signed recovery after approval but before local ID fsync preserves private key",async()=>{
  const dir=await mkdtemp(path.join(os.tmpdir(),"rc-recover-id-"));
  const key=path.join(dir,"private.pem");
  try {
    await chmod(dir,0o700);
    await writeFile(key,"unchanged protected PEM",{mode:0o600});
    const result=await inspectInstallIdentity({endpoint:"https://rc.example.org/"},key,null,{
      recover:async()=>id,verifyRevoked:async()=>{throw Error("not used");}
    });
    assert.equal(result,"approved");
    assert.equal((await readFile(key+".device-id","utf8")).trim(),id);
    assert.equal(await readFile(key,"utf8"),"unchanged protected PEM");
    assert.equal(await inspectInstallIdentity({endpoint:"https://rc.example.org/"},key,null,{
      recover:async()=>id
    }),"approved");
    await assert.rejects(persistRecoveredDeviceId(key,"c4a76f69-045d-43f0-b29d-712160486b0c"),/conflict/);
    assert.equal((await readFile(key+".device-id","utf8")).trim(),id);
  } finally {await rm(dir,{recursive:true,force:true});}
});
test("#76 unverified/offline recovery cannot write an identity or silently rotate it",async()=>{
  const dir=await mkdtemp(path.join(os.tmpdir(),"rc-recover-no-"));
  const key=path.join(dir,"private.pem");
  try {
    await writeFile(key,"original",{mode:0o600});
    await assert.rejects(inspectInstallIdentity({endpoint:"https://rc.example.org/"},key,null,{
      recover:async()=>{throw Error("offline/5xx");}
    }),/offline/);
    await assert.rejects(persistRecoveredDeviceId(key,"bad"),/Invalid recovered/);
    await assert.rejects(persistRecoveredDeviceId(key,id.slice(0,-1)),/Invalid recovered/);
    await assert.rejects(readFile(key+".device-id"),{code:"ENOENT"});
    assert.equal(await readFile(key,"utf8"),"original");
  } finally {await rm(dir,{recursive:true,force:true});}
});
