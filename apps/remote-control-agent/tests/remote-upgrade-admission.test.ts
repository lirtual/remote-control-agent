import assert from "node:assert/strict";
import { createHash, createPublicKey, generateKeyPairSync } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { ReceiptStore } from "../src/operations.ts";
import {
  admitOwnerApprovedUpgrade, localUpgradeFingerprint, parseRemoteUpgradeDispatch,
} from "../src/remote-upgrade-admission.ts";
import { collectDeviceInfo } from "../src/device-info.ts";

const DEVICE = "2a83dae6-600c-49cc-b643-ab0d5ec7e0c8";
const NOW = 1793100000000;
const PIN = {
  tag: "v0.1.32-rc.1",
  commit: "8b9eb25aadeb06b7c59b102d75a749ac8fa0c54e",
  windows_asset_sha256: "7b7bb8331caed2a84a32437e700ec6f8341de9e90aae949e38f1581bf7545ad2",
};
function privateFixture() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const pem = privateKey.export({format:"pem",type:"pkcs8"}).toString();
  const fingerprint = createHash("sha256").update(publicKey.export({format:"der",type:"spki"})).digest("hex").slice(0,24);
  assert.equal(localUpgradeFingerprint(pem), fingerprint);
  const intent = {
    operation_id: "approved-once-39",
    device_id: DEVICE,
    fingerprint,
    current_version: "v0.1.31-rc.1",
    target: PIN,
    approved_at: NOW - 1000,
    expires_at: NOW + 240000,
  };
  const local = { signedDeviceId: DEVICE, privateKeyPem:pem,
    originalVersion:"v0.1.31-rc.1", platform:"win32" as const,
    confirmedByAuthenticatedWorker:true, now:NOW };
  return { intent, local };
}
async function withStore(action:(receipts:ReceiptStore)=>Promise<void>) {
  const dir=await mkdtemp(path.join(os.tmpdir(),"rca-upgrade-receipts-"));
  const receipts=new ReceiptStore(dir);
  try {
    await receipts.open();
    await action(receipts);
  } finally {
    await receipts.close();
    await rm(dir,{recursive:true,force:true});
  }
}
test("approved exact Windows device/key/version/immutable pin is admitted once", async() => {
  const f=privateFixture();
  await withStore(async receipts => {
    const first=await admitOwnerApprovedUpgrade(receipts,f.intent,f.local);
    assert.deepEqual(first,{status:"admitted",operation_id:f.intent.operation_id});
    assert.equal((await receipts.get(f.intent.operation_id))?.tool_name,"upgrade_agent");
    const repeat=await admitOwnerApprovedUpgrade(receipts,f.intent,f.local);
    assert.equal(repeat.status,"duplicate");
    const swapped=await admitOwnerApprovedUpgrade(receipts,
      {...f.intent,target:{...PIN,windows_asset_sha256:"f".repeat(64)}},f.local);
    assert.equal(swapped.status,"conflict");
    const next=await admitOwnerApprovedUpgrade(receipts,
      {...f.intent,operation_id:"another-upgrade"},f.local);
    assert.equal(next.status,"unavailable",
      "a second operation may not race an unresolved version switch");
    assert.equal(await receipts.get("another-upgrade"),null);
  });
});
test("unapproved request, wrong paired identity/platform, expired request and version drift create no receipt",async()=>{
  const f=privateFixture();
  await withStore(async receipts => {
    const scenarios=[
      { confirmedByAuthenticatedWorker:false },
      { signedDeviceId:"11111111-1111-4111-8111-111111111111" },
      { platform:"linux" as const },
      { originalVersion:"v0.1.29-rc.1" },
      { now: f.intent.expires_at },
    ];
    for (const [i,local] of scenarios.entries()) {
      const rejected=await admitOwnerApprovedUpgrade(receipts,
        {...f.intent,operation_id:"denied-"+i},{...f.local,...local});
      assert.equal(rejected.status,"refused");
      assert.equal(await receipts.get("denied-"+i),null);
    }
    const foreign=generateKeyPairSync("ed25519").privateKey.export({type:"pkcs8",format:"pem"}).toString();
    assert.equal((await admitOwnerApprovedUpgrade(receipts,f.intent,
      {...f.local,privateKeyPem:foreign})).status,"refused");
    assert.equal(await receipts.get(f.intent.operation_id),null);
  });
});
test("untrusted extra keys, version downgrade/replacement and receipt-signature drift reject",()=>{
  const f=privateFixture();
  const requests:unknown[]=[
    {...f.intent, command:"shutdown -r"},
    {...f.intent, target:{...PIN, url:"https://evil.example"}},
    {...f.intent, current_version:"v0.1.34"},
    {...f.intent, target:{...PIN,tag:"v0.1.31-rc.2"}},
    {...f.intent, target:{...PIN,tag:"v0.1.30-rc.1"}},
    {...f.intent, target:{...PIN,tag:"v0.1.31-rc.1"}},
    {...f.intent, target:{...PIN,tag:"v99."+"1".repeat(1000)+".0"}},
    {...f.intent, target:{...PIN,commit:"x".repeat(40)}},
    {...f.intent, target:{...PIN,windows_asset_sha256:"not-a-digest"}},
    {...f.intent, approved_at:NOW + 1, expires_at:NOW},
    {...f.intent, operation_id:"../op"},
    {...f.intent, device_id:"not-a-uuid"},
  ];
  for (const req of requests) assert.equal(parseRemoteUpgradeDispatch(req),null,JSON.stringify(req).slice(0,150));
});
test("restart converts unfinished upgrade to guarded unknown, duplicate not replayable and distinct operation blocked",async()=>{
  const f=privateFixture();
  const dir=await mkdtemp(path.join(os.tmpdir(),"rca-upgrade-restart-"));
  let receipts=new ReceiptStore(dir);
  try {
    await receipts.open();
    assert.equal((await admitOwnerApprovedUpgrade(receipts,f.intent,f.local)).status,"admitted");
    await receipts.close();
    receipts=new ReceiptStore(dir);
    await receipts.open();
    const current=await receipts.get(f.intent.operation_id);
    assert.equal(current?.state,"unknown");
    assert.equal((await admitOwnerApprovedUpgrade(receipts,f.intent,f.local)).status,"duplicate");
    assert.equal((await admitOwnerApprovedUpgrade(receipts,
      {...f.intent,operation_id:"second-attempt"},f.local)).status,"unavailable");
    assert.equal(await receipts.get("second-attempt"),null);
    // Even after reconciled completion the original approval remains guarded.
    await receipts.update(f.intent.operation_id,"completed","Authenticated reconnect verified");
    assert.equal((await admitOwnerApprovedUpgrade(receipts,f.intent,f.local)).status,"duplicate");
    assert.equal((await admitOwnerApprovedUpgrade(receipts,
      {...f.intent,operation_id:"new-reviewed-version"},f.local)).status,"admitted");
  }finally{await receipts.close();await rm(dir,{recursive:true,force:true});}
});
test("same moment concurrent approvals serialize through existing SQLite receipt",async()=>{
  const f=privateFixture();
  await withStore(async receipts=>{
    const attempts=await Promise.all(Array.from({length:5},(_,i)=>
      admitOwnerApprovedUpgrade(receipts,
        {...f.intent,operation_id:"parallel-"+i},f.local)));
    assert.equal(attempts.filter(x=>x.status==="admitted").length,1);
    assert.equal(attempts.filter(x=>x.status==="unavailable").length,4);
  });
});

test("receipt-only native Agent never advertises upgrade execution readiness",()=>{
  const info=collectDeviceInfo() as Record<string,unknown>;
  assert.equal(Object.hasOwn(info,"upgrade_protocol"),false,
    "a release without a proven one-shot updater may not enable remote owner approval");
});


test("Linux signed one-shot admission requires exact arch, reviewed protocol and permanent key",async()=>{
  const f=privateFixture();
  const pin={tag:"v0.1.33",commit:"a".repeat(40),
    linux_asset_sha256:"b".repeat(64),linux_arch:"x64" as const};
  const intent={...f.intent,current_version:"v0.1.22",target:pin};
  const local={...f.local,originalVersion:"v0.1.22",
    platform:"linux" as const,arch:"x64",linuxProtocolReady:true,
    environment:"wsl2"};
  await withStore(async receipts=>{
    for(const [i,change] of [
      {linuxProtocolReady:false},{platform:"win32" as const},
      {arch:"arm64"},{environment:"container"},
      {environment:"wsl1"},{confirmedByAuthenticatedWorker:false},
    ].entries()){
      const denied=await admitOwnerApprovedUpgrade(receipts,
        {...intent,operation_id:"denied-linux-"+i},{...local,...change});
      assert.equal(denied.status,"refused",JSON.stringify(change));
    }
    assert.equal((await admitOwnerApprovedUpgrade(receipts,intent,local)).status,
      "admitted");
    assert.equal((await admitOwnerApprovedUpgrade(receipts,intent,local)).status,
      "duplicate");
    assert.equal((await admitOwnerApprovedUpgrade(receipts,
      {...intent,target:{...pin,linux_asset_sha256:"c".repeat(64)}},local)).status,
      "conflict");
  });
});

test("Linux remote dispatcher rejects foreign pin fields, prerelease and wrong-arch payload",()=>{
  const f=privateFixture();
  const intent={...f.intent,current_version:"v0.1.22",target:{
    tag:"v0.1.33",commit:"a".repeat(40),
    linux_asset_sha256:"b".repeat(64),linux_arch:"arm64"}};
  assert.ok(parseRemoteUpgradeDispatch(intent));
  for(const candidate of [
    {...intent,target:{...intent.target,command:"systemctl restart"}},
    {...intent,target:{...intent.target,windows_asset_sha256:"c".repeat(64)}},
    {...intent,target:{...intent.target,linux_arch:"unknown"}},
    {...intent,target:{...intent.target,linux_asset_sha256:"not-a-hash"}},
    {...intent,target:{...intent.target,tag:"v0.1.33-rc.1"}},
    {...intent,target:{...intent.target,tag:"v0.1.22"}},
    {...intent,target:{...intent.target,tag:"v0.1.21"}},
    {...intent,current_version:"v0.1.22-rc.1"},
    {...intent,current_version:"v000.1.22"},
  ])assert.equal(parseRemoteUpgradeDispatch(candidate),null,JSON.stringify(candidate).slice(0,160));
});
