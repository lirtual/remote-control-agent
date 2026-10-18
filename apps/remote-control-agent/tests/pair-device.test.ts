import assert from "node:assert/strict";
import { createPrivateKey, createPublicKey } from "node:crypto";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { fileURLToPath, pathToFileURL } from "node:url";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { beginDeviceEnrollment } from "../src/pair-device.ts";
import { recoverDeviceId, signedSessionProof } from "../src/v2-session-client.ts";

test("pending-only installer posts public material and displays only a short code", async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), "remote-v2-local-pair-"));
  const file = path.join(home, "state", "device.pem");
  let calls = 0;
  try {
    const result = await beginDeviceEnrollment(
      "home",
      "https://example.test/",
      file,
      async (url, init) => {
        calls++;
        assert.equal(String(url), "https://example.test/agent/pair/start");
        assert.equal(init?.method, "POST");
        assert.equal(init?.redirect, "error");
        const request = JSON.parse(String(init?.body)) as Record<string, unknown>;
        assert.equal(request.name, "home");
        assert.equal(typeof request.public_key, "string");
        assert.match(String(request.code_verifier), /^[a-f0-9]{64}$/);
        assert.equal(typeof request.proof, "string");
        assert.equal(JSON.stringify(request).includes("PRIVATE KEY"), false);
        return new Response(JSON.stringify({ status: "pending" }), { status: 202 });
      },
    );
    assert.equal(calls, 1);
    assert.match(result.code, /^[A-Z2-7]{10}$/);
    assert.equal(result.keyPath, file);
    assert.ok(result.expiresAt > Date.now());
    assert.equal((await stat(file)).mode & 0o777, 0o600);
    assert.match(await readFile(file, "utf8"), /PRIVATE KEY/);
    await assert.rejects(beginDeviceEnrollment("new", "https://example.test/", file, async () => {
      throw new Error("Existing key should reject before network.");
    }), { code: "EEXIST" });
    assert.equal(calls, 1);
  } finally { await rm(home, { recursive: true, force: true }); }
});

test("#76 first pending network/HTTP failure preserves the new private key for safe same-key retry", async () => {
  for (const first of ["lost-202-response", "http-503", "http-302"]) {
    const home = await mkdtemp(path.join(os.tmpdir(), "remote-v2-failed-pair-"));
    const key = path.join(home, "id.pem");
    const receipts = path.join(home, "receipts.sqlite");
    const originalReceipts = Buffer.from("synthetic owner SQLite receipts must not be touched");
    let oldPublicKey = "";
    let secondPublicKey = "";
    let posts = 0;
    try {
      await writeFile(receipts,originalReceipts,{mode:0o600});
      await assert.rejects(beginDeviceEnrollment("cloud", "https://example.test/", key, async (_url,init) => {
        posts++;
        oldPublicKey = (JSON.parse(String(init?.body)) as {public_key:string}).public_key;
        if(first==="lost-202-response") throw Error("server accepted pending; reply was lost");
        return new Response(null,{status:first==="http-503"?503:302});
      }),/could not be completed/);
      const originalPem = await readFile(key,"utf8");
      assert.equal((await stat(key)).mode & 0o777,0o600);
      assert.match(originalPem,/PRIVATE KEY/);
      assert.equal(Buffer.from(createPublicKey(createPrivateKey(originalPem))
        .export({type:"spki",format:"der"})).toString("base64"),oldPublicKey);
      assert.deepEqual(await readFile(receipts),originalReceipts);
      // The next invocation is a different code, but the SAME Ed25519 public
      // key. It may create pending state; it cannot authorize a grant itself.
      const retry = await beginDeviceEnrollment("cloud", "https://example.test/", key,
        async (_url,init)=>{
          posts++;
          secondPublicKey=(JSON.parse(String(init?.body)) as {public_key:string}).public_key;
          return new Response(null,{status:202});
        },true);
      assert.match(retry.code,/^[A-Z2-7]{10}$/);
      assert.equal(posts,2);
      assert.equal(oldPublicKey,secondPublicKey);
      assert.equal(await readFile(key,"utf8"),originalPem);
      assert.deepEqual(await readFile(receipts),originalReceipts);
    }finally{await rm(home,{recursive:true,force:true});}
  }
});

test("#76 pending key conflict cannot silently rotate or replace existing private identity", async()=>{
  const home=await mkdtemp(path.join(os.tmpdir(),"remote-v2-retry-conflict-"));
  const key=path.join(home,"device.pem");
  try{
    await assert.rejects(beginDeviceEnrollment("host","https://example.test/",key,
      async()=>{throw Error("lost response");}),/could not be completed/);
    const saved=await readFile(key,"utf8");
    await assert.rejects(beginDeviceEnrollment("host","https://example.test/",key,
      async()=>new Response(null,{status:409}),true),/approved or revoked identity cannot be enrolled again/);
    assert.equal(await readFile(key,"utf8"),saved);
    await assert.rejects(beginDeviceEnrollment("host","https://example.test/",key,
      async()=>{assert.fail("without explicit retry must never send another pending request");}),
      {code:"EEXIST"});
  }finally{await rm(home,{recursive:true,force:true});}
});

test("pending-only installer rejects arbitrary HTTP/URL credentials before key creation", async () => {
  const home = await mkdtemp(path.join(os.tmpdir(), "remote-v2-url-pair-"));
  try {
    for (const endpoint of [
      "http://example.test/",
      "https://user:pass@example.test/",
      "https://example.test/?token=secret",
      "https://example.test/other",
      "http://127.0.0.2:8787/",
    ]) {
      await assert.rejects(beginDeviceEnrollment("lab", endpoint, path.join(home, "private.pem")), /HTTPS endpoint/);
    }
    await assert.rejects(stat(path.join(home, "private.pem")), { code: "ENOENT" });
  } finally { await rm(home, { recursive: true, force: true }); }
});

test("#76 lost initial enrollment reply then owner approval recovers original signed identity, not a new grant", async()=>{
  const home=await mkdtemp(path.join(os.tmpdir(),"rc-v2-lost-reply-approved-"));
  const key=path.join(home,"permanent.pem");
  const serverId="b23a4e81-5f6d-47cc-99d0-7b6de752f919";
  const nonce="0123456789abcdefghij-_23";
  let enrolledPublicKey="";
  let ownerGrantCount=0, pendingCount=0, challengeCount=0, recoveryCount=0;
  try{
    await assert.rejects(beginDeviceEnrollment("lost-reply","https://rc.example.org/",key,
      async(_url,init)=>{
        pendingCount++;
        enrolledPublicKey=(JSON.parse(String(init?.body)) as {public_key:string}).public_key;
        // Backend may have accepted the pending request before TCP reply loss.
        // One independent authenticated owner approval is modeled separately.
        ownerGrantCount++;
        throw Error("HTTP reply lost after accepted pending request");
      }),/could not be completed/);
    const originalPem=await readFile(key,"utf8");
    assert.equal((await stat(key)).mode&0o777,0o600);
    await assert.rejects(readFile(key+".device-id"),{code:"ENOENT"});
    const approvedServer: typeof fetch=async(url,init)=>{
      const route=new URL(String(url)).pathname;
      const body=JSON.parse(String(init?.body)) as Record<string,string>;
      if(route==="/agent/session/challenge"){
        challengeCount++;
        assert.equal(body.public_key,enrolledPublicKey);
        return Response.json({device_id:serverId,nonce});
      }
      if(route==="/agent/session/recover"){
        recoveryCount++;
        assert.equal(body.device_id,serverId);
        assert.equal(body.nonce,nonce);
        assert.equal(body.proof,signedSessionProof(originalPem,serverId,nonce).proof);
        return Response.json({status:"verified",device_id:serverId});
      }
      assert.fail("Unexpected server route");
    };
    const recovered=await recoverDeviceId("https://rc.example.org/",key,approvedServer);
    assert.equal(recovered,serverId);
    assert.equal((await readFile(key+".device-id","utf8")).trim(),serverId);
    assert.equal(await readFile(key,"utf8"),originalPem);
    assert.equal(pendingCount,1);
    assert.equal(ownerGrantCount,1);
    assert.equal(challengeCount,1);
    assert.equal(recoveryCount,1);
  }finally{await rm(home,{recursive:true,force:true});}
});

test("#76 OS SIGKILL after first pending request preserves private key for repeat install", async()=>{
  const home=await mkdtemp(path.join(os.tmpdir(),"rc-v2-sigkill-pending-"));
  const key=path.join(home,"pending.pem");
  const pairUrl=pathToFileURL(path.resolve(path.dirname(fileURLToPath(import.meta.url)),
    "../src/pair-device.ts")).href;
  const childCode=`
    import { beginDeviceEnrollment } from ${JSON.stringify(pairUrl)};
    await beginDeviceEnrollment("sigkill-pending","https://rc.example.org/",
      process.env.RC76_TEST_KEY,async(_url,init)=>{
        const request=JSON.parse(init.body);
        process.stdout.write("PENDING_ACCEPTED_NO_REPLY:"+request.public_key+"\\n");
        await new Promise(()=>{});
        return new Response(null,{status:202});
      });
  `;
  const child=spawn(process.execPath,["--experimental-strip-types","--input-type=module",
    "--eval",childCode],{
    stdio:["ignore","pipe","pipe"],
    env:{...process.env,RC76_TEST_KEY:key},
  });
  const exited=once(child,"exit");
  try{
    let timer: NodeJS.Timeout | undefined;
    const ready=await Promise.race([
      once(child.stdout!,"data").then(([chunk])=>String(chunk)),
      exited.then(([code,signal])=>{throw Error("Pending child exited early: "+code+"/"+signal);}),
      new Promise<never>((_resolve,reject)=>{
        timer=setTimeout(()=>reject(Error("Pending child did not reach accepted request")),10_000);
      }),
    ]).finally(()=>{if(timer)clearTimeout(timer);});
    assert.match(ready,/PENDING_ACCEPTED_NO_REPLY:/);
    const originalPublic=ready.trim().split("PENDING_ACCEPTED_NO_REPLY:").at(1) ?? "";
    assert.ok(originalPublic.length>30);
    const originalPem=await readFile(key,"utf8");
    assert.equal((await stat(key)).mode&0o777,0o600);
    assert.equal(child.kill("SIGKILL"),true);
    const [code,signal]=await exited;
    assert.equal(code,null);
    assert.equal(signal,"SIGKILL");
    const retry=await beginDeviceEnrollment("sigkill-pending","https://rc.example.org/",
      key,async(_url,init)=>{
        const material=JSON.parse(String(init?.body)) as {public_key:string};
        assert.equal(material.public_key,originalPublic);
        return new Response(null,{status:202});
      },true);
    assert.match(retry.code,/^[A-Z2-7]{10}$/);
    assert.equal(await readFile(key,"utf8"),originalPem);
    await assert.rejects(readFile(key+".device-id"),{code:"ENOENT"});
  }finally{
    if(child.exitCode===null && child.signalCode===null){
      child.kill("SIGKILL");
      await exited.catch(()=>{});
    }
    await rm(home,{recursive:true,force:true});
  }
});
