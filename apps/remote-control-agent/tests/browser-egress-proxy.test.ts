import assert from "node:assert/strict";
import test from "node:test";
import http from "node:http";
import { startCandidateBrowserEgressProxy } from "../candidates/browser-egress-proxy.ts";

test("candidate egress proxy denies private URL, private DNS and an unapproved HTTP port", async () => {
  let lookupCalls = 0;
  const proxy = await startCandidateBrowserEgressProxy(async () => {
    lookupCalls++;
    return [{ address:"127.0.0.1", family:4 }];
  });
  const endpoint = new URL(proxy.server);
  const probe = (target: string): Promise<number> => new Promise((resolve,reject) => {
    const req = http.request({
      hostname:endpoint.hostname, port:Number(endpoint.port),
      method:"GET", path:target,
    }, res => { res.resume(); res.once("end", () => resolve(res.statusCode!)); });
    req.once("error",reject);
    req.end();
  });
  try {
    assert.equal(await probe("http://127.0.0.1/private"), 403);
    assert.equal(lookupCalls, 0, "Literal local address must be rejected before DNS.");
    assert.equal(await probe("http://public.example.com/resource"), 403);
    assert.equal(lookupCalls, 1, "Private DNS answer must prevent outbound dial.");
    assert.equal(await probe("http://public.example.com:8888/resource"),403);
    assert.equal(lookupCalls, 1, "Non-approved port cannot use DNS or dial.");
    assert.equal(await probe("ftp://public.example.com/resource"),403);
    assert.equal(await probe("http://public.example.com@127.0.0.1/resource"),403);
  } finally { await proxy.close(); }
});

test("candidate CONNECT proxy rejects internal and rebinding destinations", async () => {
  const proxy = await startCandidateBrowserEgressProxy(async () =>
    [{address:"93.184.216.34",family:4}, {address:"169.254.169.254",family:4}]);
  const endpoint = new URL(proxy.server);
  async function tunnel(authority: string): Promise<number> {
    return new Promise((resolve,reject) => {
      const req = http.request({
        hostname:endpoint.hostname, port:Number(endpoint.port),
        method:"CONNECT", path:authority,
      });
      req.on("connect", (res,socket) => {socket.destroy();resolve(res.statusCode!);});
      req.once("error",reject);
      req.end();
    });
  }
  try {
    assert.equal(await tunnel("127.0.0.1:443"),403);
    assert.equal(await tunnel("public.example.com:443"),403);
    assert.equal(await tunnel("public.example.com:22"),403);
    assert.equal(await tunnel("localhost:443"),403);
  } finally { await proxy.close(); }
});
