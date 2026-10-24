import assert from "node:assert/strict";
import test from "node:test";
import http from "node:http";
import net from "node:net";
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

test("proxy shutdown during pending DNS never authorizes a late dial", async () => {
  let release!: () => void, started!: () => void;
  const dnsStarted = new Promise<void>(resolve => { started = resolve; });
  const dnsGate = new Promise<void>(resolve => { release = resolve; });
  const proxy = await startCandidateBrowserEgressProxy(async () => {
    started();
    await dnsGate;
    return [{ address:"93.184.216.34", family:4 }];
  });
  const endpoint = new URL(proxy.server);
  const completed = new Promise<void>(resolve => {
    const req = http.request({
      hostname:endpoint.hostname, port:Number(endpoint.port),
      method:"GET", path:"http://public.example.com/rejected-after-close",
    }, res => { res.resume(); res.once("end", resolve); });
    req.once("error", () => resolve());
    req.end();
  });
  await dnsStarted;
  await proxy.close();
  release();
  await completed;
  // The DNS resolver was allowed to finish, but the browser-owned proxy
  // had already revoked its socket authority; no new public connection.
});

test("malformed browser proxy socket and peer reset never kill the local server", async () => {
  const proxy = await startCandidateBrowserEgressProxy(async () => {
    throw Error("Rejected requests must not resolve DNS.");
  });
  const endpoint = new URL(proxy.server);
  try {
    await new Promise<void>((resolve, reject) => {
      const socket = net.connect(Number(endpoint.port), endpoint.hostname);
      socket.on("error", () => resolve()); // Peer reset is expected.
      socket.once("connect", () => {
        socket.write("BAD \u0000 HTTP/1.1\r\nHost: invalid\r\n\r\n");
        socket.destroy();
        resolve();
      });
      socket.once("close", resolve);
      socket.once("timeout", () => reject(Error("Unexpected socket timeout.")));
      socket.setTimeout(2000);
    });
    const response = await new Promise<number>((resolve, reject) => {
      const request = http.request({
        hostname: endpoint.hostname, port: Number(endpoint.port),
        method: "GET", path: "http://127.0.0.1/blocked",
      }, result => {
        result.resume();
        result.once("end", () => resolve(result.statusCode ?? 0));
      });
      request.once("error", reject);
      request.end();
    });
    assert.equal(response, 403, "Proxy must remain available and reject unsafe destinations.");
  } finally {
    await proxy.close();
  }
});

test("HTTP 302 destination gets a fresh private-DNS check before any next-hop dial", async () => {
  // This is a test-only transport shim: it routes the *already approved*
  // synthetic public numeric IP to a disposable local origin. The proxy's
  // production dialer remains unchanged and never gets a test-only bypass.
  let publicHits = 0;
  const source = http.createServer((_req, res) => {
    publicHits++;
    res.writeHead(302, { location: "http://private.example.com/secret" });
    res.end();
  });
  await new Promise<void>((resolve, reject) => {
    source.once("error", reject);
    source.listen(0, "127.0.0.1", resolve);
  });
  const sourcePort = (source.address() as import("node:net").AddressInfo).port;
  const queried: string[] = [], outgoing: string[] = [];
  const proxy = await startCandidateBrowserEgressProxy(async host => {
    queried.push(host);
    return host === "public.example.com"
      ? [{ address: "93.184.216.34", family: 4 }]
      : [{ address: "127.0.0.1", family: 4 }];
  });
  const endpoint = new URL(proxy.server);
  const requestBefore = http.request;
  (http as any).request = (opts: any, ...rest: any[]) => {
    if (opts?.hostname === "93.184.216.34") {
      outgoing.push(opts.hostname);
      return (requestBefore as any).call(http,
        { ...opts, hostname: "127.0.0.1", port: sourcePort }, ...rest);
    }
    if (opts?.hostname === "127.0.0.1" && opts?.port === 80) {
      throw Error("Unapproved private destination reached dialer.");
    }
    return (requestBefore as any).call(http, opts, ...rest);
  };
  const viaProxy = (url: string) => new Promise<number>((resolve, reject) => {
    const req = http.request({
      hostname: endpoint.hostname, port: Number(endpoint.port),
      path: url, method: "GET",
    }, res => { res.resume(); res.once("end", () => resolve(res.statusCode!)); });
    req.once("error", reject);
    req.end();
  });
  try {
    assert.equal(await viaProxy("http://public.example.com/start"), 302);
    assert.equal(await viaProxy("http://private.example.com/secret"), 403);
    assert.deepEqual(queried, ["public.example.com", "private.example.com"]);
    assert.deepEqual(outgoing, ["93.184.216.34"],
      "Private redirected DNS address must never enter the real dialer.");
    assert.equal(publicHits, 1);
  } finally {
    (http as any).request = requestBefore;
    await proxy.close();
    await new Promise<void>(resolve => source.close(() => resolve()));
  }
});
