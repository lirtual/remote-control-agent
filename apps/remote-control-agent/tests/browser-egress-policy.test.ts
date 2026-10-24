import assert from "node:assert/strict";
import test from "node:test";
import {
  isAllowedPublicIp, resolvePinnedPublicAddress, resolvePublicDoh, resolveSyntheticDnsAnswers, type EgressResolver, type EgressAddress,
} from "../candidates/browser-egress-policy.ts";

test("public-IP guard rejects local, LAN, metadata, mapped and special ranges", () => {
  for (const address of [
    "0.0.0.0", "10.0.0.42", "100.64.1.2", "127.0.0.1",
    "169.254.169.254", "172.16.0.1", "192.168.1.1",
    "192.0.0.1", "192.0.2.4", "192.88.99.1",
    "198.18.1.1", "198.51.100.9", "203.0.113.7",
    "224.0.0.1", "240.0.0.1",
    "::", "::1", "::ffff:127.0.0.1", "fe80::1", "fc00::1",
    "fd00::1", "ff02::1", "2001:db8::1",
    "3fff::1", "3fff:fff::1",
    "2002:c0a8:0101::1", "2001::1",
    "not an address",
  ]) assert.equal(isAllowedPublicIp(address), false, address);
  for (const address of [
    "8.8.8.8", "1.1.1.1", "93.184.216.34",
    "2606:4700:4700::1111", "2001:4860:4860::8888",
  ]) assert.equal(isAllowedPublicIp(address), true, address);
});

test("DNS result returns one validated numeric destination without repeat lookup", async () => {
  let lookups = 0;
  const resolver: EgressResolver = async host => {
    assert.equal(host, "public.example.com");
    lookups++;
    return [{ address:"93.184.216.34", family:4 }];
  };
  assert.deepEqual(await resolvePinnedPublicAddress("Public.Example.Com.", resolver),
    { address:"93.184.216.34", family:4 });
  assert.equal(lookups, 1);
});

test("mixed public and private A/AAAA answers fail closed, including DNS rebinding", async () => {
  for (const answers of [
    [{address:"93.184.216.34",family:4},{address:"127.0.0.1",family:4}],
    [{address:"169.254.169.254",family:4},{address:"8.8.8.8",family:4}],
    [{address:"2606:4700:4700::1111",family:6},{address:"::1",family:6}],
    [{address:"::ffff:192.168.1.1",family:6}],
    [{address:"2606:4700:4700::1111",family:6},{address:"3fff::1",family:6}],
    [{address:"93.184.216.34",family:6}],
    [],
  ]) {
    const resolver = async () => answers as EgressAddress[];
    await assert.rejects(
      resolvePinnedPublicAddress("public.example.com",resolver),
      /not wholly public/
    );
  }
});

test("local hostname, literals, malformed names and transport errors never pass", async () => {
  for (const name of [
    "localhost", "localhost.", "a.local", "db.internal",
    "127.0.0.1", "myservice", "host..example.com",
    "http://public.example.com", "public.example.com:443",
    " public.example.com", "public.example.test",
    "192.168.1.1",
  ]) await assert.rejects(resolvePinnedPublicAddress(name, async () => {
    throw Error("Must not resolve rejected names.");
  }));
  await assert.rejects(
    resolvePinnedPublicAddress("public.example.com", async () => {throw Error("DNS failed");}),
    /DNS failed/
  );
});

test("only pure 198.18/15 synthetic DNS triggers a safe public resolver", async () => {
  let publicQueries = 0;
  const resolvePublic: EgressResolver = async host => {
    assert.equal(host, "public.example.com");
    publicQueries++;
    return [{address:"104.20.23.154",family:4}];
  };
  const fake = [{address:"198.18.1.27",family:4}] as EgressAddress[];
  assert.deepEqual(await resolveSyntheticDnsAnswers("public.example.com",fake,resolvePublic),
    [{address:"104.20.23.154",family:4}]);
  assert.equal(publicQueries,1);
  for (const answers of [
    [{address:"198.18.1.27",family:4},{address:"127.0.0.1",family:4}],
    [{address:"198.18.1.27",family:4},{address:"1.1.1.1",family:4}],
    [{address:"10.0.0.1",family:4}],
  ] as EgressAddress[][]) {
    assert.deepEqual(await resolveSyntheticDnsAnswers("public.example.com",answers,resolvePublic),answers);
    await assert.rejects(resolvePinnedPublicAddress("public.example.com",
      host => resolveSyntheticDnsAnswers(host,answers,resolvePublic)),/not wholly public/);
  }
  assert.equal(publicQueries,1,"Mixed/private answers must never trigger DoH.");
});

test("authenticated DoH validates response shape and pins only numeric public answers", async () => {
  const queried: string[] = [];
  const send: typeof fetch = async (input, options) => {
    const url=String(input);
    queried.push(url);
    assert.equal(options?.redirect,"error");
    assert.equal((options?.headers as Record<string,string>).Accept,"application/dns-json");
    const answer=url.endsWith("type=A")
      ? [{type:1,data:"104.20.23.154"}]
      : [{type:28,data:"2606:4700:4700::1111"}];
    return new Response(JSON.stringify({Status:0,Answer:answer}),
      {status:200,headers:{"content-type":"application/dns-json; charset=utf-8"}});
  };
  const results=await resolvePublicDoh("public.example.com",send);
  assert.equal(queried.length,2);
  assert.deepEqual(results,[{address:"104.20.23.154",family:4},
    {address:"2606:4700:4700::1111",family:6}]);
  const pinned=await resolvePinnedPublicAddress("public.example.com",
    host=>resolveSyntheticDnsAnswers(host,[{address:"198.18.1.27",family:4}],h=>resolvePublicDoh(h,send)));
  assert.deepEqual(pinned,{address:"104.20.23.154",family:4});
});

test("DoH errors and DoH-rebound private answers fail closed", async () => {
  const publicA = [{type:1,data:"127.0.0.1"}];
  const bad: Array<{status:number;mime:string;payload:unknown}> = [
    {status:200,mime:"application/dns-json",payload:{Status:0,Answer:publicA}},
    {status:503,mime:"application/dns-json",payload:{Status:0,Answer:[]}},
    {status:200,mime:"text/html",payload:{Status:0,Answer:[]}},
    {status:200,mime:"application/dns-json",payload:{Status:2}},
    {status:200,mime:"application/dns-json",payload:{Status:0,Answer:[{type:1,data:"not-ip"}]}},
  ];
  for (const item of bad) {
    const send: typeof fetch=async ()=>new Response(JSON.stringify(item.payload),
      {status:item.status,headers:{"content-type":item.mime}});
    await assert.rejects(resolvePinnedPublicAddress("public.example.com",
      host=>resolveSyntheticDnsAnswers(host,[{address:"198.18.1.27",family:4}],
        h=>resolvePublicDoh(h,send))));
  }
});
