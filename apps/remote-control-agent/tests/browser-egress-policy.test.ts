import assert from "node:assert/strict";
import test from "node:test";
import {
  isAllowedPublicIp, resolvePinnedPublicAddress, type EgressResolver, type EgressAddress,
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
