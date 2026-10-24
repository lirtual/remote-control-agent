/**
 * Source-only candidate policy for #33, NOT wired into the production Agent.
 *
 * A browser hostname check alone is never an SSRF boundary. A future egress
 * transport must resolve via this boundary and CONNECT TO THE VALIDATED
 * NUMERIC ADDRESS, retaining the original host for Host/SNI, so DNS cannot
 * change between validation and socket connection. Do not expose a host-only
 * "allowed" result that callers could mistakenly use before re-resolving.
 */
import { lookup } from "node:dns/promises";
import { BlockList, isIP } from "node:net";

const IPv4 = new BlockList();
for (const [subnet, prefix] of [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10],
  ["127.0.0.0", 8], ["169.254.0.0", 16], ["172.16.0.0", 12],
  ["192.0.0.0", 24], ["192.0.2.0", 24], ["192.88.99.0", 24],
  ["192.168.0.0", 16], ["198.18.0.0", 15], ["198.51.100.0", 24],
  ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4],
] as const) IPv4.addSubnet(subnet, prefix, "ipv4");

const IPv6Global = new BlockList();
IPv6Global.addSubnet("2000::", 3, "ipv6");
const IPv6Exception = new BlockList();
for (const [subnet, prefix] of [
  ["2001::", 32],   // Teredo / tunnel transition
  ["2001:2::", 48], // benchmarking
  ["2001:10::", 28], ["2001:20::", 28], // ORCHID
  ["2001:db8::", 32], // documentation (RFC 3849)
  ["2002::", 16], // 6to4 encapsulation can reach private IPv4
  ["3fff::", 20], // documentation (RFC 9637 / IANA IPv6 special-purpose registry)
] as const) IPv6Exception.addSubnet(subnet, prefix, "ipv6");

export function isAllowedPublicIp(address: string): boolean {
  const family = isIP(address);
  if (family === 4) return !IPv4.check(address, "ipv4");
  if (family === 6) {
    return IPv6Global.check(address, "ipv6") &&
      !IPv6Exception.check(address, "ipv6");
  }
  return false;
}

export type EgressAddress = { address: string; family: 4 | 6 };
export type EgressResolver = (hostname: string) => Promise<EgressAddress[]>;

const defaultResolver: EgressResolver = async hostname =>
  (await lookup(hostname, { all: true, verbatim: true }))
    .map(x => ({ address: x.address, family: x.family as 4 | 6 }));

export async function resolvePinnedPublicAddress(
  hostname: string, resolver: EgressResolver = defaultResolver
): Promise<EgressAddress> {
  if (typeof hostname !== "string" || hostname.length < 4 ||
      hostname.length > 253 || /[^a-zA-Z0-9.\-]/.test(hostname) ||
      hostname.includes("..")) throw Error("Invalid public hostname.");
  const host = hostname.replace(/\.$/, "").toLowerCase();
  if (!host.includes(".") || isIP(host) ||
      host === "localhost" || host.endsWith(".localhost") ||
      host.endsWith(".local") || host.endsWith(".internal") ||
      host.endsWith(".test")) throw Error("Private or invalid hostname.");
  // The DNS result is data, not an authority. A mixed private/public response
  // must fail closed; do not silently fall back to the public address.
  const answers = await resolver(host);
  if (!Array.isArray(answers) || answers.length === 0 || answers.length > 32 ||
      answers.some(a => a.family !== isIP(a.address) ||
        !isAllowedPublicIp(a.address)))
    throw Error("Destination is not wholly public.");
  // Caller MUST connect to this returned numeric IP. DNS lookup by hostname
  // after this point would reintroduce the TOCTOU / rebinding vulnerability.
  return { address: answers[0]!.address, family: answers[0]!.family };
}
