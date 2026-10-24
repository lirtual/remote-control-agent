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

// Transparent proxy/VPN DNS sometimes returns only 198.18/15 Fake-IP records.
// Never dial or permit those addresses. Independently resolve the public name
// over authenticated HTTPS instead, then apply the SAME IP allow-list below.
const synthetic = new BlockList();
synthetic.addSubnet("198.18.0.0", 15, "ipv4");
const dohEndpoint = "https://cloudflare-dns.com/dns-query";

export async function resolvePublicDoh(
  hostname: string, send: typeof fetch = fetch
): Promise<EgressAddress[]> {
  const query = async (kind: "A" | "AAAA"): Promise<EgressAddress[]> => {
    const url = dohEndpoint + "?name=" + encodeURIComponent(hostname) + "&type=" + kind;
    const response = await send(url, {
      headers: { Accept: "application/dns-json" },
      redirect: "error", signal: AbortSignal.timeout(7_000),
    });
    if (!response.ok ||
        !response.headers.get("content-type")?.toLowerCase().startsWith("application/dns-json"))
      throw Error("Authenticated public DNS unavailable.");
    const body = await response.text();
    if (body.length > 16_384) throw Error("Public DNS response too large.");
    const result = JSON.parse(body) as {
      Status?: unknown; Answer?: unknown;
    };
    if (!result || result.Status !== 0 ||
        (result.Answer !== undefined && !Array.isArray(result.Answer)))
      throw Error("Invalid authenticated public DNS response.");
    const records = (result.Answer ?? []) as Array<{ type?: unknown; data?: unknown }>;
    if (records.length > 32) throw Error("Public DNS answer count exceeded.");
    const family = kind === "A" ? 4 : 6;
    const type = kind === "A" ? 1 : 28;
    return records.filter(record => record.type === type).map(record => {
      if (typeof record.data !== "string" || isIP(record.data) !== family)
        throw Error("Invalid public DNS address.");
      return { address: record.data, family };
    });
  };
  // Failure of either family must fail closed, not silently drop bad answers.
  return [...await query("A"), ...await query("AAAA")];
}

export async function resolveSyntheticDnsAnswers(
  hostname: string, system: EgressAddress[],
  publicResolver: EgressResolver = resolvePublicDoh
): Promise<EgressAddress[]> {
  // A mixed fake-IP/public/private answer never authorizes a fallback.
  if (system.length > 0 && system.length <= 32 &&
      system.every(record => record.family === 4 &&
        isIP(record.address) === 4 && synthetic.check(record.address, "ipv4"))) {
    return publicResolver(hostname);
  }
  return system;
}

const defaultResolver: EgressResolver = async hostname => {
  const system = (await lookup(hostname, { all: true, verbatim: true }))
    .map(x => ({ address: x.address, family: x.family as 4 | 6 }));
  return resolveSyntheticDnsAnswers(hostname, system);
};

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
