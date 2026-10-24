/**
 * #33 candidate ONLY. Process-local HTTP CONNECT proxy; not imported by the
 * shipped BrowserManager or included in a signed release until all CI gates
 * and network escape paths are independently accepted.
 *
 * All outbound TCP dials use a numerically pinned, approved public IP from
 * browser-egress-policy. HTTP redirect hops re-enter this proxy; the proxy
 * itself never follows redirects. No DIRECT fallback, no OS proxy changes.
 */
import http, { type IncomingMessage, type ServerResponse } from "node:http";
import net, { type Socket } from "node:net";
import { resolvePinnedPublicAddress, type EgressResolver } from "./browser-egress-policy.ts";

function deny(response: ServerResponse, status = 403): void {
  response.writeHead(status, { "content-type": "text/plain", "cache-control": "no-store" });
  response.end("Browser network destination denied.");
}
function parseOrigin(raw: string): URL {
  let url: URL;
  try { url = new URL(raw); } catch { throw Error("Malformed proxy target."); }
  if (url.protocol !== "http:" || url.username || url.password ||
      url.port && url.port !== "80") throw Error("Unsupported proxy target.");
  return url;
}
function stripProxyHeaders(headers: IncomingMessage["headers"]): IncomingMessage["headers"] {
  const result = { ...headers };
  const connectionTokens = String(headers.connection ?? "").split(",")
    .map(x => x.trim().toLowerCase()).filter(Boolean);
  for (const key of ["proxy-authorization", "proxy-connection", "connection", "keep-alive",
      "te", "trailer", "transfer-encoding", "upgrade", ...connectionTokens]) {
    delete result[key];
  }
  return result;
}
function parseConnectAuthority(authority: string): { hostname: string; port: number } {
  // An absolute URL parser also correctly validates bracketed IPv6 forms
  // (which the policy itself denies as direct IP literals).
  if (/[/@?#\s]/.test(authority)) throw Error("Invalid tunnel authority.");
  let url: URL;
  try { url = new URL("https://" + authority); }
  catch { throw Error("Invalid tunnel authority."); }
  if (url.username || url.password || url.port && url.port !== "443" ||
      url.hostname.length < 4) throw Error("Tunnel port denied.");
  return { hostname: url.hostname, port: 443 };
}

export async function startCandidateBrowserEgressProxy(
  resolver?: EgressResolver
): Promise<{ server: string; close(): Promise<void> }> {
  let closed = false;
  const clientSockets = new Set<Socket>();
  const upstreamSockets = new Set<Socket>();
  const pinned = (host: string) => resolvePinnedPublicAddress(host, resolver);

  const proxy = http.createServer(async (req, res) => {
    let url: URL;
    try { url = parseOrigin(req.url ?? ""); }
    catch { deny(res); return; }
    let ip;
    try { ip = await pinned(url.hostname); }
    catch { deny(res); return; }
    if (closed || res.destroyed) { res.destroy(); return; }
    // Never forward a hostname to Node's dialer: no post-validation DNS.
    // The original hostname survives as the HTTP Host value.
    const remote = http.request({
      hostname: ip.address, family: ip.family, port: 80,
      method: req.method, path: url.pathname + url.search, agent: false,
      headers: { ...stripProxyHeaders(req.headers), host: url.host },
      timeout: 10_000,
    }, upstream => {
      res.writeHead(upstream.statusCode ?? 502, upstream.headers);
      upstream.pipe(res);
    });
    remote.on("error", () => { if (!res.headersSent) deny(res, 502); else res.destroy(); });
    remote.on("timeout", () => remote.destroy(Error("Egress timeout.")));
    req.pipe(remote);
  });
  proxy.on("connect", async (req, client, head) => {
    let target;
    try {
      target = parseConnectAuthority(req.url ?? "");
      const ip = await pinned(target.hostname);
      if (closed || client.destroyed) { client.destroy(); return; }
      const upstream = net.connect({ host: ip.address, family: ip.family, port: target.port });
      upstreamSockets.add(upstream);
      upstream.on("close", () => upstreamSockets.delete(upstream));
      upstream.setTimeout(10_000, () => upstream.destroy());
      upstream.once("connect", () => {
        client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
        if (head.length) upstream.write(head);
        client.pipe(upstream).pipe(client);
      });
      upstream.on("error", () => {
        if (!client.destroyed) {
          client.end("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n");
        }
      });
    } catch {
      client.end("HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n");
    }
  });
  // ws:// Upgrade and other non-CONNECT tunnel shapes are unsupported
  // until separately reviewed. Refuse rather than tunnel without checks.
  proxy.on("upgrade", (_request, socket) => {
    socket.end("HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n");
  });
  proxy.on("connection", socket => {
    clientSockets.add(socket);
    socket.on("close", () => clientSockets.delete(socket));
  });
  await new Promise<void>((resolve, reject) => {
    proxy.once("error", reject);
    proxy.listen(0, "127.0.0.1", resolve);
  });
  const address = proxy.address();
  if (!address || typeof address === "string") throw Error("Proxy not local.");
  return {
    server: `http://127.0.0.1:${address.port}`,
    async close() {
      closed = true;
      for (const socket of upstreamSockets) socket.destroy();
      for (const socket of clientSockets) socket.destroy();
      await new Promise<void>(resolve => proxy.close(() => resolve()));
    },
  };
}
