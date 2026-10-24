import assert from "node:assert/strict";
import dgram from "node:dgram";
import http from "node:http";
import { mkdtemp, rm } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import path from "node:path";
import os from "node:os";

// Issue #33: native Windows CI-only QUIC/HTTP3 characterization. Deliberately
// use loopback UDP and independent mode-specific ports; never probe a LAN.
// This does NOT measure all browser UDP/WebTransport or OS confinement.
if (process.platform !== "win32" || process.env.GITHUB_ACTIONS !== "true") {
  throw Error("Disposable native Windows CI only.");
}
const stage = process.argv[2], channel = process.argv[3];
if (!stage || !path.isAbsolute(stage) || !["chrome", "msedge"].includes(channel)) {
  throw Error("Pinned candidate and Chrome/Edge channel required.");
}
const { chromium } = await import(pathToFileURL(path.join(stage,
  "apps/remote-control-agent/node_modules/playwright-core/index.mjs")).href);
const folder = await mkdtemp(path.join(os.tmpdir(), "rca-ci-quic-"));
let proxyConnects = 0;
const proxy = http.createServer((_req, res) => {
  res.writeHead(403); res.end();
});
proxy.on("connect", (_req, client) => {
  proxyConnects++;
  client.on("error", () => {});
  client.end("HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n");
});
proxy.on("connection", socket => socket.on("error", () => {}));
await new Promise((resolve, reject) => {
  proxy.once("error", reject);
  proxy.listen(0, "127.0.0.1", resolve);
});
const proxyPort = proxy.address().port;

async function probe(mode) {
  const udp = dgram.createSocket("udp4");
  let packets = 0, quicInitials = 0;
  udp.on("message", data => {
    packets++;
    // QUIC v1 long-header Initials have fixed+long bits and padded >=1200.
    if (data.length >= 1200 && (data[0] & 0xc0) === 0xc0) quicInitials++;
  });
  await new Promise((resolve, reject) => {
    udp.once("error", reject);
    udp.bind(0, "127.0.0.1", resolve);
  });
  const port = udp.address().port;
  let context;
  try {
    const restricted = mode === "restricted";
    context = await chromium.launchPersistentContext(
      path.join(folder, channel + "-" + mode), {
        channel, headless: true, timeout: 20_000,
        acceptDownloads: false, serviceWorkers: "block",
        ...(restricted ? {proxy: {
          server: "http://127.0.0.1:" + proxyPort, bypass: "<-loopback>",
        }} : {}),
        args: [
          "--origin-to-force-quic-on=127.0.0.1:" + port,
          "--proxy-bypass-list=<-loopback>",
          ...(restricted ? [
            "--disable-quic",
            "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1",
            "--webrtc-ip-handling-policy=disable_non_proxied_udp",
          ] : ["--enable-quic"]),
        ],
      }
    );
    const page = context.pages()[0] ?? await context.newPage();
    // A UDP listener cannot complete TLS/HTTP3. Navigation failing is
    // expected; count real QUIC Initial packets rather than browser errors.
    await page.goto("https://127.0.0.1:" + port + "/quic-test", {
      waitUntil: "commit", timeout: 3500,
    }).catch(() => {});
    await page.waitForTimeout(300);
    return {mode, packets, quicInitials};
  } finally {
    await context?.close().catch(() => {});
    udp.close();
  }
}

try {
  const baseline = await probe("forced-quic-baseline");
  const restricted = await probe("restricted");
  assert.ok(baseline.quicInitials > 0,
    "QUIC positive control sent no Initial packets; zero restricted hits prove nothing.");
  assert.equal(restricted.packets, 0,
    "Restricted browser sent direct UDP despite proxy and disabled QUIC.");
  assert.ok(proxyConnects > 0,
    "Restricted browser did not exercise proxy CONNECT for the UDP destination.");
  console.log("WINDOWS_QUIC_PROXY_EGRESS=" + channel + ":PASS");
  console.log(JSON.stringify({channel, baseline, restricted, proxyConnects,
    verdict:"CONTROLLED_FORCED_QUIC_UDP_ONLY",
    webTransport:"NOT_TESTED", productionIsolation:"NOT_TESTED"}));
} finally {
  await new Promise(resolve => proxy.close(resolve));
  await rm(folder, {recursive:true,force:true});
}
