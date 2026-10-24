import assert from "node:assert/strict";
import dgram from "node:dgram";
import net from "node:net";
import { createServer } from "node:http";
import { mkdtemp, rm } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import path from "node:path";
import os from "node:os";

// Characterization ONLY on disposable Windows CI. Per-mode listeners prevent
// a late STUN retransmission from the baseline being assigned to another mode.
// A zero hit count without a positive baseline is not proof of protection.
if (process.platform !== "win32" || process.env.GITHUB_ACTIONS !== "true") {
  throw Error("Disposable native Windows CI runner required.");
}
const stage = process.argv[2], channel = process.argv[3];
if (!stage || !path.isAbsolute(stage) || !["chrome", "msedge"].includes(channel)) {
  throw Error("Pinned candidate and supported browser channel required.");
}
const { chromium } = await import(pathToFileURL(path.join(stage,
  "apps/remote-control-agent/node_modules/playwright-core/index.mjs")).href);

async function listen(server) {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve(server.address().port));
  });
}
async function probeSockets() {
  const stunPackets = [];
  const udp = dgram.createSocket("udp4");
  udp.on("message", (data, from) => {
    if (data.length < 20 || (data[0] & 0xc0) !== 0 ||
        data.readUInt32BE(4) !== 0x2112a442 ||
        from.address !== "127.0.0.1") return;
    stunPackets.push({
      type: data.readUInt16BE(0),
      sourcePort: from.port,
    });
  });
  const udpPort = await new Promise((resolve, reject) => {
    udp.once("error", reject);
    udp.bind(0, "127.0.0.1", () => resolve(udp.address().port));
  });
  let tcpHits = 0;
  const tcp = net.createServer(socket => {
    tcpHits++;
    socket.on("error", () => {});
    socket.destroy();
  });
  const tcpPort = await listen(tcp);
  return {
    udpPort, tcpPort, stunPackets, getTcpHits: () => tcpHits,
    async close() {
      udp.close();
      await new Promise(resolve => tcp.close(resolve));
    },
  };
}

const temp = await mkdtemp(path.join(os.tmpdir(), "rca-ci-webrtc-egress-"));
let activeContext;
const proxy = createServer((_req, response) => {
  response.writeHead(403); response.end();
});
proxy.on("connect", (_req, socket) => {
  socket.on("error", () => {});
  socket.end("HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n");
});
proxy.on("connection", socket => socket.on("error", () => {}));
const proxyPort = await listen(proxy);

try {
  const results = [];
  const modes = ["baseline", "old-unrecognized-flag", "documented-policy"];
  for (const mode of modes) {
    const probe = await probeSockets();
    try {
      const args = ["--proxy-bypass-list=<-loopback>", "--disable-quic"];
      if (mode === "old-unrecognized-flag") {
        args.push("--force-webrtc-ip-handling-policy=disable_non_proxied_udp");
      }
      if (mode === "documented-policy") {
        // Chromium's actual chrome_switches.h kWebRtcIPHandlingPolicy.
        args.push("--webrtc-ip-handling-policy=disable_non_proxied_udp");
      }
      activeContext = await chromium.launchPersistentContext(
        path.join(temp, channel + "-" + mode), {
          channel, headless: true, timeout: 20_000,
          acceptDownloads: false, serviceWorkers: "block",
          proxy: { server: "http://127.0.0.1:" + proxyPort, bypass: "<-loopback>" },
          args,
        },
      );
      const page = activeContext.pages()[0] ?? await activeContext.newPage();
      await page.goto("about:blank");
      const rtc = await page.evaluate(async ({udpPort, tcpPort}) => {
        if (typeof RTCPeerConnection !== "function") return {available: false};
        const connection = new RTCPeerConnection({
          iceServers: [
            {urls: "stun:127.0.0.1:" + udpPort},
            {urls: "turn:127.0.0.1:" + tcpPort + "?transport=tcp",
              username: "ci", credential: "ci"},
          ],
        });
        try {
          connection.createDataChannel("ci-test");
          await connection.setLocalDescription(await connection.createOffer());
          await new Promise(resolve => setTimeout(resolve, 2400));
          return {available: true, state: connection.iceGatheringState};
        } finally { connection.close(); }
      }, {udpPort: probe.udpPort, tcpPort: probe.tcpPort});
      await page.waitForTimeout(250);
      const packets = probe.stunPackets;
      results.push({
        channel, mode, ...rtc,
        validStunHits: packets.length,
        stunTypes: [...new Set(packets.map(p => p.type))],
        uniqueSourcePorts: new Set(packets.map(p => p.sourcePort)).size,
        tcpHits: probe.getTcpHits(),
      });
      console.log("WINDOWS_WEBRTC_PROXY_EGRESS_OBSERVATION=" + JSON.stringify(results.at(-1)));
    } finally {
      await activeContext?.close().catch(() => {});
      activeContext = undefined;
      await probe.close();
    }
  }
  assert.ok(results.every(x => x.available), "The WebRTC positive control was not initialized.");
  assert.ok(results[0].validStunHits > 0,
    "No baseline STUN positive control. Zero restricted packets would be INCONCLUSIVE.");
  const documented = results.find(x => x.mode === "documented-policy");
  const verdict = documented.validStunHits === 0 && documented.tcpHits === 0
    ? "DOCUMENTED_FLAG_BLOCKED_STUN_FIXTURE_ONLY"
    : "DIRECT_WEBRTC_TRAFFIC_OBSERVED";
  console.log("WINDOWS_WEBRTC_POLICY_COMPARISON=" + JSON.stringify({
    channel, verdict, modes: results.map(x=>({mode:x.mode,udp:x.validStunHits,tcp:x.tcpHits})),
    productionIsolation:"NOT_TESTED", osConfinement:"NOT_TESTED",
  }));
} finally {
  await activeContext?.close().catch(()=>{});
  await new Promise(resolve => proxy.close(resolve));
  await rm(temp, {recursive:true, force:true});
}
