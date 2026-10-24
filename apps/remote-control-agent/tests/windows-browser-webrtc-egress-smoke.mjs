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
  const stunPacketsV6 = [];
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
  const udpV6 = dgram.createSocket("udp6");
  udpV6.on("message", (data, from) => {
    if (data.length >= 20 && (data[0] & 0xc0) === 0 &&
        data.readUInt32BE(4) === 0x2112a442 && from.address === "::1") {
      stunPacketsV6.push({type:data.readUInt16BE(0),sourcePort:from.port});
    }
  });
  const udpV6Port = await new Promise((resolve,reject) => {
    udpV6.once("error",reject);
    udpV6.bind(0,"::1",()=>resolve(udpV6.address().port));
  });
  let tcpHits = 0;
  const tcp = net.createServer(socket => {
    tcpHits++;
    socket.on("error", () => {});
    socket.destroy();
  });
  const tcpPort = await listen(tcp);
  return {
    udpPort, udpV6Port, tcpPort, stunPackets, stunPacketsV6, getTcpHits: () => tcpHits,
    async close() {
      udp.close();
      udpV6.close();
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
      const rtc = await page.evaluate(async ({udpPort, udpV6Port, tcpPort}) => {
        if (typeof RTCPeerConnection !== "function") return {available: false};
        const connection = new RTCPeerConnection({
          iceServers: [
            {urls: "stun:127.0.0.1:" + udpPort},
            {urls: "stun:[::1]:" + udpV6Port},
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
      }, {udpPort: probe.udpPort, udpV6Port: probe.udpV6Port,
        tcpPort: probe.tcpPort});
      await page.waitForTimeout(250);
      const packets = probe.stunPackets;
      results.push({
        channel, mode, ...rtc,
        validStunHits: packets.length,
        validStunV6Hits: probe.stunPacketsV6.length,
        stunTypes: [...new Set(packets.map(p => p.type))],
        uniqueSourcePorts: new Set(packets.map(p => p.sourcePort)).size,
        tcpHits: probe.getTcpHits(),
        uniqueV6SourcePorts: new Set(probe.stunPacketsV6.map(p=>p.sourcePort)).size,
      });
      console.log("WINDOWS_WEBRTC_PROXY_EGRESS_OBSERVATION=" + JSON.stringify(results.at(-1)));
    } finally {
      await activeContext?.close().catch(() => {});
      activeContext = undefined;
      await probe.close();
    }
  }
  assert.ok(results.every(x => x.available), "The WebRTC positive control was not initialized.");
  // CI networking can suppress baseline STUN intermittently. A valid
  // positive control in EITHER unrestricted mode suffices; zero in both
  // remains inconclusive and must fail the gate.
  assert.ok(results.some(x=>x.mode!=="documented-policy" && x.validStunHits > 0),
    "No unrestricted STUN positive control; a zero restricted count is inconclusive.");
  assert.ok(results.some(x=>x.mode!=="documented-policy" && x.validStunV6Hits>0),
    "No unrestricted IPv6 STUN positive control; restricted zero is inconclusive.");
  const documented = results.find(x => x.mode === "documented-policy");
  const verdict = documented.validStunHits === 0 && documented.validStunV6Hits === 0 && documented.tcpHits === 0
    ? "DOCUMENTED_FLAG_BLOCKED_DUAL_STACK_STUN_FIXTURE_ONLY"
    : "DIRECT_WEBRTC_TRAFFIC_OBSERVED";
  console.log("WINDOWS_WEBRTC_POLICY_COMPARISON=" + JSON.stringify({
    channel, verdict, modes: results.map(x=>({mode:x.mode,udp4:x.validStunHits,udp6:x.validStunV6Hits,tcp:x.tcpHits})),
    productionIsolation:"NOT_TESTED", osConfinement:"NOT_TESTED",
  }));
} finally {
  await activeContext?.close().catch(()=>{});
  await new Promise(resolve => proxy.close(resolve));
  await rm(temp, {recursive:true, force:true});
}
