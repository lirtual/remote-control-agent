import assert from "node:assert/strict";
import dgram from "node:dgram";
import net from "node:net";
import {mkdtemp, rm} from "node:fs/promises";
import {pathToFileURL} from "node:url";
import path from "node:path";
import os from "node:os";

// Characterization ONLY: neither a proxy-only PASS nor zero observed probes
// establishes all-channel network confinement. All listeners are disposable
// and restricted to the CI runner's 127.0.0.1, never a real LAN service.
if (process.platform !== "win32" || process.env.GITHUB_ACTIONS !== "true")
  throw Error("Disposable native Windows CI runner required");
const stage=process.argv[2], channel=process.argv[3];
if (!stage || !path.isAbsolute(stage) || !["chrome","msedge"].includes(channel))
  throw Error("Pinned candidate + supported browser channel required");
const {chromium}=await import(pathToFileURL(path.join(stage,
  "apps/remote-control-agent/node_modules/playwright-core/index.mjs")).href);
const udp=dgram.createSocket("udp4");
const udp6=dgram.createSocket("udp6");
let tcpHits=0,tcp6Hits=0;
const stunMessages=[];
const stun6Messages=[];
udp.on("message",(payload,remote)=>{
  // Count only RFC 5389 STUN/TURN packets, not unrelated UDP on the runner.
  // A valid STUN header has top two type bits 0 and magic cookie 0x2112A442.
  if (payload.length < 20 || (payload[0] & 0xc0) !== 0 ||
      payload.readUInt32BE(4) !== 0x2112a442 ||
      remote.address !== "127.0.0.1") return;
  stunMessages.push({type:payload.readUInt16BE(0),sourcePort:remote.port});
});
udp6.on("message",(payload,remote)=>{
  if(payload.length < 20 || (payload[0] & 0xc0) !== 0 ||
      payload.readUInt32BE(4) !== 0x2112a442 || remote.address !== "::1") return;
  stun6Messages.push({type:payload.readUInt16BE(0),sourcePort:remote.port});
});
const tcp6=net.createServer(socket=>{
  tcp6Hits++;
  socket.on("error",()=>{});
  socket.destroy();
});
const tcp=net.createServer(socket=>{
  tcpHits++;
  socket.on("error",()=>{});
  socket.destroy();
});
const bindUdp=()=>new Promise((resolve,reject)=>{
  udp.once("error",reject);
  udp.bind(0,"127.0.0.1",()=>resolve(udp.address().port));
});
const bindUdp6=()=>new Promise((resolve,reject)=>{
  udp6.once("error",reject);
  udp6.bind(0,"::1",()=>resolve(udp6.address().port));
});
const bindTcp=()=>new Promise((resolve,reject)=>{
  tcp.once("error",reject);
  tcp.listen(0,"127.0.0.1",()=>resolve(tcp.address().port));
});
const uport=await bindUdp(),tport=await bindTcp();
const u6port=await bindUdp6();
const t6port=await new Promise((resolve,reject)=>{
  tcp6.once("error",reject);
  tcp6.listen(0,"::1",()=>resolve(tcp6.address().port));
});
const tmp=await mkdtemp(path.join(os.tmpdir(),"rca-webrtc-egress-"));
let context;
try{
  const {createServer}=await import("node:http");
  const proxy=createServer((_,res)=>{res.writeHead(403);res.end();});
  proxy.on("connect",(_req,socket)=>{
    socket.on("error",()=>{}); // TCP rejection can race Chromium teardown.
    socket.end("HTTP/1.1 403 Forbidden\r\n\r\n");
  });
  proxy.on("connection",socket=>socket.on("error",()=>{}));
  await new Promise((resolve,reject)=>{
    proxy.once("error",reject);
    proxy.listen(0,"127.0.0.1",resolve);
  });
  try{
    const address=proxy.address();
    assert.ok(address && typeof address!=="string");
    for (const mode of ["baseline", "proxy-udp-policy"]) {
      // A/B characterization: baseline is required to distinguish a real
      // browser probe from an inert STUN/TURN fixture. Neither result is a
      // substitute for OS-level network isolation.
      const beforeUdp=stunMessages.length, beforeTcp=tcpHits;
      const beforeUdp6=stun6Messages.length, beforeTcp6=tcp6Hits;
      const args=["--proxy-bypass-list=<-loopback>","--disable-quic"];
      if(mode==="proxy-udp-policy")
        args.push("--force-webrtc-ip-handling-policy=disable_non_proxied_udp");
      context=await chromium.launchPersistentContext(
        path.join(tmp,channel+"-"+mode),{
          channel,headless:true,acceptDownloads:false,serviceWorkers:"block",
          timeout:20000,
          proxy:{server:"http://127.0.0.1:"+address.port,bypass:"<-loopback>"},
          args,
        }
      );
      try{
        const page=context.pages()[0]??await context.newPage();
        await page.goto("about:blank");
        const result=await page.evaluate(async ({uport,tport,u6port,t6port})=>{
          const pc=new RTCPeerConnection({
            iceServers:[
              {urls:"stun:127.0.0.1:"+uport},
              {urls:"stun:[::1]:"+u6port},
              {urls:"turn:127.0.0.1:"+tport+"?transport=tcp",
                username:"ci",credential:"ci"},
              {urls:"turn:[::1]:"+t6port+"?transport=tcp",
                username:"ci",credential:"ci"},
            ],
          });
          try{
            pc.createDataChannel("isolated-ci");
            await pc.setLocalDescription(await pc.createOffer());
            await new Promise(resolve=>setTimeout(resolve,2000));
            return {webrtcAvailable:true,gatherState:pc.iceGatheringState};
          }finally{pc.close();}
        },{uport,tport,u6port,t6port});
        const deltaUdp=stunMessages.length-beforeUdp, deltaTcp=tcpHits-beforeTcp;
        const deltaUdp6=stun6Messages.length-beforeUdp6, deltaTcp6=tcp6Hits-beforeTcp6;
        const types=[...new Set(stunMessages.slice(beforeUdp).map(x=>x.type))];
        const sourcePorts=[...new Set(stunMessages.slice(beforeUdp).map(x=>x.sourcePort))];
        console.log("WINDOWS_WEBRTC_PROXY_EGRESS_OBSERVATION="+JSON.stringify({
          channel,mode,...result,udpHits:deltaUdp,tcpHits:deltaTcp,
          udp6Hits:deltaUdp6,tcp6Hits:deltaTcp6,
          stunTypes:types,uniqueSourcePorts:sourcePorts.length,
          strictIsolation:deltaUdp===0&&deltaTcp===0&&deltaUdp6===0&&deltaTcp6===0?"NOT_PROVEN":"FAILED",
          osNetworkConfinement:"NOT_TESTED"
        }));
      }finally{
        await context.close().catch(()=>{});
        context=undefined;
      }
      // Permit STUN retransmissions from the previous peer connection to
      // finish before measuring a second, separately launched process.
      await new Promise(resolve=>setTimeout(resolve,750));
    }
    // This is intentionally an observation, NOT an assertion of containment.
    // Future integration acceptance MUST assert zero hits with a separately
    // enforced OS-level boundary and a positive control verifying probe activity.
  }finally{
    await context?.close().catch(()=>{});
    await new Promise(resolve=>proxy.close(resolve));
  }
}finally{
  udp.close();
  udp6.close();
  await new Promise(resolve=>tcp.close(resolve));
  await new Promise(resolve=>tcp6.close(resolve));
  await rm(tmp,{recursive:true,force:true});
}
