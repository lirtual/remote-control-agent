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
let udpHits=0, tcpHits=0;
udp.on("message",()=>{udpHits++;});
const tcp=net.createServer(socket=>{
  tcpHits++;
  socket.on("error",()=>{});
  socket.destroy();
});
const bindUdp=()=>new Promise((resolve,reject)=>{
  udp.once("error",reject);
  udp.bind(0,"127.0.0.1",()=>resolve(udp.address().port));
});
const bindTcp=()=>new Promise((resolve,reject)=>{
  tcp.once("error",reject);
  tcp.listen(0,"127.0.0.1",()=>resolve(tcp.address().port));
});
const uport=await bindUdp(),tport=await bindTcp();
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
      const beforeUdp=udpHits, beforeTcp=tcpHits;
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
        const result=await page.evaluate(async ({uport,tport})=>{
          const pc=new RTCPeerConnection({
            iceServers:[
              {urls:"stun:127.0.0.1:"+uport},
              {urls:"turn:127.0.0.1:"+tport+"?transport=tcp",
                username:"ci",credential:"ci"},
            ],
          });
          try{
            pc.createDataChannel("isolated-ci");
            await pc.setLocalDescription(await pc.createOffer());
            await new Promise(resolve=>setTimeout(resolve,2000));
            return {webrtcAvailable:true,gatherState:pc.iceGatheringState};
          }finally{pc.close();}
        },{uport,tport});
        const deltaUdp=udpHits-beforeUdp, deltaTcp=tcpHits-beforeTcp;
        console.log("WINDOWS_WEBRTC_PROXY_EGRESS_OBSERVATION="+JSON.stringify({
          channel,mode,...result,udpHits:deltaUdp,tcpHits:deltaTcp,
          strictIsolation:deltaUdp===0&&deltaTcp===0?"NOT_PROVEN":"FAILED",
          osNetworkConfinement:"NOT_TESTED"
        }));
      }finally{
        await context.close().catch(()=>{});
        context=undefined;
      }
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
  await new Promise(resolve=>tcp.close(resolve));
  await rm(tmp,{recursive:true,force:true});
}
