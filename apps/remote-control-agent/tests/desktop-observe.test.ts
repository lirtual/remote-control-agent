import assert from "node:assert/strict";
import test from "node:test";
import { parseDesktopObserve, validDesktopImage, type DesktopImage } from "../src/desktop-observe.ts";
import { monitorDeviceSocket } from "../src/v2-connection-lifecycle.ts";
const uid = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const req = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const jpeg = Buffer.from([255,216,255,224,0,0,0,0,0,0,0,0,0,0,255,217]).toString("base64");
const image: DesktopImage = {
 type:"desktop_image", mime_type:"image/jpeg",data:jpeg, width:2,height:2,
 native_width:4,native_height:4,origin_x:-100,origin_y:0,
 target_id:"primary",session_id:1,observation_id:uid,grant_generation:uid,
};
test("computer_observe accepts only an explicit primary display and valid JPEG",()=>{
 assert.deepEqual(parseDesktopObserve({target_kind:"display",target_id:"primary"}),{target_kind:"display",target_id:"primary"});
 for(const obj of [{},{target_kind:"window",target_id:"primary"},
 {target_kind:"display",target_id:"primary",script:"x"}]){
  assert.equal(parseDesktopObserve(obj),null);
 }
 assert.equal(validDesktopImage(image),true);
 assert.equal(validDesktopImage({...image,data:"not an image"}),false);
 assert.equal(validDesktopImage({...image,width:20000}),false);
});
test("signed Agent WSS streams bounded image chunks with a matching terminal frame",async()=>{
 class Socket extends EventTarget {
  readyState=1; sent: any[]=[];
  send(data:string){this.sent.push(JSON.parse(data));this.dispatchEvent(new Event("sent"));}
  close(){this.readyState=3;}
  receive(data:unknown){this.dispatchEvent(new MessageEvent("message",{data:JSON.stringify(data)}));}
 }
 const socket=new Socket();
 const ctl=new AbortController();
 const live=monitorDeviceSocket(socket as unknown as WebSocket,ctl.signal,
  {intervalMs:10000,timeoutMs:1000},
  async(tool,args)=> {
   assert.equal(tool,"computer_observe");
   assert.deepEqual(args,{target_kind:"display",target_id:"primary"});
   return image;
  });
 const reply=new Promise<void>((resolve,reject)=>{
  const timeout=setTimeout(()=>reject(Error("image frames missing")),3000);
  const onSent=()=>{
   if(!socket.sent.some(f=>f.kind==="image_result"))return;
   clearTimeout(timeout);socket.removeEventListener("sent",onSent);resolve();
  };
  socket.addEventListener("sent",onSent);
 });
 try {
  socket.receive({kind:"read",request_id:req,tool:"computer_observe",
    arguments:{target_kind:"display",target_id:"primary"}});
  await reply;
  const chunks=socket.sent.filter(f=>f.kind==="image_chunk");
  assert.ok(chunks.length>=1);
  assert.deepEqual(chunks.map(f=>f.seq),chunks.map((_,i)=>i));
  assert.equal(chunks.map(f=>f.chunk).join(""),jpeg);
  const end=socket.sent.find(f=>f.kind==="image_result");
  assert.equal(end.status,"completed");
  assert.equal(end.metadata.observation_id,uid);
  assert.equal(end.metadata.data,undefined);
 } finally {
  ctl.abort();assert.equal(await live,"aborted");
 }
});
