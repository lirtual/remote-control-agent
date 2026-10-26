import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { request } from "node:http";
import test from "node:test";
import { isControllerDocumentPath, parseHumanAction, startHandoffController } from "../src/handoff-controller.ts";
import type { BrowserBackend } from "../src/browser-backend.ts";

const origin="https://handoff.example.test";
// Simulate Cloudflare's origin forwarding. Node fetch replaces Host with the
// loopback authority; that would not exercise the production Host boundary.
function forwardedPost(port: number, route: string, data: unknown, headers: Record<string,string> = {}): Promise<Response> {
  return new Promise((resolve, reject) => {
    const req = request({
      hostname: "127.0.0.1", port, path: route, method: "POST",
      headers: { host: new URL(origin).host, origin, "content-type": "application/json", ...headers },
    }, res => {
      const chunks: Buffer[] = [];
      res.on("data", chunk => chunks.push(Buffer.from(chunk)));
      res.on("error", reject);
      res.on("end", () => {
        const responseHeaders = new Headers();
        for (const [name, value] of Object.entries(res.headers)) {
          if (Array.isArray(value)) value.forEach(item => responseHeaders.append(name, item));
          else if (typeof value === "string") responseHeaders.append(name, value);
        }
        resolve(new Response(Buffer.concat(chunks), { status: res.statusCode ?? 500, headers: responseHeaders }));
      });
    });
    req.on("error", reject);
    req.end(JSON.stringify(data));
  });
}

// Exercise the HTTP GET that Safari performs after Cloudflare's OTP redirect.
// Node's default Host is the loopback forwarding target, not the public name.
function forwardedGet(port: number, route: string, host?: string): Promise<Response> {
  return new Promise((resolve,reject) => {
    const req=request({hostname:"127.0.0.1",port,path:route,method:"GET",
      ...(host?{headers:{host}}:{})},res=>{
      const chunks:Buffer[]=[];
      res.on("data",chunk=>chunks.push(Buffer.from(chunk)));
      res.on("error",reject);
      res.on("end",()=>resolve(new Response(Buffer.concat(chunks),{
        status:res.statusCode??500,
        headers:{"content-type":String(res.headers["content-type"]??"")},
      })));
    });
    req.on("error",reject);req.end();
  });
}

test("iOS OTP return renders the controller through a strictly bounded loopback Host",async()=>{
  const sessionId=randomUUID();let connected=0;const diagnostics:string[]=[];
  const browser={status:()=>({session_id:sessionId}),
    tabs:async()=>({selected_tab_id:"tab-1",tabs:[{tab_id:"tab-1",url:"about:blank",title:""}]}),
    humanInput:async()=>{},humanScreenshot:async()=>Buffer.from("frame"),
  } as unknown as BrowserBackend;
  const controller=await startHandoffController({browser,deviceId:randomUUID(),sessionId,
    expiresAt:Date.now()+60_000,origin:()=>origin,active:()=>true,
    connected:()=>{connected++;},explicitReturn:async()=>{},diagnostic:code=>diagnostics.push(code)});
  try {
    const url="/?handoff_token="+controller.token;
    for(const authority of [new URL(origin).host,`127.0.0.1:${controller.port}`]){
      const page=await forwardedGet(controller.port,url,authority);
      assert.equal(page.status,200,"valid public or local tunnel authority must render HTML");
      assert.match(page.headers.get("content-type")??"",/^text\/html/);
      assert.match(await page.text(),/Browser handoff/);
      assert.equal(diagnostics.at(-1),"document_served");
      for (const postOtpReturn of [
        url+"&utm_source=chatgpt.com",
        "/?utm_source=chatgpt.com&handoff_token="+controller.token,
        "/?handoff_token="+controller.token+"&tracking=opaque",
      ]) {
        const redirected=await forwardedGet(controller.port,postOtpReturn,authority);
        assert.equal(redirected.status,200,"valid current token must survive inert OTP return query metadata");
        assert.match(redirected.headers.get("content-type")??"",/^text\/html/);
        const html=await redirected.text();
        assert.match(html,/Browser handoff/);
        assert.doesNotMatch(html,/chatgpt\.com|tracking=opaque|handoff_token=/,
          "HTML must never reflect return query metadata or the bearer token");
        assert.equal(diagnostics.at(-1),"document_served");
      }
      const script=await forwardedGet(controller.port,"/controller.js",authority);
      assert.equal(script.status,200);
      assert.match(await script.text(),/\/(?:exchange|resume)/);
      assert.equal(diagnostics.at(-1),"script_served");
    }
    assert.equal((await forwardedGet(controller.port,url,"untrusted.example.test")).status,403);
    assert.equal(diagnostics.at(-1),"document_denied_host");
    assert.equal((await forwardedGet(controller.port,"/bad?handoff_token="+controller.token)).status,403);
    assert.equal((await forwardedGet(controller.port,"/?handoff_token=WRONG")).status,403);
    for (const rejected of [
      "/?utm_source=chatgpt.com",
      "/?handoff_token="+controller.token+"&handoff_token="+controller.token,
      "/?handoff%5Ftoken="+controller.token+"&handoff_token="+controller.token,
      "/?handoff_token="+controller.token+"&q="+("z".repeat(500)),
      "/?handoff_token="+controller.token+"&a=1&b=2&c=3&d=4",
    ]) {
      assert.equal((await forwardedGet(controller.port,rejected)).status,403,
        "extra query cannot bypass exact one-token, count, and length constraints");
      if (rejected === "/?utm_source=chatgpt.com")
        assert.equal(diagnostics.at(-1),"document_denied_token_missing","detect token stripped by OTP return");
    }
    assert.equal(diagnostics.at(-1),"document_denied_path");
    // An untrusted POST Origin may never exchange the token even via localhost.
    const localHost={host:`127.0.0.1:${controller.port}`};
    assert.equal((await forwardedPost(controller.port,"/exchange",{token:controller.token},
      {...localHost,origin:"https://evil.example.test"})).status,403);
    assert.equal(diagnostics.at(-1),"exchange_denied_origin");
    // The OTP callback must be consumed upstream; a leaked POST is rejected.
    assert.equal((await forwardedPost(controller.port,"/.cloudflared/qt-auth/callback",{},
      {...localHost,origin:"https://login.trycloudflare.com"})).status,403);
    assert.equal(diagnostics.at(-1),"callback_path_received");
    const exchanged=await forwardedPost(controller.port,"/exchange",{token:controller.token},localHost);
    assert.equal(exchanged.status,200);
    assert.equal(connected,1);
    assert.equal(diagnostics.at(-1),"exchange_completed");
    const cookie=exchanged.headers.get("set-cookie")?.split(";")[0];
    const csrf=(await exchanged.json() as {csrf:string}).csrf;
    assert.ok(cookie);
    assert.equal((await forwardedPost(controller.port,"/exchange",{token:controller.token},localHost)).status,403);
    assert.equal(diagnostics.at(-1),"exchange_denied_token");
    // The external status projection is a fixed enum, never request secrets.
    assert.ok(diagnostics.every(code=>!code.includes(controller.token) && !code.includes("handoff.example")));
    assert.equal((await forwardedPost(controller.port,"/tabs",{},
      {...localHost,cookie:cookie!,"x-handoff-csrf":csrf})).status,200);
    assert.equal((await forwardedPost(controller.port,"/tabs",{},
      {...localHost,cookie:cookie!,"x-handoff-csrf":csrf,origin:"https://evil.example.test"})).status,403);
  }finally{await controller.close();}
});

test("human HTTP controller: one exchange, strict origin/CSRF, bounded content, session binding and expiry",async()=>{
  const sessionId=randomUUID();let active=true,inputs=0,connected=0,returned=0;
  let liveSession=sessionId;
  const browser={status:()=>({session_id:liveSession}),
    tabs:async()=>({selected_tab_id:"tab-1",tabs:[{tab_id:"tab-1",title:"Page",url:"https://example.com/"}]}),
    humanInput:async(_id:unknown,_action:unknown,allowed:()=>boolean)=>{assert.equal(allowed(),true);inputs++;},
    humanScreenshot:async()=>Buffer.from("frame"),
  } as unknown as BrowserBackend;
  const controller=await startHandoffController({browser,deviceId:randomUUID(),sessionId,expiresAt:Date.now()+60_000,
    origin:()=>origin,active:()=>active,connected:()=>{connected++;},explicitReturn:async()=>{returned++;}});
  const post = (route:string,body:unknown,headers:Record<string,string>={}) =>
    forwardedPost(controller.port,route,body,headers);
  try {
    assert.equal((await post("/exchange",{token:controller.token},{host:"wrong.test"})).status,403);
    assert.equal((await post("/exchange",{token:controller.token},{origin:"https://evil.example"})).status,403);
    assert.equal((await post("/exchange",{token:"wrong"})).status,403);
    const first=await post("/exchange",{token:controller.token});assert.equal(first.status,200);
    assert.equal(first.headers.get("cache-control"),"no-store");assert.equal(first.headers.get("referrer-policy"),"no-referrer");
    const cookie=first.headers.get("set-cookie")!;
    for(const attribute of ["Secure","HttpOnly","SameSite=Strict","Path=/"])assert.ok(cookie.includes(attribute));
    const auth={cookie:cookie.split(";")[0]!,"x-handoff-csrf":(await first.json() as {csrf:string}).csrf};
    assert.equal(connected,1);
    assert.equal((await post("/exchange",{token:controller.token})).status,403,"second controller/token replay refused");
    assert.equal((await post("/resume",{}, {cookie:auth.cookie})).status,200,"same cookie reconnects without extending expiry");
    assert.equal((await post("/tabs",{}, {cookie:auth.cookie})).status,403,"CSRF required");
    assert.equal((await post("/screenshot",{tab_id:"tab-1"},auth)).status,200);
    assert.equal((await post("/screenshot",{tab_id:"tab-1"},auth)).status,429);
    assert.equal((await post("/input",{kind:"text",tab_id:"tab-1",text:"private"},auth)).status,200);
    assert.equal(inputs,1);
    assert.equal((await post("/input",{kind:"eval",tab_id:"tab-1",text:"ignored"},auth)).status,400);
    assert.equal((await post("/input",{kind:"text",tab_id:"tab-1",text:"x".repeat(9000)},auth)).status,400);
    liveSession=randomUUID();
    assert.equal((await post("/tabs",{},auth)).status,403,"never attaches to replacement context");
    liveSession=sessionId;
    active=false;
    assert.equal((await post("/input",{kind:"key",tab_id:"tab-1",key:"Enter"},auth)).status,403);
    assert.equal(inputs,1);assert.equal(returned,0);
  } finally {assert.equal(await controller.close(),"confirmed");}
});

test("explicit return invalidates endpoints before async cleanup",async()=>{
  const id=randomUUID();let returned=0,deadline=Date.now()+60_000;
  const browser={status:()=>({session_id:id}),humanInput:async()=>{},humanScreenshot:async()=>Buffer.from("x")} as unknown as BrowserBackend;
  const controller=await startHandoffController({browser,deviceId:randomUUID(),sessionId:id,expiresAt:deadline,origin:()=>origin,active:()=>true,connected:()=>{},explicitReturn:async()=>{returned++;}});
  const call=(route:string,body:unknown,auth:Record<string,string>={}) =>
    forwardedPost(controller.port,route,body,auth);
  try {
    const exchange=await call("/exchange",{token:controller.token});
    const auth={cookie:exchange.headers.get("set-cookie")!.split(";")[0]!,"x-handoff-csrf":(await exchange.json() as {csrf:string}).csrf};

    assert.equal((await call("/return",{},auth)).status,200);
    assert.equal(returned,1);
    assert.equal((await call("/resume",{},auth)).status,403);
  } finally {await controller.close();}
});

test("bounded human input grammar excludes JS, arbitrary keys, clipboard and file paths",()=>{
  for(const value of [{kind:"eval",tab_id:"tab-1",text:"1"},{kind:"key",tab_id:"tab-1",key:"Control+L"},
    {kind:"click",tab_id:"tab-1",x:-1,y:0},{kind:"scroll",tab_id:"tab-1",x:0,y:2001},
    {kind:"text",tab_id:"tab-1",text:"x".repeat(5001)},{kind:"text",tab_id:"tab-1",text:"ok",path:"/tmp/file"}])
    assert.equal(parseHumanAction(value),null);
  assert.ok(parseHumanAction({kind:"text",tab_id:"tab-1",text:"ordinary paste"}));
});


test("absolute expiry latches even if the wall clock moves backwards",async()=>{
  const id=randomUUID(),deadline=Date.now()+60_000;
  const browser={status:()=>({session_id:id}),humanInput:async()=>{},humanScreenshot:async()=>Buffer.from("x")} as unknown as BrowserBackend;
  const controller=await startHandoffController({browser,deviceId:randomUUID(),sessionId:id,expiresAt:deadline,origin:()=>origin,active:()=>true,connected:()=>{},explicitReturn:async()=>{}});
  const now=Date.now;
  try {
    Date.now=()=>deadline;
    assert.equal((await forwardedPost(controller.port,"/exchange",{token:controller.token})).status,403);
    Date.now=now;
    assert.equal((await forwardedPost(controller.port,"/exchange",{token:controller.token})).status,403);
  } finally {Date.now=now;await controller.close();}
});

test("controller return-path parser is rooted, bounded, and tied to one exact token",()=>{
  const token="A".repeat(42)+"_";
  assert.equal(isControllerDocumentPath("/",token),true);
  assert.equal(isControllerDocumentPath("/?handoff_token="+token,token),true);
  assert.equal(isControllerDocumentPath("/?utm_source=chatgpt.com&handoff_token="+token,token),true);
  assert.equal(isControllerDocumentPath("/?handoff_token="+token+"&utm_medium=chat",token),true);
  for (const target of [
    undefined, "", "/subpath?handoff_token="+token,
    "//evil.test/?handoff_token="+token, "https://evil.test/?handoff_token="+token,
    "/?utm_source=chatgpt.com", "/?handoff_token="+("B".repeat(43)),
    "/?handoff_token="+token+"&handoff_token="+token,
    "/?handoff_token="+token+"&a=1&b=2&c=3&d=4",
    "/?handoff_token="+token+"&a="+("x".repeat(501)),
  ]) assert.equal(isControllerDocumentPath(target,token),false,String(target));
});
