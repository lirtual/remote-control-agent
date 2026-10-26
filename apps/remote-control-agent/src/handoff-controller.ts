/** Bounded HTTP controller for the existing Agent-owned headed context. No proxy/eval/CDP. */
import { Buffer } from "node:buffer";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { randomBytes, timingSafeEqual } from "node:crypto";
import type { BrowserBackend, HumanBrowserAction } from "./browser-backend.ts";
import type { HumanAccess } from "./browser-handoff.ts";

const secret = () => Buffer.from(randomBytes(32)).toString("base64url");
function equal(a: unknown, b: string): boolean {
  return typeof a === "string" && a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));
}
export function parseHumanAction(raw: unknown): HumanBrowserAction | null {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
  const a = raw as Record<string, unknown>;
  if (typeof a.tab_id !== "string" || !/^tab-[1-9]\d{0,6}$/.test(a.tab_id)) return null;
  const keys = a.kind === "click" || a.kind === "scroll" ? ["kind","tab_id","x","y"]
    : a.kind === "text" ? ["kind","tab_id","text"] : ["kind","tab_id","key"];
  if (Object.keys(a).length !== keys.length || !keys.every(k => Object.hasOwn(a,k))) return null;
  if (a.kind === "click" || a.kind === "scroll") {
    const limit = a.kind === "click" ? 10_000 : 2000;
    if (typeof a.x !== "number" || typeof a.y !== "number" || !Number.isFinite(a.x) || !Number.isFinite(a.y) ||
        Math.abs(a.x) > limit || Math.abs(a.y) > limit || a.kind === "click" && (a.x < 0 || a.y < 0)) return null;
    return {kind:a.kind,tab_id:a.tab_id,x:a.x,y:a.y};
  }
  if (a.kind === "text" && typeof a.text === "string" && a.text.length <= 5000)
    return {kind:"text",tab_id:a.tab_id,text:a.text};
  if (a.kind === "key" && typeof a.key === "string" &&
      ["Enter","Tab","Shift+Tab","Backspace","Delete","Escape","ArrowLeft","ArrowRight","ArrowUp","ArrowDown","Home","End"].includes(a.key))
    return {kind:"key",tab_id:a.tab_id,key:a.key};
  return null;
}
const html = `<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>Browser handoff</title></head><body><p id="state">Connecting…</p><select id="tabs"></select><button id="refresh">Refresh</button><button id="return">Complete and return</button><br><img id="screen" alt="Current automation page" style="max-width:100%;touch-action:pan-y"><br><textarea id="text" maxlength="5000" placeholder="Type or paste into the focused page field"></textarea><button id="send">Send text</button><select id="key"><option>Enter</option><option>Tab</option><option>Backspace</option><option>Escape</option><option>ArrowDown</option><option>ArrowUp</option></select><button id="press">Press key</button><button id="up">Scroll up</button><button id="down">Scroll down</button><script src="/controller.js"></script></body></html>`;
const js = `
const element = id => document.getElementById(id);
let csrf = '', tab = '', busy = false, done = false, lastFrame = -Infinity;
let token = new URL(location.href).searchParams.get('handoff_token') || location.hash.slice(1);
history.replaceState(null, '', '/');
async function api(route, body) {
  const response = await fetch(route, {
    method: 'POST', headers: {'content-type':'application/json', 'x-handoff-csrf':csrf},
    body: JSON.stringify(body)
  });
  if (!response.ok) {
    const error = Error(response.status === 429 ? 'Please wait before sending another request.' :
      'Controller unavailable, expired, or already claimed. Explicit return is still required.');
    error.denied = response.status === 403;
    throw error;
  }
  return response.json();
}
function failed(error) {
  element('state').textContent = error.message;
  if (error.denied) {
    done = true;
    element('screen').removeAttribute('src');
    element('text').value = '';
  }
}
async function refresh() {
  if (busy || done || performance.now() - lastFrame < 550) return;
  busy = true;
  try {
    const result = await api('/tabs', {});
    const placeholder = document.createElement('option');
    placeholder.value = ''; placeholder.textContent = 'Select a tab';
    const choices = result.tabs.map(item => {
      const option = document.createElement('option');
      option.value = item.tab_id; option.textContent = item.title || item.tab_id;
      return option;
    });
    element('tabs').replaceChildren(placeholder, ...choices);
    tab = result.selected_tab_id || '';
    element('tabs').value = tab;
    if (!tab) {
      element('screen').removeAttribute('src');
      element('state').textContent = 'Select the page or login popup to control.';
      return;
    }
    const frame = await api('/screenshot', {tab_id:tab});
    lastFrame = performance.now();
    element('screen').src = 'data:image/jpeg;base64,' + frame.image;
    element('state').textContent = 'Human control — expires at ' + new Date(frame.expires_at).toLocaleTimeString();
  } catch (error) { failed(error); }
  finally { busy = false; }
}
async function action(input) {
  if (busy || done || !tab) return;
  busy = true;
  try { await api('/input', {tab_id:tab, ...input}); }
  catch (error) { failed(error); }
  finally { busy = false; }
  setTimeout(refresh, 550);
}
element('tabs').onchange = async () => {
  if (busy || done || !element('tabs').value) return;
  busy = true;
  try { await api('/select', {tab_id:element('tabs').value}); }
  catch (error) { failed(error); }
  finally { busy = false; }
  setTimeout(refresh, 550);
};
element('screen').onclick = event => {
  const box = event.target.getBoundingClientRect();
  action({kind:'click', x:(event.clientX-box.left)*event.target.naturalWidth/box.width,
    y:(event.clientY-box.top)*event.target.naturalHeight/box.height});
};
element('send').onclick = () => {
  if (busy || done || !tab) return;
  const text = element('text').value; element('text').value = '';
  action({kind:'text', text});
};
element('press').onclick = () => action({kind:'key', key:element('key').value});
element('up').onclick = () => action({kind:'scroll', x:0, y:-500});
element('down').onclick = () => action({kind:'scroll', x:0, y:500});
element('refresh').onclick = refresh;
element('return').onclick = async () => {
  try {
    await api('/return', {}); done = true;
    element('screen').removeAttribute('src'); element('text').value = '';
    element('state').textContent = 'Return requested. Check handoff status in ChatGPT before continuing.';
  } catch (error) { failed(error); }
};
(async () => {
  try {
    const result = await api(token ? '/exchange' : '/resume', token ? {token} : {});
    token = ''; csrf = result.csrf;
    await refresh(); setInterval(refresh, 1500);
  } catch (error) { token = ''; failed(error); }
})();`;


export async function startHandoffController(options: {
  browser: BrowserBackend; deviceId: string; sessionId: string;
  /** Absolute issuance deadline, never extended by exchange or reconnect. */
  expiresAt: number;
  readinessProbe?: string;
  origin: () => string | undefined;
  active: () => boolean;
  connected: () => void;
  explicitReturn: () => Promise<unknown>;
}): Promise<HumanAccess & {port: number; token: string}> {
  if (!/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(options.deviceId) ||
      !/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(options.sessionId) ||
      !Number.isSafeInteger(options.expiresAt) || options.expiresAt <= Date.now() ||
      options.expiresAt > Date.now() + 900_000 || !options.browser.humanInput || !options.browser.humanScreenshot)
    throw Error("Handoff binding unavailable.");
  const expiresMonotonic = performance.now() + (options.expiresAt - Date.now());
  const token = secret(), cookie = secret(), csrf = secret();
  let exchanged = false, closed = false, lastScreenshot = 0, lastInput = 0;
  let pending: Promise<void> | undefined;
  const valid = () => {
    if (Date.now() >= options.expiresAt || performance.now() >= expiresMonotonic ||
        options.browser.status()?.session_id !== options.sessionId) closed=true;
    return !closed && options.active();
  };
  const headers = {
    "cache-control":"no-store", "referrer-policy":"no-referrer", "x-content-type-options":"nosniff",
    "content-security-policy":"default-src 'none'; script-src 'self'; connect-src 'self'; img-src data:; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
  };
  function reply(res: ServerResponse, code: number, value: unknown): void {
    res.writeHead(code, {...headers,"content-type":"application/json"}); res.end(JSON.stringify(value));
  }
  async function body(req: IncomingMessage): Promise<Record<string, unknown>> {
    if (req.headers["content-type"] !== "application/json" ||
        Number(req.headers["content-length"] ?? 0) > 8192) { req.resume(); throw Error(); }
    let size = 0; const chunks: Buffer[] = [];
    for await (const chunk of req) { size += chunk.length; if (size > 8192) throw Error(); chunks.push(Buffer.from(chunk)); }
    const value: unknown = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    if (!value || typeof value !== "object" || Array.isArray(value)) throw Error();
    return value as Record<string, unknown>;
  }
  const server = createServer({maxHeaderSize:8192,requestTimeout:5000,headersTimeout:5000}, (req,res) => {
    void (async () => {
      if (options.readinessProbe && req.method === "GET" && req.url === "/__handoff_probe/"+options.readinessProbe &&
          req.headers.host === `127.0.0.1:${(server.address() as import("node:net").AddressInfo).port}` &&
          !closed && Date.now() < options.expiresAt && options.browser.status()?.session_id === options.sessionId) {
        req.resume(); reply(res,200,{probe:options.readinessProbe,device_id:options.deviceId,session_id:options.sessionId}); return;
      }
      const origin = options.origin();
      // A Quick Tunnel can forward the public request to its local --url with
      // the loopback Host rather than the public Host. The controller accepts
      // only those two exact authorities; never a forwarded-header override.
      // Every POST still requires the exact browser Origin below, plus the
      // one-time exchange token or the bound cookie and CSRF as appropriate.
      const listener = server.address() as import("node:net").AddressInfo;
      const loopbackHost = `127.0.0.1:${listener.port}`;
      if (!origin || new URL(origin).protocol !== "https:" || new URL(origin).origin !== origin ||
          (req.headers.host !== new URL(origin).host && req.headers.host !== loopbackHost) || !valid()) {
        req.resume(); reply(res,403,{}); return;
      }
      // Query credentials survive Cloudflare's OTP POST/callback via its signed return_path.
      // Strip immediately in the browser; no external resources or referrers are allowed.
      const controllerPage = req.url === "/" || /^\/\?handoff_token=[A-Za-z0-9_-]{43}$/.test(req.url ?? "");
      if (req.method === "GET" && (controllerPage || req.url === "/controller.js")) {
        req.resume(); res.writeHead(200,{...headers,"content-type":controllerPage ? "text/html; charset=utf-8" : "text/javascript; charset=utf-8"});
        res.end(controllerPage ? html : js); return;
      }
      if (req.method !== "POST" || req.headers.origin !== origin ||
          req.headers["sec-fetch-site"] && req.headers["sec-fetch-site"] !== "same-origin") {
        req.resume(); reply(res,403,{}); return;
      }
      const args = await body(req);
      if (!valid()) { reply(res,403,{}); return; }
      const authenticated = exchanged && typeof req.headers.cookie === "string" &&
        req.headers.cookie.split(";").some(c => equal(c.trim(),"__Host-handoff="+cookie));
      if (req.url === "/exchange") {
        if (exchanged || Object.keys(args).length !== 1 || !equal(args.token,token)) { reply(res,403,{}); return; }
        exchanged = true;
        res.setHeader("set-cookie",`__Host-handoff=${cookie}; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=${Math.max(0,Math.floor((options.expiresAt-Date.now())/1000))}`);
        options.connected(); reply(res,200,{csrf}); return;
      }
      if (!authenticated) { reply(res,403,{}); return; }
      if (req.url === "/resume" && Object.keys(args).length === 0) { reply(res,200,{csrf}); return; }
      if (!equal(req.headers["x-handoff-csrf"],csrf)) { reply(res,403,{}); return; }
      if (req.url === "/return" && Object.keys(args).length === 0) {
        closed = true; // Revoke before awaiting explicit-return cleanup.
        res.once("finish",()=>{void options.explicitReturn().catch(() => {});});
        reply(res,200,{status:"return_requested"}); return;
      }
      if (pending) { reply(res,429,{}); return; }
      const work = async () => {
        if (!valid()) { reply(res,403,{}); return; }
        if (req.url === "/tabs" && Object.keys(args).length === 0) {
          const tabs = await options.browser.tabs(options.sessionId,"list");
          reply(res,valid()?200:403,valid()?tabs:{}); return;
        }
        if ((req.url === "/screenshot" || req.url === "/select") &&
            Object.keys(args).length === 1 && typeof args.tab_id === "string" && /^tab-[1-9]\d{0,6}$/.test(args.tab_id)) {
          if (req.url === "/select") {
            await options.browser.tabs(options.sessionId,"select",args.tab_id);
            reply(res,valid()?200:403,{}); return;
          }
          if (Date.now()-lastScreenshot < 500) { reply(res,429,{}); return; }
          lastScreenshot = Date.now();
          const image = await options.browser.humanScreenshot!(options.sessionId,args.tab_id,valid);
          if (!valid() || image.length > 2_000_000) { reply(res,403,{}); return; }
          reply(res,200,{image:Buffer.from(image).toString("base64"),expires_at:options.expiresAt}); return;
        }
        const action = req.url === "/input" ? parseHumanAction(args) : null;
        if (!action) { reply(res,400,{}); return; }
        if (Date.now()-lastInput < 50) { reply(res,429,{}); return; }
        lastInput = Date.now();
        await options.browser.humanInput!(options.sessionId,action,valid);
        reply(res,valid()?200:403,{});
      };
      pending = work().finally(() => { pending = undefined; });
      await pending;
    })().catch(() => { if (!res.headersSent) reply(res,400,{}); else res.destroy(); });
  });
  server.maxConnections = 8;
  await new Promise<void>((resolve,reject) => { server.once("error",reject); server.listen(0,"127.0.0.1",resolve); });
  const address = server.address();
  if (!address || typeof address === "string") throw Error("Loopback bind failed.");
  let closing: Promise<"confirmed" | "uncertain"> | undefined;
  const close = (): Promise<"confirmed" | "uncertain"> => {
    closed = true;
    return closing ??= (async () => {
      server.closeAllConnections();
      const stopped = new Promise<void>((resolve,reject) => server.close(error => error ? reject(error) : resolve()));
      try {
        await Promise.race([Promise.all([stopped,pending]), new Promise<never>((_,reject) => {const t=setTimeout(()=>reject(Error()),6000); t.unref();})]);
        return "confirmed";
      } catch { return "uncertain"; }
    })();
  };
  const timer = setTimeout(() => { void close(); },Math.max(0,options.expiresAt-Date.now())); timer.unref();
  return {port:address.port,token,close:() => {clearTimeout(timer); return close();}};
}
