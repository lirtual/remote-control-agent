/** Bounded desktop observation. Never logs or persists image bytes. */
import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { promisify } from "node:util";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { readDesktopGrant, assertDesktopGrantGeneration } from "./desktop-grant.ts";

const run = promisify(execFile);
export const MAX_IMAGE_BASE64 = 700_000;
export const IMAGE_CHUNK_SIZE = 24_000;
export type DesktopObservationError = {
  type:"desktop_error";
  code:"desktop_stopped"|"desktop_session_unavailable"|"unsupported"|"permission_required";
};
const denied = (code:DesktopObservationError["code"]):DesktopObservationError => ({type:"desktop_error",code});
export function isDesktopObservationError(value:unknown):value is DesktopObservationError {
  return !!value && typeof value==="object" && !Array.isArray(value) &&
    (value as Record<string,unknown>).type==="desktop_error" &&
    ["desktop_stopped","desktop_session_unavailable","unsupported","permission_required"]
      .includes(String((value as Record<string,unknown>).code));
}
export type DesktopObservation = DesktopImage | DesktopObservationError;
export type DesktopImage = {
  type: "desktop_image";
  mime_type: "image/jpeg";
  data: string;
  width: number; height: number;
  native_width: number; native_height: number;
  origin_x: number; origin_y: number;
  target_id: "primary";
  session_id: number;
  observation_id: string;
  grant_generation: string;
};
export function parseDesktopObserve(value: unknown): {target_kind:"display";target_id:"primary"} | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const x = value as Record<string,unknown>;
  return Object.keys(x).length === 2 && x.target_kind === "display" && x.target_id === "primary"
    ? {target_kind:"display",target_id:"primary"} : null;
}
export function validDesktopImage(value: unknown): value is DesktopImage {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const x=value as Record<string, unknown>;
  const ints=["width","height","native_width","native_height","origin_x","origin_y","session_id"] as const;
  if (!ints.every(k=>Number.isSafeInteger(x[k]))) return false;
  if (!(Number(x.width)>0 && Number(x.width)<=1920 && Number(x.height)>0 && Number(x.height)<=1920 &&
    Number(x.native_width)>0 && Number(x.native_width)<=16384 &&
    Number(x.native_height)>0 && Number(x.native_height)<=16384 &&
    Number(x.session_id)>=0)) return false;
  if (x.type!=="desktop_image" || x.mime_type!=="image/jpeg" || x.target_id!=="primary" ||
    typeof x.grant_generation!=="string" || !/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(x.grant_generation) ||
    typeof x.observation_id!=="string" || !/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(x.observation_id) ||
    typeof x.data!=="string" || x.data.length<16 || x.data.length>MAX_IMAGE_BASE64 ||
    x.data.length%4!==0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(x.data)) return false;
  const bytes=Buffer.from(x.data,"base64");
  return bytes.length>4 && bytes.length<=524288 && bytes[0]===255 && bytes[1]===216 &&
    bytes[bytes.length-2]===255 && bytes[bytes.length-1]===217 &&
    bytes.toString("base64")===x.data;
}
/** The command is a package-owned fixed script; no CLI/Powershell arguments come from MCP. */
export async function captureDesktopImage(
  desktopDirectory:string, args:unknown, signal:AbortSignal,
): Promise<DesktopObservation> {
  if (!parseDesktopObserve(args)) return denied("unsupported");
  if (process.platform!=="win32") return denied("unsupported");
  if (signal.aborted) return denied("desktop_session_unavailable");
  let grant: Awaited<ReturnType<typeof readDesktopGrant>>;
  try { grant=await readDesktopGrant(desktopDirectory); }
  catch { return denied("desktop_stopped"); }
  if (grant.state!=="enabled" || !grant.generation) return denied("desktop_stopped");
  const systemRoot=process.env.SystemRoot;
  if (!systemRoot || !path.win32.isAbsolute(systemRoot)) return denied("unsupported");
  const exe=path.win32.join(systemRoot,"System32","WindowsPowerShell","v1.0","powershell.exe");
  const script=fileURLToPath(new URL("../scripts/windows-capture.ps1",import.meta.url));
  try {
    const result=await run(exe,["-NoProfile","-NonInteractive","-ExecutionPolicy","Bypass","-File",script],
      {windowsHide:true,timeout:5000,maxBuffer:800_000,signal,encoding:"utf8"});
    const answer=JSON.parse(result.stdout) as Record<string,unknown>;
    const image={...answer,type:"desktop_image",mime_type:"image/jpeg",
      target_id:"primary",observation_id:randomUUID(),grant_generation:grant.generation};
    if (!validDesktopImage(image)) return denied("desktop_session_unavailable");
    await assertDesktopGrantGeneration(desktopDirectory,grant.generation);
    if (signal.aborted) return denied("desktop_session_unavailable");
    return image;
  } catch {
    try { await assertDesktopGrantGeneration(desktopDirectory,grant.generation); }
    catch { return denied("desktop_stopped"); }
    return denied("desktop_session_unavailable");
  }
}
