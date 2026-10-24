/** Read-only byte equality between a pinned ZIP and installed Windows Agent.
 * Caller must independently verify immutable Release tag, Git commit and asset
 * digest before passing approvedSha256. No owner approval is inferred here.
 */
import {createHash} from "node:crypto";
import {spawnSync} from "node:child_process";
import {lstatSync,readFileSync,readdirSync} from "node:fs";
import path from "node:path";

const HASH=/^[a-f0-9]{64}$/;
const SAFE=/^[A-Za-z0-9._/-]+$/;
const PS=[
 "$ErrorActionPreference='Stop'",
 "Add-Type -AssemblyName System.IO.Compression",
 "Add-Type -AssemblyName System.IO.Compression.FileSystem",
 "$archiveStream=[IO.File]::Open('__ARCHIVE__',[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None)",
 "try {",
 " $sha=[Security.Cryptography.SHA256]::Create()",
 " try{$digest=[BitConverter]::ToString($sha.ComputeHash($archiveStream)).Replace('-','').ToLowerInvariant()}",
 " finally{$sha.Dispose()}",
 " if($digest -cne '__SHA__'){throw 'Approved ZIP digest mismatch'}",
 " $archiveStream.Position=0",
 " $z=[IO.Compression.ZipArchive]::new($archiveStream,[IO.Compression.ZipArchiveMode]::Read,$true)",
 " try {",
 " $entries=@($z.Entries)",
 " if($entries.Count -lt 8 -or $entries.Count -gt 80){throw 'ZIP member count'}",
 " $seen=New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)",
 " $records=New-Object 'System.Collections.Generic.List[object]'",
 " [long]$total=0",
 " foreach($item in $entries){",
 "  $name=[string]$item.FullName",
 "  if(-not $name -or $name.Length -gt 160 -or $name.Contains('\\') -or",
 "    $name.StartsWith('/') -or $name.Contains('//') -or $name.Contains(':') -or",
 "    $name -match '(^|/)\\.{1,2}(/|$)' -or $name -match '[^a-zA-Z0-9._/-]' -or",
 "    -not $seen.Add($name.TrimEnd('/'))){throw 'Unsafe ZIP name'}",
 "  $kind=($item.ExternalAttributes -shr 16) -band 0xF000",
 "  if($kind -in @(0xA000,0x6000)){throw 'ZIP link or device'}",
 "  if($name.EndsWith('/')){if($item.Length -ne 0){throw 'Unsafe directory'};continue}",
 "  $total += $item.Length",
 "  if($item.Length -lt 0 -or $item.Length -gt 100000000 -or $total -gt 150000000){throw 'ZIP bomb'}",
 "  $hash=[Security.Cryptography.SHA256]::Create()",
 "  $entryStream=$item.Open()",
 "  try{$digest=[BitConverter]::ToString($hash.ComputeHash($entryStream)).Replace('-','').ToLowerInvariant()}",
 "  finally{$entryStream.Dispose();$hash.Dispose()}",
 "  $records.Add([pscustomobject]@{name=$name;digest=$digest;length=[long]$item.Length})",
 " }",
 " @($records.ToArray()) | ConvertTo-Json -Compress -Depth 3",
 " } finally{$z.Dispose()}",
 "} finally{$archiveStream.Dispose()}",
].join("\n");
function abs(p:string):boolean {
 return /^[A-Za-z]:\\/.test(p)&&!p.includes("\0")&&path.win32.normalize(p)===p;
}
function file(p:string):void {
 const st=lstatSync(p);
 if(!st.isFile()||st.isSymbolicLink()||st.nlink!==1)
  throw Error("Untrusted Windows Agent file");
}
export interface WindowsZipProof {
 readonly targetRoot:string;
 readonly memberCount:number;
 readonly approvedSha256:string;
}
export function comparePinnedWindowsZipToInstalled(
 archive:string, targetRoot:string, approvedSha256:string,
):Readonly<WindowsZipProof> {
 if(process.platform!=="win32"||process.arch!=="x64"||
    !abs(archive)||!abs(targetRoot)||!HASH.test(approvedSha256))
  throw Error("Unsupported native Windows proof context");
 file(archive);
 const bytes=readFileSync(archive);
 if(bytes.length<100000||bytes.length>100000000||
    createHash("sha256").update(bytes).digest("hex")!==approvedSha256)
  throw Error("Immutable ZIP SHA-256 mismatch");
 const windows=process.env.SystemRoot;
 if(!windows||!abs(windows))throw Error("Missing Windows system root");
 const executable=path.win32.join(windows,"System32","WindowsPowerShell","v1.0","powershell.exe");
 const source=PS.replace("__ARCHIVE__",archive.replace(/'/g,"''"))
   .replace("__SHA__",approvedSha256);
 const outcome=spawnSync(executable,["-NoProfile","-NonInteractive","-EncodedCommand",
   Buffer.from(source,"utf16le").toString("base64")],
   {encoding:"utf8",timeout:60000,maxBuffer:100000,windowsHide:true});
 if(outcome.error||outcome.status!==0){
   // Windows PowerShell may serialize errors as CLIXML. Only report one of
   // our own fixed error categories; do not echo paths, credentials, or raw
   // PowerShell diagnostics to the caller or CI logs.
   const trace=outcome.stderr??"";
   const categories=[
     ["Approved ZIP digest mismatch","digest"],
     ["ZIP member count","member-count"],
     ["Unsafe ZIP name","unsafe-member"],
     ["ZIP link or device","link-or-device"],
     ["Unsafe directory","directory"],
     ["ZIP bomb","size"],
   ] as const;
   const code=categories.find(([phrase])=>trace.includes(phrase))?.[1]??
     (outcome.error?"process-failure":"runtime-failure");
   throw Error("Pinned ZIP SHA-256 mismatch or archive inventory unavailable ("+code+")");
 }
 const parsed:unknown=JSON.parse(outcome.stdout.trim());
 const rows=Array.isArray(parsed)?parsed:[parsed];
 if(rows.length<8||rows.length>80)throw Error("Invalid ZIP member count");
 const expected=new Map<string,string>();
 for(const value of rows) {
   if(!value||typeof value!=="object")throw Error("Invalid ZIP member");
   const record=value as {name?:unknown;digest?:unknown;length?:unknown};
   if(typeof record.name!=="string"||!SAFE.test(record.name)||
     record.name.startsWith("/")||record.name.split("/").some(p=>!p||p==="."||p==="..")||
     typeof record.digest!=="string"||!HASH.test(record.digest)||
     typeof record.length!=="number"||!Number.isSafeInteger(record.length)||
     record.length<0||expected.has(record.name.toLowerCase()))
    throw Error("Untrusted ZIP entry");
   expected.set(record.name.toLowerCase(),record.digest);
 }
 const root=lstatSync(targetRoot);
 if(!root.isDirectory()||root.isSymbolicLink())throw Error("Invalid program root");
 const seen=new Set<string>();
 const walk=(directory:string,prefix=""):void=>{
   for(const ent of readdirSync(directory,{withFileTypes:true})) {
     const name=prefix?prefix+"/"+ent.name:ent.name;
     if(!SAFE.test(name)||name.split("/").some(s=>s==="."||s===".."))
       throw Error("Unsafe program path");
     const full=path.win32.join(directory,ent.name);
     const st=lstatSync(full);
     if(st.isSymbolicLink())throw Error("Reparse point in installed program");
     if(st.isDirectory()) {walk(full,name);continue;}
     if(!st.isFile()||st.nlink!==1)throw Error("Unsupported installed program entry");
     const key=name.toLowerCase(),sha=expected.get(key);
     if(!sha||seen.has(key)||createHash("sha256").update(readFileSync(full)).digest("hex")!==sha)
      throw Error("Installed program differs from approved ZIP");
     seen.add(key);
   }
 };
 walk(targetRoot);
 if(seen.size!==expected.size)throw Error("Missing installed ZIP member");
 return Object.freeze({targetRoot,memberCount:seen.size,approvedSha256});
}
