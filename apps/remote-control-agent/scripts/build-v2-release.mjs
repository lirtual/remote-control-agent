/**
 * Offline, reviewed native-host packaging for #73.
 * Produces an UNPUBLISHED deterministic tar.gz asset; never downloads or publishes.
 * Run this separately on verified x64 and arm64 glibc build hosts.
 *
 * node scripts/build-v2-release.mjs --version v0.1.0 --target linux-x64-glibc
 *   --node-bin /trusted/node-24 --native /trusted/session-supervisor --out /tmp/stage
 */
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, readFileSync, readdirSync, realpathSync, statSync, writeFileSync, chmodSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const ts = require("typescript");
const ALLOWED = new Set(["linux-x64-glibc", "linux-arm64-glibc"]);
const source = path.join(root, "src");

export function parseArgs(argv) {
  const params = {};
  for (let i = 0; i < argv.length; i += 2) {
    if (!["--version", "--target", "--node-bin", "--native", "--out", "--node-sha256", "--native-sha256"].includes(argv[i]) ||
      !argv[i+1] || params[argv[i]]) throw new Error("Invalid packaging parameters.");
    params[{"--node-bin":"nodeBin","--node-sha256":"nodeSha256","--native-sha256":"nativeSha256"}[argv[i]] ?? argv[i].slice(2)] = argv[i+1];
  }
  if (Object.keys(params).length !== 7 ||
      !/^v[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9.-]+)?$/.test(params.version) ||
      !ALLOWED.has(params.target) ||
      !/^[a-f0-9]{64}$/.test(params.nodeSha256) ||
      !/^[a-f0-9]{64}$/.test(params.nativeSha256) ||
      ![params.nodeBin, params.native, params.out].every(x => path.isAbsolute(x))) {
    throw new Error("Specify pinned version, supported target, absolute Node24/native paths and output.");
  }
  return params;
}

function machine(binary) {
  const b = readFileSync(binary);
  if (b.length < 64 || b.toString("hex", 0, 4) !== "7f454c46" ||
      b[4] !== 2 || b[5] !== 1) throw new Error("Expected a 64-bit little-endian ELF executable.");
  return b.readUInt16LE(18);
}

export function requiredGlibcVersion(binary, invoke = spawnSync) {
  const result = invoke("readelf", ["--version-info", binary], {
    encoding: "utf8", timeout: 5000, maxBuffer: 2 * 1024 * 1024,
  });
  if (result.error || result.status !== 0) {
    throw new Error("Cannot determine native ELF glibc ABI; readelf is required on build host.");
  }
  const versions = [...result.stdout.matchAll(/\bGLIBC_(\d+)\.(\d+)\b/g)]
    .map(match => [Number(match[1]), Number(match[2])]);
  if (!versions.length) {
    throw new Error("ELF binary has no verifiable glibc version requirements.");
  }
  versions.sort((a,b) => a[0] - b[0] || a[1] - b[1]);
  return versions.at(-1).join(".");
}

export function ensureNativeTarget({ target, nodeBin, native, nodeSha256, nativeSha256 }) {
  const arch = target === "linux-x64-glibc" ? "x64" : "arm64";
  const id = arch === "x64" ? 62 : 183;
  if (process.platform !== "linux" || process.arch !== arch ||
      !process.report.getReport().header.glibcVersionRuntime) {
    throw new Error("Release must be assembled and tested on its native glibc Linux architecture.");
  }
  for (const [binary,digest] of [[nodeBin,nodeSha256],[native,nativeSha256]]) {
    if (!statSync(binary).isFile() || (statSync(binary).mode & 0o111)===0) {
      throw new Error("Required executable is not a regular file.");
    }
    if (machine(binary) !== id) throw new Error("ELF architecture mismatch.");
    if (!/^[a-f0-9]{64}$/.test(digest) ||
        createHash("sha256").update(readFileSync(binary)).digest("hex")!==digest)
      throw new Error("Pinned native binary checksum mismatch.");
  }
  const version = spawnSync(nodeBin, ["--version"], { encoding:"utf8", timeout:5000 });
  if (version.error || version.status !== 0 || !/^v24\.[0-9]+\.[0-9]+\s*$/.test(version.stdout)) {
    throw new Error("Bundle requires a real Node 24 executable.");
  }
  // Actual native group-pidfd probe: no command or separate process signaled.
  const probe = spawnSync(native, ["--probe"], { detached:true, stdio:"ignore", timeout:5000 });
  if (probe.error || probe.status !== 0) throw new Error("Native Supervisor pidfd ABI is unavailable.");
  const requires = [requiredGlibcVersion(nodeBin), requiredGlibcVersion(native)]
    .map(version => version.split(".").map(Number))
    .sort((a,b) => a[0] - b[0] || a[1] - b[1]);
  return { arch, nodeVersion: version.stdout.trim(), glibcMin: requires.at(-1).join("."),
    libc: process.report.getReport().header.glibcVersionRuntime };
}

function rewriteExtensions(text) {
  return text.replace(/(\b(?:from\s*|import\s*\(\s*)["'][^"']+)\.ts(["'])/g, "$1.js$2");
}

/** Follow static source dependency graph, no tests, checkout or node_modules copied. */
export function runtimeSources(entries = ["v2-main.ts", "pair-device.ts", "confirm-device.ts", "v2-repair.ts"]) {
  const visited = new Set();
  function walk(name) {
    if (!/^[a-z0-9-]+\.ts$/.test(name)) throw new Error("Unreviewed runtime import: " + name);
    if (visited.has(name)) return;
    const file = path.join(source, name);
    if (!existsSync(file) || !realpathSync(file).startsWith(realpathSync(source) + path.sep)) {
      throw new Error("Missing or linked runtime source: " + name);
    }
    visited.add(name);
    const src = readFileSync(file, "utf8");
    const pp = ts.preProcessFile(src, true, true);
    for (const imp of pp.importedFiles) {
      const dependency = imp.fileName;
      if (dependency.startsWith("node:")) continue;
      if (!dependency.startsWith("./") || !dependency.endsWith(".ts")) {
        throw new Error("An external dependency needs separate review: " + dependency);
      }
      walk(dependency.slice(2));
    }
  }
  for (const e of entries) walk(e);
  return [...visited].sort();
}

function tarball(dir, file) {
  const args = ["--format=ustar", "--sort=name", "--owner=0", "--group=0",
    "--numeric-owner", "--mtime=@0", "--mode=u+rwX,go-rwx", "-cf", "-",
    "bin", "apps", "bundle.json"];
  const tar = spawnSync("tar", args, { cwd:dir, maxBuffer:220*1024*1024 });
  if (tar.status !== 0 || tar.error) throw new Error("Deterministic tar creation failed.");
  const gzip = spawnSync("gzip", ["-n", "-9"], { input:tar.stdout, maxBuffer:220*1024*1024 });
  if (gzip.status !== 0 || gzip.error) throw new Error("Deterministic gzip failed.");
  writeFileSync(file, gzip.stdout, {flag:"wx", mode:0o600});
}

export function build(args) {
  const { arch, nodeVersion, libc, glibcMin } = ensureNativeTarget(args);
  if (existsSync(args.out) && readdirSync(args.out).length) {
    throw new Error("Output must be a new or empty directory.");
  }
  mkdirSync(args.out, {recursive:true, mode:0o700});
  const work = path.join(args.out, "bundle");
  mkdirSync(path.join(work, "bin"), {recursive:true,mode:0o700});
  mkdirSync(path.join(work, "apps/remote-control-agent/src"), {recursive:true,mode:0o700});
  mkdirSync(path.join(work, "apps/remote-control-agent/scripts"), {recursive:true,mode:0o700});
  mkdirSync(path.join(work, "apps/remote-control-agent/.build"), {recursive:true,mode:0o700});
  copyFileSync(args.nodeBin, path.join(work, "bin/node"));
  copyFileSync(args.native, path.join(work, "apps/remote-control-agent/.build/session-supervisor"));
  for (const relative of ["bin/node","apps/remote-control-agent/.build/session-supervisor"]) {
    chmodSync(path.join(work,relative),0o700);
  }
  // Only a statically read-only, Shell-disabled Agent can be upgraded without
  // a new live-session quiescence IPC. All future mutable profiles fail closed.
  const entrySource=readFileSync(path.join(source,"v2-main.ts"),"utf8");
  if(!/readOnly:\s*true,\s*writeFile:\s*false,\s*shell:\s*false,/.test(entrySource)) {
    throw new Error("Standalone unattended-session upgrade safety profile is not proven.");
  }
  const modules=runtimeSources();
  for(const file of modules){
    const src=readFileSync(path.join(source,file),"utf8");
    const compiled=ts.transpileModule(src,{fileName:file,reportDiagnostics:true,
      compilerOptions:{ module:ts.ModuleKind.ESNext, target:ts.ScriptTarget.ES2022, removeComments:false }});
    const errors=(compiled.diagnostics||[]).filter(d=>d.category===ts.DiagnosticCategory.Error);
    if(errors.length) throw new Error("TS compilation error in "+file);
    writeFileSync(path.join(work,"apps/remote-control-agent/src",file.replace(/\.ts$/,".js")),
      rewriteExtensions(compiled.outputText),{mode:0o600});
  }
  const installer=readFileSync(path.join(root,"scripts/install-v2.mjs"),"utf8");
  writeFileSync(path.join(work,"apps/remote-control-agent/scripts/install-v2.mjs"),
    rewriteExtensions(installer),{mode:0o600});
  writeFileSync(path.join(work,"apps/remote-control-agent/package.json"),JSON.stringify({type:"module"})+"\n",{mode:0o600});
  writeFileSync(path.join(work,"bundle.json"),JSON.stringify({
    name:"remote-control-agent",version:args.version,target:args.target,
    node:nodeVersion,glibc_build:libc,glibc_min:glibcMin,modules,
    artifact_schema:1,device_protocol:2,receipt_schema:1,
    upgrade_profile:"read-only-no-shell-v1"
  })+"\n",{mode:0o600});
  const name="remote-control-agent-"+args.version+"-"+args.target+".tar.gz";
  tarball(work,path.join(args.out,name));
  const artifact=readFileSync(path.join(args.out,name));
  return {file:path.join(args.out,name),sha256:createHash("sha256").update(artifact).digest("hex"),
    bytes:artifact.length,arch,nodeVersion,libc,glibcMin,modules};
}
if (process.argv[1] && path.resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
  try { console.log(JSON.stringify(build(parseArgs(process.argv.slice(2))))); }
  catch(error){ process.stderr.write("Local release package blocked: "+error.message+"\n"); process.exitCode=1; }
}
