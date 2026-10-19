/**
 * Windows x64 portable preview staging only. No upload or Release publishing.
 * CI must pass the independently pinned Node.js 24.21.0 node.exe SHA-256.
 * Only the static runtime dependency graph and the ACL helper are included.
 */
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync, copyFileSync, existsSync, mkdirSync, readFileSync, readdirSync,
  statSync, writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { runtimeSources } from "./build-v2-release.mjs";

const require = createRequire(import.meta.url);
const ts = require("typescript");
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const EXPECTED_NODE_VERSION = "v24.21.0";
const EXPECTED_NODE_SHA256 =
  "ba4e6d110e8c1592a1ecd390f6b05f3da124b13871a5be62b341a07a853c6c32";

export function parseWindowsPreviewBuildArgs(argv) {
  const keys = new Map([
    ["--version", "version"], ["--node-bin", "nodeBin"], ["--node-sha256", "nodeSha256"],
    ["--out", "out"],
  ]);
  const out = {};
  if (argv.length !== keys.size * 2) throw Error("Windows candidate requires four pinned arguments.");
  for (let i = 0; i < argv.length; i += 2) {
    const key = keys.get(argv[i]);
    if (!key || out[key] !== undefined || !argv[i + 1]) throw Error("Unsafe packaging arguments.");
    out[key] = argv[i + 1];
  }
  if (!/^v[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9.-]+)?$/.test(out.version) ||
      !/^[a-f0-9]{64}$/.test(out.nodeSha256) ||
      out.nodeSha256 !== EXPECTED_NODE_SHA256 ||
      !path.isAbsolute(out.nodeBin) || !path.isAbsolute(out.out)) {
    throw Error("A reviewed version, paths and official pinned node.exe digest are required.");
  }
  return out;
}

function digest(contents) {
  return createHash("sha256").update(contents).digest("hex");
}

function rewriteImports(source) {
  return source.replace(/(\b(?:from\s*|import\s*\(\s*)["'][^"']+)\.ts(["'])/g, "$1.js$2");
}

export function buildWindowsPreview(args) {
  if (process.platform !== "win32" || process.arch !== "x64")
    throw Error("Windows x64 native packaging is required.");
  if (!statSync(args.nodeBin).isFile() ||
      digest(readFileSync(args.nodeBin)) !== EXPECTED_NODE_SHA256)
    throw Error("Official Node.js Windows x64 checksum mismatch.");
  const version = spawnSync(args.nodeBin, ["--version"], {
    encoding: "utf8", timeout: 10_000, windowsHide: true,
  });
  if (version.error || version.status !== 0 || version.stdout.trim() !== EXPECTED_NODE_VERSION)
    throw Error("Pinned native Windows Node.js 24 executable unavailable.");
  if (existsSync(args.out) && readdirSync(args.out).length !== 0)
    throw Error("Untrusted non-empty candidate output directory.");
  mkdirSync(args.out, { recursive: true, mode: 0o700 });
  const stage = path.join(args.out, "remote-control-agent-" + args.version + "-windows-x64");
  for (const relative of ["bin", "apps/remote-control-agent/src", "apps/remote-control-agent/scripts"]) {
    mkdirSync(path.join(stage, relative), { recursive: true, mode: 0o700 });
  }
  copyFileSync(args.nodeBin, path.join(stage, "bin/node.exe"));
  const modules = runtimeSources(["windows-v2.ts"]);
  const hashes = { "bin/node.exe": EXPECTED_NODE_SHA256 };
  for (const file of modules) {
    const src = readFileSync(path.join(root, "src", file), "utf8");
    const compiled = ts.transpileModule(src, {
      fileName: file,
      reportDiagnostics: true,
      compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
    });
    if ((compiled.diagnostics || []).some(item => item.category === ts.DiagnosticCategory.Error))
      throw Error("Windows runtime TypeScript compilation failed.");
    const name = "apps/remote-control-agent/src/" + file.replace(/\.ts$/, ".js");
    const content = rewriteImports(compiled.outputText);
    writeFileSync(path.join(stage, name), content, { mode: 0o600 });
    hashes[name] = digest(Buffer.from(content));
  }
  const scripts = ["windows-private-store.ps1"];
  for (const name of scripts) {
    const relative = "apps/remote-control-agent/scripts/" + name;
    const bytes = readFileSync(path.join(root, "scripts", name));
    writeFileSync(path.join(stage, relative), bytes, { mode: 0o600 });
    hashes[relative] = digest(bytes);
  }
  const packageJson = Buffer.from('{"type":"module"}\n');
  const packagePath = "apps/remote-control-agent/package.json";
  writeFileSync(path.join(stage, packagePath), packageJson, { mode: 0o600 });
  hashes[packagePath] = digest(packageJson);
  writeFileSync(path.join(stage, "bundle.json"), JSON.stringify({
    name: "remote-control-agent", version: args.version, target: "windows-x64",
    node: EXPECTED_NODE_VERSION, device_protocol: 2, artifact_schema: 1,
    upgrade_profile: "read-only-no-shell-v1", preview: true, modules, hashes,
  }, null, 2) + "\n", { mode: 0o600 });
  return {
    stage, target: "windows-x64", modules: modules.length,
    nodeSha256: EXPECTED_NODE_SHA256,
    releasePublished: false,
  };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const result = buildWindowsPreview(parseWindowsPreviewBuildArgs(process.argv.slice(2)));
    process.stdout.write(JSON.stringify(result) + "\n");
  } catch {
    process.stderr.write("Windows bundle candidate refused: untrusted native input.\n");
    process.exitCode = 1;
  }
}
