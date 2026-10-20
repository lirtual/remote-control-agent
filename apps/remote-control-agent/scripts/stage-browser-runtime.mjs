/**
 * Opt-in, unpublished browser runtime layer for an EXISTING Windows candidate.
 * Never downloads packages or changes the signed Agent's default build.
 * A CI-owned matching headless-shell cache must already exist.
 */
import { createHash } from "node:crypto";
import { cpSync, existsSync, lstatSync, mkdirSync, readFileSync, realpathSync,
  readdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const ts = require("typescript");
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const EXPECTED_VERSION = "1.64.1";
const PREFIX = "apps/remote-control-agent/vendor";
const MAX_ENTRIES = 2000;
const MAX_BYTES = 400 * 1024 * 1024;

function digest(bytes) { return createHash("sha256").update(bytes).digest("hex"); }

function walkSafeFiles(rootDir) {
  const files = [];
  const visit = (dir, prefix = "") => {
    for (const entry of readdirSync(dir, { withFileTypes: true }).sort((a,b) => a.name.localeCompare(b.name))) {
      const name = prefix ? prefix + "/" + entry.name : entry.name;
      if (entry.isSymbolicLink() || (!entry.isDirectory() && !entry.isFile()) ||
          name.split("/").some(x => x === "." || x === "..") || name.includes("\\"))
        throw Error("Symlink or unsafe browser runtime entry rejected.");
      if (entry.isDirectory()) visit(path.join(dir, entry.name), name);
      else files.push(name);
      if (files.length > MAX_ENTRIES) throw Error("Browser runtime contains too many entries.");
    }
  };
  visit(rootDir);
  return files;
}

export function stageBrowserRuntime(stage, browserCache, platform = process.platform) {
  if (platform !== "win32" || !path.isAbsolute(stage) ||
      !path.isAbsolute(browserCache) || !existsSync(path.join(stage, "bundle.json"))) {
    throw Error("An existing absolute native Agent stage and browser cache are required.");
  }
  const bundlePath = path.join(stage, "bundle.json");
  const manifest = JSON.parse(readFileSync(bundlePath, "utf8"));
  if (manifest.browser_runtime || manifest.name !== "remote-control-agent" ||
      manifest.target !== "windows-x64" ||
      manifest.upgrade_profile !== "paired-full-v1" ||
      !manifest.hashes || typeof manifest.hashes !== "object") {
    throw Error("Unexpected browser candidate manifest.");
  }
  const sourcePackage = path.join(root, "node_modules", "playwright-core");
  const sourceReal = realpathSync(sourcePackage);
  const packageJson = JSON.parse(readFileSync(path.join(sourceReal, "package.json"), "utf8"));
  if (packageJson.name !== "playwright-core" || packageJson.version !== EXPECTED_VERSION)
    throw Error("Pinned Playwright package version mismatch.");

  const revisions = JSON.parse(readFileSync(path.join(sourceReal, "browsers.json"), "utf8")).browsers;
  const shell = revisions.find(x => x.name === "chromium-headless-shell");
  if (!shell || !/^[0-9]+$/.test(shell.revision))
    throw Error("Matching Chromium headless-shell revision unavailable.");
  const sourceBrowser = path.join(browserCache, "chromium_headless_shell-" + shell.revision);
  const exeName = platform === "win32"
    ? "chrome-headless-shell-win64/chrome-headless-shell.exe"
    : "chrome-headless-shell-linux64/chrome-headless-shell";
  const sourceExecutable = path.join(sourceBrowser, ...exeName.split("/"));
  if (!existsSync(sourceExecutable) || !lstatSync(sourceExecutable).isFile() ||
      !realpathSync(sourceExecutable).startsWith(realpathSync(sourceBrowser) + path.sep)) {
    throw Error("Matching headless-shell binary is not installed in the supplied cache.");
  }
  // The existing build's manifest is trustworthy only after outer archive SHA
  // verification. Never silently replace an existing layer or foreign file.
  const vendorRoot = path.join(stage, ...PREFIX.split("/"));
  if (existsSync(vendorRoot) || existsSync(path.join(stage, "apps/remote-control-agent/src/browser-offline.js")) ||
      existsSync(path.join(stage, "apps/remote-control-agent/src/browser-playwright.js"))) {
    throw Error("Browser runtime staging is not idempotently overwritable.");
  }
  const sources = ["browser-offline.ts", "browser-playwright.ts"];
  const compiled = sources.map(filename => {
    const output = ts.transpileModule(
      readFileSync(path.join(root, "src", filename), "utf8"),
      { fileName: filename, compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 } },
    ).outputText.replace(/(\bfrom\s+["'][^"']+)\.ts(["'])/g, "$1.js$2");
    return [filename.replace(/\.ts$/, ".js"), output];
  });
  const packageFiles = walkSafeFiles(sourceReal);
  const browserFiles = walkSafeFiles(sourceBrowser);
  const sourceBytes = packageFiles.reduce((sum, f) => sum + lstatSync(path.join(sourceReal, ...f.split("/"))).size, 0) +
    browserFiles.reduce((sum, f) => sum + lstatSync(path.join(sourceBrowser, ...f.split("/"))).size, 0);
  if (sourceBytes > MAX_BYTES || packageFiles.length + browserFiles.length + compiled.length > MAX_ENTRIES)
    throw Error("Browser runtime exceeds bounded candidate limits.");

  const packageDst = path.join(vendorRoot, "playwright-core");
  const browserDst = path.join(vendorRoot, "browsers", "chromium_headless_shell-" + shell.revision);
  mkdirSync(path.dirname(packageDst), { recursive: true });
  cpSync(sourceReal, packageDst, { recursive: true, dereference: false, errorOnExist: true, force: false });
  cpSync(sourceBrowser, browserDst, { recursive: true, dereference: false, errorOnExist: true, force: false });
  for (const [filename, code] of compiled) {
    writeFileSync(path.join(stage, "apps/remote-control-agent/src", filename), code, { flag: "wx", mode: 0o600 });
  }
  const hashes = { ...manifest.hashes };
  for (const entry of walkSafeFiles(vendorRoot)) {
    const rel = PREFIX + "/" + entry;
    hashes[rel] = digest(readFileSync(path.join(vendorRoot, ...entry.split("/"))));
  }
  for (const [filename, code] of compiled) {
    const rel = "apps/remote-control-agent/src/" + filename;
    hashes[rel] = digest(Buffer.from(code));
  }
  manifest.hashes = hashes;
  manifest.browser_runtime = {
    playwright_core: EXPECTED_VERSION,
    browser: "chromium-headless-shell",
    revision: shell.revision,
    executable: PREFIX + "/browsers/chromium_headless_shell-" + shell.revision + "/" + exeName,
  };
  writeFileSync(bundlePath, JSON.stringify(manifest, null, 2) + "\n", { mode: 0o600 });
  return { version: EXPECTED_VERSION, revision: shell.revision, files: Object.keys(hashes).length,
    browser: manifest.browser_runtime.executable };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length !== 4) throw Error("Expected stage directory and pinned browser cache only.");
    console.log(JSON.stringify(stageBrowserRuntime(process.argv[2], process.argv[3])));
  } catch (error) {
    console.error("Unpublished browser candidate rejected:", error.message);
    process.exitCode = 1;
  }
}
