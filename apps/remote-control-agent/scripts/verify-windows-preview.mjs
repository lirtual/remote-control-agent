/**
 * Verify a Windows preview candidate after extracting to an isolated directory.
 * The future installer must FIRST validate the outer official GitHub Release
 * asset SHA-256 before any archive extraction, then use this file inventory.
 */
import { createHash } from "node:crypto";
import { lstatSync, readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

// Independent audit pinning for the nine-file Windows preview payload.
// Deliberately not loaded from the mutable preview manifest.
// These source-compiled module pins are intentionally independent from the
// mutable archive manifest and MUST be updated only after source review.
export const PINNED_WINDOWS_BROWSER_MODULES=Object.freeze({
  "apps/remote-control-agent/candidates/browser-playwright.js":
    "2cfc5f91675795794502331755ec2b1c46691ad44d47dd169bb4f7d6a2c4cb0e",
  "apps/remote-control-agent/candidates/browser-egress-proxy.js":
    "2b340d3c5173d41be741f604da609d697ecfa862090264c540202f751bc9ca7f",
  "apps/remote-control-agent/candidates/browser-egress-policy.js":
    "24b94978c89db86f0986e4026046c2f8acf70c831f123afe7c3fa9063f6e8bd3",
});
export const PINNED_WINDOWS_PLAYWRIGHT_VERSION="1.64.1";
export const PINNED_WINDOWS_PLAYWRIGHT_FILES=Object.freeze({
  "apps/remote-control-agent/node_modules/playwright-core/LICENSE":"45873d00a0dd243596deb4aa23b2493b3d1f0671921bf2538ea431d7380220eb",
  "apps/remote-control-agent/node_modules/playwright-core/package.json":"8aa1c9863fa8dea324e674254158cdc79440f4124ef2d84d38053013541cb7d6",
  "apps/remote-control-agent/node_modules/playwright-core/browsers.json":"2cfd419f71ac6475d81e1301fa86c34cf2a2a6bae2a0da4b5a2b18310216b6bf",
  "apps/remote-control-agent/node_modules/playwright-core/index.js":"a58fb2cec4293e7dcf73c58a179898a4f3986666451a19da4e731fa3af63265b",
  "apps/remote-control-agent/node_modules/playwright-core/index.mjs":"3d36e2132d3c8b62397d23f0bb4177336aaee503203ae2a2c90fbeb5bf3317dd",
  "apps/remote-control-agent/node_modules/playwright-core/lib/bootstrap.js":"39dd64cc9472275d1b25c170fefa2a98353bcca598b741788faac2e6e15fc737",
  "apps/remote-control-agent/node_modules/playwright-core/lib/coreBundle.js":"829521b67ed7be90c7d6d6098ff39f2241562d47e4ad7ccab13710924a56001d",
  "apps/remote-control-agent/node_modules/playwright-core/lib/utilsBundle.js":"75f1431ea7ee00b2b291a0a72d4fa1c07ae04d999f21a00cd03b8f454a5840fc",
  "apps/remote-control-agent/node_modules/playwright-core/lib/utilsBundle.js.LICENSE":"1362b7f413c08083af537384162ab69a323d019fe26e0a2cd78536fafd6b9cbf",
});

export function inspectWindowsPreview(root) {
  if (process.platform !== "win32" || !path.isAbsolute(root))
    throw Error("Native Windows directory required.");
  const manifestPath = path.join(root, "bundle.json");
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  if (manifest.name !== "remote-control-agent" ||
      manifest.target !== "windows-x64" || manifest.preview !== true ||
      manifest.node !== "v24.21.0" ||
      manifest.upgrade_profile !== "paired-full-v1" ||
      manifest.artifact_schema !== 1 || manifest.device_protocol !== 2 ||
      typeof manifest.hashes !== "object" || Array.isArray(manifest.hashes) ||
      !manifest.hashes) {
    throw Error("Untrusted native Windows bundle manifest.");
  }
  const expected = new Map(Object.entries(manifest.hashes));
  if (!expected.has("bin/node.exe") ||
      !expected.has("bin/rca-background.exe") ||
      !expected.has("rca.cmd") ||
      !expected.has("apps/remote-control-agent/scripts/verify-windows-preview.mjs") ||
      !expected.has("apps/remote-control-agent/scripts/windows-private-store.ps1") ||
      !expected.has("apps/remote-control-agent/scripts/windows-user-task.ps1") ||
      !expected.has("apps/remote-control-agent/scripts/windows-handoff-tunnel.ps1") ||
      !expected.has("apps/remote-control-agent/src/windows-v2.js") ||
      expected.size < 9 || expected.size > 42 ||
      expected.get("bin/node.exe") !==
        "ba4e6d110e8c1592a1ecd390f6b05f3da124b13871a5be62b341a07a853c6c32") {
    throw Error("Incomplete or unknown Windows preview files.");
  }
  if (expected.get("apps/remote-control-agent/scripts/windows-handoff-tunnel.ps1") !== "8c5e2110eba11e135357d16278488669df45cbd4e6ffb72d4431989e95c03154")
    throw Error("Unreviewed handoff supervisor.");
  const names=Object.keys(PINNED_WINDOWS_PLAYWRIGHT_FILES);
  const candidate=Object.keys(manifest.hashes).filter(k=>Object.hasOwn(PINNED_WINDOWS_PLAYWRIGHT_FILES,k));
  if (manifest.browser_runtime===undefined){
    if(candidate.length ||
        Object.keys(PINNED_WINDOWS_BROWSER_MODULES).some(k=>expected.has(k)))
      throw Error("Unrequested browser runtime.");
  }else{
    if (Object.entries(PINNED_WINDOWS_BROWSER_MODULES)
      .some(([name,hash])=>expected.get(name)!==hash))
      throw Error("Missing or unreviewed packaged browser network modules.");
    const info=manifest.browser_runtime;
    if (!info || typeof info!=="object" || Array.isArray(info) ||
        Object.keys(info).sort().join(",")!=="files,name,version" ||
        info.name!=="playwright-core" || info.version!==PINNED_WINDOWS_PLAYWRIGHT_VERSION ||
        !Array.isArray(info.files) || info.files.length!==names.length ||
        new Set(info.files).size!==names.length ||
        names.some(k=>!info.files.includes(k)) ||
        candidate.length!==names.length ||
        names.some(k=>manifest.hashes[k]!==PINNED_WINDOWS_PLAYWRIGHT_FILES[k]))
      throw Error("Unreviewed Windows browser runtime manifest.");
  }
  const seen = new Set();
  function walk(dir, relative = "") {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const name = relative ? relative + "/" + entry.name : entry.name;
      if (entry.isSymbolicLink() || !entry.isDirectory() && !entry.isFile() ||
          /(^|\/)\.\.?($|\/)/.test(name)) throw Error("Untrusted preview entry.");
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) { walk(full, name); continue; }
      if (name === "bundle.json") continue;
      if (!(/^(?:bin\/(?:node\.exe|rca-background\.exe)|rca\.cmd|apps\/remote-control-agent\/(?:package\.json|src\/[a-z0-9-]+\.js|scripts\/(?:(?:windows-private-store|windows-user-task|windows-handoff-tunnel)\.ps1|verify-windows-preview\.mjs)))$/.test(name) ||
          Object.hasOwn(PINNED_WINDOWS_PLAYWRIGHT_FILES,name) ||
          Object.hasOwn(PINNED_WINDOWS_BROWSER_MODULES,name)) ||
          seen.has(name) || !expected.has(name) ||
          typeof expected.get(name) !== "string" ||
          !/^[a-f0-9]{64}$/.test(expected.get(name))) {
        throw Error("Unexpected native Windows runtime entry.");
      }
      const sha = createHash("sha256").update(readFileSync(full)).digest("hex");
      if (sha !== expected.get(name) ||
          (Object.hasOwn(PINNED_WINDOWS_PLAYWRIGHT_FILES,name) && sha!==PINNED_WINDOWS_PLAYWRIGHT_FILES[name]) ||
          (Object.hasOwn(PINNED_WINDOWS_BROWSER_MODULES,name) &&
            sha!==PINNED_WINDOWS_BROWSER_MODULES[name]))
        throw Error("Windows runtime entry checksum mismatch.");
      seen.add(name);
    }
  }
  const stat = lstatSync(root);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw Error("Untrusted Windows bundle root.");
  walk(root);
  if (seen.size !== expected.size || [...expected.keys()].some(key => !seen.has(key)))
    throw Error("Missing native Windows runtime entry.");
  return { target: manifest.target, version: manifest.version, files: seen.size };
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const info = inspectWindowsPreview(process.argv[2]);
    process.stdout.write(JSON.stringify(info) + "\n");
  } catch {
    process.stderr.write("Windows bundle verification refused.\n");
    process.exitCode = 1;
  }
}
