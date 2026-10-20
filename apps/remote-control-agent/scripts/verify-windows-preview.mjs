/**
 * Verify a Windows preview candidate after extracting to an isolated directory.
 * The future installer must FIRST validate the outer official GitHub Release
 * asset SHA-256 before any archive extraction, then use this file inventory.
 */
import { createHash } from "node:crypto";
import { lstatSync, readFileSync, readdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export function inspectWindowsPreview(root) {
  if (process.platform !== "win32" || !path.isAbsolute(root))
    throw Error("Native Windows directory required.");
  const manifestPath = path.join(root, "bundle.json");
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  if (manifest.name !== "remote-control-agent" ||
      manifest.target !== "windows-x64" || manifest.preview !== true ||
      manifest.node !== "v24.21.0" ||
      manifest.upgrade_profile !== "read-only-no-shell-v1" ||
      manifest.artifact_schema !== 1 || manifest.device_protocol !== 2 ||
      typeof manifest.hashes !== "object" || Array.isArray(manifest.hashes) ||
      !manifest.hashes) {
    throw Error("Untrusted native Windows bundle manifest.");
  }
  const expected = new Map(Object.entries(manifest.hashes));
  if (!expected.has("bin/node.exe") ||
      !expected.has("rca.cmd") ||
      !expected.has("apps/remote-control-agent/scripts/windows-private-store.ps1") ||
      !expected.has("apps/remote-control-agent/scripts/windows-user-task.ps1") ||
      !expected.has("apps/remote-control-agent/src/windows-v2.js") ||
      expected.size < 8 || expected.size > 40 ||
      expected.get("bin/node.exe") !==
        "ba4e6d110e8c1592a1ecd390f6b05f3da124b13871a5be62b341a07a853c6c32") {
    throw Error("Incomplete or unknown Windows preview files.");
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
      if (!/^(?:bin\/node\.exe|rca\.cmd|apps\/remote-control-agent\/(?:package\.json|src\/[a-z0-9-]+\.js|scripts\/(?:windows-private-store|windows-user-task)\.ps1))$/.test(name) ||
          seen.has(name) || !expected.has(name) ||
          typeof expected.get(name) !== "string" ||
          !/^[a-f0-9]{64}$/.test(expected.get(name))) {
        throw Error("Unexpected native Windows runtime entry.");
      }
      const sha = createHash("sha256").update(readFileSync(full)).digest("hex");
      if (sha !== expected.get(name)) throw Error("Windows runtime entry checksum mismatch.");
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
