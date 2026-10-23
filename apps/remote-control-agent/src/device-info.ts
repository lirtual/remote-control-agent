/** Bounded OS/runtime identity reported over an already signed device socket. */
import { existsSync, readFileSync } from "node:fs";
import os from "node:os";
import { fileURLToPath } from "node:url";

function releaseVersion(): string | undefined {
  // Immutable release bundles contain this version; development checkouts may not.
  try {
    const file = fileURLToPath(new URL("../../../bundle.json", import.meta.url));
    const bundle = JSON.parse(readFileSync(file, "utf8")) as { version?: unknown };
    if (typeof bundle.version === "string" && /^v[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9.-]+)?$/.test(bundle.version)) {
      return bundle.version;
    }
  } catch { /* No release manifest in source checkout. */ }
  return undefined;
}

export function collectDeviceInfo() {
  const platform = process.platform;
  const system = platform === "win32" ? "windows" : platform === "darwin" ? "darwin" : "linux";
  const kernel = os.release();
  let osVersion = kernel;
  if (system === "linux") {
    try {
      const file = readFileSync("/etc/os-release", "utf8");
      const match = /^PRETTY_NAME=(?:"([^"\n]+)"|([^\n]+))$/m.exec(file);
      if (match) osVersion = match[1] || match[2] || kernel;
    } catch { /* Fall back to a kernel release string. */ }
  }
  const isWsl2 = system === "linux" && (/microsoft.*wsl2?/i.test(kernel) ||
    Boolean(process.env.WSL_DISTRO_NAME && /microsoft/i.test(kernel)));
  const environment = isWsl2 ? "wsl2" : system === "linux" &&
    (existsSync("/.dockerenv") || existsSync("/run/.containerenv")) ? "container" : "native";
  const clean = (value: string, max: number) => value.replace(/[\x00-\x1f\x7f]/g, "").trim().slice(0, max);
  const version = releaseVersion();
  return {
    kind: "device_info" as const,
    hostname: clean(os.hostname(), 64) || "unknown",
    os: system,
    os_version: clean(osVersion, 96) || "unknown",
    arch: clean(process.arch, 16) || "unknown",
    environment,
    ...(version ? { agent_version: version } : {}),
  };
}
