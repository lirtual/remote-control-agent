/** Bounded OS/runtime identity reported over an already signed device socket. */
import { existsSync, readFileSync } from "node:fs";
import os from "node:os";
import { fileURLToPath } from "node:url";

function installedRelease(): {version?:string} {
  try {
    const manifest = JSON.parse(readFileSync(fileURLToPath(
      new URL("../../../bundle.json", import.meta.url)), "utf8")) as {
        name?:unknown; version?:unknown;
      };
    if (manifest.name === "remote-control-agent" &&
        typeof manifest.version === "string" &&
        /^v[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9.-]+)?$/.test(manifest.version)) {
      return {version:manifest.version};
    }
  } catch { /* Unpackaged source has no immutable version. */ }
  return {};
}

/** Container identity takes precedence over WSL2 host kernel metadata. */
export function classifyLinuxEnvironment(
  isLinux:boolean,isWsl2:boolean,isContainer:boolean,
):"native"|"wsl2"|"container" {
  return isLinux && isContainer ? "container" : isLinux && isWsl2 ? "wsl2" : "native";
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
  // Containers hosted by WSL2 still are containers. Do not upgrade them
  // under the native/WSL2 owner-once policy merely because the kernel string
  // contains "microsoft"; the stricter environment classification wins.
  const isContainer = system === "linux" &&
    (existsSync("/.dockerenv") || existsSync("/run/.containerenv"));
  const environment = classifyLinuxEnvironment(system==="linux",isWsl2,isContainer);
  const clean = (value: string, max: number) => value.replace(/[\x00-\x1f\x7f]/g, "").trim().slice(0, max);
  const release = installedRelease();
  return {
    kind: "device_info" as const,
    hostname: clean(os.hostname(), 64) || "unknown",
    os: system,
    os_version: clean(osVersion, 96) || "unknown",
    arch: clean(process.arch, 16) || "unknown",
    environment,
    ...(release.version ? { agent_version: release.version } : {}),
  };
}
