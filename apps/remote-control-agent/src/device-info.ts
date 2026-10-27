/** Bounded OS/runtime identity reported over an already signed device socket. */
import { existsSync, readFileSync } from "node:fs";
import os from "node:os";
import { fileURLToPath } from "node:url";

function installedRelease(): {version?:string;upgrade_protocol?:"owner-one-shot-v1"} {
  // Only the immutable package manifest can advertise the native protocol.
  // Unpackaged source and legacy releases must remain upgrade-ineligible.
  try {
    const file = fileURLToPath(new URL("../../../bundle.json", import.meta.url));
    const bundle = JSON.parse(readFileSync(file, "utf8")) as {
      name?:unknown;version?:unknown;target?:unknown;upgrade_profile?:unknown;
      upgrade_protocol?:unknown;modules?:unknown;hashes?:Record<string,unknown>;
    };
    if (bundle.name !== "remote-control-agent" || typeof bundle.version !== "string" ||
        !/^v[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9.-]+)?$/.test(bundle.version))return {};
    const windowsReady = process.platform === "win32" && process.arch === "x64" &&
      bundle.target === "windows-x64" && bundle.upgrade_profile === "paired-full-v1" &&
      bundle.upgrade_protocol === "owner-one-shot-v1" &&
      Array.isArray(bundle.modules) &&
      bundle.modules.includes("windows-upgrade-executor.ts") &&
      typeof bundle.hashes?.["apps/remote-control-agent/scripts/windows-upgrade-once.ps1"] === "string" &&
      typeof bundle.hashes?.["apps/remote-control-agent/scripts/windows-stage-install.ps1"] === "string";
    const linuxReady = process.platform === "linux" &&
      ["x64","arm64"].includes(process.arch) &&
      bundle.target === "linux-"+process.arch+"-glibc" &&
      bundle.upgrade_profile === "paired-full-v1" &&
      bundle.upgrade_protocol === "owner-one-shot-v1" &&
      Array.isArray(bundle.modules) &&
      ["linux-upgrade-executor.ts","linux-upgrade-reconnect.ts"].every(
        name => (bundle.modules as string[]).includes(name)) &&
      ["linux-upgrade-detached.mjs","linux-upgrade-watchdog.mjs",
        "bootstrap-v2.py"].every(name => existsSync(fileURLToPath(new URL(
        "../scripts/"+name, import.meta.url))));
    const ready=windowsReady||linuxReady;
    return {version:bundle.version,...(ready ? {upgrade_protocol:"owner-one-shot-v1" as const}:{})};
  } catch { return {}; }
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
  const environment = isContainer ? "container" : isWsl2 ? "wsl2" : "native";
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
    ...(release.upgrade_protocol ? {upgrade_protocol:release.upgrade_protocol} : {}),
  };
}
