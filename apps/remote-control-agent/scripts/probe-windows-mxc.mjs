/**
 * Source-only MXC ProcessContainer OS-tier preflight.
 * Installs nothing; imports exact-pinned SDK from a temporary CI location
 * and calls only its read-only probe API.
 * Does not create an AppContainer, launch a process or modify host policy.
 */
import { readFile } from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

const out = data => console.log("RCA_WINDOWS_MXC_PROBE=" + JSON.stringify(data));
const unavailable = reason => {
  out({ status: "UNAVAILABLE", reason: String(reason).slice(0, 450), os: process.platform });
  console.log("::warning::Windows MXC capability probe not accepted: " + String(reason).slice(0, 180));
};

if (process.platform !== "win32" || process.argv.length !== 3 ||
    !path.isAbsolute(process.argv[2])) {
  unavailable("This probe requires a Windows runner and absolute temporary SDK prefix.");
} else {
  const sdkDir = path.join(process.argv[2], "node_modules", "@microsoft", "mxc-sdk");
  try {
    const pkg = JSON.parse(await readFile(path.join(sdkDir, "package.json"), "utf8"));
    if (pkg.name !== "@microsoft/mxc-sdk" || pkg.version !== "1.0.1") {
      unavailable("Unexpected MXC SDK package identity or version.");
    } else {
      const { probe } = await import(pathToFileURL(path.join(sdkDir, "dist", "v1", "index.js")).href);
      const strictPolicy = {
        command: "cmd.exe /d /c echo RCA_NO_RUN",
        network: {
          egress: {
            default: "deny",
            // IANA TEST-NET-2 is a POLICY SELECTOR ONLY; no socket opened.
            allow: [{ to: [{ cidr: "198.51.100.1/32" }],
              ports: [{ protocol: "tcp", port: 443 }] }],
          },
          ingress: { default: "deny", hostLoopback: "deny" },
        },
        timeoutMs: 3000,
      };
      const result = probe(strictPolicy);
      const tier = result.tier ?? null;
      out({
        status: result.error ? "NOT_ACCEPTED" : tier === "base-container"
          ? "OS_TIER_CANDIDATE" : "WEAKER_TIER_NOT_ACCEPTED",
        sdk_version: pkg.version,
        tier,
        base_container_api: result.probes.baseContainerApiPresent,
        warnings: result.warnings.slice(0, 5).map(s => s.slice(0, 240)),
        error: result.error?.slice(0, 350) ?? null,
        process_spawned: false,
        network_tested: false,
      });
      if (tier !== "base-container" || result.error) {
        console.log("::warning::OS-isolated browser egress P0 remains unverified on this Windows CI host.");
      }
    }
  } catch (error) {
    unavailable(error instanceof Error ? error.message : String(error));
  }
}
