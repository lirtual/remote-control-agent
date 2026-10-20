/**
 * Source-only, zero-host-mutation Linux netns feasibility gate.
 * Tests only an ephemeral 127.0.0.1 fixture on a CI runner.
 * No sudo, sysctl, AppArmor changes, Docker daemon or real addresses.
 *
 * UNAVAILABLE and NAMESPACE_ONLY are not acceptance for public browsing.
 */
import { spawn } from "node:child_process";
import { createServer } from "node:net";
import { connect } from "node:net";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const script = fileURLToPath(import.meta.url);
const output = value => console.log("RCA_NETNS_PROBE=" + JSON.stringify(value));

function dialLocal(port) {
  return new Promise(resolve => {
    const socket = connect({ host: "127.0.0.1", port });
    let settled = false;
    const finish = result => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(result);
    };
    socket.setTimeout(2000, () => finish("timeout"));
    socket.once("connect", () => finish("connected"));
    socket.once("error", error => finish(error.code ?? "socket-error"));
  });
}

async function childProbe(port) {
  const network = await dialLocal(port);
  const result = { scope: "linux-user-netns", network, browser: "not_run" };
  const root = await mkdtemp(path.join(os.tmpdir(), "rc-netns-browser-"));
  try {
    try {
      const { chromium } = await import("playwright-core");
      const context = await chromium.launchPersistentContext(path.join(root, "profile"), {
        headless: true, offline: true, javaScriptEnabled: false,
        serviceWorkers: "block", acceptDownloads: false,
        args: ["--disable-background-networking", "--disable-sync"],
      });
      try {
        const page = await context.newPage();
        await page.setContent("<html><body>NETNS_OFFLINE_CHROMIUM_OK</body></html>");
        const snapshot = await page.ariaSnapshot();
        result.browser = snapshot.includes("NETNS_OFFLINE_CHROMIUM_OK") ? "pass" : "no_marker";
      } finally {
        await context.close();
      }
    } catch (error) {
      result.browser = "failed";
      result.browser_error = String(error?.message || error).slice(0, 350);
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
  output(result);
}

async function parentProbe() {
  if (process.platform !== "linux" || process.getuid?.() === 0) {
    output({ status: "UNAVAILABLE", reason: "requires non-root Linux runner" });
    return;
  }
  let hits = 0;
  const server = createServer(socket => {
    hits++;
    socket.end("synthetic-loopback-only");
  });
  try {
    await new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });
    const address = server.address();
    if (!address || typeof address === "string") throw Error("Cannot bind local fixture");
    const port = address.port;
    const positiveControl = await dialLocal(port);
    // TCP connect completion and the server's connection event need not
    // settle in the same event-loop turn.
    await new Promise(resolve => setTimeout(resolve, 30));
    if (positiveControl !== "connected" || hits !== 1)
      throw Error("Positive-control localhost fixture is not reachable.");

    // CLONE_NEWUSER + CLONE_NEWNET only: no global routing, iptables,
    // device configuration, sudo or privileged fallback. If Ubuntu's AppArmor
    // blocks user namespace capabilities, report UNAVAILABLE, not PASS.
    const result = await new Promise(resolve => {
      const child = spawn("unshare", [
        "--user", "--map-root-user", "--net", "--",
        process.execPath, script, "--child", String(port),
      ], { stdio: ["ignore", "pipe", "pipe"] });
      let stdout = "", stderr = "", settled = false;
      const finish = item => {
        if (settled) return;
        settled = true;
        clearTimeout(timeout);
        resolve(item);
      };
      child.stdout.on("data", chunk => { stdout += String(chunk).slice(0, 4096); });
      child.stderr.on("data", chunk => { stderr += String(chunk).slice(0, 4096); });
      child.once("error", error => finish({ status: "UNAVAILABLE", reason: error.code }));
      child.once("close", (code, signal) => finish({ code, signal, stdout, stderr }));
      const timeout = setTimeout(() => {
        child.kill("SIGKILL");
        finish({ status: "UNAVAILABLE", reason: "netns-probe-timeout" });
      }, 25000);
    });
    if (result.status === "UNAVAILABLE") { output(result); return; }
    if (result.code !== 0) {
      output({ status: "UNAVAILABLE", reason: "unshare-or-child-exit", code: result.code,
        detail: result.stderr?.trim().slice(0, 350) });
      return;
    }
    const reportLine = result.stdout.split("\n").find(line => line.startsWith("RCA_NETNS_PROBE="));
    if (!reportLine) throw Error("Namespace child did not supply a structured result.");
    const report = JSON.parse(reportLine.slice("RCA_NETNS_PROBE=".length));
    if (hits !== 1 || report.network === "connected") {
      throw Error("SECURITY_REGRESSION: namespace child reached host loopback fixture.");
    }
    output({ status: report.browser === "pass" ? "NAMESPACE_AND_OFFLINE_BROWSER_PASS" : "NAMESPACE_ONLY",
      parent_positive_hits: 1, isolated_extra_hits: hits - 1, ...report });
  } finally {
    await new Promise(resolve => server.close(() => resolve()));
  }
}

if (process.argv[2] === "--child") {
  await childProbe(Number(process.argv[3]));
} else if (process.argv.length === 2) {
  await parentProbe();
} else {
  throw Error("Unsupported probe arguments.");
}
