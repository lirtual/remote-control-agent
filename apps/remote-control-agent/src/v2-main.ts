/** Linux-only v2 service entry. Never starts the deployed v1 loopback Agent. */
import { lstat } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { maintainAuthenticatedDeviceSession } from "./v2-connection-lifecycle.ts";

const keyPath = process.env.REMOTE_CONTROL_V2_KEY_PATH ??
  path.join(os.homedir(), ".local", "share", "mcp-workers", "remote-control", "v2-identity.pem");
const endpoint = process.env.REMOTE_CONTROL_V2_ENDPOINT;
const log = (event: string) =>
  process.stderr.write(JSON.stringify({ service: "remote-control-v2-agent", event }) + "\n");

if (!endpoint || process.platform !== "linux") {
  process.stderr.write("The Linux v2 Agent requires a trusted endpoint.\n");
  process.exitCode = 1;
} else {
  try {
    const privateKey = await lstat(keyPath);
    const deviceId = await lstat(keyPath + ".device-id");
    if (!privateKey.isFile() || !deviceId.isFile() ||
        (privateKey.mode & 0o077) !== 0 || (deviceId.mode & 0o077) !== 0 ||
        privateKey.uid !== process.getuid?.() || deviceId.uid !== process.getuid?.()) {
      throw new Error("unsafe identity");
    }
    // Only the signed device identity authenticates outbound HTTPS/WSS.
    // No Portal, Cloudflare, v1 device, or per-machine bearer token is needed.
    process.umask(0o077);
    const controller = new AbortController();
    for (const name of ["SIGINT", "SIGTERM"] as const) {
      process.on(name, () => controller.abort());
    }
    let rejected = false;
    await maintainAuthenticatedDeviceSession(endpoint, keyPath, controller.signal, {
      readOnly: true,
      writeFile: false,
      shell: false,
      onState: state => {
        log(state);
        if (state === "rejected") rejected = true;
      },
    });
    // 1008 policy denial stops the service with exit 0 (Restart=on-failure),
    // not an authentication-hammer loop. Other transient faults reconnect inside
    // maintainAuthenticatedDeviceSession with bounded backoff.
    if (rejected) log("identity_rejected");
  } catch {
    log("startup_unavailable");
    process.exitCode = 1;
  }
}
