/**
 * Windows-native live Cloudflare readiness check for the existing candidate gate.
 * Opted into the existing manual CI dispatch, never called on every PR.
 * No OTP is sent and no real browser credentials or user email are used.
 */
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { spawn, type ChildProcess } from "node:child_process";
import { createServer } from "node:http";
import { createReadStream } from "node:fs";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import path from "node:path";
import os from "node:os";
import { once } from "node:events";
import test from "node:test";
import { isProtectedChallenge, tunnelOriginFromLog } from "../src/protected-tunnel.ts";

const EXPECTED_SHA256 = "76b2805253d0d6ffacb092a7acfbee99e7af6917835c0c5410e23f3ef5052da2";

async function hashFile(filename: string): Promise<string> {
  const hash = createHash("sha256");
  for await (const data of createReadStream(filename)) hash.update(data);
  return hash.digest("hex");
}

test("real Windows Quick Tunnel blocks anonymous GET and POST before reporting Link Ready", {
  skip: process.platform !== "win32",
  timeout: 160_000,
}, async () => {
  const executable = process.env.RCA_WIN_CLOUDFLARED_CANDIDATE;
  assert.ok(executable, "Pinned cloudflared candidate path required");
  assert.equal(await hashFile(executable), EXPECTED_SHA256, "Official Cloudflare binary digest changed");

  const dir = await mkdtemp(path.join(os.tmpdir(), "spec280-quicktunnel-"));
  const probePath = "/__handoff_probe/" + randomBytes(32).toString("base64url");
  const server = createServer((_request, response) => {
    response.writeHead(200, { "content-type": "text/plain", "cache-control": "no-store" });
    response.end("PRIVATE_TEST_ORIGIN_NOT_AUTHORIZED");
  });
  let child: ChildProcess | undefined;
  let childExit: Promise<unknown> | undefined;
  try {
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });
    const address = server.address();
    assert.ok(address && typeof address === "object");
    await writeFile(path.join(dir, "empty.yml"), "{}\n", { flag: "wx", mode: 0o600 });

    // Origin is never handed to another user and contains no login/session data.
    child = spawn(executable, [
      "tunnel", "--config", path.join(dir, "empty.yml"), "--no-autoupdate",
      "--output", "json", "--url", `http://127.0.0.1:${address.port}`,
      "--allowed-mail", "spec280-ci@example.com",
    ], {
      cwd: dir, windowsHide: true, stdio: ["ignore", "pipe", "pipe"],
      env: {
        SystemRoot: process.env.SystemRoot,
        PATH: path.join(process.env.SystemRoot ?? "C:\\Windows", "System32"),
        USERPROFILE: dir, HOME: dir, TEMP: dir, TMP: dir,
      },
    });
    childExit = once(child, "exit");
    // Attach the rejection handler now, even when the spawn fails.
    void childExit.catch(() => {});
    const tunnel = child;
    const origin = await new Promise<string>((resolve, reject) => {
      let settled = false;
      let bytes = 0;
      const timeout = setTimeout(() => finish(Error("Quick Tunnel URL not emitted")), 35_000);
      function finish(error?: Error, value?: string) {
        if (settled) return;
        settled = true;
        clearTimeout(timeout);
        if (error) reject(error);
        else resolve(value!);
      }
      for (const stream of [tunnel.stdout!, tunnel.stderr!]) {
        let partial = "";
        stream.on("data", (data: Buffer) => {
          bytes += data.length;
          if (bytes > 256_000) return finish(Error("Cloudflare log limit"));
          partial += data.toString("utf8");
          let end: number;
          while ((end = partial.indexOf("\n")) >= 0) {
            const url = tunnelOriginFromLog(partial.slice(0, end));
            partial = partial.slice(end + 1);
            if (url) return finish(undefined, url);
          }
          if (partial.length > 8192) finish(Error("Cloudflare log line limit"));
        });
      }
      tunnel.once("error", () => finish(Error("Quick Tunnel failed to start")));
      tunnel.once("exit", () => finish(Error("Quick Tunnel exited before ready")));
    });
    let proven = false;
    // Public DNS may initially return NXDOMAIN even after cloudflared emits a URL.
    const readinessDeadline = Date.now() + 90_000;
    let result = "no-response";
    for (let attempt = 0; attempt < 90 && !proven && Date.now() < readinessDeadline; attempt++) {
      if (child.exitCode !== null || child.signalCode !== null) break;
      try {
        const get = await fetch(origin + probePath, {
          redirect: "manual", credentials: "omit", signal: AbortSignal.timeout(5000),
        });
        const getProtected = isProtectedChallenge(get, origin, probePath);
        result = `GET ${get.status}, challenge ${getProtected}`;
        await get.body?.cancel();
        if (getProtected) {
          const post = await fetch(origin + probePath, {
            method: "POST", redirect: "manual", credentials: "omit",
            signal: AbortSignal.timeout(5000),
          });
          proven = post.status === 401;
          result += `, POST ${post.status}`;
          await post.body?.cancel();
        }
      } catch (error) {
        // Only a fixed transport code is reported: never log URL, email, cookies or headers.
        const cause = error && typeof error === "object" && "cause" in error ? error.cause : undefined;
        const code = cause && typeof cause === "object" && "code" in cause ? cause.code : undefined;
        result = "HTTPS transport unavailable (" + (typeof code === "string" && /^[A-Z_0-9]+$/.test(code) ? code : "unknown") + ")";
      }
      if (!proven) await new Promise(resolve => setTimeout(resolve, 1000));
    }
    assert.ok(proven, "Fail closed: live anonymous GET 302 / POST 401 not verified (" + result + ")");
    console.log("Native Windows live Quick Tunnel: anonymous GET 302 + POST 401 verified.");
  } finally {
    if (child && child.exitCode === null && child.signalCode === null) {
      child.kill();
      if (childExit) {
        await Promise.race([
          childExit.catch(() => {}),
          new Promise((_, reject) => setTimeout(() => reject(Error("Tunnel cleanup uncertain")), 8000)),
        ]);
      }
    }
    await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    await rm(dir, { recursive: true, force: true });
  }
});
