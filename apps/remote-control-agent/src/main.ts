import { startAgent, type RunningAgent } from "./server.ts";

const token = process.env.REMOTE_CONTROL_DEVICE_TOKEN;
if (!token) {
  process.stderr.write("REMOTE_CONTROL_DEVICE_TOKEN is not configured.\n");
  process.exit(1);
}

const host = process.env.REMOTE_CONTROL_AGENT_HOST ?? "127.0.0.1";
const portValue = process.env.REMOTE_CONTROL_AGENT_PORT ?? "9477";
const port = Number(portValue);
if (!Number.isInteger(port) || port < 0 || port > 65535) {
  process.stderr.write("REMOTE_CONTROL_AGENT_PORT is invalid.\n");
  process.exit(1);
}

const agent: RunningAgent = await startAgent({
  deviceToken: token,
  host,
  port,
  receiptHistoricalBackupPath: process.env.REMOTE_CONTROL_RECEIPT_HISTORICAL_BACKUP || undefined,
  log: (event) => {
    process.stderr.write(`${JSON.stringify({ service: "remote-control-agent", event })}\n`);
  },
}).catch((error: unknown) => {
  process.stderr.write("The remote control agent failed to start.\n");
  if (error instanceof Error && error.message === "Agent listens on loopback only.") {
    process.stderr.write("Agent listens on loopback only.\n");
  }
  process.exit(1);
});

process.stderr.write(
  `${JSON.stringify({ service: "remote-control-agent", event: "listen", port: agent.port })}\n`,
);

let closing = false;
async function shutdown(): Promise<void> {
  if (closing) return;
  closing = true;
  await agent.close();
}

process.on("SIGINT", () => {
  void shutdown().then(() => process.exit(0));
});
process.on("SIGTERM", () => {
  void shutdown().then(() => process.exit(0));
});
