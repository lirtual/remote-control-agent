import { spawnSync } from "node:child_process";
import { chmodSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

if (process.platform !== "linux") {
  throw new Error("The managed Shell supervisor requires Linux pidfd process-group signaling.");
}

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const outputDirectory = path.join(packageRoot, ".build");
const outputPath = path.join(outputDirectory, "session-supervisor");
const sourcePath = path.join(packageRoot, "scripts", "session-supervisor.c");
mkdirSync(outputDirectory, { recursive: true, mode: 0o700 });
chmodSync(outputDirectory, 0o700);

const result = spawnSync("cc", [
  "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-fstack-protector-strong",
  "-D_FORTIFY_SOURCE=2", "-Wl,-z,relro,-z,now", sourcePath, "-o", outputPath,
], {
  encoding: "utf8",
});
if (result.error) throw result.error;
if (result.status !== 0) {
  throw new Error(`Could not build the managed Shell supervisor: ${result.stderr || result.stdout || "C compiler failed."}`);
}
chmodSync(outputPath, 0o700);
