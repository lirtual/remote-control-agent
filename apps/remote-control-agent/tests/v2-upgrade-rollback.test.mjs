import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, rm, writeFile, access } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { installUnit, renderV2Service, UNIT } from "../scripts/install-v2.mjs";

async function withFakeUserService(callback) {
  const root = await mkdtemp(path.join(os.tmpdir(), "rc-v2-t08-inject-"));
  const fake = path.join(root, "fake-bin");
  const home = path.join(root, "home");
  const logs = path.join(root, "systemctl.log");
  const activeOk = path.join(root, "active-ok");
  const preserved = path.join(home, ".local", "state", "mcp-workers", "remote-control-agent");
  const oldEnv = {
    PATH: process.env.PATH, RC_SYS_LOG: process.env.RC_SYS_LOG, RC_SYS_ACTIVE: process.env.RC_SYS_ACTIVE,
  };
  try {
    await mkdir(fake, { recursive: true });
    await mkdir(preserved, { recursive: true });
    await mkdir(path.join(home, ".config", "systemd", "user"), { recursive: true });
    await writeFile(path.join(fake, "systemd-analyze"), "#!/bin/sh\nexit 0\n", {mode: 0o700});
    await writeFile(path.join(fake, "systemctl"), [
      "#!/bin/sh",
      'printf "%s\\n" "$*" >> "$RC_SYS_LOG"',
      'case " $* " in',
      '  *" is-active "*) [ -e "$RC_SYS_ACTIVE" ] && exit 0; : > "$RC_SYS_ACTIVE"; exit 1;;',
      "esac",
      "exit 0",
      "",
    ].join("\n"), {mode: 0o700});
    process.env.PATH = fake + ":" + oldEnv.PATH;
    process.env.RC_SYS_LOG = logs;
    process.env.RC_SYS_ACTIVE = activeOk;
    const key = path.join(home, ".local", "share", "mcp-workers", "remote-control", "v2-identity.pem");
    await mkdir(path.dirname(key), {recursive:true});
    await writeFile(key, "private-unchanged", {mode:0o600});
    await writeFile(key + ".device-id", "e11d9c70-16fe-4d47-aafc-d01db72750fd", {mode:0o600});
    const receipt = path.join(preserved, "operation-receipts.sqlite");
    await writeFile(receipt, "receipts-must-not-change", {mode:0o600});
    const unitPath = path.join(home, ".config", "systemd", "user", UNIT);
    const oldRoot = path.join(home, ".local/share/mcp-workers/remote-control/programs/v0.1.0-linux-x64-glibc");
    const newRoot = path.join(home, ".local/share/mcp-workers/remote-control/programs/v0.2.0-linux-x64-glibc");
    const from = renderV2Service({node:oldRoot+"/bin/node",home,repoRoot:oldRoot,
      keyPath:key,endpoint:"https://rc.example.org/",entryExt:"js"});
    const to = renderV2Service({node:newRoot+"/bin/node",home,repoRoot:newRoot,
      keyPath:key,endpoint:"https://rc.example.org/",entryExt:"js"});
    await callback({unitPath, from, to, key, receipt, logs, activeOk});
    assert.equal(await readFile(key, "utf8"), "private-unchanged");
    assert.equal(await readFile(key + ".device-id", "utf8"), "e11d9c70-16fe-4d47-aafc-d01db72750fd");
    assert.equal(await readFile(receipt, "utf8"), "receipts-must-not-change");
  } finally {
    for(const [k,v] of Object.entries(oldEnv)) {
      if(v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
    await rm(root, {recursive:true, force:true});
  }
}

test("#77 local upgrade activation failure restores exact owned v2 unit and keeps identity/SQLite", async()=>{
  await withFakeUserService(async ({unitPath,from,to,logs})=>{
    await writeFile(unitPath, from, {mode:0o600});
    await assert.rejects(installUnit(unitPath,to,from), /could not be activated/);
    assert.equal(await readFile(unitPath,"utf8"),from);
    const calls=(await readFile(logs,"utf8")).trim().split("\n");
    assert.ok(calls.filter(x=>x.includes("restart " + UNIT)).length>=2);
    assert.ok(calls.some(x=>x.includes("is-active --quiet " + UNIT)));
    assert.equal(calls.some(x=>x.includes("disable --now")), false);
  });
});

test("#77 successful local upgrade writes new v2 unit without identity reset", async()=>{
  await withFakeUserService(async ({unitPath,from,to,logs,activeOk})=>{
    await writeFile(unitPath,from,{mode:0o600});
    await writeFile(activeOk,"preauthorized",{mode:0o600});
    await installUnit(unitPath,to,from);
    assert.equal(await readFile(unitPath,"utf8"),to);
    const calls=await readFile(logs,"utf8");
    assert.match(calls,/--user restart remote-control-v2-agent\.service/);
  });
});

test("#77 failed first activation deletes only the newly installed v2 unit", async()=>{
  await withFakeUserService(async ({unitPath,to,logs})=>{
    await assert.rejects(installUnit(unitPath,to,null), /could not be activated/);
    await assert.rejects(access(unitPath),{code:"ENOENT"});
    const calls=await readFile(logs,"utf8");
    assert.match(calls,/--user enable --now remote-control-v2-agent\.service/);
    assert.match(calls,/--user disable --now remote-control-v2-agent\.service/);
  });
});
