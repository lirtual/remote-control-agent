import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, mkdir, readFile, rm, writeFile, access, chmod, symlink } from "node:fs/promises";
import { DatabaseSync } from "node:sqlite";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { installUnit, recoverInterruptedUpgrade, renderV2Service, installerCommandTimeoutMs, UNIT } from "../scripts/install-v2.mjs";
import { ReceiptStore } from "../src/operations.ts";

async function withFakeUserService(callback, {blockRestart = false} = {}) {
  const root = await mkdtemp(path.join(os.tmpdir(), "rc-v2-t08-inject-"));
  const fake = path.join(root, "fake-bin");
  const home = path.join(root, "home");
  const logs = path.join(root, "systemctl.log");
  const activeOk = path.join(root, "active-ok");
  const restartOnce = path.join(root, "restart-once");
  const restartReached = path.join(root, "restart-reached");
  const releaseRestart = path.join(root, "release-restart");
  const preserved = path.join(home, ".local", "state", "mcp-workers", "remote-control-agent");
  const oldEnv = {
    PATH: process.env.PATH, RC_SYS_LOG: process.env.RC_SYS_LOG, RC_SYS_ACTIVE: process.env.RC_SYS_ACTIVE,
    RC_SYS_RESTART_ONCE: process.env.RC_SYS_RESTART_ONCE, RC_SYS_RESTART_REACHED: process.env.RC_SYS_RESTART_REACHED,
    RC_SYS_RELEASE_RESTART: process.env.RC_SYS_RELEASE_RESTART, RC_SYS_ACTIVE_ON_RESTART: process.env.RC_SYS_ACTIVE_ON_RESTART,
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
      '  *" restart "*)',
      '    if [ "$RC_SYS_ACTIVE_ON_RESTART" = "1" ]; then : > "$RC_SYS_ACTIVE"; fi',
      '    if [ -n "$RC_SYS_RESTART_ONCE" ] && [ ! -e "$RC_SYS_RESTART_ONCE" ]; then',
      '      : > "$RC_SYS_RESTART_ONCE"; : > "$RC_SYS_RESTART_REACHED";',
      '      while [ ! -e "$RC_SYS_RELEASE_RESTART" ]; do sleep 0.02; done',
      '    fi;;',
      '  *" is-active "*) [ -e "$RC_SYS_ACTIVE" ] && exit 0; : > "$RC_SYS_ACTIVE"; exit 1;;',
      "esac",
      "exit 0",
      "",
    ].join("\n"), {mode: 0o700});
    process.env.PATH = fake + ":" + oldEnv.PATH;
    process.env.RC_SYS_LOG = logs;
    process.env.RC_SYS_ACTIVE = activeOk;
    if (blockRestart) {
      process.env.RC_SYS_RESTART_ONCE = restartOnce;
      process.env.RC_SYS_RESTART_REACHED = restartReached;
      process.env.RC_SYS_RELEASE_RESTART = releaseRestart;
      process.env.RC_SYS_ACTIVE_ON_RESTART = "1";
    } else {
      delete process.env.RC_SYS_RESTART_ONCE;
      delete process.env.RC_SYS_RESTART_REACHED;
      delete process.env.RC_SYS_RELEASE_RESTART;
      delete process.env.RC_SYS_ACTIVE_ON_RESTART;
    }
    const key = path.join(home, ".local", "share", "mcp-workers", "remote-control", "v2-identity.pem");
    await mkdir(path.dirname(key), {recursive:true});
    await writeFile(key, "private-unchanged", {mode:0o600});
    await writeFile(key + ".device-id", "e11d9c70-16fe-4d47-aafc-d01db72750fd", {mode:0o600});
    const receipt = path.join(preserved, "operation-receipts.sqlite");
    const store = new ReceiptStore(preserved);
    await store.open();
    await store.admit("t08-unknown-guarded", "start_process", "a".repeat(64));
    await store.update("t08-unknown-guarded", "unknown", "Effect cannot be established.");
    await store.admit("t08-completed", "write_file", "b".repeat(64));
    await store.update("t08-completed", "completed", "Effect completed.");
    await store.close();
    const beforeReceiptBytes = await readFile(receipt);
    const db = new DatabaseSync(receipt, {readOnly:true});
    try {
      const states = db.prepare("SELECT operation_id, state, guarded FROM receipts ORDER BY operation_id").all().map(row=>({...row}));
      assert.deepEqual(states, [
        {operation_id:"t08-completed", state:"completed", guarded:0},
        {operation_id:"t08-unknown-guarded", state:"unknown", guarded:1},
      ]);
      assert.equal(db.prepare("PRAGMA quick_check").get().quick_check, "ok");
    } finally { db.close(); }
    const unitPath = path.join(home, ".config", "systemd", "user", UNIT);
    const target = process.arch === "arm64" ? "linux-arm64-glibc" : "linux-x64-glibc";
    const oldRoot = path.join(home, ".local/share/mcp-workers/remote-control/programs/v0.1.0-" + target);
    const newRoot = path.join(home, ".local/share/mcp-workers/remote-control/programs/v0.2.0-" + target);
    for (const [root, version] of [[oldRoot,"v0.1.0"],[newRoot,"v0.2.0"]]) {
      await mkdir(path.join(root, "bin"), {recursive:true, mode:0o700});
      await mkdir(path.join(root, "apps/remote-control-agent/src"), {recursive:true, mode:0o700});
      await mkdir(path.join(root, "apps/remote-control-agent/.build"), {recursive:true, mode:0o700});
      await chmod(root,0o700);
      await writeFile(path.join(root,"bin/node"),"node-fixture",{mode:0o700});
      await writeFile(path.join(root,"apps/remote-control-agent/.build/session-supervisor"),"supervisor-fixture",{mode:0o700});
      await writeFile(path.join(root,"apps/remote-control-agent/src/v2-main.js"),
        "export const policy = { readOnly: true, writeFile: false, shell: false, };",{mode:0o600});
      await writeFile(path.join(root,"bundle.json"),JSON.stringify({
        name:"remote-control-agent",artifact_schema:1,version,target,
        device_protocol:2,receipt_schema:1,upgrade_profile:"read-only-no-shell-v1"
      }),{mode:0o600});
    }
    const from = renderV2Service({node:oldRoot+"/bin/node",home,repoRoot:oldRoot,
      keyPath:key,endpoint:"https://rc.example.org/",entryExt:"js"});
    const to = renderV2Service({node:newRoot+"/bin/node",home,repoRoot:newRoot,
      keyPath:key,endpoint:"https://rc.example.org/",entryExt:"js"});
    await callback({unitPath, from, to, key, receipt, beforeReceiptBytes, logs, activeOk, home, restartReached, restartOnce, releaseRestart});
    assert.equal(await readFile(key, "utf8"), "private-unchanged");
    assert.equal(await readFile(key + ".device-id", "utf8"), "e11d9c70-16fe-4d47-aafc-d01db72750fd");
    assert.deepEqual(await readFile(receipt), beforeReceiptBytes);
  } finally {
    for(const [k,v] of Object.entries(oldEnv)) {
      if(v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
    await rm(root, {recursive:true, force:true});
  }
}

test("#539 manual Agent upgrade gives systemd restart time beyond its 15-second stop budget", () => {
  assert.equal(installerCommandTimeoutMs("systemctl", ["--user", "restart", UNIT]), 45_000);
  assert.equal(installerCommandTimeoutMs("systemctl", ["--user", "daemon-reload"]), 15_000);
  assert.equal(installerCommandTimeoutMs("systemctl", ["--user", "is-active", "--quiet", UNIT]), 15_000);
  assert.equal(installerCommandTimeoutMs("systemd-analyze", ["--user", "verify", UNIT]), 15_000);
  assert.equal(installerCommandTimeoutMs("systemctl", ["--system", "restart", UNIT]), 15_000);
});

test("#77 SIGKILL during unit activation is recovered from a durable previous-unit backup", async()=> {
  await withFakeUserService(async ({unitPath,from,to,key,receipt,beforeReceiptBytes,home,restartReached,releaseRestart})=> {
    await writeFile(unitPath,from,{mode:0o600});
    const installerUrl = new URL("../scripts/install-v2.mjs", import.meta.url).href;
    const childSource = "import { installUnit } from " + JSON.stringify(installerUrl) + ";\n" +
      "await installUnit(" + JSON.stringify(unitPath) + "," + JSON.stringify(to) + "," + JSON.stringify(from) + ");\n";
    const child = spawn(process.execPath, ["--experimental-strip-types","--input-type=module","-e",childSource],
      {stdio:"ignore",env:process.env});
    const exited = new Promise(resolve=>child.once("exit",(code,signal)=>resolve({code,signal})));
    try {
      let reached = false;
      const started = Date.now();
      while (Date.now()-started < 5000) {
        try { await access(restartReached); reached=true; break; } catch {}
        if (child.exitCode !== null || child.signalCode !== null) break;
        await new Promise(resolve=>setTimeout(resolve,20));
      }
      assert.equal(reached,true,"installer did not reach the interrupted restart");
      assert.equal(await readFile(unitPath,"utf8"),to);
      assert.equal(await access(unitPath+".upgrade-backup").then(()=>true,()=>false),true);
      assert.equal(child.kill("SIGKILL"),true);
      await writeFile(releaseRestart,"release",{mode:0o600});
      const exit = await exited;
      assert.equal(exit.signal,"SIGKILL");
      assert.equal(await recoverInterruptedUpgrade({home,unitPath}),true);
      assert.equal(await readFile(unitPath,"utf8"),from);
      await assert.rejects(access(unitPath+".upgrade-backup"),{code:"ENOENT"});
      assert.equal(await readFile(key,"utf8"),"private-unchanged");
      assert.deepEqual(await readFile(receipt), beforeReceiptBytes);
    } finally {
      if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
      await writeFile(releaseRestart,"release",{mode:0o600}).catch(()=>{});
    }
  },{blockRestart:true});
});

test("#77 interrupted recovery refuses a linked backup without changing unit or identity", async()=>{
  await withFakeUserService(async ({unitPath,from,key,home})=>{
    await writeFile(unitPath,from,{mode:0o600});
    await symlink(key,unitPath+".upgrade-backup");
    await assert.rejects(recoverInterruptedUpgrade({home,unitPath}),/backup is unsafe/);
    assert.equal(await readFile(unitPath,"utf8"),from);
    assert.equal(await readFile(key,"utf8"),"private-unchanged");
  });
});

test("#77 interrupted recovery rejects noncanonical backup directives", async()=>{
  await withFakeUserService(async ({unitPath,from,to,home,logs})=>{
    // The backup can name the expected old binary but must not add arbitrary
    // systemd activation directives or change the approved service template.
    const altered=from.replace("RestartSec=15s", ["ExecStartPost=/usr/bin/true", "RestartSec=15s"].join(String.fromCharCode(10)));
    await writeFile(unitPath,to,{mode:0o600});
    const backup=unitPath+".upgrade-backup";
    await writeFile(backup,altered,{mode:0o600});
    await assert.rejects(recoverInterruptedUpgrade({home,unitPath}),/differs from the managed service template/);
    assert.equal(await readFile(unitPath,"utf8"),to);
    assert.equal(await readFile(backup,"utf8"),altered);
    await assert.rejects(access(logs),{code:"ENOENT"});
  });
});

test("#77 interrupted recovery refuses a noncanonical current unit before systemctl", async()=>{
  await withFakeUserService(async ({unitPath,from,to,home,logs})=>{
    const altered=to.replace("RestartSec=15s",
      ["ExecStartPost=/usr/bin/true","RestartSec=15s"].join(String.fromCharCode(10)));
    await writeFile(unitPath,altered,{mode:0o600});
    const backup=unitPath+".upgrade-backup";
    await writeFile(backup,from,{mode:0o600});
    await assert.rejects(recoverInterruptedUpgrade({home,unitPath}),/Current Agent unit is noncanonical/);
    assert.equal(await readFile(unitPath,"utf8"),altered);
    assert.equal(await readFile(backup,"utf8"),from);
    await assert.rejects(access(logs),{code:"ENOENT"});
  });
});

test("#77 interrupted recovery refuses endpoint drift before touching systemd", async()=>{
  await withFakeUserService(async ({unitPath,from,to,home,logs})=>{
    const moved=to.replace("https://rc.example.org/", "https://other.example.org/");
    await writeFile(unitPath,moved,{mode:0o600});
    await writeFile(unitPath+".upgrade-backup",from,{mode:0o600});
    await assert.rejects(recoverInterruptedUpgrade({home,unitPath}),/changes the endpoint or device identity/);
    assert.equal(await readFile(unitPath,"utf8"),moved);
    await assert.rejects(access(logs),{code:"ENOENT"});
  });
});

test("#77 interrupted recovery refuses device-key drift before touching systemd", async()=>{
  await withFakeUserService(async ({unitPath,from,to,home,logs,key})=>{
    // Keep the modified unit internally canonical; change both Environment and
    // ExecStartPre key paths so we specifically exercise cross-version ID drift.
    const moved=to.replaceAll(key,key+".different");
    await writeFile(unitPath,moved,{mode:0o600});
    await writeFile(unitPath+".upgrade-backup",from,{mode:0o600});
    await assert.rejects(recoverInterruptedUpgrade({home,unitPath}),/changes the endpoint or device identity/);
    assert.equal(await readFile(unitPath,"utf8"),moved);
    await assert.rejects(access(logs),{code:"ENOENT"});
  });
});

test("#77 interrupted recovery keeps backup if existing unit is absent", async()=>{
  await withFakeUserService(async ({unitPath,from,home})=>{
    const backup=unitPath+".upgrade-backup";
    await writeFile(backup,from,{mode:0o600});
    await assert.rejects(recoverInterruptedUpgrade({home,unitPath}),/Current Agent unit is missing/);
    assert.equal(await readFile(backup,"utf8"),from);
  });
});

test("#77 interrupted recovery retries only once when old unit already exists", async()=>{
  await withFakeUserService(async ({unitPath,from,home,activeOk,logs})=>{
    await writeFile(unitPath,from,{mode:0o600});
    await writeFile(unitPath+".upgrade-backup",from,{mode:0o600});
    await writeFile(activeOk,"active",{mode:0o600});
    assert.equal(await recoverInterruptedUpgrade({home,unitPath}),true);
    assert.equal(await recoverInterruptedUpgrade({home,unitPath}),false);
    await assert.rejects(access(unitPath+".upgrade-backup"),{code:"ENOENT"});
    const lines=(await readFile(logs,"utf8")).split("\n");
    assert.equal(lines.filter(line=>line.includes("restart "+UNIT)).length,1);
  });
});

test("#77 local upgrade activation failure restores exact owned v2 unit and keeps identity/SQLite", async()=>{
  await withFakeUserService(async ({unitPath,from,to,logs})=>{
    await writeFile(unitPath, from, {mode:0o600});
    await assert.rejects(installUnit(unitPath,to,from), /could not be activated/);
    assert.equal(await readFile(unitPath,"utf8"),from);
    await assert.rejects(access(unitPath+".upgrade-backup"),{code:"ENOENT"});
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
    await assert.rejects(access(unitPath+".upgrade-backup"),{code:"ENOENT"});
    const calls=await readFile(logs,"utf8");
    assert.match(calls,/--user restart remote-control-agent\.service/);
  });
});

test("#77 cloud WSS reachability is not a local activation gate or a rollback trigger",async()=>{
  await withFakeUserService(async ({unitPath,from,to,logs,activeOk})=>{
    // This intentionally unreachable endpoint remains IDENTICAL across versions.
    // A successful local systemd unit transition MUST NOT fabricate cloud
    // authorization/signed WSS or revert merely because cloud cannot be reached.
    assert.match(from,/https:\/\/rc\.example\.org\//);
    assert.match(to,/https:\/\/rc\.example\.org\//);
    await writeFile(unitPath,from,{mode:0o600});
    await writeFile(activeOk,"locally-active; remote WSS unreachable",{mode:0o600});
    await installUnit(unitPath,to,from);
    assert.equal(await readFile(unitPath,"utf8"),to);
    await assert.rejects(access(unitPath+".upgrade-backup"),{code:"ENOENT"});
    const calls=(await readFile(logs,"utf8")).trim().split("\n");
    assert.equal(calls.filter(line=>line.includes("restart "+UNIT)).length,1);
    assert.ok(calls.some(line=>line.includes("is-active --quiet "+UNIT)));
    assert.equal(calls.some(line=>line.includes("disable --now")),false);
    // This is strictly a local-only verdict; no network/WSS access is
    // performed or claimed, and the previous executable remains available.
  });
});

test("#77 failed first activation deletes only the newly installed v2 unit", async()=>{
  await withFakeUserService(async ({unitPath,to,logs})=>{
    await assert.rejects(installUnit(unitPath,to,null), /could not be activated/);
    await assert.rejects(access(unitPath),{code:"ENOENT"});
    const calls=await readFile(logs,"utf8");
    assert.match(calls,/--user enable --now remote-control-agent\.service/);
    assert.match(calls,/--user disable --now remote-control-agent\.service/);
  });
});
