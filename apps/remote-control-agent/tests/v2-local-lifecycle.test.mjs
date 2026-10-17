import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";
import path from "node:path";
const script=path.resolve(path.dirname(fileURLToPath(import.meta.url)),"../scripts/bootstrap-v2.py");
const python=String.raw`import importlib.util, pathlib, tempfile, os, json, stat, sys
spec=importlib.util.spec_from_file_location("bootstrap",sys.argv[1])
b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
with tempfile.TemporaryDirectory(prefix="issue69-t09-") as home:
    root=pathlib.Path(home)
    programs=root/".local/share/mcp-workers/remote-control/programs"
    ver=programs/"v0.2.0-linux-x64-glibc"
    entry=ver/"apps/remote-control-agent/src/v2-main.js"
    entry.parent.mkdir(parents=True,mode=0o700)
    entry.write_text("readOnly: true, writeFile: false, shell: false,")
    mf=ver/"bundle.json"
    mf.write_text(json.dumps({"version":"v0.2.0","target":"linux-x64-glibc","artifact_schema":1,
      "device_protocol":2,"receipt_schema":1,"upgrade_profile":"read-only-no-shell-v1"}))
    for p in (programs.parent,programs,ver,ver/"apps",ver/"apps/remote-control-agent",
              ver/"apps/remote-control-agent/src"):
        p.chmod(0o700)
    entry.chmod(0o600);mf.chmod(0o600)
    state=root/".local/state/mcp-workers/remote-control-agent"
    state.mkdir(parents=True); receipts=state/"operation-receipts.sqlite"
    receipts.write_text("untouched receipts")
    keys=root/".local/share/mcp-workers/remote-control/v2-identity.pem"
    keys.write_text("untouched private key");keys.chmod(0o600)
    did=pathlib.Path(str(keys)+".device-id")
    did.write_text("e11d9c70-16fe-4d47-aafc-d01db72750fd");did.chmod(0o600)
    st=b.local_status(home)
    assert st["cloud_authorization"]=="unconfirmed"
    assert st["cloud_revoke"]=="not_performed"
    assert st["installed_versions"]==[ver.name]
    assert st["device_ids"]["permanent"]=="e11d9c70-16fe-4d47-aafc-d01db72750fd"
    try:b.local_uninstall(home,False,process_check=lambda _:True);raise AssertionError("No-confirmation delete")
    except ValueError:pass
    assert ver.exists()
    try:b.local_uninstall(home,True,process_check=lambda _:False);raise AssertionError("Running process delete")
    except ValueError:pass
    assert ver.exists()
    # Simulated owned permanent unit must be matched exactly, no real systemctl.
    unit=root/".config/systemd/user/remote-control-v2-agent.service"
    unit.parent.mkdir(parents=True)
    unit.write_text(b.MARKER+"\n[Unit]\n[Service]\nWorkingDirectory="+str(ver/"apps/remote-control-agent")+
      "\nExecStart="+str(ver/"bin/node")+" "+str(ver/"apps/remote-control-agent/src/v2-main.js")+"\n")
    systemcalls=[]
    result=b.local_uninstall(home,True,systemctl=lambda args:systemcalls.append(args),
      process_check=lambda _:True)
    assert result["cloud_revocation"]=="NOT_PERFORMED"
    assert len(systemcalls)==2 and systemcalls[0][-1]==b.UNIT
    assert not ver.exists() and not unit.exists()
    assert keys.read_text()=="untouched private key" and receipts.read_text()=="untouched receipts"
    assert did.is_file()
    # A foreign program or service causes refusal, no blind removal.
    ver.mkdir(mode=0o700)
    alien=ver/"alien-link"
    alien.symlink_to(keys)
    try:b.local_uninstall(home,True,process_check=lambda _:True);raise AssertionError("malicious tree")
    except ValueError:pass
    assert alien.is_symlink() and keys.exists()
print("T09_PRESERVE_KEYS_RECEIPTS_AND_REVOKE_WARNING_OK")
`;
test("#78 status reports local and cloud states separately; uninstall preserves keys and receipts",()=>{
  const result=spawnSync("python3",["-c",python,script],{encoding:"utf8",timeout:15000});
  assert.equal(result.status,0,result.stderr);
  assert.match(result.stdout,/T09_PRESERVE_KEYS_RECEIPTS_AND_REVOKE_WARNING_OK/);
});
test("#78 no terminal refuses local uninstall before touching local files",()=>{
  const r=spawnSync("python3",[script,"--uninstall"],{encoding:"utf8",input:"",timeout:15000});
  assert.equal(r.status,1);
  assert.match(r.stderr,/real terminal|interactive terminal|non-root/);
});

test("#78 uninstall process guard catches disguised executables and working-directory ownership",()=>{
 const code=String.raw`import importlib.util,os,pathlib,sys,tempfile
spec=importlib.util.spec_from_file_location("b",sys.argv[1])
b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
with tempfile.TemporaryDirectory(prefix="rc-process-owner-") as d:
    root=pathlib.Path(d); version=root/"programs/v1"
    version.mkdir(parents=True)
    processes=root/"proc"; processes.mkdir()
    pid=processes/"999999"; pid.mkdir()
    (pid/"cmdline").write_bytes(b"unrelated-executable\0")
    (pid/"status").write_text("Name:\tuserprocess\nState:\tS (sleeping)\n")
    (pid/"exe").symlink_to(version/"bin/node")
    (pid/"cwd").symlink_to("/")
    assert not b.no_running_programs([version],processes), "executable was disguised by argv"
    (pid/"exe").unlink(); (pid/"exe").symlink_to("/usr/bin/bash")
    (pid/"cwd").unlink(); (pid/"cwd").symlink_to(version/"apps/remote-control-agent")
    assert not b.no_running_programs([version],processes), "program cwd ignored"
    (pid/"cwd").unlink(); (pid/"cwd").symlink_to("/")
    (pid/"cmdline").write_bytes((str(version)+"/bin/node").encode()+b"\0")
    assert not b.no_running_programs([version],processes), "program argv ignored"
    (pid/"cmdline").write_bytes(b"unrelated-executable\0")
    assert b.no_running_programs([version],processes)
    (pid/"exe").unlink()
    assert not b.no_running_programs([version],processes), "uncertain process silently allowed"
    (pid/"status").write_text("Name:\tuserprocess\nState:\tZ (zombie)\n")
    assert b.no_running_programs([version],processes)
print("PROCESS_OWNER_FAIL_CLOSED_OK")
`;
 const r=spawnSync("python3",["-B","-c",code,script],{encoding:"utf8",timeout:15000});
 assert.equal(r.status,0,r.stderr);
 assert.match(r.stdout,/PROCESS_OWNER_FAIL_CLOSED_OK/);
});

test("#78 optional v2-only identity purge needs separate consent; shared receipts and foreign files survive",()=>{
 const code=String.raw`import importlib.util,sys,tempfile,pathlib,os
spec=importlib.util.spec_from_file_location("b",sys.argv[1])
b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
with tempfile.TemporaryDirectory(prefix="rc-v2-purge-sandbox-") as home:
    root=pathlib.Path(home)
    base=root/b.STORE
    base.mkdir(parents=True,mode=0o700)
    base.chmod(0o700)
    tmp=base/"temporary";tmp.mkdir(mode=0o700)
    perm=base/"v2-identity.pem"
    temp=tmp/"v2-identity.pem"
    first="e11d9c70-16fe-4d47-aafc-d01db72750fd"
    second="e11d9c70-16fe-4d47-aafc-d01db72750fe"
    for key,did in [(perm,first),(temp,second)]:
        key.write_text("test-private-key");key.chmod(0o600)
        f=pathlib.Path(str(key)+".device-id");f.write_text(did);f.chmod(0o600)
    receipt=root/".local/state/mcp-workers/remote-control-agent/operation-receipts.sqlite"
    receipt.parent.mkdir(parents=True)
    receipt.write_bytes(b"shared-v1-v2-unknown-receipts")
    foreign=base/"v1-identity.pem";foreign.write_text("v1-must-survive")
    paths,ids=b.local_identity_purge_plan(home)
    assert len(paths)==4 and first==ids["permanent"] and second==ids["temporary"]
    assert all("v2-identity.pem" in str(p) for p in paths)
    for confirm,check in [(False,lambda:True),(True,lambda:False)]:
        try:b.local_identity_purge(home,confirm,process_check=check);raise AssertionError("unsafe purge accepted")
        except ValueError:pass
        assert perm.exists() and temp.exists()
    staging=pathlib.Path(str(perm)+".re-pair-transition")
    staging.write_text("pending owner confirmation")
    try:b.local_identity_purge_plan(home);raise AssertionError("re-pair transition ignored")
    except ValueError:pass
    staging.unlink()
    base.chmod(0o755)
    try:b.local_identity_purge_plan(home);raise AssertionError("public key directory accepted")
    except ValueError:pass
    base.chmod(0o700)
    archived=base/("revoked-"+first)
    archived.mkdir(mode=0o700)
    try:b.local_identity_purge_plan(home);raise AssertionError("old key archive ignored")
    except ValueError:pass
    archived.rmdir()
    linked=tmp/"v2-identity.pem.device-id"
    linked.unlink();linked.symlink_to(foreign)
    try:b.local_identity_purge_plan(home);raise AssertionError("linked identity accepted")
    except ValueError:pass
    linked.unlink();linked.write_text(second);linked.chmod(0o600)
    version=base/"programs/v0.5.0-linux-x64-glibc";version.mkdir(parents=True)
    try:b.local_identity_purge_plan(home);raise AssertionError("installed version ignored")
    except ValueError:pass
    version.rmdir()
    unit=root/".config/systemd/user"/b.UNIT;unit.parent.mkdir(parents=True)
    unit.write_text(b.MARKER+"\\n")
    try:b.local_identity_purge_plan(home);raise AssertionError("active v2 unit ignored")
    except ValueError:pass
    unit.unlink()
    result=b.local_identity_purge(home,True,process_check=lambda:True)
    assert len(result["removed_identity_paths"])==4
    assert result["preserved_sqlite_receipts"] is True and result["cloud_revocation"]=="NOT_PERFORMED"
    assert not perm.exists() and not temp.exists()
    assert receipt.read_bytes()==b"shared-v1-v2-unknown-receipts"
    assert foreign.read_text()=="v1-must-survive"
print("T09_SAFE_IDENTITY_ONLY_PURGE_OK")
`;
 const result=spawnSync("python3",["-B","-c",code,script],{encoding:"utf8",timeout:15000});
 assert.equal(result.status,0,result.stderr);
 assert.match(result.stdout,/T09_SAFE_IDENTITY_ONLY_PURGE_OK/);
});
test("#78 optional identity purge cannot run non-interactively",()=>{
 const r=spawnSync("python3",["-B",script,"--purge-local-identity"],
   {encoding:"utf8",input:"PURGE-V2-IDENTITY\n",timeout:15000});
 assert.equal(r.status,1);
 assert.match(r.stderr,/non-root interactive terminal/);
});

test("#78 real PTY opt-in identity-purge command shows exact scope and never touches shared receipts",()=>{
 const code=String.raw`import os,sys,tempfile,pathlib,pty,subprocess,select,time
script=sys.argv[1]
with tempfile.TemporaryDirectory(prefix="rc-v2-identity-cli-") as home:
    base=pathlib.Path(home)/".local/share/mcp-workers/remote-control"
    base.mkdir(parents=True,mode=0o700);base.chmod(0o700)
    key=base/"v2-identity.pem";key.write_text("dummy-key");key.chmod(0o600)
    did=pathlib.Path(str(key)+".device-id")
    did.write_text("e11d9c70-16fe-4d47-aafc-d01db72750fd");did.chmod(0o600)
    receipt=pathlib.Path(home)/".local/state/mcp-workers/remote-control-agent/operation-receipts.sqlite"
    receipt.parent.mkdir(parents=True);receipt.write_text("unknown-v1-v2-receipt")
    master,slave=pty.openpty()
    env=dict(os.environ,HOME=home)
    child=subprocess.Popen([sys.executable,"-B",script,"--purge-local-identity"],
        stdin=slave,stdout=slave,stderr=slave,env=env,close_fds=True)
    os.close(slave)
    output=b"";written=False;deadline=time.monotonic()+8
    while time.monotonic()<deadline:
        ready,_,_=select.select([master],[],[],0.1)
        if ready:
            try:chunk=os.read(master,8192)
            except OSError:break
            if not chunk:break
            output+=chunk
        if b"PURGE-V2-IDENTITY to irreversibly remove" in output and not written:
            assert str(key).encode() in output and str(did).encode() in output
            assert b"Cloud authorization has NOT been revoked" in output
            assert b"SQLite receipts" in output
            os.write(master,b"PURGE-V2-IDENTITY\n");written=True
        if child.poll() is not None:
            break
    os.close(master)
    if child.poll() is None:child.kill()
    assert child.wait(timeout=5)==0,output.decode(errors="replace")
    assert written and not key.exists() and not did.exists()
    assert receipt.read_text()=="unknown-v1-v2-receipt"
print("PTY_CONFIRMED_KEY_ONLY_PURGE_OK")
`;
 const r=spawnSync("python3",["-B","-c",code,script],{encoding:"utf8",timeout:17000});
 assert.equal(r.status,0,r.stderr);
 assert.match(r.stdout,/PTY_CONFIRMED_KEY_ONLY_PURGE_OK/);
});
