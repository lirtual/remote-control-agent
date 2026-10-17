#!/usr/bin/env python3
"""Verify an UNPUBLISHED native candidate; no network, enrollment, or Release upload."""
import importlib.util
import json
import pathlib
import platform
import subprocess
import sys
import tempfile


def verify_refuses_unsafe_onboarding(node, installer, root):
    """Exercise the *actual bundled* CLI, never contact the owner/Worker."""
    import os
    import pty
    import select
    import time

    home = root / "disposable-unpaired-home"
    home.mkdir(mode=0o700)
    env = {**os.environ, "HOME": str(home)}
    cli = [str(node), str(installer), "--endpoint", "https://rc.example.org/"]

    # No TTY: never select a default device lifetime or create an identity.
    result = subprocess.run(cli, env=env, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=10, check=False)
    if result.returncode == 0:
        raise SystemExit("noninteractive portable installer activated unexpectedly")

    # Real PTY: the owner must choose; an invalid selection must fail closed
    # *before* any pairing request or identity key is produced.
    master, slave = pty.openpty()
    proc = subprocess.Popen(cli, env=env, stdin=slave, stdout=slave, stderr=slave,
                            start_new_session=True, close_fds=True)
    os.close(slave)
    transcript = b""
    challenged = False
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            ready, _, _ = select.select([master], [], [], 0.1)
            if ready:
                try:
                    chunk = os.read(master, 8192)
                except OSError:
                    break
                if not chunk:
                    break
                transcript += chunk
            if b"Choose [1-2]:" in transcript and not challenged:
                os.write(master, b"x\n")
                challenged = True
            if proc.poll() is not None:
                break
        if proc.poll() is None:
            proc.kill()
        if proc.wait(timeout=3) == 0 or not challenged:
            raise SystemExit("portable target-local mode-choice gate failed")
    finally:
        os.close(master)

    private = home / ".local/share/mcp-workers/remote-control"
    if (private / "v2-identity.pem").exists() or (private / "temporary/v2-identity.pem").exists():
        raise SystemExit("portable installer created identity before owner approval")
    return "noninteractive_and_invalid_local_mode_rejected"


# Real immutable candidate exercise: no cloud, no installer activation.

def verify_node_bootstrap_offline(node, bootstrap, archive, tag, work):
    """Exercise real bundled Node+archive without ever enrolling a device."""
    import hashlib
    import os
    import pty
    import select
    import shutil
    import time
    home = work / "disposable-node-bootstrap-home"
    home.mkdir(mode=0o700)
    local_archive = home / "verified-release.tar.gz"
    shutil.copyfile(archive, local_archive)
    local_archive.chmod(0o600)
    digest = hashlib.sha256(local_archive.read_bytes()).hexdigest()
    env = {**os.environ, "HOME": str(home), "NODE_OPTIONS": "", "NODE_PATH": ""}
    argv = [str(node), str(bootstrap), "--archive", str(local_archive),
            "--tag", tag, "--commit", "a"*40, "--sha256", digest,
            "--endpoint", "https://rc.example.org/"]
    result = subprocess.run(argv, env=env, stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            check=False, timeout=10)
    if result.returncode == 0 or (home / ".local").exists():
        raise SystemExit("Node bootstrap bypassed local terminal gate")
    master, slave = pty.openpty()
    proc = subprocess.Popen(argv, env=env, stdin=slave, stdout=slave, stderr=slave,
                            start_new_session=True, close_fds=True)
    os.close(slave)
    transcript = b""
    rejected = False
    try:
        deadline = time.monotonic()+16
        while time.monotonic()<deadline:
            ready,_,_ = select.select([master],[],[],0.1)
            if ready:
                try:
                    chunk = os.read(master,8192)
                except OSError:
                    break
                if not chunk:
                    break
                transcript += chunk
            if b"Choose [1-2]:" in transcript and not rejected:
                os.write(master,b"x\n")
                rejected = True
            if proc.poll() is not None:
                break
        if proc.poll() is None:
            proc.kill()
        if proc.wait(timeout=4)==0 or not rejected:
            raise SystemExit("Node bootstrap did not enforce owner mode selection")
    finally:
        os.close(master)
    private = home / ".local/share/mcp-workers/remote-control"
    if ((private / "v2-identity.pem").exists()
            or (private / "temporary/v2-identity.pem").exists()):
        raise SystemExit("Unapproved Node bootstrap created a device identity")
    return "node_bootstrap_real_pty_no_approval"


if len(sys.argv) != 4:
    raise SystemExit("usage: validate-local-archive.py <archive> <tag> <target>")
archive, tag, target = sys.argv[1:]
machine = {"x86_64": "linux-x64-glibc", "aarch64": "linux-arm64-glibc"}.get(platform.machine())
if not machine or machine != target:
    raise SystemExit("local native architecture does not match candidate target")

bootstrap = pathlib.Path(__file__).with_name("bootstrap-v2.py")
spec = importlib.util.spec_from_file_location("local_bootstrap", bootstrap)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
records = module.inspect_archive(archive, tag, target)
with tempfile.TemporaryDirectory(prefix="remote-agent-package-test-") as work:
    root = pathlib.Path(work)
    candidate = root / "candidate"
    module.unpack_verified(archive, candidate, records, tag, target)
    manifest = json.loads((candidate / "bundle.json").read_text("utf-8"))
    node = candidate / "bin/node"
    helper = candidate / "apps/remote-control-agent/.build/session-supervisor"
    script = candidate / "apps/remote-control-agent/src/v2-main.js"
    installer = candidate / "apps/remote-control-agent/scripts/install-v2.mjs"
    for argv in ([str(node), "--version"], [str(helper), "--probe"],
                 [str(node), "--check", str(script)],
                 [str(node), "--check", str(installer)]):
        proc = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=10, check=False,
                              start_new_session=True)
        if proc.returncode:
            raise SystemExit("unpublished bundle failed native runtime verification")
    onboarding = verify_refuses_unsafe_onboarding(node, installer, root)
    node_bootstrap = verify_node_bootstrap_offline(node, candidate / "apps/remote-control-agent/scripts/bootstrap-node.mjs", archive, tag, root)
    # Real bundled manager: status must work without Node/git/worker credentials,
    # and a headless interactive menu must refuse before pairing.
    import os
    home = root / "disposable-cli-home"
    home.mkdir(mode=0o700)
    programs = home / ".local/share/mcp-workers/remote-control/programs"
    programs.mkdir(parents=True, mode=0o700)
    for owned in (home / ".local/share/mcp-workers/remote-control", programs):
        owned.chmod(0o700)
    version = programs / (tag + "-" + target)
    module.unpack_verified(archive, version, records, tag, target)
    manager = version / "apps/remote-control-agent/scripts/manage-v2.mjs"
    shim = version / "apps/remote-control-agent/scripts/rca.sh"
    assert manager.stat().st_mode & 0o777 == 0o600
    assert shim.stat().st_mode & 0o777 == 0o700
    env = {**os.environ, "HOME": str(home)}
    status = subprocess.run([str(node), str(manager), "status"], env=env,
                            stdin=subprocess.DEVNULL, capture_output=True,
                            text=True, timeout=10)
    if status.returncode or '"cloud_authorization": "unconfirmed"' not in status.stdout:
        raise SystemExit("Packaged manager local status failed")
    help_out = subprocess.run([str(node), str(manager), "--help"], env=env,
                              stdin=subprocess.DEVNULL, capture_output=True,
                              text=True, timeout=10)
    version_out = subprocess.run([str(node), str(manager), "--version"], env=env,
                                 stdin=subprocess.DEVNULL, capture_output=True,
                                 text=True, timeout=10)
    if (help_out.returncode or "rca [status" not in help_out.stdout
            or version_out.returncode or version_out.stdout.strip() != tag):
        raise SystemExit("Packaged management help/version commands failed")
    menu = subprocess.run([str(node), str(manager)], env=env,
                          stdin=subprocess.DEVNULL, capture_output=True,
                          text=True, timeout=10)
    if menu.returncode == 0:
        raise SystemExit("Packaged manager menu accepted headless invocation")
    # A REAL target-local PTY must display the manager menu, report local-only
    # status on option 1, and exit cleanly on 6. No Worker or device identity.
    import pty
    import select
    import time
    master, slave = pty.openpty()
    proc = subprocess.Popen([str(node), str(manager)], env=env,
                            stdin=slave, stdout=slave, stderr=slave,
                            start_new_session=True, close_fds=True)
    os.close(slave)
    transcript = b""
    sent_status = False
    sent_exit = False
    try:
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            ready, _, _ = select.select([master], [], [], 0.1)
            if ready:
                try:
                    chunk = os.read(master, 8192)
                except OSError:
                    break
                if not chunk:
                    break
                transcript += chunk
            if b"Choose an option:" in transcript and not sent_status:
                os.write(master, b"1\n")
                sent_status = True
            if (sent_status and not sent_exit and
                    b"installed_versions" in transcript and
                    transcript.count(b"Choose an option:") >= 2):
                os.write(master, b"6\n")
                sent_exit = True
            if proc.poll() is not None:
                break
        if proc.poll() is None:
            proc.kill()
        if proc.wait(timeout=3) != 0 or not sent_exit or b"installed_versions" not in transcript:
            raise SystemExit("Packaged manager interactive PTY menu/status/exit failed")
    finally:
        os.close(master)
    menu = b"1. Status\r\n2. Pair / repair\r\n3. Logs\r\n4. Upgrade\r\n5. Uninstall\r\n6. Exit"
    if menu not in transcript:
        raise SystemExit("Packaged Node manager menu must show one option per line")
    # Uninstall is local-only: remove precisely the owned command; never erase
    # identity or historical SQLite receipts and never claim cloud revocation.
    bin_dir = home / ".local/bin"
    bin_dir.mkdir(mode=0o700)
    launcher = bin_dir / "rca"
    launcher.symlink_to(shim)
    shell_status = subprocess.run([str(launcher), "status"], env=env,
                                  stdin=subprocess.DEVNULL, capture_output=True,
                                  text=True, timeout=10)
    if shell_status.returncode or "installed_versions" not in shell_status.stdout:
        raise SystemExit("Bundled Node rca shim failed")
    base = home / ".local/share/mcp-workers/remote-control"
    identity = base / "v2-identity.pem"
    identity.write_text("test-only identity fixture", encoding="utf-8")
    identity.chmod(0o600)
    receipts = home / ".local/state/mcp-workers/remote-control-agent"
    receipts.mkdir(parents=True,mode=0o700)
    receipt = receipts / "operation-receipts.sqlite"
    receipt.write_bytes(b"test-only receipt fixture")
    uninstall_master, uninstall_slave = pty.openpty()
    removing = subprocess.Popen([str(node), str(manager), "uninstall"], env=env,
                                stdin=uninstall_slave, stdout=uninstall_slave,
                                stderr=uninstall_slave, start_new_session=True,
                                close_fds=True)
    os.close(uninstall_slave)
    transcript = b""
    confirmed = False
    try:
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            ready, _, _ = select.select([uninstall_master], [], [], 0.1)
            if ready:
                try:
                    chunk = os.read(uninstall_master, 8192)
                except OSError:
                    break
                if not chunk:
                    break
                transcript += chunk
            if b"Type UNINSTALL-V2 to confirm" in transcript and not confirmed:
                os.write(uninstall_master, b"UNINSTALL-V2\n")
                confirmed = True
            if removing.poll() is not None:
                break
        if removing.poll() is None:
            removing.kill()
        if (removing.wait(timeout=3) != 0 or not confirmed
                or b"NOT_PERFORMED" not in transcript):
            raise SystemExit("Packaged manager real-TTY uninstall failed closed")
    finally:
        os.close(uninstall_master)
    if (launcher.exists() or launcher.is_symlink() or version.exists()
            or identity.read_text("utf-8") != "test-only identity fixture"
            or receipt.read_bytes() != b"test-only receipt fixture"):
        raise SystemExit("Packaged manager uninstall safety/receipt preservation failed")
    print(json.dumps({"onboarding_gate": onboarding, "node_bootstrap": node_bootstrap, "kind": "UNPUBLISHED_SOURCE_CI_CANDIDATE",
                      "target": target, "node": manifest["node"],
                      "glibc_min": manifest["glibc_min"],
                      "archive_entries": len(records),
                      "native_probe": "passed",
                      "release_published": False}, sort_keys=True))
