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
            if b"Choose 1 = Permanent (systemd); 2 = Temporary (24h):" in transcript and not challenged:
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
    # Real bundled manager: status must work without Node/git/worker credentials,
    # and a headless interactive menu must refuse before pairing.
    import os
    home = root / "disposable-cli-home"
    home.mkdir(mode=0o700)
    programs = home / ".local/share/mcp-workers/remote-control/programs"
    programs.mkdir(parents=True, mode=0o700)
    version = programs / (tag + "-" + target)
    module.unpack_verified(archive, version, records, tag, target)
    manager = version / "apps/remote-control-agent/scripts/manage-v2.py"
    assert manager.stat().st_mode & 0o777 == 0o700
    env = {**os.environ, "HOME": str(home)}
    status = subprocess.run(["python3", "-B", str(manager), "status"], env=env,
                            stdin=subprocess.DEVNULL, capture_output=True,
                            text=True, timeout=10)
    if status.returncode or '"cloud_authorization": "unconfirmed"' not in status.stdout:
        raise SystemExit("Packaged manager local status failed")
    help_out = subprocess.run(["python3", "-B", str(manager), "--help"], env=env,
                              stdin=subprocess.DEVNULL, capture_output=True,
                              text=True, timeout=10)
    version_out = subprocess.run(["python3", "-B", str(manager), "--version"], env=env,
                                 stdin=subprocess.DEVNULL, capture_output=True,
                                 text=True, timeout=10)
    if (help_out.returncode or "Usage: rca" not in help_out.stdout
            or version_out.returncode or version_out.stdout.strip() != tag):
        raise SystemExit("Packaged management help/version commands failed")
    menu = subprocess.run(["python3", "-B", str(manager)], env=env,
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
    proc = subprocess.Popen(["python3", "-B", str(manager)], env=env,
                            stdin=slave, stdout=slave, stderr=slave,
                            start_new_session=True, close_fds=True)
    os.close(slave)
    transcript = b""
    sent = False
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
            if b"Choose an option:" in transcript and not sent:
                os.write(master, b"1\n6\n")
                sent = True
            if proc.poll() is not None:
                break
        if proc.poll() is None:
            proc.kill()
        if proc.wait(timeout=3) != 0 or not sent or b"installed_versions" not in transcript:
            raise SystemExit("Packaged manager interactive PTY menu/status/exit failed")
    finally:
        os.close(master)
    # Uninstall is local-only: remove precisely the owned command; never erase
    # identity or historical SQLite receipts and never claim cloud revocation.
    bin_dir = home / ".local/bin"
    bin_dir.mkdir(mode=0o700)
    launcher = bin_dir / "rca"
    launcher.symlink_to(manager)
    base = home / ".local/share/mcp-workers/remote-control"
    identity = base / "v2-identity.pem"
    identity.write_text("test-only identity fixture", encoding="utf-8")
    identity.chmod(0o600)
    receipts = home / ".local/state/mcp-workers/remote-control-agent"
    receipts.mkdir(parents=True,mode=0o700)
    receipt = receipts / "operation-receipts.sqlite"
    receipt.write_bytes(b"test-only receipt fixture")
    removed = module.local_uninstall(str(home), True,
                                     process_check=lambda unused: True)
    if (launcher.exists() or launcher.is_symlink() or version.exists()
            or identity.read_text("utf-8") != "test-only identity fixture"
            or receipt.read_bytes() != b"test-only receipt fixture"
            or removed["cloud_revocation"] != "NOT_PERFORMED"):
        raise SystemExit("Packaged manager uninstall safety/receipt preservation failed")
    print(json.dumps({"onboarding_gate": onboarding, "kind": "UNPUBLISHED_SOURCE_CI_CANDIDATE",
                      "target": target, "node": manifest["node"],
                      "glibc_min": manifest["glibc_min"],
                      "archive_entries": len(records),
                      "native_probe": "passed",
                      "release_published": False}, sort_keys=True))
