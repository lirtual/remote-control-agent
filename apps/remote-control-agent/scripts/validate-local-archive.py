#!/usr/bin/env python3
"""Verify an UNPUBLISHED native candidate; no network, enrollment, or Release upload."""
import importlib.util
import json
import pathlib
import platform
import subprocess
import sys
import tempfile

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
    print(json.dumps({"kind": "UNPUBLISHED_SOURCE_CI_CANDIDATE",
                      "target": target, "node": manifest["node"],
                      "glibc_min": manifest["glibc_min"],
                      "archive_entries": len(records),
                      "native_probe": "passed",
                      "release_published": False}, sort_keys=True))
