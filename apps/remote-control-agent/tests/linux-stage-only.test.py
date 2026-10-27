"""Issue #39: isolated immutable Linux one-shot staging checks.

No Github request, systemd command, Service mutation, device or release is used.
"""
import contextlib
import hashlib
import importlib.util
import io
import json
import pathlib
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

SOURCE = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "bootstrap-v2.py"
SPEC = importlib.util.spec_from_file_location("rca_bootstrap_v2_stage", SOURCE)
bootstrap = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bootstrap)
TAG = "v0.1.33"
COMMIT = "a" * 40
ENDPOINT = "https://rca.example.org/"
TARGET = "linux-x64-glibc"


def archive_bytes(protocol="owner-one-shot-v1"):
    raw = json.dumps({
        "name": "remote-control-agent", "version": TAG, "target": TARGET,
        "upgrade_profile": "paired-full-v1", "upgrade_protocol": protocol,
        "device_protocol": 2, "receipt_schema": 1,
    }).encode("utf8")
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        item = tarfile.TarInfo("bundle.json")
        item.size = len(raw)
        tar.addfile(item, io.BytesIO(raw))
    return buf.getvalue()


class LinuxStageOnly(unittest.TestCase):
    def stage(self, data, expected=None):
        digest = hashlib.sha256(data).hexdigest()
        with tempfile.TemporaryDirectory() as folder, contextlib.redirect_stdout(io.StringIO()):
            with (mock.patch.object(bootstrap, "preflight", return_value=TARGET),
                  mock.patch.object(bootstrap, "program_home", return_value=pathlib.Path(folder)),
                  mock.patch.object(bootstrap, "resolve_pinned", return_value={
                      "download": "https://github.com/test/release.tar.gz",
                      "size": len(data), "digest": digest,
                  }),
                  mock.patch.object(bootstrap, "fetch", return_value=data) as download,
                  mock.patch.object(bootstrap, "inspect_archive", return_value=[]) as inspect,
                  mock.patch.object(bootstrap, "unpack_verified") as unpack,
                  mock.patch.object(bootstrap.os, "execv", side_effect=AssertionError("No Agent launch"))):
                bootstrap.install(TAG, COMMIT, ENDPOINT, stage_only=True,
                                  asset_sha256=expected if expected is not None else digest)
                download.assert_called_once()
                inspect.assert_called_once()
                unpack.assert_called_once()
                staged_path = unpack.call_args.args[1]
                self.assertEqual(staged_path.name, TAG + "-" + TARGET)

    def test_only_stage_only_bypasses_tty_not_non_root_or_runtime_safety(self):
        with (mock.patch.object(bootstrap.sys, "platform", "linux"),
              mock.patch.object(bootstrap.os, "getuid", return_value=1001),
              mock.patch.object(bootstrap.sys, "stdin", mock.Mock(isatty=lambda: False)),
              mock.patch.object(bootstrap.sys, "stdout", mock.Mock(isatty=lambda: False)),
              mock.patch.object(bootstrap.platform, "machine", return_value="x86_64"),
              mock.patch.object(bootstrap.platform, "release", return_value="6.9.0"),
              mock.patch.object(bootstrap.platform, "libc_ver", return_value=("glibc", "2.39"))):
            self.assertEqual(bootstrap.preflight(TAG, COMMIT, ENDPOINT, stage_only=True), TARGET)
            with self.assertRaisesRegex(ValueError, "real interactive terminal"):
                bootstrap.preflight(TAG, COMMIT, ENDPOINT, stage_only=False)
            with mock.patch.object(bootstrap.os, "getuid", return_value=0):
                with self.assertRaisesRegex(ValueError, "non-root"):
                    bootstrap.preflight(TAG, COMMIT, ENDPOINT, stage_only=True)
            with mock.patch.object(bootstrap.platform, "libc_ver", return_value=("glibc", "2.27")):
                with self.assertRaisesRegex(ValueError, "glibc 2.28"):
                    bootstrap.preflight(TAG, COMMIT, ENDPOINT, stage_only=True)

    def test_reviewed_sha_and_protocol_stage_without_install(self):
        self.stage(archive_bytes())

    def test_wrong_independent_pin_never_downloads_or_modifies_program(self):
        data = archive_bytes()
        digest = hashlib.sha256(data).hexdigest()
        with tempfile.TemporaryDirectory() as folder:
            with (mock.patch.object(bootstrap, "preflight", return_value=TARGET),
                  mock.patch.object(bootstrap, "program_home", return_value=pathlib.Path(folder)),
                  mock.patch.object(bootstrap, "resolve_pinned", return_value={
                      "download": "https://github.com/test/release.tar.gz",
                      "size": len(data), "digest": digest,
                  }),
                  mock.patch.object(bootstrap, "fetch") as download,
                  mock.patch.object(bootstrap, "unpack_verified") as unpack,
                  contextlib.redirect_stdout(io.StringIO())):
                with self.assertRaisesRegex(ValueError, "Reviewed SHA-256"):
                    bootstrap.install(TAG, COMMIT, ENDPOINT, stage_only=True,
                                      asset_sha256="f" * 64)
                download.assert_not_called()
                unpack.assert_not_called()

    def test_missing_protocol_blocks_stage_before_extraction(self):
        data = archive_bytes(protocol=None)
        with self.assertRaisesRegex(ValueError, "lacks reviewed protocol"):
            self.stage(data)

    def test_non_stage_call_refuses_sha_and_stage_refuses_install_options(self):
        for overrides in [
            {"stage_only": True, "asset_sha256": None},
            {"stage_only": True, "asset_sha256": "F" * 64},
            {"stage_only": True, "asset_sha256": "a" * 64, "upgrade": True},
            {"stage_only": True, "asset_sha256": "a" * 64, "name": "wrong"},
            {"stage_only": False, "asset_sha256": "a" * 64},
        ]:
            with mock.patch.object(bootstrap, "preflight") as preflight:
                with self.assertRaisesRegex(ValueError, "Stage-only|stage-only"):
                    bootstrap.install(TAG, COMMIT, ENDPOINT, **overrides)
                preflight.assert_not_called()


if __name__ == "__main__":
    unittest.main()
