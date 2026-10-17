#!/usr/bin/env python3
"""Pinned, public-GitHub-only bootstrap for the standalone v2 Agent.

Reviewed source MUST be fetched from an immutable commit URL, not 'main' or
'latest'. Python 3 stdlib is the initial bootstrap dependency; no local Node,
git, pnpm or compiler is required on the target host. This entrypoint is not
advertised until a real immutable Release is explicitly approved.
"""
import argparse
import fcntl
import hashlib
import json
import os
import pathlib
import platform
import re
import subprocess
import shutil
import ssl
import stat
import struct
import sys
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request

OWNER = "lirtual/remote-control-agent"
API = "https://api.github.com/repos/" + OWNER
APP = "apps/remote-control-agent"
MAX_ARCHIVE = 180 * 1024 * 1024
MAX_UNPACK = 240 * 1024 * 1024
MAX_FILES = 80
META_LIMIT = 1024 * 1024
ALLOWED_HOSTS = frozenset((
    "api.github.com", "github.com",
    "release-assets.githubusercontent.com", "objects.githubusercontent.com"
))
ALLOWED_DIRS = frozenset((
    "bin", "apps", APP, APP + "/src",
    APP + "/scripts", APP + "/.build"
))
ALLOWED_FILES = frozenset((
    "bin/node", "bundle.json", APP + "/package.json",
    APP + "/scripts/install-v2.mjs", APP + "/.build/session-supervisor",
))
EXEC_FILES = frozenset(("bin/node", APP + "/.build/session-supervisor"))
TAG = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9.-]+)?\Z")
SHA = re.compile(r"[0-9a-f]{40}\Z")
HASH = re.compile(r"sha256:([0-9a-f]{64})\Z")


def https_origin(url):
    parsed = urllib.parse.urlsplit(url)
    return (parsed.scheme == "https"
            and parsed.hostname in ALLOWED_HOSTS
            and not parsed.username and not parsed.password
            and not parsed.fragment and parsed.port in (None, 443))


class StrictRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not https_origin(newurl) or getattr(self, "hops", 0) >= 3:
            raise ValueError("Release redirect outside trusted HTTPS hosts or limit")
        self.hops = getattr(self, "hops", 0) + 1
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(url, accept="application/vnd.github+json", limit=META_LIMIT):
    if not https_origin(url):
        raise ValueError("Untrusted release URL")
    handler = StrictRedirects()
    client = urllib.request.build_opener(handler)
    headers = {
        "Accept": accept, "User-Agent": "mcp-workers-agent-bootstrap",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    req = urllib.request.Request(url, headers=headers)
    with client.open(req, timeout=25) as response:
        if response.status != 200:
            raise ValueError("GitHub metadata or release asset not available")
        if response.headers.get("Content-Length"):
            size = int(response.headers["Content-Length"])
            if size > limit:
                raise ValueError("Release response exceeds byte limit")
        parts = []
        total = 0
        while True:
            block = response.read(min(65536, limit + 1 - total))
            if not block:
                return b"".join(parts)
            total += len(block)
            if total > limit:
                raise ValueError("Release response exceeds byte limit")
            parts.append(block)


def json_api(path):
    return json.loads(fetch(API + path).decode("utf-8"))


def resolve_pinned(tag, commit, target):
    if not TAG.fullmatch(tag) or not SHA.fullmatch(commit) or target not in (
            "linux-x64-glibc", "linux-arm64-glibc"):
        raise ValueError("Pinned tag/commit/target missing or invalid")
    release = json_api("/releases/tags/" + tag)
    if (release.get("immutable") is not True
            or release.get("draft") is not False
            or release.get("tag_name") != tag
            or not isinstance(release.get("id"), int)):
        raise ValueError("This Release is not published and immutable")
    reference = json_api("/git/ref/tags/" + tag)
    if reference.get("ref") != "refs/tags/" + tag:
        raise ValueError("Git tag reference mismatch")
    obj = reference["object"]
    if obj.get("type") == "tag":
        if not SHA.fullmatch(str(obj.get("sha", ""))):
            raise ValueError("Invalid annotated Git tag")
        obj = json_api("/git/tags/" + obj["sha"])["object"]
    if obj.get("type") != "commit" or obj.get("sha") != commit:
        raise ValueError("Git Release tag does not match reviewed commit")
    name = "remote-control-agent-" + tag + "-" + target + ".tar.gz"
    assets = [a for a in release.get("assets", []) if a.get("name") == name]
    if len(assets) != 1:
        raise ValueError("Missing or duplicate Release asset")
    asset = assets[0]
    digest = HASH.fullmatch(str(asset.get("digest", "")))
    download = "https://github.com/" + OWNER + "/releases/download/" + tag + "/" + name
    if (not digest or asset.get("state") != "uploaded"
            or not isinstance(asset.get("id"), int) or asset["id"] < 1
            or not isinstance(asset.get("size"), int)
            or not 1024 <= asset["size"] <= MAX_ARCHIVE
            or asset.get("url") != API + "/releases/assets/" + str(asset["id"])
            or asset.get("browser_download_url") != download):
        raise ValueError("Release asset digest, ID, URL or length invalid")
    return {"download": download, "size": asset["size"], "digest": digest.group(1)}


def safe_member(name, directory):
    name = name[:-1] if directory and name.endswith("/") else name
    if (not name or len(name) > 160 or name.startswith("/")
            or "\\" in name or any(part in ("", ".", "..") for part in name.split("/"))
            or not re.fullmatch(r"[A-Za-z0-9._/-]+", name)):
        raise ValueError("Unsafe archive pathname")
    if directory:
        if name not in ALLOWED_DIRS:
            raise ValueError("Unexpected archive directory")
    elif name not in ALLOWED_FILES and not re.fullmatch(
            re.escape(APP) + r"/src/[a-z0-9-]+\.js", name):
        raise ValueError("Unexpected archive file")
    return name


def inspect_archive(archive, tag, target):
    records = []
    names = set()
    cumulative = 0
    with tarfile.open(archive, "r:gz") as tf:
        for member in tf:
            if len(records) >= MAX_FILES or (not member.isfile() and not member.isdir()):
                raise ValueError("Too many entries or archive link/special file")
            name = safe_member(member.name, member.isdir())
            if name in names or member.pax_headers:
                raise ValueError("Duplicate or extended archive metadata")
            names.add(name)
            if member.isfile():
                cumulative += member.size
                if member.size < 0 or cumulative > MAX_UNPACK:
                    raise ValueError("Oversized uncompressed archive")
            records.append((name, member))
        if not EXEC_FILES.issubset(names) or "bundle.json" not in names \
                or APP + "/src/v2-main.js" not in names \
                or APP + "/scripts/install-v2.mjs" not in names:
            raise ValueError("Incomplete Agent Release archive")
        manifest = json.load(tf.extractfile(tf.getmember("bundle.json")))
        if (manifest.get("artifact_schema") != 1 or manifest.get("name") != "remote-control-agent"
                or manifest.get("version") != tag or manifest.get("target") != target
                or not re.fullmatch(r"v24\.[0-9]+\.[0-9]+", str(manifest.get("node", "")))):
            raise ValueError("Bundle version, architecture, or runtime mismatch")
        # The official manifest is covered by the GitHub asset SHA-256.
        # Refuse ABI-incompatible binaries before unpacking OR executing Node.
        minimum = str(manifest.get("glibc_min", ""))
        if not re.fullmatch(r"[0-9]+\.[0-9]+", minimum):
            raise ValueError("Missing or invalid Release glibc ABI requirement")
        host_libc, host_version = platform.libc_ver()
        if (host_libc != "glibc" or not re.fullmatch(r"[0-9]+\.[0-9]+", host_version)
                or tuple(map(int, host_version.split("."))) <
                   tuple(map(int, minimum.split(".")))):
            raise ValueError("Release requires a newer glibc ABI; no execution attempted")
        machine = 62 if target.startswith("linux-x64-") else 183
        for binary in EXEC_FILES:
            b = tf.extractfile(tf.getmember(binary)).read(64)
            if (len(b) < 64 or b[:4] != b"\x7fELF" or b[4:6] != b"\x02\x01"
                    or struct.unpack_from("<H", b, 18)[0] != machine):
                raise ValueError("Prebuilt executable ELF architecture mismatch")
    return records


def private_dir(path):
    path = pathlib.Path(path)
    if path.is_symlink() or (path.exists() and (not path.is_dir()
            or path.stat().st_uid != os.getuid()
            or stat.S_IMODE(path.stat().st_mode) & 0o077)):
        raise ValueError("Unsafe installer-owned directory or symlink")
    if not path.exists():
        path.mkdir(mode=0o700)
    return path


def program_home(home):
    # Do not follow a symlink from HOME through a privilege-bearing directory.
    home = pathlib.Path(home)
    if not home.is_dir() or home.is_symlink() or home.stat().st_uid != os.getuid():
        raise ValueError("Invalid device HOME")
    node = home
    for name in (".local", "share"):
        node = node / name
        if node.is_symlink():
            raise ValueError("Symlink in installer parent path")
        if not node.exists():
            node.mkdir(mode=0o700)
        if not node.is_dir() or node.stat().st_uid != os.getuid():
            raise ValueError("Invalid installer parent ownership")
    for name in ("mcp-workers", "remote-control", "programs"):
        node = private_dir(node / name)
    return node


def unpack_verified(archive, destination, records, tag, target):
    if destination.exists() or destination.is_symlink():
        raise ValueError("This version is already installed: review before changing files")
    stage = pathlib.Path(tempfile.mkdtemp(prefix=".unverified-", dir=str(destination.parent)))
    try:
        os.chmod(stage, 0o700)
        with tarfile.open(archive, "r:gz") as tf:
            for name, member in records:
                output = stage / name
                if member.isdir():
                    output.mkdir(parents=True, exist_ok=True, mode=0o700)
                    continue
                output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                fd = os.open(output, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
                try:
                    with os.fdopen(fd, "wb") as stream:
                        reader = tf.extractfile(member)
                        remaining = member.size
                        while remaining:
                            data = reader.read(min(65536, remaining))
                            if not data:
                                raise ValueError("Truncated archive entry")
                            stream.write(data)
                            remaining -= len(data)
                        stream.flush()
                        os.fsync(stream.fileno())
                except Exception:
                    raise
                if name in EXEC_FILES:
                    output.chmod(0o700)
        # Under this private parent and exclusive flock, only the current user
        # can create destination; never replace it, even on a repeated run.
        if destination.exists() or destination.is_symlink():
            raise ValueError("Version became installed concurrently")
        stage.rename(destination)
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def verify_existing_program(archive, destination, records):
    """Rerun only if on-disk program matches the SAME officially verified asset.

    Local modification or a foreign file never causes silent replacement.
    All private identity and SQLite state stay outside this program directory.
    """
    root = pathlib.Path(destination)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("Existing program is not an owned directory")
    names = {name for name, _ in records}
    actual = {str(p.relative_to(root)) for p in root.rglob("*")}
    if actual != names:
        raise ValueError("Existing program has missing or unexpected files")
    with tarfile.open(archive, "r:gz") as tf:
        for name, member in records:
            item = root / name
            st = item.lstat()
            if st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) & 0o077:
                raise ValueError("Existing program has unsafe file permissions")
            if member.isdir():
                if not stat.S_ISDIR(st.st_mode):
                    raise ValueError("Existing program directory was replaced")
                continue
            if not stat.S_ISREG(st.st_mode) or st.st_size != member.size:
                raise ValueError("Existing executable or JS does not match the reviewed Release")
            with open(item, "rb") as installed:
                expected = tf.extractfile(member)
                remaining = member.size
                while remaining:
                    old = installed.read(min(65536, remaining))
                    new = expected.read(len(old))
                    if not old or old != new:
                        raise ValueError("Existing program modified since trusted Release")
                    remaining -= len(old)
    return True


def clean_orphaned_staging(parent):
    """Remove only known owner-private interrupted archives, never identity data."""
    for entry in pathlib.Path(parent).iterdir():
        if not entry.name.startswith((".unverified-", ".download-")):
            continue
        st = entry.lstat()
        if st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) & 0o077                 or not (stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode)):
            raise ValueError("Untrusted leftover staging file needs manual review")
        if stat.S_ISDIR(st.st_mode):
            shutil.rmtree(entry)
        else:
            entry.unlink()


def preflight(tag, commit, endpoint):
    if (sys.platform != "linux" or os.getuid() == 0
            or not sys.stdin.isatty() or not sys.stdout.isatty()):
        raise ValueError("Run as a non-root Linux user in a real interactive terminal")
    cpu = platform.machine().lower()
    if cpu not in ("x86_64", "aarch64"):
        raise ValueError("Only Linux x86_64 and ARM64 are supported")
    kernel = re.match(r"^([0-9]+)\.([0-9]+)", platform.release())
    if not kernel or (int(kernel[1]), int(kernel[2])) < (6, 9):
        raise ValueError("Linux kernel 6.9+ is needed for pidfd group safety")
    libc, ver = platform.libc_ver()
    if libc != "glibc" or not re.match(r"^\d+\.\d+$", ver) \
            or tuple(map(int, ver.split("."))) < (2, 28):
        raise ValueError("glibc 2.28+ required; musl is unsupported")
    uri = urllib.parse.urlsplit(endpoint)
    if (uri.scheme != "https" or not uri.hostname or uri.username or uri.password
            or uri.query or uri.fragment or uri.path not in ("", "/")):
        raise ValueError("Supply the reviewed HTTPS Worker origin, without credentials")
    if not TAG.fullmatch(tag) or not SHA.fullmatch(commit):
        raise ValueError("Pinned Release tag and commit are required")
    return "linux-" + ("x64" if cpu == "x86_64" else "arm64") + "-glibc"


def install(tag, commit, endpoint, name=None, upgrade=False):
    target = preflight(tag, commit, endpoint)
    location = program_home(os.path.expanduser("~"))
    version = location / (tag + "-" + target)
    # Existing lock + protected OS state: no new installer state database.
    with open(location / "install.lock", "a+b") as lock:
        os.chmod(location / "install.lock", 0o600)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError("Another v2 standalone installer is already running")
        clean_orphaned_staging(location)
        pinned = resolve_pinned(tag, commit, target)
        archive_path = None
        try:
            with tempfile.NamedTemporaryFile(prefix=".download-", dir=location, delete=False) as f:
                archive_path = pathlib.Path(f.name)
                os.chmod(archive_path, 0o600)
                data = fetch(pinned["download"], "application/octet-stream", MAX_ARCHIVE)
                if (len(data) != pinned["size"] or hashlib.sha256(data).hexdigest() != pinned["digest"]):
                    raise ValueError("Official GitHub SHA-256 or byte length mismatch")
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            records = inspect_archive(archive_path, tag, target)
            if version.exists() or version.is_symlink():
                verify_existing_program(archive_path, version, records)
            else:
                unpack_verified(archive_path, version, records, tag, target)
        finally:
            if archive_path is not None:
                archive_path.unlink(missing_ok=True)
        binary = version / "bin/node"
        command = [str(binary), str(version / APP / "scripts/install-v2.mjs"),
                   "--endpoint", endpoint]
        if name:
            command += ["--name", name]
        if upgrade:
            command += ["--upgrade"]
        print("Verified GitHub Release " + tag + " for " + target
              + ". Local permanent/temporary pairing requires independent MCP approval.",
              flush=True)
        # Only the cryptographically checked, safe-unpacked program runs.
        os.execv(str(binary), command)


UNIT = "remote-control-v2-agent.service"
MARKER = "# Managed by mcp-workers v2 Linux installer; NOT the v1 Agent."
STORE = pathlib.Path(".local/share/mcp-workers/remote-control")


def local_inventory(home):
    home = pathlib.Path(home)
    if home.is_symlink() or not home.is_dir() or home.stat().st_uid != os.getuid():
        raise ValueError("Untrusted account home")
    base = home / STORE
    # Never follow a link in any trusted uninstall root component.
    for relative in (".local", ".local/share", ".local/share/mcp-workers",
                     str(STORE), str(STORE / "programs"),
                     ".config", ".config/systemd", ".config/systemd/user"):
        item = home / relative
        if item.is_symlink() or (item.exists() and
                (not item.is_dir() or item.stat().st_uid != os.getuid())):
            raise ValueError("Linked or unowned path in v2 install tree")
    programs = base / "programs"
    unit_file = home / ".config/systemd/user" / UNIT
    if programs.is_symlink() or unit_file.is_symlink():
        raise ValueError("Untrusted v2 installation symlink")
    versions = []
    if programs.exists():
        if not programs.is_dir() or programs.stat().st_uid != os.getuid():
            raise ValueError("Untrusted program directory")
        for p in programs.iterdir():
            if p.name == "install.lock" or p.name.startswith((".download-", ".unverified-")):
                continue
            if not re.fullmatch(r"v\d+\.\d+\.\d+(?:-[a-z0-9.-]+)?-linux-(?:x64|arm64)-glibc", p.name) \
                    or p.is_symlink() or not p.is_dir() or p.stat().st_uid != os.getuid():
                raise ValueError("Unknown version entry: do not remove")
            versions.append(p)
    unit = None
    if unit_file.exists():
        if unit_file.stat().st_uid != os.getuid() or not unit_file.is_file():
            raise ValueError("Unowned v2 user service")
        unit = unit_file.read_text("utf8")
        if not unit.startswith(MARKER + "\n"):
            raise ValueError("Foreign user service; do not remove")
    ids = {}
    for mode, relative in (("permanent", "v2-identity.pem"),
                           ("temporary", "temporary/v2-identity.pem")):
        f = pathlib.Path(str(base / relative) + ".device-id")
        if f.is_symlink():
            raise ValueError("Linked identity ID")
        if f.exists():
            st = f.stat()
            if not f.is_file() or st.st_uid != os.getuid() or st.st_mode & 0o077:
                raise ValueError("Unsafe identity metadata")
            value = f.read_text("utf8").strip()
            if not re.fullmatch(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", value):
                raise ValueError("Invalid device ID")
            ids[mode] = value
    return programs, versions, unit_file, unit, ids


def local_status(home):
    programs, versions, unit_file, unit, ids = local_inventory(home)
    service = "not_installed"
    if unit:
        result = subprocess.run(["systemctl", "--user", "is-active", "--quiet", UNIT],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                timeout=5, check=False)
        service = "active" if result.returncode == 0 else "inactive_or_unconfirmed"
    return {"installed_versions": sorted(x.name for x in versions),
            "local_permanent_service": service, "device_ids": ids,
            "cloud_authorization": "unconfirmed", "signed_wss": "unconfirmed",
            "read_only_access": "unconfirmed", "cloud_revoke": "not_performed",
            "temporary_expires_at": "server_authoritative_unconfirmed",
            "sqlite_receipts": "preserved"}


def validated_owned_version(p):
    f = p / "bundle.json"
    source = p / APP / "src/v2-main.js"
    if f.is_symlink() or source.is_symlink() or not f.is_file() or not source.is_file():
        raise ValueError("Missing/linked runtime manifest")
    manifest = json.loads(f.read_text("utf8"))
    if (manifest.get("artifact_schema") != 1 or manifest.get("device_protocol") != 2
            or manifest.get("receipt_schema") != 1
            or manifest.get("upgrade_profile") != "read-only-no-shell-v1"
            or p.name != manifest.get("version") + "-" + manifest.get("target")
            or not re.search(r"readOnly:\s*true,\s*writeFile:\s*false,\s*shell:\s*false,",
                             source.read_text("utf8"))):
        raise ValueError("Unverified or Shell-enabled Agent; cannot uninstall")
    for parent, dirs, files in os.walk(p, followlinks=False):
        for name in dirs + files:
            file = pathlib.Path(parent) / name
            st = file.lstat()
            if st.st_uid != os.getuid() or st.st_mode & 0o077 or not (
                    stat.S_ISDIR(st.st_mode) or stat.S_ISREG(st.st_mode)):
                raise ValueError("Untrusted file in v2 program")
    return True


def owned_unit_root(unit, versions):
    if not unit:
        return None
    lines = unit.splitlines()
    cwd = [line.partition("=")[2] for line in lines if line.startswith("WorkingDirectory=")]
    start = [line.partition("=")[2] for line in lines if line.startswith("ExecStart=")]
    if len(cwd) != 1 or len(start) != 1:
        raise ValueError("Ambiguous v2 user service")
    root = pathlib.Path(cwd[0]).parent.parent
    if root not in versions or start[0] != (
            str(root / "bin/node") + " " + str(root / APP / "src/v2-main.js")):
        raise ValueError("Current v2 service does not belong to standalone installer")
    return root


def no_running_programs(versions, proc_root=pathlib.Path("/proc")):
    """Fail closed on owned processes even when argv hides the executable.

    The local v2 unit is stopped before uninstall. A manually started Agent
    may still have its /proc/PID/exe or cwd within an installed version,
    regardless of how its command line was changed.
    """
    if not versions:
        return True
    prefixes = tuple(os.fsencode(str(v) + "/") for v in versions)
    for p in proc_root.iterdir():
        if not p.name.isdigit() or int(p.name) == os.getpid():
            continue
        try:
            if p.stat().st_uid != os.getuid():
                continue
            status = (p / "status").read_text("ascii")
            if re.search(r"^State:\s*Z\b", status, re.MULTILINE):
                continue  # Exited zombie is not a running Agent.
            argv = (p / "cmdline").read_bytes().split(b"\0")
            if any(arg.startswith(prefix) for arg in argv for prefix in prefixes):
                return False
            for link in ("exe", "cwd"):
                resolved = os.fsencode(os.readlink(p / link))
                if any(resolved.startswith(prefix) for prefix in prefixes):
                    return False
        except (FileNotFoundError, ProcessLookupError):
            if p.exists():
                return False  # Process remains but its executable state vanished.
            continue  # Process exited during inspection.
        except OSError:
            return False  # Can't establish process ownership/state.
    return True


def local_uninstall(home, confirm, systemctl=None, process_check=no_running_programs):
    if os.getuid() == 0 or not confirm:
        raise ValueError("Owner-only explicit local uninstall required")
    programs, versions, unit_file, unit, ids = local_inventory(home)
    owned = owned_unit_root(unit, versions)
    for version in versions:
        validated_owned_version(version)
    # For an owned permanent user service, its explicit stop is required first;
    # refuse cleanup if any Agent remains after stopping it.
    if owned is None and not process_check(versions):
        raise ValueError("Active or uncertain v2 process; do not delete")
    if owned is not None:
        if systemctl is None:
            raise ValueError("Cannot stop owned service")
        systemctl(["--user", "disable", "--now", UNIT])
        if not process_check(versions):
            raise ValueError("v2 Agent still active after service stop")
        unit_file.unlink()
        systemctl(["--user", "daemon-reload"])
    for version in versions:
        shutil.rmtree(version)
    return {"removed_versions": [v.name for v in versions],
            "removed_owned_v2_service": owned is not None,
            "preserved_device_ids": ids, "preserved_keys_and_sqlite": True,
            "cloud_revocation": "NOT_PERFORMED"}


def local_identity_purge_plan(home):
    """Review exact v2 identity files; NEVER remove shared SQLite receipts."""
    programs, versions, unit_file, unit, ids = local_inventory(home)
    if versions or unit or unit_file.is_symlink():
        raise ValueError("Uninstall installer-owned v2 software before purging identity")
    base = pathlib.Path(home) / STORE
    if base.is_symlink():
        raise ValueError("Linked v2 identity directory")
    if not base.exists():
        return [], ids
    info = base.stat()
    if not base.is_dir() or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise ValueError("Untrusted v2 identity directory")
    for relative in ("temporary",):
        directory = base / relative
        if directory.is_symlink() or (directory.exists() and (
                not directory.is_dir() or directory.stat().st_uid != os.getuid()
                or stat.S_IMODE(directory.stat().st_mode) & 0o077)):
            raise ValueError("Unsafe v2 identity subdirectory")
    # A re-pair transaction or archived key requires deliberate operator
    # reconciliation. Never discard old or pending evidence implicitly.
    for item in base.iterdir():
        if item.name.startswith("revoked-") or item.name.endswith(
                (".re-pair-new", ".re-pair-transition", ".re-pair-new.device-id")):
            raise ValueError("Unresolved v2 re-pair/archive state; purge blocked")
    files = []
    for relative in ("v2-identity.pem", "v2-identity.pem.device-id",
                     "temporary/v2-identity.pem",
                     "temporary/v2-identity.pem.device-id"):
        file = base / relative
        if file.is_symlink():
            raise ValueError("Linked identity file; purge blocked")
        if not file.exists():
            continue
        info = file.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600):
            raise ValueError("Untrusted v2 identity file; purge blocked")
        files.append(file)
    return files, ids


def local_identity_purge(home, confirm, process_check=None):
    if os.getuid() == 0 or not confirm:
        raise ValueError("Non-root explicit v2 identity purge confirmation required")
    files, ids = local_identity_purge_plan(home)
    if process_check is None:
        process_check = no_live_v2_identity_processes
    if not process_check():
        raise ValueError("Active or uncertain v2 pairing/Agent process; purge blocked")
    for file in files:
        file.unlink()
    return {"removed_identity_paths": [str(f) for f in files],
            "preserved_sqlite_receipts": True, "cloud_revocation": "NOT_PERFORMED",
            "previous_device_ids": ids}


def no_live_v2_identity_processes(proc_root=pathlib.Path("/proc")):
    # No portable way to certify no copied key is in use. Refuse known local
    # CLI or Agent processes, including an active temporary foreground v2.
    for process in proc_root.iterdir():
        if not process.name.isdigit() or int(process.name) == os.getpid():
            continue
        try:
            if process.stat().st_uid != os.getuid():
                continue
            argv = (process / "cmdline").read_bytes()
            if (b"/remote-control-agent/src/v2-main." in argv
                    or b"/remote-control-agent/scripts/install-v2.mjs" in argv
                    or b"/remote-control-agent/src/pair-device." in argv):
                return False
        except (FileNotFoundError, ProcessLookupError):
            if process.exists():
                return False
        except OSError:
            return False
    return True


def systemctl_user(args):
    result = subprocess.run(["systemctl"] + args, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, timeout=15, check=False)
    if result.returncode:
        raise ValueError("Owned v2 systemd user service action failed")


def main():
    parser = argparse.ArgumentParser(description="Verified Remote Control v2 GitHub Release bootstrap")
    parser.add_argument("--tag")
    parser.add_argument("--commit")
    parser.add_argument("--endpoint")
    actions=parser.add_mutually_exclusive_group()
    actions.add_argument("--status", action="store_true")
    actions.add_argument("--uninstall", action="store_true")
    actions.add_argument("--purge-local-identity", action="store_true",
                         help="separate explicit v2 key/ID purge after uninstall; shared SQLite retained")
    parser.add_argument("--name")
    parser.add_argument("--upgrade", action="store_true", help="manual owned v2 program upgrade only")
    args = parser.parse_args()
    try:
        if args.status:
            print(json.dumps(local_status(os.path.expanduser("~")), indent=2))
        elif args.uninstall:
            if os.getuid() == 0 or not (sys.stdin.isatty() and sys.stdout.isatty()):
                raise ValueError("Local uninstall requires a non-root interactive terminal")
            _, versions, _, _, ids = local_inventory(os.path.expanduser("~"))
            print("Owned local v2 versions:", ", ".join(v.name for v in versions))
            print("Device IDs (cloud grants will NOT be revoked):", ids)
            print("Private keys and SQLite receipts will be retained; use MCP revoke_device separately.")
            if input("Type UNINSTALL-V2 to confirm local removal: ").strip() != "UNINSTALL-V2":
                raise ValueError("Local uninstall not confirmed")
            print(json.dumps(local_uninstall(os.path.expanduser("~"), True, systemctl_user), indent=2))
        elif args.purge_local_identity:
            if os.getuid() == 0 or not (sys.stdin.isatty() and sys.stdout.isatty()):
                raise ValueError("Local identity purge requires a non-root interactive terminal")
            home = os.path.expanduser("~")
            local_inventory(home)  # Reject unowned path components before opening lock.
            base = pathlib.Path(home) / STORE
            if not base.is_dir() or base.is_symlink() or base.stat().st_uid != os.getuid() \
                    or stat.S_IMODE(base.stat().st_mode) & 0o077:
                raise ValueError("No safe v2 identity directory to purge")
            # Existing v2 installer flock: avoid racing local pairing or re-pair.
            fd = os.open(base / "v2-installer.lock",
                         os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "r+b") as lock:
                info = os.fstat(lock.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() \
                        or stat.S_IMODE(info.st_mode) != 0o600:
                    raise ValueError("Untrusted v2 installer lock")
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise ValueError("Another v2 installer is running")
                files, ids = local_identity_purge_plan(home)
                print("Exact v2-only identity files:", *(str(f) for f in files),
                      sep="\\n  ")
                print("Device IDs:", ids)
                print("Cloud authorization has NOT been revoked. In authenticated MCP,",
                      "call revoke_device separately BEFORE discarding the local key.")
                print("SQLite receipts and historical/local operation evidence are",
                      "shared and WILL NOT be deleted. Already executed effects persist.")
                if input("Type PURGE-V2-IDENTITY to irreversibly remove only the listed keys/IDs: "
                         ).strip() != "PURGE-V2-IDENTITY":
                    raise ValueError("Local identity purge not confirmed")
                print(json.dumps(local_identity_purge(home, True), indent=2))
        else:
            if not args.tag or not args.commit or not args.endpoint:
                raise ValueError("Pinned --tag, --commit, and --endpoint are required")
            install(args.tag, args.commit, args.endpoint, args.name, args.upgrade)
    except ValueError as exc:
        # Only messages from explicitly authored validation branches.
        print("Standalone v2 install refused: " + str(exc), file=sys.stderr)
        return 1
    except (OSError, KeyError, json.JSONDecodeError, tarfile.TarError,
            urllib.error.URLError):
        # Network errors may include signed GitHub redirect URLs; never log them.
        print("Standalone v2 install refused: release network, filesystem or archive error.",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
