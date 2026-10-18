#!/bin/sh
# Minimal immutable GitHub prerelease bootstrap. No sudo, checkout or local Node.
# Only runnable after an independently approved/public v0.1.1 Release.
set -eu
printf '%s\n' '==> Installing Remote Control Agent (immutable GitHub Release)'
[ "$(id -u)" != "0" ] || { echo 'Refusing root installation' >&2; exit 1; }
[ -t 1 ] && [ -r /dev/tty ] || {
  echo 'Run from an interactive non-root Linux terminal' >&2; exit 1
}
command -v python3 >/dev/null 2>&1 || {
  echo 'Python 3 is required for the initial bootstrap' >&2; exit 1
}
if [ -z "${REMOTE_CONTROL_AGENT_ENDPOINT:-}" ]; then
  printf 'Approved Worker HTTPS origin: ' > /dev/tty
  IFS= read -r REMOTE_CONTROL_AGENT_ENDPOINT < /dev/tty || exit 1
fi
export REMOTE_CONTROL_AGENT_ENDPOINT
python3 - <<'PY'
import json
import os
import re
import sys
import urllib.request

OWNER = "lirtual/remote-control-agent"
API = "https://api.github.com/repos/" + OWNER
TAG = "v0.1.1"

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("Unexpected bootstrap source redirect")

opener = urllib.request.build_opener(NoRedirect())

def get(url, limit=1048576):
    if not (url.startswith(API + "/") or
            url.startswith("https://raw.githubusercontent.com/" + OWNER + "/")):
        raise ValueError("Unexpected download host")
    req = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "remote-control-agent-pinned-install"
    })
    with opener.open(req, timeout=25) as response:
        if response.status != 200:
            raise ValueError("GitHub bootstrap source not available")
        data = response.read(limit+1)
        if len(data) > limit:
            raise ValueError("GitHub metadata or bootstrap too large")
        return data

try:
    print("==> Resolving published immutable " + TAG, flush=True)
    release = json.loads(get(API + "/releases/tags/" + TAG))
    if (release.get("immutable") is not True or release.get("draft") is not False
            or release.get("tag_name") != TAG):
        raise ValueError("Release is not published and immutable")
    ref = json.loads(get(API + "/git/ref/tags/" + TAG))
    if ref.get("ref") != "refs/tags/" + TAG:
        raise ValueError("Unexpected tag reference")
    pointer = ref["object"]
    if pointer["type"] == "tag":
        if not re.fullmatch(r"[a-f0-9]{40}", str(pointer.get("sha"))):
            raise ValueError("Invalid annotated tag object")
        pointer = json.loads(get(API + "/git/tags/" + pointer["sha"]))["object"]
    sha = pointer.get("sha")
    if pointer.get("type") != "commit" or not re.fullmatch(r"[a-f0-9]{40}", str(sha)):
        raise ValueError("Git Release does not resolve to one commit")
    url = ("https://raw.githubusercontent.com/" + OWNER + "/" + sha
           + "/apps/remote-control-agent/scripts/bootstrap-v2.py")
    script = get(url, 250000)
    print("==> Pinned source commit " + sha[:12], flush=True)
    with open("/dev/tty", "r") as terminal:
        os.dup2(terminal.fileno(), 0)
    sys.stdin = open(0, "r", closefd=False)
    sys.argv = ["bootstrap-v2.py", "--tag", TAG, "--commit", sha,
                "--endpoint", os.environ["REMOTE_CONTROL_AGENT_ENDPOINT"]]
    exec(compile(script, url, "exec"),
         {"__name__": "__main__", "__file__": url})
except (OSError, ValueError, KeyError, urllib.error.URLError, json.JSONDecodeError):
    print("Install refused: pinned public GitHub Release or terminal verification failed.",
          file=sys.stderr)
    sys.exit(1)
PY
