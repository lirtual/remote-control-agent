#!/bin/sh
# Portable rca entry, executed from the installer-owned versioned release.
# Uses the verified bundled Node 24, never the host's node or Python.
set -eu
resolved=$(readlink -f -- "$0") || exit 1
root=$(dirname -- "$(dirname -- "$(dirname -- "$(dirname -- "$resolved")")")")
case "$root" in
  "$HOME"/.local/share/mcp-workers/remote-control/programs/v*-linux-*-glibc)
    ;;
  *)
    echo "rca: untrusted installed program path" >&2
    exit 1
    ;;
esac
test -x "$root/bin/node" || exit 1
test -r "$root/apps/remote-control-agent/scripts/manage-v2.mjs" || exit 1
unset NODE_OPTIONS NODE_PATH
exec "$root/bin/node" "$root/apps/remote-control-agent/scripts/manage-v2.mjs" "$@"
