#!/bin/sh
# #660 reviewed local-only offline candidate. NOT a published installer.
# Verify the exact reviewed archive BEFORE executing its bundled Node.
set -eu
umask 077
if [ "$(uname -s)" != Darwin ] || [ "$(uname -m)" != arm64 ]; then
  echo 'Native macOS ARM64 required.' >&2; exit 1
fi
major="$(sw_vers -productVersion | cut -d. -f1)"
case "$major" in ''|*[!0-9]*) exit 1;; esac
if [ "$major" -lt 15 ] || [ "$(id -u)" -eq 0 ]; then
  echo 'macOS 15+ under a non-root login required.' >&2; exit 1
fi
[ -t 0 ] && [ -t 1 ] || { echo 'Real owner terminal required.' >&2; exit 1; }
[ "$#" -eq 9 ] || { echo 'Usage: sh macos-local.sh install|upgrade --archive ABS --sha256 SHA256 --source-sha COMMIT --endpoint HTTPS_ROOT' >&2; exit 1; }
action="$1"; shift
case "$action" in install|upgrade) ;; *) exit 1;; esac
[ "$1" = '--archive' ] && [ "$3" = '--sha256' ] && [ "$5" = '--source-sha' ] && [ "$7" = '--endpoint' ] || exit 1
archive="$2"; digest="$4"; source="$6"; endpoint="$8"
case "$archive" in /*) ;; *) exit 1;; esac
case "$digest" in *[!a-f0-9]*|'') exit 1;; esac
case "$source" in *[!a-f0-9]*|'') exit 1;; esac
[ "${#digest}" -eq 64 ] && [ "${#source}" -eq 40 ] || exit 1
[ -f "$archive" ] && [ ! -L "$archive" ] || exit 1
actual="$(shasum -a 256 "$archive" | awk '{print $1}')"
[ "$actual" = "$digest" ] || { echo 'Pinned archive SHA-256 mismatch.' >&2; exit 1; }
tmp="$(mktemp -d "${TMPDIR:-/tmp}/rca-local.XXXXXXXX")"
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
# Explicit USTAR allowlist: no traversals, links, devices, or unknown executables.
members="$tmp/members"; types="$tmp/types"
tar -tzf "$archive" > "$members"
tar -tvzf "$archive" > "$types"
awk '
  /(^\/|(^|\/)\.\.?($|\/)|[^A-Za-z0-9._\/-])/ {bad=1}
  !($0 ~ /^bin\/?$/ || $0=="bin/node" ||
    $0 ~ /^apps\/?$/ || $0 ~ /^apps\/remote-control-agent\/?$/ ||
    $0 ~ /^apps\/remote-control-agent\/src\/?$/ ||
    $0 ~ /^apps\/remote-control-agent\/src\/[a-z0-9-]+\.js$/ ||
    $0 ~ /^apps\/remote-control-agent\/scripts\/?$/ ||
    $0=="apps/remote-control-agent/scripts/macos-local.mjs" ||
    $0 ~ /^apps\/remote-control-agent\/\.build\/?$/ ||
    $0=="apps/remote-control-agent/.build/darwin-session-supervisor" ||
    $0=="apps/remote-control-agent/package.json" || $0=="bundle.json") {bad=1}
  END {exit bad}
' "$members" || { echo 'Untrusted archive member.' >&2; exit 1; }
[ "$(sort "$members" | uniq -d | wc -l | tr -d ' ')" -eq 0 ] || exit 1
awk '{if (substr($1,1,1)!="-" && substr($1,1,1)!="d")exit 1}' "$types" || exit 1
mkdir "$tmp/unpacked"; chmod 700 "$tmp/unpacked"
tar -xzf "$archive" -C "$tmp/unpacked"
node="$tmp/unpacked/bin/node"
manager="$tmp/unpacked/apps/remote-control-agent/scripts/macos-local.mjs"
[ -x "$node" ] && [ -f "$manager" ] && [ ! -L "$node" ] || exit 1
"$node" "$manager" "$action" --bundle "$tmp/unpacked" --source-sha "$source" --endpoint "$endpoint"
