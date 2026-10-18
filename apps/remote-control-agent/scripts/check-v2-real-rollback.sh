#!/usr/bin/env bash
# Operator-run, disposable rc-v012-lab only. Intentionally makes the new
# v0.1.6 user service fail at ExecStartPre; old v0.1.3 may restart normally.
set -Eeuo pipefail
umask 077
die() { echo "RC77_BLOCKED: $*" >&2; exit 1; }
expected_sha=0a8cd48a5a844c01bd7632b1f5c7d477433e8d06e0961fccaeac393aa037d707
test "${WSL_DISTRO_NAME:-}" = rc-v012-lab || die "Wrong WSL distribution"
test "$(id -un)" = ray && test "$(id -u)" -ne 0 || die "Wrong user"
test "$(ps -p 1 -o comm=)" = systemd || die "PID1 must be systemd"
test -t 0 && test -t 1 || die "Run directly in the WSL terminal"
home=/home/ray
test "$HOME" = "$home" || die "Unexpected HOME"
svc=remote-control-v2-agent.service
unit="$home/.config/systemd/user/$svc"
root="$home/.local/share/mcp-workers/remote-control"
old="$root/programs/v0.1.3-linux-x64-glibc"
key="$root/v2-identity.pem"
snapshot="$home/.local/state/rc77-v012-zbPoVsYG"
receipt="$home/.local/state/mcp-workers/remote-control-agent"
dropdir="$home/.config/systemd/user/$svc.d"
dropin="$dropdir/90-rc77-test-only.conf"
fault="$snapshot/fail-v016-only.sh"
test -d "$snapshot" && test ! -L "$snapshot" || die "Missing acceptance baseline"
test "$(stat -c %u "$snapshot")" = "$(id -u)" || die "Unowned acceptance baseline"
test -f "$snapshot/unit.before" && test -f "$snapshot/identity.sha256" || die "Incomplete baseline"
test -f "$unit" && test ! -L "$unit" && cmp -s "$unit" "$snapshot/unit.before" || die "Current unit differs from the saved old unit"
grep -Fxq "WorkingDirectory=$old/apps/remote-control-agent" "$unit" || die "Not canonical old version"
grep -Fxq "ExecStart=$old/bin/node $old/apps/remote-control-agent/src/v2-main.js" "$unit" || die "Not pinned old executable"
grep -Fxq 'Environment=REMOTE_CONTROL_V2_ENDPOINT=https://remote-control-v2-preview.aiyaya.workers.dev/' "$unit" || die "Unexpected endpoint"
grep -Fxq "Environment=REMOTE_CONTROL_V2_KEY_PATH=$key" "$unit" || die "Unexpected private-key path"
grep -Fxq '# Managed by mcp-workers v2 Linux installer; NOT the v1 Agent.' "$unit" || die "Unowned service"
test -f "$key" && test -f "$key.device-id" || die "Missing identity"
sha256sum --status -c "$snapshot/identity.sha256" || die "Identity differs before test"
test "$("$home/.local/bin/rca" version)" = v0.1.3 || die "Expected old CLI"
systemctl --user is-active --quiet "$svc" || die "Old service is not active"
test -z "$(systemctl --user show "$svc" -p DropInPaths --value)" || die "Pre-existing unit drop-in"
test ! -e "$unit.upgrade-backup" || die "Existing recovery backup"
test ! -e "$dropdir" || die "Existing service drop-in directory"
test ! -e "$fault" && test ! -e "$snapshot/fault-fired" || die "Test already attempted"
for f in operation-receipts.sqlite operation-receipts.json operation-receipts.pre-sqlite.json; do
  test ! -e "$receipt/$f" || die "Receipt state changed since baseline"
done

# Download full Worker shell BEFORE injecting systemd failure, verify the
# already-reviewed deployed script byte-for-byte.
installer="$snapshot/rc77-installer-v016.sh"
test ! -e "$installer" || die "Installer staging path already exists"
curl -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2 --max-time 45 \
  'https://remote-control-v2-preview.aiyaya.workers.dev/install.sh' -o "$installer"
printf '%s  %s\n' "$expected_sha" "$installer" | sha256sum --check --status || die "Unexpected deployed Preview installer"
sh -n "$installer" || die "Invalid Preview installer shell"
grep -Fq 'remote-control-agent-v0.1.6' "$installer" || die "Wrong new version"

# A terminal can close while a WSL service is restarting. Persist a
# result only after all checks and cleanup, never retroactively from state.
verdict="$snapshot/rc77-result.txt"
test ! -e "$verdict" || die "Existing acceptance receipt; never overwrite"
printf 'RC77_STATUS=STARTED\n' > "$verdict"
chmod 600 "$verdict"
armed=0
product_verified=0
emergency_used=0
cleanup() {
  local prior_rc=$?
  trap - EXIT INT TERM HUP
  if test "$armed" -eq 1; then
    if ! rm -f -- "$dropin"; then
      echo 'RC77_CLEANUP=FAILED_DROPIN' >&2
      prior_rc=1
    fi
    rmdir "$dropdir" 2>/dev/null || true
    if ! systemctl --user daemon-reload; then
      echo 'RC77_CLEANUP=FAILED_RELOAD' >&2
      prior_rc=1
    fi
    if test -n "$(systemctl --user show "$svc" -p DropInPaths --value)" || test -e "$dropin"; then
      echo 'RC77_CLEANUP=DROPIN_REMAINS' >&2
      prior_rc=1
    fi
    if ! cmp -s "$unit" "$snapshot/unit.before" || ! systemctl --user is-active --quiet "$svc"; then
      echo 'RC77_PRODUCT_ROLLBACK=FAILED; attempting separately identified emergency recovery' >&2
      emergency_used=1
      cp -- "$snapshot/unit.before" "$unit"
      chmod 600 "$unit"
      systemctl --user daemon-reload && systemctl --user restart "$svc" || echo 'RC77_EMERGENCY_RECOVERY=FAILED' >&2
      prior_rc=1
    fi
    if ! sha256sum --status -c "$snapshot/identity.sha256"; then
      echo 'RC77_IDENTITY_PRESERVATION=FAILED' >&2
      prior_rc=1
    fi
  fi
  if test "$prior_rc" -eq 0 && test "$product_verified" -eq 1 && test "$emergency_used" -eq 0; then
    printf 'RC77_STATUS=PRODUCT_ROLLBACK_PASS\n' >> "$verdict"
    echo 'RC77_PRODUCT_ROLLBACK=PASS (finalized after clean systemd recovery)'
  elif test "$emergency_used" -eq 1; then
    printf 'RC77_STATUS=EMERGENCY_RECOVERY_USED\n' >> "$verdict"
    echo 'RC77_STATUS=EMERGENCY_RECOVERY_USED' >&2
  else
    printf 'RC77_STATUS=INCOMPLETE_OR_FAILED\n' >> "$verdict"
    echo 'RC77_STATUS=INCOMPLETE_OR_FAILED' >&2
  fi
  exit "$prior_rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

# The extra ExecStartPre runs inside REAL user systemd. It rejects ONLY the
# new v0.1.6 executable; the old v0.1.3 service passes and can be recovered.
cat > "$fault" <<'FAULT'
#!/bin/sh
set -eu
if /usr/bin/grep -Fq '/programs/v0.1.6-linux-x64-glibc/bin/node ' '/home/ray/.config/systemd/user/remote-control-v2-agent.service'; then
  /usr/bin/touch '/home/ray/.local/state/rc77-v012-zbPoVsYG/fault-fired'
  exit 73
fi
exit 0
FAULT
chmod 700 "$fault"
armed=1
mkdir -m 700 "$dropdir"
printf '[Service]\nExecStartPre=/bin/sh %s\n' "$fault" > "$dropin"
chmod 600 "$dropin"
systemctl --user daemon-reload
test "$(systemctl --user show "$svc" -p DropInPaths --value)" = "$dropin" || die "Fault drop-in was not loaded"

echo 'RC77_FAULT=ARMED_FOR_NEW_v0.1.6_ONLY'
echo 'RC77_EXPECTED=Installer fails and restores real v0.1.3 user service'
set +e
sh "$installer" --upgrade
upgrade_status=$?
set -e
echo "RC77_UPGRADE_EXIT=$upgrade_status (expected nonzero)"
printf 'RC77_UPGRADE_EXIT=%s\n' "$upgrade_status" >> "$verdict"
test "$upgrade_status" -ne 0 || die "Upgrade succeeded despite forced new-service failure"
test -f "$snapshot/fault-fired" || die "Real new-version ExecStartPre was not triggered"
cmp -s "$unit" "$snapshot/unit.before" || die "Installer did not restore original unit"
test ! -e "$unit.upgrade-backup" || die "Installer left interrupted-upgrade backup"
test "$("$home/.local/bin/rca" version)" = v0.1.3 || die "Old CLI version not retained"
systemctl --user is-active --quiet "$svc" || die "Old v0.1.3 service is not active"
sha256sum --status -c "$snapshot/identity.sha256" || die "Device identity changed"
product_verified=1
echo 'RC77_PRODUCT_CHECKS=PASS; waiting for final cleanup verification'
echo 'RC77_IDENTITY_PRESERVED=PASS'
echo 'RC77_CLEANUP=ON_EXIT'
