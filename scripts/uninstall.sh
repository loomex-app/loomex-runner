#!/bin/bash
# Resolve and verify the installed native bootstrap, then hand off. All
# journalling, draining and deletion live in Rust.
set -euo pipefail

base="${HOME:?}/Library/Application Support/Loomex/runner"
state="${HOME:?}/.local/share/loomex/runner"
values=("$@")
while ((${#values[@]})); do
  case "${values[0]}" in
    --install-base) ((${#values[@]} >= 2)) || { echo "--install-base requires a path" >&2; exit 2; }; base="${values[1]}"; values=("${values[@]:2}");;
    --state-dir) ((${#values[@]} >= 2)) || { echo "--state-dir requires a path" >&2; exit 2; }; state="${values[1]}"; values=("${values[@]:2}");;
    --launch-agents-dir) ((${#values[@]} >= 2)) || { echo "--launch-agents-dir requires a path" >&2; exit 2; }; values=("${values[@]:2}");;
    *) echo "usage: $0 [--install-base DIR --state-dir DIR --launch-agents-dir DIR]" >&2; exit 2;;
  esac
done

receipt="$state/install-receipt.json"
bootstrap="$base/current/bin/loomex-lifecycle-bootstrap"
helper="$state/bootstrap-uninstall-helper"
journal="$state/bootstrap-uninstall.json"
terminal="$state/bootstrap-uninstall-terminal.json"
# A crash after journal removal but before helper unlink leaves this exact
# terminal marker set.  It cannot be an incomplete uninstall because both the
# sealed journal and ownership inventory are gone; never execute the orphaned
# helper in this state.
if [[ ! -e "$receipt" && ! -e "$bootstrap" && ! -e "$journal" && -f "$terminal" ]]; then
  [[ "$(/usr/bin/sed -nE 's/.*"schema":"app\.loomex\.runner\.bootstrap-uninstall\/v1".*/ok/p' "$terminal")" == ok ]] || { echo "terminal uninstall marker is invalid" >&2; exit 1; }
  [[ "$(/usr/bin/sed -nE 's/.*"phase":"terminal".*/ok/p' "$terminal")" == ok ]] || { echo "terminal uninstall marker is incomplete" >&2; exit 1; }
  digest="$(/usr/bin/sed -nE 's/.*"helperSha256":"([0-9a-f]{64})".*/\1/p' "$terminal")"
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || { echo "terminal uninstall helper identity is invalid" >&2; exit 1; }
  if [[ -e "$helper" ]]; then
    [[ -f "$helper" && ! -L "$helper" ]] || { echo "terminal uninstall helper is unsafe" >&2; exit 1; }
    actual="$(/usr/bin/shasum -a 256 "$helper" | /usr/bin/awk '{print $1}')"
    [[ "$actual" == "$digest" ]] || { echo "terminal uninstall helper digest mismatch" >&2; exit 1; }
    /bin/rm -f "$helper"
  fi
  /bin/rm -f "$terminal"
  echo "Loomex runner is already uninstalled."
  exit 0
fi
if [[ ! -e "$receipt" && ! -e "$bootstrap" && ! -e "$state/bootstrap-uninstall-helper" && ! -e "$state/bootstrap-uninstall.json" ]]; then
  echo "Loomex runner is already uninstalled."
  exit 0
fi
if [[ ! -f "$receipt" ]]; then
  [[ -f "$journal" && -x "$helper" ]] || { echo "installed native lifecycle receipt is unavailable" >&2; exit 1; }
  [[ "$(/usr/bin/sed -nE 's/.*"schema":"app\.loomex\.runner\.bootstrap-uninstall\/v1".*/ok/p' "$journal")" == ok ]] || { echo "uninstall recovery journal is invalid" >&2; exit 1; }
  [[ "$(/usr/bin/sed -nE 's/.*"phase":"revoked".*/ok/p' "$journal")" == ok ]] || { echo "uninstall recovery is not terminally revoked" >&2; exit 1; }
  digest="$(/usr/bin/sed -nE 's/.*"helperSha256":"([0-9a-f]{64})".*/\1/p' "$journal")"
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || { echo "uninstall recovery helper identity is invalid" >&2; exit 1; }
  actual="$(/usr/bin/shasum -a 256 "$helper" | /usr/bin/awk '{print $1}')"
  [[ "$actual" == "$digest" ]] || { echo "uninstall recovery helper digest mismatch" >&2; exit 1; }
  exec "$helper" uninstall "$@"
fi
if [[ ! -x "$bootstrap" ]]; then
  bootstrap="$state/bootstrap-uninstall-helper"
fi
[[ -x "$bootstrap" ]] || { echo "installed native lifecycle bootstrap is unavailable" >&2; exit 1; }
digest="$(/usr/bin/sed -nE 's/.*"bootstrapSha256":"([0-9a-f]{64})".*/\1/p' "$receipt")"
[[ "$digest" =~ ^[0-9a-f]{64}$ ]] || { echo "installed bootstrap identity is unavailable; use native lifecycle repair" >&2; exit 1; }
actual="$(/usr/bin/shasum -a 256 "$bootstrap" | /usr/bin/awk '{print $1}')"
[[ "$actual" == "$digest" ]] || { echo "installed lifecycle bootstrap digest mismatch" >&2; exit 1; }
exec "$bootstrap" uninstall "$@"
