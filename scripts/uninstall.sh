#!/bin/bash
# Resolve and verify the installed native bootstrap, then hand off. All
# journalling, draining and deletion live in Rust.
set -euo pipefail

# Explicit legacy recovery executes a reviewed release bootstrap. The installed
# helper remains immutable; a candidate is never copied over its old identity.
if [[ "${1:-}" == recover-uninstall ]]; then
  shift
  [[ $# -ge 1 ]] || { echo "recover-uninstall requires a release" >&2; exit 2; }
  release="$1"; shift
  manifest="$release/manifest.json"; recovery_bootstrap="$release/loomex-lifecycle-bootstrap"
  [[ -f "$manifest" && ! -L "$manifest" && -x "$recovery_bootstrap" && ! -L "$recovery_bootstrap" ]] || { echo "recovery release bootstrap unavailable" >&2; exit 1; }
  public_key=""; allow_development=0; expected_old=""
  arguments=("$@")
  for ((index=0; index<${#arguments[@]}; index++)); do
    case "${arguments[index]}" in
      --public-key) ((index + 1 < ${#arguments[@]})) || exit 2; public_key="${arguments[index + 1]}"; index=$((index + 1));;
      --allow-unsigned-development) allow_development=1;;
      --expected-old-journal-sha256) ((index + 1 < ${#arguments[@]})) || exit 2; expected_old="${arguments[index + 1]}"; index=$((index + 1));;
    esac
  done
  [[ "$expected_old" =~ ^[0-9a-f]{64}$ ]] || { echo "explicit recovery requires --expected-old-journal-sha256 SHA256" >&2; exit 2; }
  development="$(/usr/bin/sed -nE 's/.*"developmentOnly":(true|false).*/\1/p' "$manifest")"
  if [[ "$development" == false ]]; then
    [[ -n "$public_key" && -f "$public_key" && -f "$release/manifest.sig" ]] || { echo "production recovery requires --public-key" >&2; exit 1; }
    /usr/bin/openssl dgst -sha256 -verify "$public_key" -signature "$release/manifest.sig" "$manifest" >/dev/null || exit 1
  else
    [[ "$development" == true && "$allow_development" == 1 && "${LOOMEX_ALLOW_UNSAFE_DEV_INSTALL:-}" == 1 ]] || { echo "development recovery requires explicit opt-in" >&2; exit 1; }
  fi
  digest="$(/usr/bin/sed -nE 's/.*"bootstrap":\{"file":"loomex-lifecycle-bootstrap","sha256":"([0-9a-f]{64})","size":[0-9]+\}.*/\1/p' "$manifest")"
  [[ "$digest" =~ ^[0-9a-f]{64}$ && "$(/usr/bin/shasum -a 256 "$recovery_bootstrap" | /usr/bin/awk '{print $1}')" == "$digest" ]] || { echo "recovery bootstrap digest mismatch" >&2; exit 1; }
  exec "$recovery_bootstrap" recover-uninstall "$release" "$@"
fi

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
# A terminal marker still requires the native owner to acquire the stable
# singleton before unlinking its bound helper and terminal metadata.
if [[ ! -e "$receipt" && ! -e "$bootstrap" && ! -e "$journal" && -f "$terminal" ]]; then
  [[ "$(/usr/bin/sed -nE 's/.*"schema":"app\.loomex\.runner\.bootstrap-uninstall\/v2".*/ok/p' "$terminal")" == ok ]] || { echo "legacy terminal marker requires explicit recovery" >&2; exit 1; }
  [[ "$(/usr/bin/sed -nE 's/.*"phase":"terminal".*/ok/p' "$terminal")" == ok ]] || { echo "terminal uninstall marker is incomplete" >&2; exit 1; }
  digest="$(/usr/bin/sed -nE 's/.*"helperSha256":"([0-9a-f]{64})".*/\1/p' "$terminal")"
  [[ "$digest" =~ ^[0-9a-f]{64}$ && -x "$helper" && ! -L "$helper" ]] || { echo "terminal helper unavailable; use explicit recovery release" >&2; exit 1; }
  [[ "$(/usr/bin/shasum -a 256 "$helper" | /usr/bin/awk '{print $1}')" == "$digest" ]] || { echo "terminal helper digest mismatch" >&2; exit 1; }
  exec "$helper" uninstall "$@"
fi
if [[ ! -e "$receipt" && ! -e "$bootstrap" && ! -e "$state/bootstrap-uninstall-helper" && ! -e "$state/bootstrap-uninstall.json" ]]; then
  echo "Loomex runner is already uninstalled."
  exit 0
fi
if [[ ! -f "$receipt" ]]; then
  [[ -f "$journal" && -x "$helper" ]] || { echo "installed native lifecycle receipt is unavailable" >&2; exit 1; }
  [[ "$(/usr/bin/sed -nE 's/.*"schema":"app\.loomex\.runner\.bootstrap-uninstall\/v2".*/ok/p' "$journal")" == ok ]] || { echo "uninstall recovery journal is invalid" >&2; exit 1; }
  [[ "$(/usr/bin/sed -nE 's/.*"phase":"(revoked|cleanup)".*/ok/p' "$journal")" == ok ]] || { echo "uninstall recovery is not terminally revoked" >&2; exit 1; }
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
