#!/bin/bash
# This launcher deliberately owns no lifecycle logic. A release supplies the
# signed native bootstrap, which validates the envelope and executes the
# transaction without a source checkout or interpreter.
set -euo pipefail

usage() { echo "usage: $0 RELEASE_DIR [native bootstrap options]" >&2; exit 2; }
[[ $# -ge 1 ]] || usage
release="$1"
manifest="$release/manifest.json"
bootstrap="$release/loomex-lifecycle-bootstrap"
[[ -f "$manifest" && -x "$bootstrap" ]] || { echo "release does not contain a native lifecycle bootstrap" >&2; exit 1; }

public_key=""; allow_development=0
arguments=("$@")
for ((index=1; index<${#arguments[@]}; index++)); do
  case "${arguments[index]}" in
    --public-key) ((index + 1 < ${#arguments[@]})) || usage; public_key="${arguments[index + 1]}"; index=$((index + 1));;
    --allow-unsigned-development) allow_development=1;;
  esac
done
development="$(/usr/bin/sed -nE 's/.*"developmentOnly":(true|false).*/\1/p' "$manifest")"
[[ "$development" == true || "$development" == false ]] || { echo "release class is invalid" >&2; exit 1; }
if [[ "$development" == false ]]; then
  [[ -n "$public_key" && -f "$public_key" && -f "$release/manifest.sig" ]] || { echo "production release requires --public-key" >&2; exit 1; }
  /usr/bin/openssl dgst -sha256 -verify "$public_key" -signature "$release/manifest.sig" "$manifest" >/dev/null || { echo "release signature verification failed" >&2; exit 1; }
else
  [[ "$allow_development" == 1 && "${LOOMEX_ALLOW_UNSAFE_DEV_INSTALL:-}" == 1 ]] || { echo "unsigned development release requires explicit opt-in" >&2; exit 1; }
fi

# The bootstrap is bound into the manifest. The native program verifies the
# full canonical manifest, payload inventory and signature before mutation.
digest="$(/usr/bin/sed -nE 's/.*"bootstrap":\{"file":"loomex-lifecycle-bootstrap","sha256":"([0-9a-f]{64})","size":[0-9]+\}.*/\1/p' "$manifest")"
size="$(/usr/bin/sed -nE 's/.*"bootstrap":\{"file":"loomex-lifecycle-bootstrap","sha256":"[0-9a-f]{64}","size":([0-9]+)\}.*/\1/p' "$manifest")"
[[ "$digest" =~ ^[0-9a-f]{64}$ ]] || { echo "release bootstrap metadata is invalid" >&2; exit 1; }
[[ "$size" =~ ^[0-9]+$ && "$(/usr/bin/stat -f %z "$bootstrap")" == "$size" ]] || { echo "release bootstrap size mismatch" >&2; exit 1; }
actual="$(/usr/bin/shasum -a 256 "$bootstrap" | /usr/bin/awk '{print $1}')"
[[ "$actual" == "$digest" ]] || { echo "release bootstrap digest mismatch" >&2; exit 1; }
exec "$bootstrap" install "$@"
