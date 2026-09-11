#!/bin/bash
set -euo pipefail
usage(){ echo "usage: $0 (--production | --unsigned-development) [--output DIR]" >&2; exit 2; }
mode=""; output=""
while (($#)); do case "$1" in --production|--unsigned-development) mode="$1"; shift;; --output) output="${2:?}"; shift 2;; *) usage;; esac; done
[[ -n "$mode" ]] || usage
repo="$(cd "$(dirname "$0")/.." && pwd -P)"; version="$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$repo/Cargo.toml" | head -1)"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "package version is not SemVer: $version" >&2; exit 1; }
output="${output:-$repo/release/loomex-runner-$version-darwin-arm64}"
[[ ! -e "$output" ]] || { echo "output already exists; refusing to replace it: $output" >&2; exit 1; }
if [[ "$mode" == "--production" ]]; then
  : "${LOOMEX_CODESIGN_IDENTITY:?production requires LOOMEX_CODESIGN_IDENTITY}"; : "${LOOMEX_NOTARY_PROFILE:?production requires LOOMEX_NOTARY_PROFILE}"; : "${LOOMEX_MANIFEST_SIGNING_KEY:?production requires LOOMEX_MANIFEST_SIGNING_KEY}"
  security find-identity -v -p codesigning | grep -Fq "$LOOMEX_CODESIGN_IDENTITY" || { echo "configured production signing identity is unavailable" >&2; exit 1; }
  [[ "$LOOMEX_CODESIGN_IDENTITY" == Developer\ ID\ Application:* ]] || { echo "production requires a Developer ID Application identity" >&2; exit 1; }
  openssl rsa -in "$LOOMEX_MANIFEST_SIGNING_KEY" -check -noout >/dev/null
  [[ -z "$(git -C "$repo" status --porcelain)" ]] || { echo "production release requires a clean source tree" >&2; exit 1; }
  revision="$(git -C "$repo" rev-parse --verify HEAD)"
fi
temporary="$(mktemp -d)"; trap 'rm -rf "$temporary"' EXIT
build_root="$repo"
if [[ "$mode" == "--production" ]]; then
  mkdir "$temporary/source"
  git -C "$repo" archive "$revision" | tar -x -C "$temporary/source"
  build_root="$temporary/source"
  snapshot_version="$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$build_root/Cargo.toml" | head -1)"
  [[ "$snapshot_version" == "$version" ]] || { echo "snapshot version changed during build" >&2; exit 1; }
fi
remap_flags="${RUSTFLAGS:-} --remap-path-prefix=$build_root=/loomex/src --remap-path-prefix=${HOME:?}=/loomex/home"
remap_cflags="${CFLAGS:-} -ffile-prefix-map=$build_root=/loomex/src -ffile-prefix-map=${HOME:?}=/loomex/home"
(cd "$build_root" && CARGO_TARGET_DIR="$temporary/target" RUSTFLAGS="$remap_flags" CFLAGS="$remap_cflags" cargo test --locked)
python3 "$build_root/scripts/export-compatibility.py" --check
if [[ "$mode" == "--production" ]]; then
  (cd "$build_root" && CARGO_TARGET_DIR="$temporary/target" RUSTFLAGS="$remap_flags" CFLAGS="$remap_cflags" cargo build --locked --release --target aarch64-apple-darwin)
  binary_root="$temporary/target/aarch64-apple-darwin/release"
else
  [[ "$(uname -s)-$(uname -m)" == "Darwin-arm64" ]] || { echo "unsigned development artifact requires a macOS arm64 host" >&2; exit 1; }
  (cd "$build_root" && CARGO_TARGET_DIR="$temporary/target" RUSTFLAGS="$remap_flags" CFLAGS="$remap_cflags" cargo build --locked)
  binary_root="$temporary/target/debug"
fi
payload="$temporary/payload"
mkdir -p "$payload/bin" "$payload/metadata" "$payload/launchd"
cp "$binary_root/loomex" "$payload/bin/loomex"
cp "$binary_root/loomex-runner" "$payload/bin/loomex-runner"
chmod 0755 "$payload/bin/loomex" "$payload/bin/loomex-runner"
python3 - "$version" "$payload/metadata/project.json" <<'PY'
import json,sys
from pathlib import Path
version,out=sys.argv[1:]; Path(out).write_text(json.dumps({"project":"loomex-runner","version":version,"platform":"darwin-arm64","stateSchema":"app.loomex.runner.state/v1"},sort_keys=True,indent=2)+"\n")
PY
cp "$build_root/contracts/compatibility-manifest.json" "$payload/metadata/compatibility-manifest.json"
cp "$build_root/scripts/app.loomex.runner.template.plist" "$payload/launchd/app.loomex.runner.template.plist"
python3 "$build_root/scripts/validate_package.py" "$payload" --expected-version "$version"
if [[ "$mode" == "--production" ]]; then
  codesign --force --timestamp --options runtime --sign "$LOOMEX_CODESIGN_IDENTITY" "$payload/bin/loomex"
  codesign --force --timestamp --options runtime --sign "$LOOMEX_CODESIGN_IDENTITY" "$payload/bin/loomex-runner"
else
  strip -S "$payload/bin/loomex" "$payload/bin/loomex-runner"
  echo "WARNING: building unsigned development artifact for isolated testing only" >&2
fi
python3 - "$payload" "${HOME:?}" <<'PY'
import sys
from pathlib import Path
root=Path(sys.argv[1]); needle=sys.argv[2].encode()
for path in root.rglob('*'):
 if path.is_file() and needle in path.read_bytes(): raise SystemExit(f'payload embeds build home path: {path.relative_to(root)}')
PY
revision="${revision:-$(git -C "$repo" rev-parse HEAD 2>/dev/null || printf unknown)}"; release_stage="$temporary/release"
arguments=(create --payload "$payload" --output "$release_stage" --project loomex-runner --version "$version" --platform darwin-arm64 --source-revision "$revision")
if [[ "$mode" == "--production" ]]; then arguments+=(--signing-key "$LOOMEX_MANIFEST_SIGNING_KEY"); else arguments+=(--unsigned-development); fi
python3 "$build_root/scripts/artifact.py" "${arguments[@]}"
if [[ "$mode" == "--production" ]]; then
  ditto -c -k --keepParent "$payload/bin" "$temporary/notary.zip"
  xcrun notarytool submit "$temporary/notary.zip" --keychain-profile "$LOOMEX_NOTARY_PROFILE" --wait --output-format json > "$temporary/notary.json"
  python3 -c 'import json,sys; assert json.load(open(sys.argv[1]))["status"]=="Accepted"' "$temporary/notary.json"
  for binary in "$payload/bin/loomex" "$payload/bin/loomex-runner"; do codesign --verify --strict --verbose=2 "$binary"; spctl --assess --type execute --verbose=2 "$binary"; done
fi
[[ ! -e "$output" ]] || { echo "output appeared during build; refusing to replace it: $output" >&2; exit 1; }
mkdir -p "$(dirname "$output")"
mv "$release_stage" "$output"
echo "$output"
