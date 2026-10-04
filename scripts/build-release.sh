#!/bin/bash
set -euo pipefail
usage(){ echo "usage: $0 (--production | --unsigned-development | --unsigned-cloud-preview) [--output DIR] [--retain-failure-workspace DIR]" >&2; exit 2; }
mode=""; output=""; failure_workspace=""
while (($#)); do case "$1" in --production|--unsigned-development|--unsigned-cloud-preview) [[ -z "$mode" ]] || usage; mode="$1"; shift;; --output) output="${2:?}"; shift 2;; --retain-failure-workspace) failure_workspace="${2:?}"; shift 2;; *) usage;; esac; done
[[ -n "$mode" ]] || usage
repo="$(cd "$(dirname "$0")/.." && pwd -P)"; version="$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$repo/Cargo.toml" | head -1)"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "package version is not SemVer: $version" >&2; exit 1; }
output="${output:-$repo/release/loomex-runner-$version-darwin-arm64}"
[[ ! -e "$output" ]] || { echo "output already exists; refusing to replace it: $output" >&2; exit 1; }
if [[ "$mode" == "--production" || "$mode" == "--unsigned-cloud-preview" ]]; then
  python3 "$repo/scripts/verify-production-config.py"
  [[ -z "$(git -C "$repo" status --porcelain)" ]] || { echo "production and cloud preview releases require a clean source tree" >&2; exit 1; }
  revision="$(git -C "$repo" rev-parse --verify HEAD)"
fi
if [[ "$mode" == "--unsigned-cloud-preview" ]]; then
  export LOOMEX_PREVIEW_SOURCE_REVISION="$revision"
fi
if [[ "$mode" == "--production" ]]; then
  : "${LOOMEX_CODESIGN_IDENTITY:?production requires LOOMEX_CODESIGN_IDENTITY}"; : "${LOOMEX_NOTARY_PROFILE:?production requires LOOMEX_NOTARY_PROFILE}"; : "${LOOMEX_MANIFEST_SIGNING_KEY:?production requires LOOMEX_MANIFEST_SIGNING_KEY}"
  security find-identity -v -p codesigning | grep -Fq "$LOOMEX_CODESIGN_IDENTITY" || { echo "configured production signing identity is unavailable" >&2; exit 1; }
  [[ "$LOOMEX_CODESIGN_IDENTITY" == Developer\ ID\ Application:* ]] || { echo "production requires a Developer ID Application identity" >&2; exit 1; }
  openssl rsa -in "$LOOMEX_MANIFEST_SIGNING_KEY" -check -noout >/dev/null
fi
if [[ -n "$failure_workspace" ]]; then
  [[ ! -e "$failure_workspace" && ! -L "$failure_workspace" ]] || { echo "failure workspace already exists; refusing replacement" >&2; exit 1; }
  [[ -d "$(dirname "$failure_workspace")" && ! -L "$(dirname "$failure_workspace")" ]] || { echo "failure workspace parent must be an existing directory" >&2; exit 1; }
fi
feedback_tool="$repo/scripts/build-feedback.py"
temporary="$(mktemp -d)"
export LOOMEX_BUILD_TEMP="$temporary"
cleanup(){
  result=$?
  trap - EXIT
  if ((result != 0)) && [[ -n "$failure_workspace" ]]; then
    # Reserve the destination atomically. No failed evidence overwrites an
    # existing directory; unsuccessful retention still cleans temporary data.
    if mkdir -m 700 "$failure_workspace"; then
      if ! python3 "$feedback_tool" failure "$temporary" "$result"; then
        echo "Failure metadata unavailable; retaining private workspace for diagnosis" >&2
      fi
      if cp -R "$temporary/." "$failure_workspace/"; then
        echo "Private failure workspace retained: $failure_workspace" >&2
      else
        echo "Failure workspace copy incomplete: $failure_workspace" >&2
      fi
    else
      echo "Failure workspace retention unavailable: destination exists" >&2
    fi
  fi
  rm -rf "$temporary"
  exit "$result"
}
trap cleanup EXIT
run_build(){
  python3 "$feedback_tool" record "$temporary" "$@"
  "$@" 2>&1 | python3 "$feedback_tool" log "$temporary/build.log"
}
revision="${revision:-$(git -C "$repo" rev-parse --verify HEAD 2>/dev/null || printf unknown)}"
source_manifest="$temporary/source-content-manifest.json"
build_root="$temporary/source"
if [[ "$mode" == "--production" || "$mode" == "--unsigned-cloud-preview" ]]; then
  python3 "$repo/scripts/artifact.py" source-manifest --source-root "$repo" --source-revision "$revision" --output "$source_manifest"
  mkdir "$build_root"
  git -C "$repo" archive "$revision" | tar -x -C "$temporary/source"
  python3 "$repo/scripts/artifact.py" verify-source --source-root "$build_root" --manifest "$source_manifest"
  snapshot_version="$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$build_root/Cargo.toml" | head -1)"
  [[ "$snapshot_version" == "$version" ]] || { echo "snapshot version changed during build" >&2; exit 1; }
else
  python3 "$repo/scripts/artifact.py" source-manifest --source-root "$repo" --source-revision "$revision" --output "$source_manifest" --snapshot "$build_root"
fi
feedback_tool="$build_root/scripts/build-feedback.py"
# Cargo/rustc canonicalize snapshot paths (macOS /var resolves to /private/var).
# Keep the lexical snapshot/temporary paths for manifest and failure ownership,
# while remapping both exact source spellings used by Rust and C compilers.
canonical_build_root="$(cd "$build_root" && pwd -P)"
remap_flags="${RUSTFLAGS:-} --remap-path-prefix=$canonical_build_root=/loomex/src --remap-path-prefix=$build_root=/loomex/src --remap-path-prefix=${HOME:?}=/loomex/home"
remap_cflags="${CFLAGS:-} -ffile-prefix-map=$canonical_build_root=/loomex/src -ffile-prefix-map=$build_root=/loomex/src -ffile-prefix-map=${HOME:?}=/loomex/home"
(cd "$build_root" && CARGO_TARGET_DIR="$temporary/target" RUSTFLAGS="$remap_flags" CFLAGS="$remap_cflags" run_build cargo test --locked)
python3 "$build_root/scripts/export-compatibility.py" --check
if [[ "$mode" == "--production" ]]; then
  (cd "$build_root" && CARGO_TARGET_DIR="$temporary/target" RUSTFLAGS="$remap_flags" CFLAGS="$remap_cflags" run_build cargo build --locked --release --target aarch64-apple-darwin --bin loomex --bin loomex-runner --bin loomex-lifecycle-bootstrap)
  binary_root="$temporary/target/aarch64-apple-darwin/release"
else
  [[ "$(uname -s)-$(uname -m)" == "Darwin-arm64" ]] || { echo "unsigned development artifact requires a macOS arm64 host" >&2; exit 1; }
  (cd "$build_root" && CARGO_TARGET_DIR="$temporary/target" RUSTFLAGS="$remap_flags" CFLAGS="$remap_cflags" run_build cargo build --locked --profile distribution-dev --bin loomex --bin loomex-runner --bin loomex-lifecycle-bootstrap)
  binary_root="$temporary/target/distribution-dev"
fi
payload="$temporary/payload"
mkdir -p "$payload/bin" "$payload/metadata" "$payload/launchd"
cp "$binary_root/loomex" "$payload/bin/loomex"
cp "$binary_root/loomex-runner" "$payload/bin/loomex-runner"
cp "$binary_root/loomex-lifecycle-bootstrap" "$payload/bin/loomex-lifecycle-bootstrap"
chmod 0755 "$payload/bin/loomex" "$payload/bin/loomex-runner" "$payload/bin/loomex-lifecycle-bootstrap"
python3 - "$version" "$payload/metadata/project.json" "$mode" <<'PY'
import json,sys
from pathlib import Path
version,out,mode=sys.argv[1:]
metadata={"project":"loomex-runner","version":version,"platform":"darwin-arm64","stateSchema":"app.loomex.runner.state/v1"}
if mode in ('--unsigned-development', '--unsigned-cloud-preview'):
    metadata['build']={'profile':'distribution-dev','optimizationLevel':'2','debugAssertions':True,'classification':'development'}
Path(out).write_text(json.dumps(metadata,sort_keys=True,indent=2)+"\n")
PY
if [[ "$mode" == "--unsigned-cloud-preview" ]]; then
  python3 - "$payload/metadata/preview-origin.json" "$revision" "$version" <<'PY'
import json,os,sys
from pathlib import Path
from urllib.parse import urlsplit,urlunsplit
out,revision,version=sys.argv[1:]
url=urlsplit(os.environ['LOOMEX_API_ORIGIN'])
host=url.hostname.encode('idna').decode('ascii').lower()
if ':' in host: host='['+host+']'
authority=host + (f':{url.port}' if url.port not in (None,443) else '')
origin=urlunsplit(('https',authority,'/','',''))
metadata={'schema':'app.loomex.runner.preview-origin/v1','apiOrigin':origin,'sourceRevision':revision,'version':version}
Path(out).write_text(json.dumps(metadata,sort_keys=True,separators=(',',':'))+'\n')
PY
fi
cp "$build_root/contracts/compatibility-manifest.json" "$payload/metadata/compatibility-manifest.json"
cp "$source_manifest" "$payload/metadata/source-content-manifest.json"
cp "$build_root/scripts/app.loomex.runner.template.plist" "$payload/launchd/app.loomex.runner.template.plist"
python3 "$build_root/scripts/validate_package.py" "$payload" --expected-version "$version" --source-root "$build_root"
if [[ "$mode" == "--production" ]]; then
  codesign --force --timestamp --options runtime --sign "$LOOMEX_CODESIGN_IDENTITY" "$payload/bin/loomex"
  codesign --force --timestamp --options runtime --sign "$LOOMEX_CODESIGN_IDENTITY" "$payload/bin/loomex-runner"
  codesign --force --timestamp --options runtime --sign "$LOOMEX_CODESIGN_IDENTITY" "$payload/bin/loomex-lifecycle-bootstrap"
else
  strip -S "$payload/bin/loomex" "$payload/bin/loomex-runner" "$payload/bin/loomex-lifecycle-bootstrap"
  if [[ -n "${LOOMEX_DEVELOPMENT_CODESIGN_IDENTITY:-}" ]]; then
    [[ "$LOOMEX_DEVELOPMENT_CODESIGN_IDENTITY" != - ]] || { echo "ad-hoc development signing is not a stable identity" >&2; exit 1; }
    if [[ -n "${LOOMEX_DEVELOPMENT_CODESIGN_KEYCHAIN:-}" ]]; then
      [[ -f "$LOOMEX_DEVELOPMENT_CODESIGN_KEYCHAIN" ]] || { echo "development signing keychain is missing" >&2; exit 1; }
    fi
    for name in loomex loomex-runner loomex-lifecycle-bootstrap; do
      if [[ -n "${LOOMEX_DEVELOPMENT_CODESIGN_KEYCHAIN:-}" ]]; then
        codesign --force --sign "$LOOMEX_DEVELOPMENT_CODESIGN_IDENTITY" --keychain "$LOOMEX_DEVELOPMENT_CODESIGN_KEYCHAIN" --identifier "app.loomex.runner.$name" "$payload/bin/$name"
      else
        codesign --force --sign "$LOOMEX_DEVELOPMENT_CODESIGN_IDENTITY" --identifier "app.loomex.runner.$name" "$payload/bin/$name"
      fi
      codesign --verify --strict "$payload/bin/$name"
    done
    python3 - "$payload" <<'PY'
import json,re,subprocess,sys
from pathlib import Path
root=Path(sys.argv[1]); requirements={}
def stable_requirement(requirement,name):
    prefix=f'identifier "app.loomex.runner.{name}" and '
    if not requirement.startswith(prefix) or 'cdhash ' in requirement:
        return False
    policy=requirement[len(prefix):]
    return policy.startswith('anchor ') or re.fullmatch(r'certificate leaf = H"[0-9a-fA-F]{40}"',policy) is not None
for name in ('loomex','loomex-runner','loomex-lifecycle-bootstrap'):
    path=root/'bin'/name
    info=subprocess.run(['/usr/bin/codesign','-dv','--verbose=4',str(path)],capture_output=True,text=True,check=True).stderr
    if 'Signature=adhoc' in info or 'TeamIdentifier=not set' in info and 'Authority=' not in info:
        raise SystemExit(f'{name} has no stable signing identity')
    display=subprocess.run(['/usr/bin/codesign','-dr','-',str(path)],capture_output=True,text=True,check=True)
    lines=[line.split('designated => ',1)[1].strip() for line in (display.stdout+display.stderr).splitlines() if line.startswith(('designated => ','# designated => '))]
    if len(lines)!=1 or not stable_requirement(lines[0],name):
        raise SystemExit(f'{name} has no stable designated requirement')
    requirements[name]=lines[0]
manifest={'schema':'app.loomex.runner.development-signing/v1','requirements':requirements}
(root/'metadata'/'development-signing.json').write_text(json.dumps(manifest,sort_keys=True,separators=(',',':'))+'\n')
PY
    python3 "$build_root/scripts/validate_package.py" "$payload" --expected-version "$version" --source-root "$build_root"
  else
    echo "WARNING: building unsigned development artifact for isolated testing only" >&2
  fi
fi
python3 - "$payload" "${HOME:?}" "$build_root" "$canonical_build_root" <<'PY'
import sys
from pathlib import Path
root=Path(sys.argv[1])
needles=[(sys.argv[2].encode(), 'home'), (sys.argv[3].encode(), 'source'), (sys.argv[4].encode(), 'source')]
for path in root.rglob('*'):
 if path.is_file():
  content=path.read_bytes()
  for needle, label in needles:
   if needle in content: raise SystemExit(f'payload embeds build {label} path: {path.relative_to(root)}')
PY
release_stage="$temporary/release"
arguments=(create --payload "$payload" --output "$release_stage" --project loomex-runner --version "$version" --platform darwin-arm64 --source-revision "$revision" --bootstrap "$payload/bin/loomex-lifecycle-bootstrap")
if [[ "$mode" == "--production" ]]; then arguments+=(--signing-key "$LOOMEX_MANIFEST_SIGNING_KEY"); else arguments+=(--unsigned-development); fi
python3 "$build_root/scripts/artifact.py" "${arguments[@]}"
if [[ "$mode" == "--production" ]]; then
  ditto -c -k --keepParent "$payload/bin" "$temporary/notary.zip"
  xcrun notarytool submit "$temporary/notary.zip" --keychain-profile "$LOOMEX_NOTARY_PROFILE" --wait --output-format json > "$temporary/notary.json"
  python3 -c 'import json,sys; assert json.load(open(sys.argv[1]))["status"]=="Accepted"' "$temporary/notary.json"
  for binary in "$payload/bin/loomex" "$payload/bin/loomex-runner" "$payload/bin/loomex-lifecycle-bootstrap" "$release_stage/loomex-lifecycle-bootstrap"; do codesign --verify --strict --verbose=2 "$binary"; spctl --assess --type execute --verbose=2 "$binary"; done
fi
[[ ! -e "$output" ]] || { echo "output appeared during build; refusing to replace it: $output" >&2; exit 1; }
mkdir -p "$(dirname "$output")"
mv "$release_stage" "$output"
echo "$output"
