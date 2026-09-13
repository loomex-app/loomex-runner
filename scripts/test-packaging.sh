#!/bin/bash
# Native release/bootstrap packaging smoke test.  This intentionally runs the
# copied administrative launchers from a fixture, proving they do not need the
# source checkout or Python/npm/cargo at operation time.
set -euo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd -P)"
fixture="$(mktemp -d)"
trap 'rm -rf "$fixture"' EXIT
version="$(/usr/bin/sed -nE 's/^version = "([0-9]+\.[0-9]+\.[0-9]+)"/\1/p' "$repo/Cargo.toml" | head -1)"
[[ -n "$version" ]] || { echo "package version is invalid" >&2; exit 1; }

(cd "$repo" && cargo build --locked --bin loomex --bin loomex-runner --bin loomex-lifecycle-bootstrap >/dev/null)
payload="$fixture/payload"
mkdir -p "$payload/bin" "$payload/metadata" "$payload/launchd"
cp "$repo/target/debug/loomex" "$payload/bin/loomex"
cp "$repo/target/debug/loomex-runner" "$payload/bin/loomex-runner"
cp "$repo/target/debug/loomex-lifecycle-bootstrap" "$payload/bin/loomex-lifecycle-bootstrap"
chmod 0755 "$payload/bin/loomex" "$payload/bin/loomex-runner" "$payload/bin/loomex-lifecycle-bootstrap"
python3 - "$version" "$payload/metadata/project.json" "$payload/metadata/source-content-manifest.json" <<'PY'
import json,sys
version,project,source=sys.argv[1:]
open(project,'w').write(json.dumps({'platform':'darwin-arm64','project':'loomex-runner','stateSchema':'app.loomex.runner.state/v1','version':version},sort_keys=True,indent=2)+'\n')
open(source,'w').write(json.dumps({'files':[],'schema':'app.loomex.source-content/v1','sourceRevision':'packaging-fixture'},sort_keys=True,separators=(',',':'))+'\n')
PY
cp "$repo/contracts/compatibility-manifest.json" "$payload/metadata/compatibility-manifest.json"
cp "$repo/scripts/app.loomex.runner.template.plist" "$payload/launchd/app.loomex.runner.template.plist"
python3 "$repo/scripts/validate_package.py" "$payload" --expected-version "$version"

release="$fixture/release"
SOURCE_DATE_EPOCH=1 python3 "$repo/scripts/artifact.py" create --payload "$payload" --output "$release" --project loomex-runner --version "$version" --platform darwin-arm64 --source-revision packaging-fixture --unsigned-development --bootstrap "$payload/bin/loomex-lifecycle-bootstrap"
launcher="$fixture/install"; unlauncher="$fixture/uninstall"
cp "$repo/scripts/install.sh" "$launcher"; cp "$repo/scripts/uninstall.sh" "$unlauncher"
chmod 0755 "$launcher" "$unlauncher"

no_python="$fixture/no-python"; mkdir "$no_python"
printf '%s\n' '#!/bin/bash' 'exit 97' > "$no_python/python3"; chmod 0755 "$no_python/python3"
base="$fixture/install-root"; state="$fixture/state"; agents="$fixture/agents"
PATH="$no_python:/usr/bin:/bin" LOOMEX_ALLOW_UNSAFE_DEV_INSTALL=1 LOOMEX_INSTALL_TEST_MODE=1 "$launcher" "$release" --allow-unsigned-development --development-api-origin http://127.0.0.1:9 --install-base "$base" --state-dir "$state" --launch-agents-dir "$agents"
test -L "$base/current"
test -f "$state/install-receipt.json"
test -f "$state/lifecycle-operation.json"
python3 - "$state/install-receipt.json" <<'PY'
import json,sys
receipt=json.load(open(sys.argv[1]))
assert receipt['schema']=='app.loomex.runner.install-receipt/v2'
assert len(receipt['bootstrapSha256'])==64
PY
if PATH="$no_python:/usr/bin:/bin" LOOMEX_INSTALL_TEST_MODE=1 LOOMEX_TEST_UNINSTALL_FAIL_AFTER_PAYLOAD=1 "$unlauncher" --install-base "$base" --state-dir "$state" --launch-agents-dir "$agents"; then
  echo "faulted uninstall unexpectedly completed" >&2
  exit 1
else
  :
fi
test -x "$state/bootstrap-uninstall-helper"
test ! -e "$base/versions/$version"
# `current` now points at a removed payload; retry must resolve the verified
# state-owned helper and complete the journal.
if PATH="$no_python:/usr/bin:/bin" LOOMEX_INSTALL_TEST_MODE=1 LOOMEX_TEST_UNINSTALL_FAIL_AFTER_RECEIPT_REMOVAL=1 "$unlauncher" --install-base "$base" --state-dir "$state" --launch-agents-dir "$agents"; then
  echo "post-receipt-removal fault unexpectedly completed" >&2
  exit 1
fi
test ! -e "$state/install-receipt.json"
test -f "$state/bootstrap-uninstall.json"
test -x "$state/bootstrap-uninstall-helper"
# The receipt-less retry validates the sealed journal helper before executing
# it, then faults after journal removal and before helper unlink.
if PATH="$no_python:/usr/bin:/bin" LOOMEX_INSTALL_TEST_MODE=1 LOOMEX_TEST_UNINSTALL_FAIL_AFTER_JOURNAL_REMOVAL=1 "$unlauncher" --install-base "$base" --state-dir "$state" --launch-agents-dir "$agents"; then
  echo "post-journal-removal fault unexpectedly completed" >&2
  exit 1
fi
test -f "$state/bootstrap-uninstall-terminal.json"
test -x "$state/bootstrap-uninstall-helper"
# The metadata is terminal at this point, so the thin launcher recognizes the
# exact completed state without trying to execute a removed payload.
PATH="$no_python:/usr/bin:/bin" LOOMEX_INSTALL_TEST_MODE=1 "$unlauncher" --install-base "$base" --state-dir "$state" --launch-agents-dir "$agents"
test ! -e "$base/current"
test ! -e "$state/install-receipt.json"
test ! -e "$state/bootstrap-uninstall-helper"
test ! -e "$state/bootstrap-uninstall-terminal.json"

# A helper at the same path without the sealed terminal marker is unrelated
# state and must never be removed by the launcher.
never_base="$fixture/never-base"; never_state="$fixture/never-state"; mkdir -p "$never_state"
printf unrelated > "$never_state/bootstrap-uninstall-helper"; chmod 0755 "$never_state/bootstrap-uninstall-helper"
if "$unlauncher" --install-base "$never_base" --state-dir "$never_state" --launch-agents-dir "$fixture/never-agents" >/dev/null 2>&1; then
  echo "launcher accepted an unrelated helper without a terminal marker" >&2
  exit 1
fi
test -f "$never_state/bootstrap-uninstall-helper"

legacy="$fixture/legacy-release"; mkdir "$legacy"
if "$launcher" "$legacy" >/dev/null 2>&1; then
  echo "launcher accepted a release without a native bootstrap" >&2
  exit 1
fi

# A production launcher must establish the manifest signature boundary before
# it executes the sidecar. Rebinding both the manifest's bootstrap hash and
# the sidecar itself still leaves the old signature invalid.
openssl genrsa -out "$fixture/private.pem" 2048 >/dev/null 2>&1
openssl rsa -in "$fixture/private.pem" -pubout -out "$fixture/public.pem" >/dev/null 2>&1
signed="$fixture/signed"
SOURCE_DATE_EPOCH=1 python3 "$repo/scripts/artifact.py" create --payload "$payload" --output "$signed" --project loomex-runner --version "$version" --platform darwin-arm64 --source-revision packaging-fixture --signing-key "$fixture/private.pem" --bootstrap "$payload/bin/loomex-lifecycle-bootstrap"
tampered="$fixture/tampered"; cp -R "$signed" "$tampered"
printf tampered > "$tampered/loomex-lifecycle-bootstrap"; chmod 0755 "$tampered/loomex-lifecycle-bootstrap"
python3 - "$tampered/manifest.json" "$tampered/loomex-lifecycle-bootstrap" <<'PY'
import hashlib,json,sys
manifest,binary=sys.argv[1:]
data=json.load(open(manifest)); data['bootstrap']['sha256']=hashlib.sha256(open(binary,'rb').read()).hexdigest(); data['bootstrap']['size']=len(open(binary,'rb').read())
open(manifest,'w').write(json.dumps(data,sort_keys=True,separators=(',',':'))+'\n')
PY
if "$launcher" "$tampered" --public-key "$fixture/public.pem" >/dev/null 2>&1; then
  echo "launcher executed a bootstrap after its signed manifest was replaced" >&2
  exit 1
fi
echo "runner packaging tests passed"
