#!/bin/bash
set -euo pipefail
repo="$(cd "$(dirname "$0")/.." && pwd -P)"; fixture="$(mktemp -d)"; trap 'rm -rf "$fixture"' EXIT
mkdir "$fixture/existing-output"
if "$repo/scripts/build-release.sh" --unsigned-development --output "$fixture/existing-output" >/dev/null 2>&1; then echo "build replaced an existing output directory" >&2; exit 1; fi
base="$(python3 -c 'from pathlib import Path; import sys; print(Path(sys.argv[1]).resolve())' "$fixture/install")"; state="$(python3 -c 'from pathlib import Path; import sys; print(Path(sys.argv[1]).resolve())' "$fixture/state")"; agents="$(python3 -c 'from pathlib import Path; import sys; print(Path(sys.argv[1]).resolve())' "$fixture/agents")"; mkdir -p "$base" "$state" "$agents"

make_payload(){
  version="$1"; payload="$2"
  mkdir -p "$payload/bin" "$payload/metadata" "$payload/launchd"
  printf '%s\n' '#!/bin/bash' "VERSION='$version'" 'track(){ [[ ! -f "${LOOMEX_STATE_DIR}/test-track-uninstall" ]] || printf '\''%s\n'\'' "$1" >> "${LOOMEX_STATE_DIR}/test-uninstall-order"; }' 'case "${1:-}" in' 'status) track status; if [[ -f "${LOOMEX_STATE_DIR}/test-race" && ! -f "${LOOMEX_STATE_DIR}/drain.json" ]]; then touch "${LOOMEX_STATE_DIR}/test-race-triggered"; active=1; else active="$(test -f "${LOOMEX_STATE_DIR}/test-active" && cat "${LOOMEX_STATE_DIR}/test-active" || printf 0)"; fi; reported="$VERSION"; [[ ! -f "${LOOMEX_STATE_DIR}/test-health-bad" ]] || reported=bad; [[ -f "${LOOMEX_STATE_DIR}/drain.json" ]] && draining=true || draining=false; printf '\''{"version":"%s","activeJobs":%s,"draining":%s,"updateDeferred":false}\n'\'' "$reported" "$active" "$draining";;' 'drain) track drain; touch "${LOOMEX_STATE_DIR}/drain.json"; printf '\''{"updateDeferred":true}\n'\'';;' 'logout) track logout; [[ "${2:-}" == --offline ]] || exit 70; [[ -f "${LOOMEX_STATE_DIR}/uninstall-ready.json" ]] || exit 71; [[ ! -f "${LOOMEX_STATE_DIR}/test-logout-fail" ]] || exit 72; touch "${LOOMEX_STATE_DIR}/test-revoked";;' '*) exit 0;;' 'esac' > "$payload/bin/loomex"
  printf '%s\n' '#!/bin/bash' 'exit 0' > "$payload/bin/loomex-runner"
  chmod 0755 "$payload/bin/loomex" "$payload/bin/loomex-runner"
  python3 - "$version" "$payload/metadata/project.json" <<'PY'
import json,sys
from pathlib import Path
v,o=sys.argv[1:]; Path(o).write_text(json.dumps({'project':'loomex-runner','version':v,'platform':'darwin-arm64','stateSchema':'app.loomex.runner.state/v1'},indent=2,sort_keys=True)+'\n')
PY
  cp "$repo/scripts/app.loomex.runner.template.plist" "$payload/launchd/app.loomex.runner.template.plist"
  python3 "$repo/scripts/validate_package.py" "$payload" --expected-version "$version"
}

payload="$fixture/payload"; make_payload 0.1.0 "$payload"
touch "$payload/.env"
if python3 "$repo/scripts/validate_package.py" "$payload" --expected-version 0.1.0 2>/dev/null; then echo "forbidden development file accepted" >&2; exit 1; fi
rm "$payload/.env"
openssl genrsa -out "$fixture/private.pem" 2048 >/dev/null 2>&1; openssl rsa -in "$fixture/private.pem" -pubout -out "$fixture/public.pem" >/dev/null 2>&1
signed="$fixture/signed"; SOURCE_DATE_EPOCH=1 python3 "$repo/scripts/artifact.py" create --payload "$payload" --output "$signed" --project loomex-runner --version 0.1.0 --platform darwin-arm64 --source-revision test --signing-key "$fixture/private.pem"
SOURCE_DATE_EPOCH=1 python3 "$repo/scripts/artifact.py" create --payload "$payload" --output "$fixture/signed-repeat" --project loomex-runner --version 0.1.0 --platform darwin-arm64 --source-revision test --signing-key "$fixture/private.pem"
cmp "$signed/manifest.json" "$fixture/signed-repeat/manifest.json"; cmp "$signed/payload.tar.gz" "$fixture/signed-repeat/payload.tar.gz"; cmp "$signed/manifest.sig" "$fixture/signed-repeat/manifest.sig"
if SOURCE_DATE_EPOCH=1 python3 "$repo/scripts/artifact.py" create --payload "$payload" --output "$signed" --project loomex-runner --version 0.1.0 --platform darwin-arm64 --source-revision test --signing-key "$fixture/private.pem" 2>/dev/null; then echo "artifact create overwrote an existing output" >&2; exit 1; fi
mkdir "$fixture/extract-existing"; printf preserve > "$fixture/extract-existing/sentinel"
if python3 "$repo/scripts/artifact.py" extract --release "$signed" --project loomex-runner --platform darwin-arm64 --public-key "$fixture/public.pem" --extract "$fixture/extract-existing" 2>/dev/null; then echo "artifact extract overwrote an existing destination" >&2; exit 1; fi
test "$(cat "$fixture/extract-existing/sentinel")" = preserve
python3 "$repo/scripts/artifact.py" verify --release "$signed" --project loomex-runner --platform darwin-arm64 --public-key "$fixture/public.pem"
cp "$signed/manifest.sig" "$fixture/signature"; printf ' ' >> "$signed/manifest.json"
if python3 "$repo/scripts/artifact.py" verify --release "$signed" --project loomex-runner --platform darwin-arm64 --public-key "$fixture/public.pem" 2>/dev/null; then echo "tampered manifest accepted" >&2; exit 1; fi

release="$fixture/release"; SOURCE_DATE_EPOCH=1 python3 "$repo/scripts/artifact.py" create --payload "$payload" --output "$release" --project loomex-runner --version 0.1.0 --platform darwin-arm64 --source-revision test --unsigned-development
collision_state="$fixture/collision-state"; mkdir -p "$collision_state/logs"; printf preserve > "$collision_state/logs/preexisting-unrelated"
if LOOMEX_ALLOW_UNSAFE_DEV_INSTALL=1 LOOMEX_INSTALL_TEST_MODE=1 "$repo/scripts/install.sh" "$release" --allow-unsigned-development --install-base "$fixture/collision-install" --state-dir "$collision_state" --launch-agents-dir "$fixture/collision-agents" >/dev/null 2>&1; then echo "initial install claimed a preexisting state namespace" >&2; exit 1; fi
test "$(cat "$collision_state/logs/preexisting-unrelated")" = preserve
retry_base="$fixture/retry-install"; retry_state="$fixture/retry-state"; retry_agents="$fixture/retry-agents"
if "$repo/scripts/install.sh" "$release" --install-base "$retry_base" --state-dir "$retry_state" --launch-agents-dir "$retry_agents" >/dev/null 2>&1; then echo "unsigned artifact installed without development opt-in" >&2; exit 1; fi
test ! -e "$retry_state/logs"
if LOOMEX_ALLOW_UNSAFE_DEV_INSTALL=1 LOOMEX_INSTALL_TEST_MODE=1 LOOMEX_TEST_BOOTSTRAP_FAIL=1 "$repo/scripts/install.sh" "$release" --allow-unsigned-development --install-base "$retry_base" --state-dir "$retry_state" --launch-agents-dir "$retry_agents" >/dev/null 2>&1; then echo "forced initial bootstrap failure succeeded" >&2; exit 1; fi
test ! -e "$retry_state/logs"; test ! -e "$retry_state/owned-versions.json"; test ! -e "$retry_base/versions/0.1.0"
LOOMEX_ALLOW_UNSAFE_DEV_INSTALL=1 LOOMEX_INSTALL_TEST_MODE=1 "$repo/scripts/install.sh" "$release" --allow-unsigned-development --install-base "$retry_base" --state-dir "$retry_state" --launch-agents-dir "$retry_agents" >/dev/null
touch "$retry_state/test-track-uninstall" "$retry_state/test-logout-fail"; : > "$retry_state/test-uninstall-order"
if LOOMEX_INSTALL_TEST_MODE=1 "$repo/scripts/uninstall.sh" --install-base "$retry_base" --state-dir "$retry_state" --launch-agents-dir "$retry_agents" >/dev/null 2>&1; then echo "offline revocation failure deleted installation" >&2; exit 1; fi
test -L "$retry_base/current"; test -f "$retry_state/uninstall-ready.json"; test ! -e "$retry_state/test-revoked"
test "$(paste -sd, "$retry_state/test-uninstall-order")" = "drain,status,logout"
printf interrupted > "$retry_state/uninstall-ready.json.new"
rm "$retry_state/test-logout-fail"; : > "$retry_state/test-uninstall-order"
LOOMEX_INSTALL_TEST_MODE=1 "$repo/scripts/uninstall.sh" --install-base "$retry_base" --state-dir "$retry_state" --launch-agents-dir "$retry_agents" >/dev/null
test "$(paste -sd, "$retry_state/test-uninstall-order")" = logout; test ! -e "$retry_state/uninstall-ready.json.new"
old="$base/versions/0.0.9"; mkdir -p "$old/bin" "$state"; cp "$payload/bin/loomex" "$old/bin/loomex"; ln -s "$old" "$base/current"
python3 - "$old" "$agents/app.loomex.runner.plist" "$state" <<'PY'
import json,sys
from pathlib import Path
old,agent,state=sys.argv[1:]; state=Path(state)
(state/'owned-versions.json').write_text(json.dumps({'schema':'app.loomex.runner.owned-versions/v1','paths':[old]},sort_keys=True)+'\n')
(state/'install-receipt.json').write_text(json.dumps({'schema':'app.loomex.runner.install-receipt/v1','version':'0.0.9','versionPath':old,'launchAgent':agent},sort_keys=True)+'\n')
PY
printf 1 > "$state/test-active"
LOOMEX_ALLOW_UNSAFE_DEV_INSTALL=1 LOOMEX_INSTALL_TEST_MODE=1 "$repo/scripts/install.sh" "$release" --allow-unsigned-development --install-base "$base" --state-dir "$state" --launch-agents-dir "$agents"
test "$(readlink "$base/current")" = "$old"; test -f "$state/pending-update.json"; test -f "$state/drain.json"
printf '%s\n' '{"schema":"app.loomex.runner.uninstall-ready/v1","versionPath":"'"$old"'"}' > "$state/uninstall-ready.json"; printf interrupted > "$state/uninstall-ready.json.new"
printf 0 > "$state/test-active"
LOOMEX_ALLOW_UNSAFE_DEV_INSTALL=1 LOOMEX_INSTALL_TEST_MODE=1 "$repo/scripts/install.sh" "$release" --allow-unsigned-development --install-base "$base" --state-dir "$state" --launch-agents-dir "$agents"
test "$(readlink "$base/current")" = "$base/versions/0.1.0"; test ! -e "$old"; test ! -e "$state/drain.json"; test ! -e "$state/uninstall-ready.json"; test ! -e "$state/uninstall-ready.json.new"
grep -Fq "$base/current/bin/loomex-runner" "$agents/app.loomex.runner.plist"
! grep -Fq "$old/bin/loomex-runner" "$agents/app.loomex.runner.plist"

payload2="$fixture/payload2"; make_payload 0.1.1 "$payload2"; release2="$fixture/release2"; SOURCE_DATE_EPOCH=2 python3 "$repo/scripts/artifact.py" create --payload "$payload2" --output "$release2" --project loomex-runner --version 0.1.1 --platform darwin-arm64 --source-revision test2 --unsigned-development
touch "$state/test-race"
launchctl_bin="$fixture/launchctl-bin"; mkdir "$launchctl_bin"; touch "$state/test-launchctl-loaded"; : > "$state/test-launchctl-log"
printf '%s\n' '#!/bin/bash' "log='$state/test-launchctl-log'; loaded='$state/test-launchctl-loaded'" 'printf '\''%s\n'\'' "$1" >> "$log"' 'case "$1" in bootout) rm -f "$loaded";; bootstrap) [[ ! -e "$loaded" ]] || exit 1; touch "$loaded";; *) exit 1;; esac' > "$launchctl_bin/launchctl"; chmod 0755 "$launchctl_bin/launchctl"
if PATH="$launchctl_bin:$PATH" LOOMEX_ALLOW_UNSAFE_DEV_INSTALL=1 LOOMEX_TEST_HEALTH_FAIL=1 "$repo/scripts/install.sh" "$release2" --allow-unsigned-development --install-base "$base" --state-dir "$state" --launch-agents-dir "$agents" 2>/dev/null; then echo "unhealthy accepted service was treated as activated" >&2; exit 1; fi
test "$(readlink "$base/current")" = "$base/versions/0.1.0"; test ! -e "$base/versions/0.1.1"; test ! -e "$state/test-race-triggered"
test "$(paste -sd, "$state/test-launchctl-log")" = "bootout,bootstrap,bootout,bootstrap"
payload3="$fixture/payload3"; make_payload 0.1.2 "$payload3"; release3="$fixture/release3"; SOURCE_DATE_EPOCH=3 python3 "$repo/scripts/artifact.py" create --payload "$payload3" --output "$release3" --project loomex-runner --version 0.1.2 --platform darwin-arm64 --source-revision test3 --unsigned-development
printf 1 > "$state/test-active"
LOOMEX_ALLOW_UNSAFE_DEV_INSTALL=1 LOOMEX_INSTALL_TEST_MODE=1 "$repo/scripts/install.sh" "$release2" --allow-unsigned-development --install-base "$base" --state-dir "$state" --launch-agents-dir "$agents"
LOOMEX_ALLOW_UNSAFE_DEV_INSTALL=1 LOOMEX_INSTALL_TEST_MODE=1 "$repo/scripts/install.sh" "$release3" --allow-unsigned-development --install-base "$base" --state-dir "$state" --launch-agents-dir "$agents"
test -d "$base/versions/0.1.1"; test -d "$base/versions/0.1.2"
python3 - "$state/owned-versions.json" "$base" <<'PY'
import json,sys
data=json.load(open(sys.argv[1])); base=sys.argv[2]
assert data['paths']==[f'{base}/versions/0.1.0',f'{base}/versions/0.1.1',f'{base}/versions/0.1.2']
PY
test "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["path"])' "$state/pending-update.json")" = "$base/versions/0.1.2"
touch "$state/test-track-uninstall"; : > "$state/test-uninstall-order"
if LOOMEX_INSTALL_TEST_MODE=1 "$repo/scripts/uninstall.sh" --install-base "$base" --state-dir "$state" --launch-agents-dir "$agents" >/dev/null 2>&1; then echo "active uninstall removed installation" >&2; exit 1; fi
test -L "$base/current"; test ! -e "$state/uninstall-ready.json"; test ! -e "$state/test-revoked"; test "$(paste -sd, "$state/test-uninstall-order")" = "drain,status"
printf 0 > "$state/test-active"; printf preserve > "$state/unrelated-sentinel"; : > "$state/test-uninstall-order"
LOOMEX_INSTALL_TEST_MODE=1 "$repo/scripts/uninstall.sh" --install-base "$base" --state-dir "$state" --launch-agents-dir "$agents"
test "$(paste -sd, "$state/test-uninstall-order")" = "drain,status,logout"
test "$(cat "$state/unrelated-sentinel")" = preserve; test -f "$state/test-revoked"; test ! -e "$base/current"; test ! -e "$base/versions/0.1.0"; test ! -e "$base/versions/0.1.1"; test ! -e "$base/versions/0.1.2"

victim="$fixture/victim"; mkdir "$victim"; printf preserve > "$victim/sentinel"
attack_base="$fixture/attack-install"; attack_state="$fixture/attack-state"; attack_agents="$fixture/attack-agents"; mkdir -p "$attack_base/versions" "$attack_state" "$attack_agents"
ln -s "$victim" "$attack_base/current"
printf '%s\n' '{"schema":"app.loomex.runner.install-receipt/v1","version":"9.9.9","versionPath":"'"$victim"'","launchAgent":"'"$attack_agents/app.loomex.runner.plist"'"}' > "$attack_state/install-receipt.json"
printf '%s\n' '{"schema":"app.loomex.runner.owned-versions/v1","paths":["'"$victim"'"]}' > "$attack_state/owned-versions.json"
if LOOMEX_INSTALL_TEST_MODE=1 "$repo/scripts/uninstall.sh" --install-base "$attack_base" --state-dir "$attack_state" --launch-agents-dir "$attack_agents" >/dev/null 2>&1; then echo "traversal uninstall target accepted" >&2; exit 1; fi
test "$(cat "$victim/sentinel")" = preserve
symlink_base="$fixture/symlink-install"; mkdir "$symlink_base"; ln -s "$victim" "$symlink_base/versions"
if LOOMEX_ALLOW_UNSAFE_DEV_INSTALL=1 LOOMEX_INSTALL_TEST_MODE=1 "$repo/scripts/install.sh" "$release" --allow-unsigned-development --install-base "$symlink_base" --state-dir "$fixture/symlink-state" --launch-agents-dir "$fixture/symlink-agents" >/dev/null 2>&1; then echo "symlinked versions directory accepted" >&2; exit 1; fi
test "$(cat "$victim/sentinel")" = preserve
echo "runner packaging tests passed"
