#!/bin/bash
set -euo pipefail
repo="$(cd "$(dirname "$0")/.." && pwd -P)"; fixture="$(mktemp -d)"; trap 'rm -rf "$fixture"' EXIT
dev_origin="http://127.0.0.1:9"
mkdir "$fixture/existing-output"
if "$repo/scripts/build-release.sh" --unsigned-development --output "$fixture/existing-output" >/dev/null 2>&1; then echo "build replaced an existing output directory" >&2; exit 1; fi
base="$(python3 -c 'from pathlib import Path; import sys; print(Path(sys.argv[1]).resolve())' "$fixture/install")"; state="$(python3 -c 'from pathlib import Path; import sys; print(Path(sys.argv[1]).resolve())' "$fixture/state")"; agents="$(python3 -c 'from pathlib import Path; import sys; print(Path(sys.argv[1]).resolve())' "$fixture/agents")"; mkdir -p "$base" "$state" "$agents"
provider_bin="$fixture/provider-bin"; mkdir "$provider_bin"; provider_bin="$(cd "$provider_bin" && pwd -P)"
for provider in codex claude gemini; do printf '%s\n' '#!/bin/bash' 'exit 0' > "$provider_bin/$provider"; chmod 0755 "$provider_bin/$provider"; done
printf '%s\n' '#!/bin/bash' 'exit 0' > "$provider_bin/not-executable"; chmod 0644 "$provider_bin/not-executable"
ln -s "$provider_bin/codex" "$fixture/codex-link"

make_payload(){
  version="$1"; payload="$2"
  mkdir -p "$payload/bin" "$payload/metadata" "$payload/launchd"
  printf '%s\n' '#!/bin/bash' "VERSION='$version'" 'track(){ [[ ! -f "${LOOMEX_STATE_DIR}/test-track-uninstall" ]] || printf '\''%s\n'\'' "$1" >> "${LOOMEX_STATE_DIR}/test-uninstall-order"; }' 'case "${1:-}" in' 'status) track status; if [[ -f "${LOOMEX_STATE_DIR}/test-race" && ! -f "${LOOMEX_STATE_DIR}/drain.json" ]]; then touch "${LOOMEX_STATE_DIR}/test-race-triggered"; active=1; else active="$(test -f "${LOOMEX_STATE_DIR}/test-active" && cat "${LOOMEX_STATE_DIR}/test-active" || printf 0)"; fi; reported="$VERSION"; [[ ! -f "${LOOMEX_STATE_DIR}/test-health-bad" ]] || reported=bad; [[ -f "${LOOMEX_STATE_DIR}/drain.json" ]] && draining=true || draining=false; printf '\''{"version":"%s","activeJobs":%s,"draining":%s,"updateDeferred":false}\n'\'' "$reported" "$active" "$draining";;' 'drain) track drain; touch "${LOOMEX_STATE_DIR}/drain.json"; printf '\''{"updateDeferred":true}\n'\'';;' 'logout) track logout; [[ "${2:-}" == --offline ]] || exit 70; [[ -f "${LOOMEX_STATE_DIR}/uninstall-ready.json" ]] || exit 71; [[ ! -f "${LOOMEX_STATE_DIR}/test-logout-fail" ]] || exit 72; [[ "${LOOMEX_DEV_API_ORIGIN:-}" == "http://127.0.0.1:9/" ]] || exit 73; touch "${LOOMEX_STATE_DIR}/test-revoked";;' '*) exit 0;;' 'esac' > "$payload/bin/loomex"
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
for invalid_origin in 'http://example.com' 'http://user@127.0.0.1:9' 'http://127.0.0.1:9/path' 'http://127.0.0.1:9?query' 'http://127.0.0.1:9#fragment' 'http://[::1%lo0]:9' 'http://[::1%25lo0]:9'; do
  if python3 "$repo/scripts/validate_development_origin.py" "$invalid_origin" >/dev/null 2>&1; then echo "invalid development origin accepted: $invalid_origin" >&2; exit 1; fi
done
test "$(python3 "$repo/scripts/validate_development_origin.py" 'HTTP://LOCALHOST:8000')" = 'http://localhost:8000/'
test "$(python3 "$repo/scripts/validate_development_origin.py" 'http://[::1]:8000')" = 'http://[::1]:8000/'
python3 - "$provider_bin" "$fixture/provider-executables.json" <<'PY'
import json,sys
from pathlib import Path
root=Path(sys.argv[1]); Path(sys.argv[2]).write_text(json.dumps({name:str((root/name).resolve()) for name in ('codex','claude','gemini')})+'\n')
PY
python3 "$repo/scripts/render_launch_agent.py" --template "$repo/scripts/app.loomex.runner.template.plist" --binary "$fixture/bin/loomex-runner" --state "$fixture/render-state" --development-api-origin 'http://[::1]:8000' --provider-executables-file "$fixture/provider-executables.json" --output "$fixture/development.plist"
python3 "$repo/scripts/render_launch_agent.py" --template "$repo/scripts/app.loomex.runner.template.plist" --binary "$fixture/bin/loomex-runner" --state "$fixture/render-state" --output "$fixture/production.plist"
python3 - "$fixture/development.plist" "$fixture/production.plist" "$provider_bin" <<'PY'
import plistlib,sys
from pathlib import Path
development=plistlib.load(open(sys.argv[1],'rb'))['EnvironmentVariables']
production=plistlib.load(open(sys.argv[2],'rb'))['EnvironmentVariables']
assert development=={'LOOMEX_STATE_DIR':sys.argv[1].rsplit('/',1)[0]+'/render-state','LOOMEX_DEV_API_ORIGIN':'http://[::1]:8000/','LOOMEX_CODEX_EXECUTABLE':str(Path(sys.argv[3],'codex').resolve()),'LOOMEX_CLAUDE_EXECUTABLE':str(Path(sys.argv[3],'claude').resolve()),'LOOMEX_GEMINI_EXECUTABLE':str(Path(sys.argv[3],'gemini').resolve())}
assert production=={'LOOMEX_STATE_DIR':sys.argv[1].rsplit('/',1)[0]+'/render-state'}
PY
printf '%s\n' '{"codex":"/missing/provider"}' > "$fixture/missing-provider.json"
if python3 "$repo/scripts/render_launch_agent.py" --template "$repo/scripts/app.loomex.runner.template.plist" --binary "$fixture/bin/loomex-runner" --state "$fixture/render-state" --provider-executables-file "$fixture/missing-provider.json" --output "$fixture/invalid-provider.plist" 2>/dev/null; then echo "LaunchAgent renderer accepted a missing configured provider" >&2; exit 1; fi
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
production_release="$fixture/production-release"; SOURCE_DATE_EPOCH=1 python3 "$repo/scripts/artifact.py" create --payload "$payload" --output "$production_release" --project loomex-runner --version 0.1.0 --platform darwin-arm64 --source-revision test --signing-key "$fixture/private.pem"
if "$repo/scripts/install.sh" "$production_release" --public-key "$fixture/public.pem" --development-api-origin "$dev_origin" --install-base "$fixture/production-install" --state-dir "$fixture/production-state" --launch-agents-dir "$fixture/production-agents" >/dev/null 2>&1; then echo "production artifact accepted a development API origin" >&2; exit 1; fi
test ! -e "$fixture/production-state/logs"
if LOOMEX_ALLOW_UNSAFE_DEV_INSTALL=1 LOOMEX_INSTALL_TEST_MODE=1 "$repo/scripts/install.sh" "$release" --allow-unsigned-development --install-base "$fixture/missing-origin-install" --state-dir "$fixture/missing-origin-state" --launch-agents-dir "$fixture/missing-origin-agents" >/dev/null 2>&1; then echo "development artifact installed without an API origin" >&2; exit 1; fi
test ! -e "$fixture/missing-origin-state/logs"
for invalid_origin in 'http://example.com' 'http://user@127.0.0.1:9' 'http://127.0.0.1:9/path' 'http://127.0.0.1:9?query' 'http://127.0.0.1:9#fragment' 'http://[::1%lo0]:9' 'http://[::1%25lo0]:9'; do
  suffix="$(printf %s "$invalid_origin" | shasum -a 256 | cut -c1-8)"
  if LOOMEX_ALLOW_UNSAFE_DEV_INSTALL=1 LOOMEX_INSTALL_TEST_MODE=1 "$repo/scripts/install.sh" "$release" --allow-unsigned-development --development-api-origin "$invalid_origin" --install-base "$fixture/invalid-install-$suffix" --state-dir "$fixture/invalid-state-$suffix" --launch-agents-dir "$fixture/invalid-agents-$suffix" >/dev/null 2>&1; then echo "installer accepted invalid development origin: $invalid_origin" >&2; exit 1; fi
  test ! -e "$fixture/invalid-state-$suffix/logs"
done
for invalid_provider in 'unknown=/bin/sh' 'codex=relative/path' 'codex=/missing/provider'; do
  suffix="$(printf %s "$invalid_provider" | shasum -a 256 | cut -c1-8)"
  if LOOMEX_ALLOW_UNSAFE_DEV_INSTALL=1 LOOMEX_INSTALL_TEST_MODE=1 "$repo/scripts/install.sh" "$release" --allow-unsigned-development --development-api-origin "$dev_origin" --provider-executable "$invalid_provider" --install-base "$fixture/invalid-provider-install-$suffix" --state-dir "$fixture/invalid-provider-state-$suffix" --launch-agents-dir "$fixture/invalid-provider-agents-$suffix" >/dev/null 2>&1; then echo "installer accepted invalid provider executable: $invalid_provider" >&2; exit 1; fi
  test ! -e "$fixture/invalid-provider-state-$suffix/logs"
done
if LOOMEX_ALLOW_UNSAFE_DEV_INSTALL=1 LOOMEX_INSTALL_TEST_MODE=1 "$repo/scripts/install.sh" "$release" --allow-unsigned-development --development-api-origin "$dev_origin" --provider-executable "codex=$provider_bin/not-executable" --install-base "$fixture/nonexec-install" --state-dir "$fixture/nonexec-state" --launch-agents-dir "$fixture/nonexec-agents" >/dev/null 2>&1; then echo "installer accepted a non-executable provider file" >&2; exit 1; fi
test ! -e "$fixture/nonexec-state/logs"
collision_state="$fixture/collision-state"; mkdir -p "$collision_state/logs"; printf preserve > "$collision_state/logs/preexisting-unrelated"
if LOOMEX_ALLOW_UNSAFE_DEV_INSTALL=1 LOOMEX_INSTALL_TEST_MODE=1 "$repo/scripts/install.sh" "$release" --allow-unsigned-development --development-api-origin "$dev_origin" --install-base "$fixture/collision-install" --state-dir "$collision_state" --launch-agents-dir "$fixture/collision-agents" >/dev/null 2>&1; then echo "initial install claimed a preexisting state namespace" >&2; exit 1; fi
test "$(cat "$collision_state/logs/preexisting-unrelated")" = preserve
retry_base="$fixture/retry-install"; retry_state="$fixture/retry-state"; retry_agents="$fixture/retry-agents"
if "$repo/scripts/install.sh" "$release" --install-base "$retry_base" --state-dir "$retry_state" --launch-agents-dir "$retry_agents" >/dev/null 2>&1; then echo "unsigned artifact installed without development opt-in" >&2; exit 1; fi
test ! -e "$retry_state/logs"
if LOOMEX_ALLOW_UNSAFE_DEV_INSTALL=1 LOOMEX_INSTALL_TEST_MODE=1 LOOMEX_TEST_BOOTSTRAP_FAIL=1 "$repo/scripts/install.sh" "$release" --allow-unsigned-development --development-api-origin "$dev_origin" --install-base "$retry_base" --state-dir "$retry_state" --launch-agents-dir "$retry_agents" >/dev/null 2>&1; then echo "forced initial bootstrap failure succeeded" >&2; exit 1; fi
test ! -e "$retry_state/logs"; test ! -e "$retry_state/owned-versions.json"; test ! -e "$retry_base/versions/0.1.0"
LOOMEX_ALLOW_UNSAFE_DEV_INSTALL=1 LOOMEX_INSTALL_TEST_MODE=1 "$repo/scripts/install.sh" "$release" --allow-unsigned-development --development-api-origin "$dev_origin" --provider-executable "codex=$fixture/codex-link" --install-base "$retry_base" --state-dir "$retry_state" --launch-agents-dir "$retry_agents" >/dev/null
python3 - "$retry_agents/app.loomex.runner.plist" "$retry_state/install-receipt.json" "$provider_bin/codex" <<'PY'
import json,plistlib,sys
environment=plistlib.load(open(sys.argv[1],'rb'))['EnvironmentVariables']
receipt=json.load(open(sys.argv[2]))
assert environment['LOOMEX_DEV_API_ORIGIN']=='http://127.0.0.1:9/'
assert environment['LOOMEX_CODEX_EXECUTABLE']==sys.argv[3]
assert receipt['developmentOnly'] is True
assert receipt['developmentApiOrigin']=='http://127.0.0.1:9/'
assert receipt['providerExecutables']=={'codex':sys.argv[3]}
PY
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
LOOMEX_ALLOW_UNSAFE_DEV_INSTALL=1 LOOMEX_INSTALL_TEST_MODE=1 "$repo/scripts/install.sh" "$release" --allow-unsigned-development --development-api-origin "$dev_origin" --provider-executable "codex=$fixture/codex-link" --install-base "$base" --state-dir "$state" --launch-agents-dir "$agents"
test "$(readlink "$base/current")" = "$old"; test -f "$state/pending-update.json"; test -f "$state/drain.json"
test "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["providerExecutables"]["codex"])' "$state/pending-update.json")" = "$provider_bin/codex"
printf '%s\n' '{"schema":"app.loomex.runner.uninstall-ready/v1","versionPath":"'"$old"'"}' > "$state/uninstall-ready.json"; printf interrupted > "$state/uninstall-ready.json.new"
printf 0 > "$state/test-active"
LOOMEX_ALLOW_UNSAFE_DEV_INSTALL=1 LOOMEX_INSTALL_TEST_MODE=1 "$repo/scripts/install.sh" "$release" --allow-unsigned-development --development-api-origin "$dev_origin" --install-base "$base" --state-dir "$state" --launch-agents-dir "$agents"
test "$(readlink "$base/current")" = "$base/versions/0.1.0"; test ! -e "$old"; test ! -e "$state/drain.json"; test ! -e "$state/uninstall-ready.json"; test ! -e "$state/uninstall-ready.json.new"
grep -Fq "$base/current/bin/loomex-runner" "$agents/app.loomex.runner.plist"
! grep -Fq "$old/bin/loomex-runner" "$agents/app.loomex.runner.plist"
python3 - "$agents/app.loomex.runner.plist" "$state/install-receipt.json" "$provider_bin/codex" <<'PY'
import json,plistlib,sys
environment=plistlib.load(open(sys.argv[1],'rb'))['EnvironmentVariables']; receipt=json.load(open(sys.argv[2]))
assert environment['LOOMEX_CODEX_EXECUTABLE']==sys.argv[3]
assert receipt['providerExecutables']=={'codex':sys.argv[3]}
PY

payload2="$fixture/payload2"; make_payload 0.1.1 "$payload2"; release2="$fixture/release2"; SOURCE_DATE_EPOCH=2 python3 "$repo/scripts/artifact.py" create --payload "$payload2" --output "$release2" --project loomex-runner --version 0.1.1 --platform darwin-arm64 --source-revision test2 --unsigned-development
touch "$state/test-race"
launchctl_bin="$fixture/launchctl-bin"; mkdir "$launchctl_bin"; touch "$state/test-launchctl-loaded"; : > "$state/test-launchctl-log"
printf '%s\n' '#!/bin/bash' "log='$state/test-launchctl-log'; loaded='$state/test-launchctl-loaded'" 'printf '\''%s\n'\'' "$1" >> "$log"' 'case "$1" in bootout) rm -f "$loaded";; bootstrap) [[ ! -e "$loaded" ]] || exit 1; touch "$loaded";; *) exit 1;; esac' > "$launchctl_bin/launchctl"; chmod 0755 "$launchctl_bin/launchctl"
if PATH="$launchctl_bin:$PATH" LOOMEX_ALLOW_UNSAFE_DEV_INSTALL=1 LOOMEX_TEST_HEALTH_FAIL=1 "$repo/scripts/install.sh" "$release2" --allow-unsigned-development --development-api-origin "$dev_origin" --provider-executable "codex=$provider_bin/claude" --install-base "$base" --state-dir "$state" --launch-agents-dir "$agents" 2>/dev/null; then echo "unhealthy accepted service was treated as activated" >&2; exit 1; fi
test "$(readlink "$base/current")" = "$base/versions/0.1.0"; test ! -e "$base/versions/0.1.1"; test ! -e "$state/test-race-triggered"
test "$(paste -sd, "$state/test-launchctl-log")" = "bootout,bootstrap,bootout,bootstrap"
python3 - "$agents/app.loomex.runner.plist" "$state/install-receipt.json" "$provider_bin/codex" <<'PY'
import json,plistlib,sys
assert plistlib.load(open(sys.argv[1],'rb'))['EnvironmentVariables']['LOOMEX_CODEX_EXECUTABLE']==sys.argv[3]
assert json.load(open(sys.argv[2]))['providerExecutables']=={'codex':sys.argv[3]}
PY
payload3="$fixture/payload3"; make_payload 0.1.2 "$payload3"; release3="$fixture/release3"; SOURCE_DATE_EPOCH=3 python3 "$repo/scripts/artifact.py" create --payload "$payload3" --output "$release3" --project loomex-runner --version 0.1.2 --platform darwin-arm64 --source-revision test3 --unsigned-development
printf 1 > "$state/test-active"
LOOMEX_ALLOW_UNSAFE_DEV_INSTALL=1 LOOMEX_INSTALL_TEST_MODE=1 "$repo/scripts/install.sh" "$release2" --allow-unsigned-development --development-api-origin "$dev_origin" --install-base "$base" --state-dir "$state" --launch-agents-dir "$agents"
LOOMEX_ALLOW_UNSAFE_DEV_INSTALL=1 LOOMEX_INSTALL_TEST_MODE=1 "$repo/scripts/install.sh" "$release3" --allow-unsigned-development --development-api-origin "$dev_origin" --install-base "$base" --state-dir "$state" --launch-agents-dir "$agents"
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
printf 0 > "$state/test-active"; printf preserve > "$state/unrelated-sentinel"; touch "$state/presentation.sqlite3" "$state/presentation.sqlite3-wal" "$state/presentation.sqlite3-shm"; : > "$state/test-uninstall-order"
LOOMEX_INSTALL_TEST_MODE=1 "$repo/scripts/uninstall.sh" --install-base "$base" --state-dir "$state" --launch-agents-dir "$agents"
test "$(paste -sd, "$state/test-uninstall-order")" = "drain,status,logout"
test "$(cat "$state/unrelated-sentinel")" = preserve; test -f "$state/test-revoked"; test ! -e "$state/presentation.sqlite3"; test ! -e "$state/presentation.sqlite3-wal"; test ! -e "$state/presentation.sqlite3-shm"; test ! -e "$base/current"; test ! -e "$base/versions/0.1.0"; test ! -e "$base/versions/0.1.1"; test ! -e "$base/versions/0.1.2"

victim="$fixture/victim"; mkdir "$victim"; printf preserve > "$victim/sentinel"
attack_base="$fixture/attack-install"; attack_state="$fixture/attack-state"; attack_agents="$fixture/attack-agents"; mkdir -p "$attack_base/versions" "$attack_state" "$attack_agents"
ln -s "$victim" "$attack_base/current"
printf '%s\n' '{"schema":"app.loomex.runner.install-receipt/v1","version":"9.9.9","versionPath":"'"$victim"'","launchAgent":"'"$attack_agents/app.loomex.runner.plist"'"}' > "$attack_state/install-receipt.json"
printf '%s\n' '{"schema":"app.loomex.runner.owned-versions/v1","paths":["'"$victim"'"]}' > "$attack_state/owned-versions.json"
if LOOMEX_INSTALL_TEST_MODE=1 "$repo/scripts/uninstall.sh" --install-base "$attack_base" --state-dir "$attack_state" --launch-agents-dir "$attack_agents" >/dev/null 2>&1; then echo "traversal uninstall target accepted" >&2; exit 1; fi
test "$(cat "$victim/sentinel")" = preserve
symlink_base="$fixture/symlink-install"; mkdir "$symlink_base"; ln -s "$victim" "$symlink_base/versions"
if LOOMEX_ALLOW_UNSAFE_DEV_INSTALL=1 LOOMEX_INSTALL_TEST_MODE=1 "$repo/scripts/install.sh" "$release" --allow-unsigned-development --development-api-origin "$dev_origin" --install-base "$symlink_base" --state-dir "$fixture/symlink-state" --launch-agents-dir "$fixture/symlink-agents" >/dev/null 2>&1; then echo "symlinked versions directory accepted" >&2; exit 1; fi
test "$(cat "$victim/sentinel")" = preserve
echo "runner packaging tests passed"
