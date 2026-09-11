#!/bin/bash
set -euo pipefail

usage(){ echo "usage: $0 RELEASE_DIR [--public-key FILE | --allow-unsigned-development --development-api-origin LOOPBACK_URL] [--provider-executable PROVIDER=/absolute/path] [--install-base DIR --state-dir DIR --launch-agents-dir DIR]" >&2; exit 2; }
[[ $# -ge 1 ]] || usage
release="$(cd "$1" && pwd -P)"; shift
public_key=""; allow_dev=0; development_origin=""; base=""; state=""; agents=""; provider_specs=(); provider_spec_count=0
while (($#)); do
  case "$1" in
    --public-key) public_key="${2:?}"; shift 2;;
    --allow-unsigned-development) allow_dev=1; shift;;
    --development-api-origin) development_origin="${2:?}"; shift 2;;
    --provider-executable) provider_specs+=("${2:?}"); provider_spec_count=$((provider_spec_count+1)); shift 2;;
    --install-base) base="${2:?}"; shift 2;;
    --state-dir) state="${2:?}"; shift 2;;
    --launch-agents-dir) agents="${2:?}"; shift 2;;
    *) usage;;
  esac
done

repo="$(cd "$(dirname "$0")/.." && pwd -P)"; manifest="$release/manifest.json"
[[ -f "$manifest" ]] || { echo "release manifest missing" >&2; exit 1; }
version="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["version"])' "$manifest")"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "invalid release version" >&2; exit 1; }
base="${base:-${HOME:?}/Library/Application Support/Loomex/runner}"
state="${state:-${HOME:?}/.local/share/loomex/runner}"
agents="${agents:-${HOME:?}/Library/LaunchAgents}"
base="$(python3 -c 'from pathlib import Path; import sys; print(Path(sys.argv[1]).resolve())' "$base")"
state="$(python3 -c 'from pathlib import Path; import sys; print(Path(sys.argv[1]).resolve())' "$state")"
agents="$(python3 -c 'from pathlib import Path; import sys; print(Path(sys.argv[1]).resolve())' "$agents")"
for path in "$base" "$state" "$agents"; do [[ "$path" != / && "$path" != "${HOME:-}" ]] || { echo "unsafe installation directory: $path" >&2; exit 1; }; done
versions="$base/versions"
[[ ! -L "$versions" ]] || { echo "versions directory may not be a symlink" >&2; exit 1; }
install_journal="$state/install-operation.json"
owned_state_names=(state.json operations preparations jobs tombstones run-bindings preparation-tombstones responses presentation.sqlite3 presentation.sqlite3-wal presentation.sqlite3-shm follow.sqlite3 follow.sqlite3-wal follow.sqlite3-shm recovery.sqlite3 recovery.sqlite3-wal recovery.sqlite3-shm daemon.lock control.sock pending-update.json uninstall-ready.json uninstall-ready.json.new install-operation.json install-receipt.json owned-versions.json logs drain.json)
[[ ! -L "$install_journal" && ! -L "$install_journal.new" ]] || { echo "installation journal may not be a symlink" >&2; exit 1; }
fresh_state=0
resuming_install=0
if [[ ! -f "$state/install-receipt.json" && ! -f "$state/owned-versions.json" && ! -f "$install_journal" ]]; then
  fresh_state=1
  for name in "${owned_state_names[@]}"; do
    [[ ! -e "$state/$name" && ! -L "$state/$name" ]] || { echo "unowned runner state namespace already exists: $state/$name" >&2; exit 1; }
  done
elif [[ ! -f "$state/install-receipt.json" && -f "$install_journal" ]]; then
  # A process may have died anywhere from the pre-move journal write through
  # activation.  Permit only that narrow state shape, then require the verified
  # release below to match its journal exactly.
  resuming_install=1
  fresh_state=1
  for name in "${owned_state_names[@]}"; do
    case "$name" in
      install-operation.json|install-operation.json.new|owned-versions.json) continue;;
      logs) [[ ! -L "$state/$name" ]] || { echo "installation logs directory may not be a symlink" >&2; exit 1; }; continue;;
    esac
    [[ ! -e "$state/$name" && ! -L "$state/$name" ]] || { echo "unexpected state alongside incomplete installation journal: $state/$name" >&2; exit 1; }
  done
elif [[ -f "$state/install-receipt.json" && -f "$state/owned-versions.json" ]]; then
  : # An installed runner may also have a journal left by an interrupted update.
elif [[ ! -f "$state/install-receipt.json" || ! -f "$state/owned-versions.json" ]]; then
  echo "incomplete runner ownership metadata" >&2; exit 1
fi
mkdir -p "$versions" "$agents"
[[ "$(cd "$versions" && pwd -P)" == "$versions" ]] || { echo "versions directory escaped the install base" >&2; exit 1; }
expected="$versions/$version"; agent="$agents/app.loomex.runner.plist"; current="$base/current"

validate_version_path() {
  python3 - "$versions" "$current" "$1" <<'PY'
import re,sys
from pathlib import Path
versions_raw=Path(sys.argv[1]); current=Path(sys.argv[2]); raw=Path(sys.argv[3])
if versions_raw.is_symlink(): raise SystemExit('versions directory may not be a symlink')
versions=versions_raw.resolve(strict=True)
if not raw.is_absolute(): raw=current.parent/raw
if raw.is_symlink(): raise SystemExit('version path may not be a symlink')
if raw.parent.resolve(strict=True) != versions or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+',raw.name): raise SystemExit('version path is not a direct SemVer child')
print(raw.absolute())
PY
}

write_receipt() {
  python3 - "$version" "$expected" "$agent" "$development" "$development_origin" "$provider_config" "$state/install-receipt.json" <<'PY'
import json,os,sys
from pathlib import Path
version,path,agent,development,origin,providers_file,out=sys.argv[1:]; out=Path(out); tmp=out.with_name(out.name+'.new')
data={'schema':'app.loomex.runner.install-receipt/v1','version':version,'versionPath':path,'launchAgent':agent,'developmentOnly':development=='true','developmentApiOrigin':origin or None,'providerExecutables':json.load(open(providers_file))}
with tmp.open('w') as f: json.dump(data,f,sort_keys=True); f.write('\n'); f.flush(); os.fsync(f.fileno())
os.replace(tmp,out)
PY
}

write_install_journal() {
  python3 - "$version" "$expected" "$agent" "$manifest" "$install_journal" <<'PY'
import hashlib,json,os,sys
from pathlib import Path
version,path,agent,manifest,out=sys.argv[1:]; out=Path(out); tmp=out.with_name(out.name+'.new')
data={'schema':'app.loomex.runner.install-operation/v1','version':version,'versionPath':path,'launchAgent':agent,'manifestSha256':hashlib.sha256(Path(manifest).read_bytes()).hexdigest()}
with tmp.open('w') as f: json.dump(data,f,sort_keys=True); f.write('\n'); f.flush(); os.fsync(f.fileno())
os.replace(tmp,out); fd=os.open(out.parent,os.O_RDONLY); os.fsync(fd); os.close(fd)
PY
}

validate_install_journal() {
  python3 - "$install_journal" "$version" "$expected" "$agent" "$manifest" <<'PY'
import hashlib,json,sys
from pathlib import Path
journal,version,path,agent,manifest=sys.argv[1:]
data=json.loads(Path(journal).read_text())
expected={'schema':'app.loomex.runner.install-operation/v1','version':version,'versionPath':path,'launchAgent':agent,'manifestSha256':hashlib.sha256(Path(manifest).read_bytes()).hexdigest()}
if data != expected: raise SystemExit('install journal does not match the verified release')
PY
}

completed_install_journal() {
  python3 - "$install_journal" "$state/install-receipt.json" "$state/owned-versions.json" "$versions" "$agent" <<'PY'
import json,re,sys
from pathlib import Path
journal,receipt,owned,versions_raw,agent=map(Path,sys.argv[1:]); versions=versions_raw.resolve(strict=True)
j=json.loads(journal.read_text()); r=json.loads(receipt.read_text()); o=json.loads(owned.read_text())
if j.get('schema')!='app.loomex.runner.install-operation/v1' or not re.fullmatch(r'[0-9a-f]{64}',j.get('manifestSha256','')): raise SystemExit(1)
if r.get('schema')!='app.loomex.runner.install-receipt/v1': raise SystemExit(1)
if (r.get('version'),r.get('versionPath'),r.get('launchAgent')) != (j.get('version'),j.get('versionPath'),str(agent)): raise SystemExit(1)
if o.get('schema')!='app.loomex.runner.owned-versions/v1' or not isinstance(o.get('paths'),list): raise SystemExit(1)
for value in o['paths']:
 raw=Path(value)
 if raw.is_symlink() or raw.parent.resolve(strict=True)!=versions or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+',raw.name): raise SystemExit(1)
if j['versionPath'] not in o['paths']: raise SystemExit(1)
PY
}

current_path=""
if [[ -e "$current" || -L "$current" ]]; then
  [[ -L "$current" ]] || { echo "current installation pointer is not a symlink" >&2; exit 1; }
  current_path="$(validate_version_path "$(readlink "$current")")"
  [[ -x "$current_path/bin/loomex" ]] || { echo "current runner executable is missing" >&2; exit 1; }
fi

stage="$(mktemp -d "$base/.stage.XXXXXX")"; trap 'rm -rf "$stage"' EXIT
verify=(extract --release "$release" --project loomex-runner --platform darwin-arm64 --extract "$stage/payload")
if [[ -n "$public_key" ]]; then verify+=(--public-key "$public_key"); fi
if ((allow_dev)); then [[ "${LOOMEX_ALLOW_UNSAFE_DEV_INSTALL:-}" == "1" ]] || { echo "set LOOMEX_ALLOW_UNSAFE_DEV_INSTALL=1 for isolated development installs" >&2; exit 1; }; verify+=(--allow-unsigned-development); fi
python3 "$repo/scripts/artifact.py" "${verify[@]}"
python3 "$repo/scripts/validate_package.py" "$stage/payload" --expected-version "$version"
if [[ -f "$install_journal" ]]; then
  if validate_install_journal 2>/dev/null; then
    : # Resume the exact release that owns the incomplete transaction.
  elif [[ -f "$state/install-receipt.json" && -f "$state/owned-versions.json" ]] && completed_install_journal; then
    # Receipt persistence completed before the process died; the journal is a
    # stale terminal record and must not prevent a later upgrade.
    rm -f "$install_journal" "$install_journal.new"
  else
    validate_install_journal
  fi
fi
development="$(python3 -c 'import json,sys; print(str(json.load(open(sys.argv[1]))["developmentOnly"]).lower())' "$manifest")"
provider_config="$stage/provider-executables.json"
write_provider_config() {
python3 - "$state/install-receipt.json" "$state/pending-update.json" "$expected" "$provider_config" "$@" <<'PY'
import json,os,stat,sys
from pathlib import Path
receipt,pending,expected,out=map(Path,sys.argv[1:5]); specs=sys.argv[5:]; allowed={'codex','claude','gemini','antigravity'}
providers={}
if receipt.exists():
 data=json.loads(receipt.read_text())
 stored=data.get('providerExecutables',{})
 if not isinstance(stored,dict) or any(name not in allowed or not isinstance(value,str) for name,value in stored.items()): raise SystemExit('invalid provider executable configuration in installation receipt')
 providers.update(stored)
if pending.exists():
 data=json.loads(pending.read_text())
 stored=data.get('providerExecutables',{})
 if data.get('path')==str(expected) and (not isinstance(stored,dict) or any(name not in allowed or not isinstance(value,str) for name,value in stored.items())): raise SystemExit('invalid provider executable configuration in pending update')
 if data.get('path')==str(expected): providers.update(stored)
seen=set()
for spec in specs:
 name,separator,value=spec.partition('=')
 if not separator or name not in allowed or not value: raise SystemExit(f'invalid --provider-executable value: {spec}')
 if name in seen: raise SystemExit(f'duplicate --provider-executable provider: {name}')
 seen.add(name); path=Path(value)
 if not path.is_absolute(): raise SystemExit(f'provider executable path must be absolute: {name}')
 try: canonical=path.resolve(strict=True); mode=canonical.stat().st_mode
 except OSError as error: raise SystemExit(f'provider executable unavailable: {name}') from error
 if not stat.S_ISREG(mode) or not os.access(canonical,os.X_OK): raise SystemExit(f'provider executable is not an executable file: {name}')
 providers[name]=str(canonical)
for name,value in providers.items():
 path=Path(value)
 try: canonical=path.resolve(strict=True); mode=canonical.stat().st_mode
 except OSError as error: raise SystemExit(f'configured provider executable unavailable: {name}') from error
 if not path.is_absolute() or path!=canonical or not stat.S_ISREG(mode) or not os.access(canonical,os.X_OK): raise SystemExit(f'configured provider path is not an absolute canonical executable: {name}')
out.write_text(json.dumps(providers,sort_keys=True)+'\n')
PY
}
if ((provider_spec_count)); then write_provider_config "${provider_specs[@]}"; else write_provider_config; fi
render_args=(--template "$stage/payload/launchd/app.loomex.runner.template.plist" --binary "$base/current/bin/loomex-runner" --state "$state" --provider-executables-file "$provider_config" --output "$stage/app.loomex.runner.plist")
if [[ "$development" == true ]]; then
  ((allow_dev)) || { echo "development artifact requires explicit development opt-in" >&2; exit 1; }
  [[ -n "$development_origin" ]] || { echo "development artifact requires --development-api-origin" >&2; exit 1; }
  development_origin="$(python3 "$repo/scripts/validate_development_origin.py" "$development_origin")"
  render_args+=(--development-api-origin "$development_origin")
elif [[ "$development" == false ]]; then
  [[ -z "$development_origin" ]] || { echo "production artifacts reject --development-api-origin" >&2; exit 1; }
  for binary in "$stage/payload/bin/loomex" "$stage/payload/bin/loomex-runner"; do codesign --verify --strict --verbose=2 "$binary"; spctl --assess --type execute --verbose=2 "$binary"; done
else
  echo "invalid development classification" >&2; exit 1
fi
python3 "$repo/scripts/render_launch_agent.py" "${render_args[@]}"
mkdir -p "$state/logs"

# Journal before the version move.  A retry can prove it is resuming this exact
# verified release even if interruption happens in the move/ownership window.
if [[ ! -f "$install_journal" ]]; then write_install_journal; fi

installed_new=0
if [[ -e "$expected" || -L "$expected" ]]; then
  [[ -d "$expected" && ! -L "$expected" ]] || { echo "installed version path is not a regular directory" >&2; exit 1; }
  python3 - "$manifest" "$expected" <<'PY'
import hashlib,json,stat,sys
from pathlib import Path
manifest=json.load(open(sys.argv[1])); root=Path(sys.argv[2]); actual=[]
for p in sorted(root.rglob('*')):
 if p.is_symlink(): raise SystemExit('installed version contains a symlink')
 if p.is_file(): actual.append({'path':p.relative_to(root).as_posix(),'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'size':p.stat().st_size,'mode':stat.S_IMODE(p.stat().st_mode)})
if actual!=manifest['payload']['files']: raise SystemExit('installed version differs from signed artifact')
PY
  rm -rf "$stage/payload"
  ((resuming_install==0)) || installed_new=1
else
  mv "$stage/payload" "$expected"; installed_new=1
fi

# Persist ownership immediately after bytes enter versions/, before any operation that can fail.
python3 - "$versions" "$expected" "$state/owned-versions.json" <<'PY'
import json,os,re,sys
from pathlib import Path
versions=Path(sys.argv[1]).resolve(strict=True); expected=Path(sys.argv[2]); out=Path(sys.argv[3]); paths=[]
if out.exists():
 data=json.loads(out.read_text())
 if data.get('schema')!='app.loomex.runner.owned-versions/v1' or not isinstance(data.get('paths'),list): raise SystemExit('invalid owned versions inventory')
 paths=data['paths']
paths.append(str(expected)); clean=[]
for value in paths:
 raw=Path(value)
 if raw.is_symlink() or raw.parent.resolve(strict=True)!=versions or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+',raw.name): raise SystemExit('unsafe owned version path')
 value=str(raw.absolute())
 if value not in clean: clean.append(value)
tmp=out.with_name(out.name+'.new'); encoded=(json.dumps({'schema':'app.loomex.runner.owned-versions/v1','paths':clean},sort_keys=True)+'\n').encode()
with tmp.open('wb') as f: f.write(encoded); f.flush(); os.fsync(f.fileno())
os.replace(tmp,out); fd=os.open(out.parent,os.O_RDONLY); os.fsync(fd); os.close(fd)
PY

if [[ "${LOOMEX_TEST_INSTALL_INTERRUPT_AFTER_OWNERSHIP:-}" == 1 ]]; then
  echo "installation interrupted after durable ownership journal" >&2
  exit 75
fi

active=0
if [[ -n "$current_path" ]]; then
  LOOMEX_STATE_DIR="$state" "$current_path/bin/loomex" drain >/dev/null
  status="$(LOOMEX_STATE_DIR="$state" "$current_path/bin/loomex" status)"
  active="$(python3 -c 'import json,sys; data=json.load(sys.stdin); value=data["activeJobs"]; assert isinstance(value,int) and value>=0; print(value)' <<<"$status")"
fi
if ((active>0)); then
  digest="$(shasum -a 256 "$manifest" | awk '{print $1}')"
  python3 - "$version" "$expected" "$digest" "$provider_config" "$state/pending-update.json" <<'PY'
import json,os,sys
from pathlib import Path
version,path,digest,providers_file,out=sys.argv[1:]; out=Path(out); tmp=out.with_name(out.name+'.new')
encoded=(json.dumps({'schema':'app.loomex.runner.pending-update/v1','version':version,'path':path,'manifestSha256':digest,'providerExecutables':json.load(open(providers_file))},sort_keys=True)+'\n').encode()
with tmp.open('wb') as f: f.write(encoded); f.flush(); os.fsync(f.fileno())
os.replace(tmp,out); fd=os.open(out.parent,os.O_RDONLY); os.fsync(fd); os.close(fd)
PY
  # A pending-update record is now the durable terminal staging state; the
  # transaction journal is no longer needed and must not block a later update.
  rm -f "$install_journal" "$install_journal.new"
  echo "Runner $version staged; activation deferred until active jobs reach zero. Run this installer again to activate."
  exit 0
fi

old="$current_path"; plist_backup="$stage/agent.previous"; [[ ! -f "$agent" ]] || cp "$agent" "$plist_backup"
if [[ "${LOOMEX_INSTALL_TEST_MODE:-}" != 1 ]]; then
  # `bootout` can return before launchd has fully released the label. Starting
  # the replacement in that interval intermittently returns EIO and leaves an
  # otherwise healthy version staged. Wait for the exact label to disappear;
  # this is a lifecycle boundary, not a best-effort delay.
  launchctl bootout "gui/$UID/app.loomex.runner" 2>/dev/null || true
  unloaded=0
  for _ in {1..20}; do
    if ! launchctl print "gui/$UID/app.loomex.runner" >/dev/null 2>&1; then
      unloaded=1; break
    fi
    sleep 0.25
  done
  ((unloaded)) || { echo "previous runner service did not unload" >&2; exit 1; }
fi
ln -s "$expected" "$base/.current.new"; mv -fh "$base/.current.new" "$current"; cp "$stage/app.loomex.runner.plist" "$agent"
rm -f "$state/uninstall-ready.json" "$state/uninstall-ready.json.new" "$state/drain.json"
activation_failed=0; service_loaded=0
if [[ "${LOOMEX_TEST_BOOTSTRAP_FAIL:-}" == 1 ]]; then
  activation_failed=1
elif [[ "${LOOMEX_INSTALL_TEST_MODE:-}" == 1 ]]; then
  service_loaded=1
else
  # launchctl can report EIO while its previous unload is still settling. A
  # bounded retry either observes the exact label or gives launchd a clean
  # second bootstrap opportunity. Health remains the authority for activation.
  for _ in {1..5}; do
    if launchctl bootstrap "gui/$UID" "$agent" 2>/dev/null \
      || launchctl print "gui/$UID/app.loomex.runner" >/dev/null 2>&1; then
      break
    fi
    sleep 0.25
  done
  service_loaded=1
fi
if ((activation_failed==0)) && [[ "${LOOMEX_TEST_HEALTH_FAIL:-}" == 1 ]]; then
  activation_failed=1
elif ((activation_failed==0)) && [[ "${LOOMEX_INSTALL_TEST_MODE:-}" != 1 ]]; then
  healthy=0
  for _ in {1..20}; do
    if health="$(LOOMEX_STATE_DIR="$state" "$expected/bin/loomex" status 2>/dev/null)" && python3 -c 'import json,sys; data=json.load(sys.stdin); expected=sys.argv[1]; assert data["version"]==expected and isinstance(data["activeJobs"],int) and data["activeJobs"]>=0 and data["draining"] is False' "$version" <<<"$health" >/dev/null 2>&1
    then healthy=1; break; fi
    sleep 0.25
  done
  ((healthy==1)) || activation_failed=1
fi
if ((activation_failed)); then
  rollback_safe=1
  if ((service_loaded)) && [[ "${LOOMEX_INSTALL_TEST_MODE:-}" != 1 ]]; then
    rollback_safe=0
    if LOOMEX_STATE_DIR="$state" "$expected/bin/loomex" drain >/dev/null 2>&1; then
      failed_status="$(LOOMEX_STATE_DIR="$state" "$expected/bin/loomex" status 2>/dev/null || true)"
      failed_active="$(python3 -c 'import json,sys; data=json.load(sys.stdin); value=data["activeJobs"]; assert isinstance(value,int) and value>=0; print(value)' <<<"$failed_status" 2>/dev/null || true)"
      [[ "$failed_active" == 0 ]] && rollback_safe=1
    fi
  fi
  if ((rollback_safe==0)); then
    write_receipt
    echo "activation health is unconfirmed; current service and all version bytes were retained because zero active jobs could not be proven" >&2
    exit 1
  fi
  if ((service_loaded)) && [[ "${LOOMEX_INSTALL_TEST_MODE:-}" != 1 ]] && ! launchctl bootout "gui/$UID/app.loomex.runner" 2>/dev/null; then
    write_receipt
    echo "failed candidate could not be unloaded; current service and all version bytes were retained" >&2
    exit 1
  fi
  rm -f "$current"; [[ -z "$old" ]] || ln -s "$old" "$current"
  if [[ -f "$plist_backup" ]]; then cp "$plist_backup" "$agent"; else rm -f "$agent"; fi
  [[ -z "$old" || "${LOOMEX_INSTALL_TEST_MODE:-}" == 1 ]] || launchctl bootstrap "gui/$UID" "$agent" || true
  if ((installed_new)); then
    rm -rf "$expected"
    python3 - "$expected" "$state/owned-versions.json" <<'PY'
import json,os,sys
from pathlib import Path
remove=str(Path(sys.argv[1]).absolute()); out=Path(sys.argv[2]); data=json.loads(out.read_text()); data['paths']=[p for p in data['paths'] if p!=remove]
tmp=out.with_name(out.name+'.new')
with tmp.open('w') as f: json.dump(data,f,sort_keys=True); f.write('\n'); f.flush(); os.fsync(f.fileno())
os.replace(tmp,out)
PY
  fi
  if ((fresh_state)) && [[ -z "$old" ]]; then
    for name in "${owned_state_names[@]}"; do rm -rf "$state/$name"; done
    rmdir "$state" 2>/dev/null || true
  fi
  rm -f "$install_journal" "$install_journal.new"
  echo "activation failed; previous runner restored" >&2; exit 1
fi

rm -f "$state/pending-update.json"
python3 - "$versions" "$expected" "$state/owned-versions.json" <<'PY'
import json,os,re,shutil,sys
from pathlib import Path
versions=Path(sys.argv[1]).resolve(strict=True); keep=str(Path(sys.argv[2]).absolute()); out=Path(sys.argv[3]); data=json.loads(out.read_text())
for value in data['paths']:
 raw=Path(value)
 if raw.is_symlink() or raw.parent.resolve(strict=True)!=versions or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+',raw.name): raise SystemExit('unsafe owned version path')
 if str(raw.absolute())!=keep and raw.exists(): shutil.rmtree(raw)
data['paths']=[keep]; tmp=out.with_name(out.name+'.new')
with tmp.open('w') as f: json.dump(data,f,sort_keys=True); f.write('\n'); f.flush(); os.fsync(f.fileno())
os.replace(tmp,out)
PY
write_receipt
rm -f "$install_journal" "$install_journal.new"
trap - EXIT; rm -rf "$stage"
echo "Installed and activated Loomex runner $version"
