#!/bin/bash
set -euo pipefail

base=""; state=""; agents=""
while (($#)); do
  case "$1" in
    --install-base) base="${2:?}"; shift 2;;
    --state-dir) state="${2:?}"; shift 2;;
    --launch-agents-dir) agents="${2:?}"; shift 2;;
    *) echo "usage: $0 [--install-base DIR --state-dir DIR --launch-agents-dir DIR]" >&2; exit 2;;
  esac
done
base="${base:-${HOME:?}/Library/Application Support/Loomex/runner}"
state="${state:-${HOME:?}/.local/share/loomex/runner}"
agents="${agents:-${HOME:?}/Library/LaunchAgents}"
base="$(python3 -c 'from pathlib import Path; import sys; print(Path(sys.argv[1]).resolve())' "$base")"
state="$(python3 -c 'from pathlib import Path; import sys; print(Path(sys.argv[1]).resolve())' "$state")"
agents="$(python3 -c 'from pathlib import Path; import sys; print(Path(sys.argv[1]).resolve())' "$agents")"
for path in "$base" "$state" "$agents"; do [[ "$path" != / && "$path" != "${HOME:-}" ]] || { echo "unsafe installation directory: $path" >&2; exit 1; }; done

versions="$base/versions"; receipt="$state/install-receipt.json"; owned="$state/owned-versions.json"; current="$base/current"
ready="$state/uninstall-ready.json"
uninstall_journal="$state/uninstall-operation.json"
[[ ! -L "$uninstall_journal" && ! -L "$uninstall_journal.new" ]] || { echo "uninstall journal may not be a symlink" >&2; exit 1; }
[[ ! -L "$versions" ]] || { echo "versions directory may not be a symlink" >&2; exit 1; }
[[ -d "$versions" && "$(cd "$versions" && pwd -P)" == "$versions" ]] || { echo "invalid versions directory" >&2; exit 1; }

# Validate every future deletion before running credential or launchd operations.
repo="$(cd "$(dirname "$0")/.." && pwd -P)"
paths_file="$(mktemp)"; trap 'rm -f "$paths_file"' EXIT
resume_cleanup=0
journal_phase=""
if [[ -f "$uninstall_journal" ]]; then
  journal_phase="$(python3 - "$uninstall_journal" "$versions" "$agents/app.loomex.runner.plist" "$paths_file" <<'PY'
import json,re,sys
from pathlib import Path
journal,versions_raw,agent,output=map(Path,sys.argv[1:]); versions=versions_raw.resolve(strict=True)
data=json.loads(journal.read_text())
if data.get('schema')!='app.loomex.runner.uninstall-operation/v1' or data.get('phase') not in {'revoking','revoked'}: raise SystemExit('invalid uninstall journal')
if data.get('launchAgent')!=str(agent) or not isinstance(data.get('developmentApiOrigin'),(str,type(None))): raise SystemExit('invalid uninstall journal')
paths=data.get('paths')
if not isinstance(paths,list) or not paths: raise SystemExit('invalid uninstall journal')
clean=[]
for value in paths:
 raw=Path(value)
 if raw.is_symlink() or raw.parent.resolve(strict=True)!=versions or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+',raw.name): raise SystemExit('unsafe uninstall journal path')
 canonical=str(raw.absolute())
 if canonical not in clean: clean.append(canonical)
if data.get('versionPath') not in clean: raise SystemExit('invalid uninstall journal current path')
output.write_text('\n'.join(clean)+'\n')
print(data['phase'])
PY
 )"
  [[ "$journal_phase" == "revoking" || "$journal_phase" == "revoked" ]] || { echo "invalid uninstall journal" >&2; exit 1; }
  if [[ "$journal_phase" == "revoked" ]]; then resume_cleanup=1; fi
fi

development_origin=""
current_path=""
if ((resume_cleanup==0)); then
[[ -f "$receipt" && -f "$owned" ]] || { echo "no complete Loomex-owned installation inventory; refusing broad cleanup" >&2; exit 1; }
[[ -L "$current" ]] || { echo "installed runner pointer missing; credentials cannot be revoked safely" >&2; exit 1; }
development_origin="$(python3 - "$versions" "$current" "$receipt" "$owned" "$agents/app.loomex.runner.plist" "$paths_file" <<'PY'
import json,re,sys
from pathlib import Path
versions=Path(sys.argv[1]).resolve(strict=True); current=Path(sys.argv[2]); receipt=Path(sys.argv[3]); owned=Path(sys.argv[4]); expected_agent=sys.argv[5]; output=Path(sys.argv[6])
link=Path(current.readlink())
if not link.is_absolute(): link=current.parent/link
if link.is_symlink(): raise SystemExit('current points through a symlinked version')
current_path=link.absolute()
r=json.loads(receipt.read_text()); data=json.loads(owned.read_text())
if r.get('schema')!='app.loomex.runner.install-receipt/v1' or r.get('launchAgent')!=expected_agent: raise SystemExit('unexpected installation receipt')
providers=r.get('providerExecutables',{})
if not isinstance(providers,dict) or any(name not in {'codex','claude','gemini','antigravity'} or not isinstance(value,str) or not Path(value).is_absolute() for name,value in providers.items()): raise SystemExit('unexpected provider executable ownership metadata')
development=r.get('developmentOnly')
origin=r.get('developmentApiOrigin')
if not isinstance(development,bool): raise SystemExit('installation receipt lacks authenticated release class')
if development:
 if not isinstance(origin,str) or not origin: raise SystemExit('development installation receipt lacks its API origin')
 print(origin)
elif origin is not None: raise SystemExit('production installation receipt contains a development API origin')
else: print('')
if data.get('schema')!='app.loomex.runner.owned-versions/v1' or not isinstance(data.get('paths'),list) or not data['paths']: raise SystemExit('unexpected owned versions inventory')
clean=[]
for value in data['paths']:
 raw=Path(value)
 if raw.is_symlink() or raw.parent.resolve(strict=True)!=versions or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+',raw.name): raise SystemExit('unsafe owned version path')
 path=str(raw.absolute())
 if path not in clean: clean.append(path)
receipt_path=str(Path(r.get('versionPath','')).absolute())
if str(current_path) != receipt_path or receipt_path not in clean: raise SystemExit('current runner does not match owned receipt')
output.write_text('\n'.join(clean)+'\n')
PY
 )"
if [[ -n "$development_origin" ]]; then
  canonical_origin="$(python3 "$repo/scripts/validate_development_origin.py" "$development_origin")"
  [[ "$canonical_origin" == "$development_origin" ]] || { echo "development API origin in receipt is not canonical" >&2; exit 1; }
fi
current_path="$(python3 - "$versions" "$current" <<'PY'
import re,sys
from pathlib import Path
versions=Path(sys.argv[1]).resolve(strict=True); current=Path(sys.argv[2]); raw=Path(current.readlink())
if not raw.is_absolute(): raw=current.parent/raw
if raw.is_symlink() or raw.parent.resolve(strict=True)!=versions or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+',raw.name): raise SystemExit('unsafe current runner')
print(raw.absolute())
PY
)"
[[ -x "$current_path/bin/loomex" ]] || { echo "installed runner executable missing; credentials cannot be revoked safely" >&2; exit 1; }

if [[ -n "$journal_phase" ]]; then
  # A revoking journal must still describe the exact inventory validated above.
  python3 - "$uninstall_journal" "$current_path" "$development_origin" "$paths_file" <<'PY'
import json,sys
from pathlib import Path
data=json.loads(Path(sys.argv[1]).read_text())
if data['versionPath']!=sys.argv[2] or data['developmentApiOrigin']!=(sys.argv[3] or None) or data['paths']!=[line for line in Path(sys.argv[4]).read_text().splitlines() if line]: raise SystemExit('uninstall journal does not match current inventory')
PY
fi
fi

checkpoint_valid=0
if ((resume_cleanup==0)) && [[ -f "$ready" ]]; then
  python3 - "$ready" "$current_path" <<'PY'
import json,sys
data=json.load(open(sys.argv[1]))
if data != {'schema':'app.loomex.runner.uninstall-ready/v1','versionPath':sys.argv[2]}: raise SystemExit('invalid uninstall checkpoint')
PY
  if [[ -f "$state/drain.json" && ! -L "$state/drain.json" ]]; then checkpoint_valid=1; else rm -f "$ready" "$ready.new"; fi
fi
if ((resume_cleanup==0)) && ((checkpoint_valid==0)); then
  LOOMEX_STATE_DIR="$state" "$current_path/bin/loomex" drain >/dev/null
  active="$(LOOMEX_STATE_DIR="$state" "$current_path/bin/loomex" status | python3 -c 'import json,sys; data=json.load(sys.stdin); value=data["activeJobs"]; assert isinstance(value,int) and value>=0; print(value)')"
  ((active==0)) || { echo "uninstall deferred: $active active jobs or lifecycle writers; retry after they finish" >&2; exit 1; }
  python3 - "$ready" "$current_path" <<'PY'
import json,os,sys
from pathlib import Path
out=Path(sys.argv[1]); tmp=out.with_name(out.name+'.new'); encoded=(json.dumps({'schema':'app.loomex.runner.uninstall-ready/v1','versionPath':sys.argv[2]},sort_keys=True)+'\n').encode()
with tmp.open('wb') as f: f.write(encoded); f.flush(); os.fsync(f.fileno())
os.replace(tmp,out); fd=os.open(out.parent,os.O_RDONLY); os.fsync(fd); os.close(fd)
PY
fi

write_uninstall_journal() {
  python3 - "$uninstall_journal" "$1" "$current_path" "$agents/app.loomex.runner.plist" "$development_origin" "$paths_file" <<'PY'
import json,os,sys
from pathlib import Path
out,phase,current,agent,origin,paths=sys.argv[1:]; out=Path(out); tmp=out.with_name(out.name+'.new')
data={'schema':'app.loomex.runner.uninstall-operation/v1','phase':phase,'versionPath':current,'launchAgent':agent,'developmentApiOrigin':origin or None,'paths':[line for line in Path(paths).read_text().splitlines() if line]}
with tmp.open('w') as f: json.dump(data,f,sort_keys=True); f.write('\n'); f.flush(); os.fsync(f.fileno())
os.replace(tmp,out); fd=os.open(out.parent,os.O_RDONLY); os.fsync(fd); os.close(fd)
PY
}

if ((resume_cleanup==0)); then
  [[ -n "$journal_phase" ]] || write_uninstall_journal revoking
  if [[ "${LOOMEX_INSTALL_TEST_MODE:-}" != 1 ]]; then launchctl bootout "gui/$UID/app.loomex.runner" 2>/dev/null || true; fi
  # Offline logout takes the daemon's exclusive lock and performs only native
  # credential revocation/cleanup. Failure leaves ownership and the journal intact.
  offline_env=(env "LOOMEX_STATE_DIR=$state")
  [[ -z "$development_origin" ]] || offline_env+=("LOOMEX_DEV_API_ORIGIN=$development_origin")
  "${offline_env[@]}" "$current_path/bin/loomex" logout --offline >/dev/null
  write_uninstall_journal revoked
  if [[ "${LOOMEX_TEST_UNINSTALL_INTERRUPT_AFTER_REVOCATION:-}" == 1 ]]; then
    echo "uninstall interrupted after credential revocation" >&2
    exit 75
  fi
fi

# The revoked journal is the durable cleanup inventory.  It remains until all
# owned state metadata has been removed, so an interrupted cleanup can resume
# without a current symlink or a runnable daemon.
rm -f "$agents/app.loomex.runner.plist" "$current"
while IFS= read -r version_path; do [[ -z "$version_path" ]] || rm -rf "$version_path"; done < "$paths_file"
for name in state.json operations preparations jobs tombstones run-bindings preparation-tombstones responses presentation.sqlite3 presentation.sqlite3-wal presentation.sqlite3-shm follow.sqlite3 follow.sqlite3-wal follow.sqlite3-shm recovery.sqlite3 recovery.sqlite3-wal recovery.sqlite3-shm daemon.lock control.sock pending-update.json logs drain.json; do
  rm -rf "$state/$name"
done
rm -f "$ready" "$ready.new" "$receipt" "$owned"
rm -f "$uninstall_journal" "$uninstall_journal.new"
rmdir "$state" "$versions" "$base" 2>/dev/null || true
trap - EXIT; rm -f "$paths_file"
echo "Revoked Loomex credentials and removed only the inventoried runner files and state."
