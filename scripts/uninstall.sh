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
[[ ! -L "$versions" ]] || { echo "versions directory may not be a symlink" >&2; exit 1; }
[[ -d "$versions" && "$(cd "$versions" && pwd -P)" == "$versions" ]] || { echo "invalid versions directory" >&2; exit 1; }
[[ -f "$receipt" && -f "$owned" ]] || { echo "no complete Loomex-owned installation inventory; refusing broad cleanup" >&2; exit 1; }
[[ -L "$current" ]] || { echo "installed runner pointer missing; credentials cannot be revoked safely" >&2; exit 1; }

# Validate every future deletion before running credential or launchd operations.
paths_file="$(mktemp)"; trap 'rm -f "$paths_file"' EXIT
python3 - "$versions" "$current" "$receipt" "$owned" "$agents/app.loomex.runner.plist" "$paths_file" <<'PY'
import json,re,sys
from pathlib import Path
versions=Path(sys.argv[1]).resolve(strict=True); current=Path(sys.argv[2]); receipt=Path(sys.argv[3]); owned=Path(sys.argv[4]); expected_agent=sys.argv[5]; output=Path(sys.argv[6])
link=Path(current.readlink())
if not link.is_absolute(): link=current.parent/link
if link.is_symlink(): raise SystemExit('current points through a symlinked version')
current_path=link.absolute()
r=json.loads(receipt.read_text()); data=json.loads(owned.read_text())
if r.get('schema')!='app.loomex.runner.install-receipt/v1' or r.get('launchAgent')!=expected_agent: raise SystemExit('unexpected installation receipt')
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

LOOMEX_STATE_DIR="$state" "$current_path/bin/loomex" drain >/dev/null
active="$(LOOMEX_STATE_DIR="$state" "$current_path/bin/loomex" status | python3 -c 'import json,sys; data=json.load(sys.stdin); value=data["activeJobs"]; assert isinstance(value,int) and value>=0; print(value)')"
((active==0)) || { echo "uninstall deferred: $active active jobs; retry after they finish" >&2; exit 1; }

# Revocation is deliberately before deletion. Failure leaves launchd and all files intact for a safe retry.
LOOMEX_STATE_DIR="$state" "$current_path/bin/loomex" logout >/dev/null
if [[ "${LOOMEX_INSTALL_TEST_MODE:-}" != 1 ]]; then launchctl bootout "gui/$UID/app.loomex.runner" 2>/dev/null || true; fi
rm -f "$agents/app.loomex.runner.plist" "$current"
while IFS= read -r version_path; do [[ -z "$version_path" ]] || rm -rf "$version_path"; done < "$paths_file"
for name in state.json operations preparations jobs tombstones run-bindings preparation-tombstones responses daemon.lock control.sock pending-update.json install-receipt.json owned-versions.json logs drain.json; do
  rm -rf "$state/$name"
done
rmdir "$state" "$versions" "$base" 2>/dev/null || true
trap - EXIT; rm -f "$paths_file"
echo "Revoked Loomex credentials and removed only the inventoried runner files and state."
