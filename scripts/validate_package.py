#!/usr/bin/env python3
import argparse,json,subprocess,sys
from pathlib import Path

parser=argparse.ArgumentParser(); parser.add_argument("root"); parser.add_argument("--expected-version",required=True); parser.add_argument("--source-root"); parser.add_argument("--allow-legacy-source-provenance",action="store_true"); args=parser.parse_args()
root=Path(args.root).resolve()
for path in root.rglob("*"):
    relative=path.relative_to(root)
    if any(part in {".git","credentials","secrets","target",".cache","__pycache__",".DS_Store"} or part.startswith(".env") or part.endswith((".pem",".key",".log")) or "credential" in part.lower() or "secret" in part.lower() for part in relative.parts): raise SystemExit(f"forbidden packaged path: {relative}")
for name in ("loomex","loomex-runner"):
    binary=root/"bin"/name
    if not binary.is_file() or not (binary.stat().st_mode & 0o111): raise SystemExit(f"runner executable missing: {name}")
metadata=json.loads((root/"metadata/project.json").read_text())
if metadata!={"project":"loomex-runner","version":args.expected_version,"platform":"darwin-arm64","stateSchema":"app.loomex.runner.state/v1"}: raise SystemExit("runner metadata mismatch")
compatibility=root/"metadata/compatibility-manifest.json"
if not compatibility.is_file(): raise SystemExit("runner compatibility manifest missing")
source_root=Path(__file__).resolve().parent.parent
exporter=source_root/"scripts"/"export-compatibility.py"
if not exporter.is_file(): raise SystemExit("runner compatibility verifier missing")
checked=subprocess.run([sys.executable,str(exporter),"--check-package-root",str(root)],text=True,capture_output=True)
if checked.returncode: raise SystemExit(f"runner compatibility manifest mismatch: {checked.stderr.strip() or checked.stdout.strip()}")
source_manifest=root/"metadata/source-content-manifest.json"
if source_manifest.is_file():
    command=[sys.executable,str(source_root/"scripts"/"artifact.py"),"verify-source","--manifest",str(source_manifest)]
    if args.source_root: command.extend(["--source-root",args.source_root])
    provenance=subprocess.run(command,text=True,capture_output=True)
    if provenance.returncode: raise SystemExit(f"runner source content mismatch: {provenance.stderr.strip() or provenance.stdout.strip()}")
elif not args.allow_legacy_source_provenance:
    raise SystemExit("runner source content manifest missing; explicit legacy compatibility required")
plist=(root/"launchd/app.loomex.runner.template.plist").read_text()
if plist.count("__LOOMEX_DAEMON__")!=1 or plist.count("__LOOMEX_STATE_DIR__")!=3 or plist.count("__LOOMEX_DEV_API_ORIGIN_ENTRY__")!=1 or plist.count("__LOOMEX_PROVIDER_EXECUTABLE_ENTRIES__")!=1: raise SystemExit("LaunchAgent template placeholders are invalid")
