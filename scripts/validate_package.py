#!/usr/bin/env python3
import argparse,json
from pathlib import Path

parser=argparse.ArgumentParser(); parser.add_argument("root"); parser.add_argument("--expected-version",required=True); args=parser.parse_args()
root=Path(args.root).resolve()
for path in root.rglob("*"):
    relative=path.relative_to(root)
    if any(part in {".git","credentials","secrets","target",".cache","__pycache__",".DS_Store"} or part.startswith(".env") or part.endswith((".pem",".key",".log")) or "credential" in part.lower() or "secret" in part.lower() for part in relative.parts): raise SystemExit(f"forbidden packaged path: {relative}")
for name in ("loomex","loomex-runner"):
    binary=root/"bin"/name
    if not binary.is_file() or not (binary.stat().st_mode & 0o111): raise SystemExit(f"runner executable missing: {name}")
metadata=json.loads((root/"metadata/project.json").read_text())
if metadata!={"project":"loomex-runner","version":args.expected_version,"platform":"darwin-arm64","stateSchema":"app.loomex.runner.state/v1"}: raise SystemExit("runner metadata mismatch")
plist=(root/"launchd/app.loomex.runner.template.plist").read_text()
if plist.count("__LOOMEX_DAEMON__")!=1 or plist.count("__LOOMEX_STATE_DIR__")!=3: raise SystemExit("LaunchAgent template placeholders are invalid")
