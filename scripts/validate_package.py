#!/usr/bin/env python3
import argparse,json,subprocess,sys,runpy,re
from pathlib import Path
from urllib.parse import urlsplit,urlunsplit

parser=argparse.ArgumentParser(); parser.add_argument("root"); parser.add_argument("--expected-version",required=True); parser.add_argument("--source-root"); parser.add_argument("--allow-legacy-source-provenance",action="store_true"); args=parser.parse_args()
root=Path(args.root).resolve()
for path in root.rglob("*"):
    relative=path.relative_to(root)
    if any(part in {".git","credentials","secrets","target",".cache","__pycache__",".DS_Store"} or part.startswith(".env") or part.endswith((".pem",".key",".log")) or "credential" in part.lower() or "secret" in part.lower() for part in relative.parts): raise SystemExit(f"forbidden packaged path: {relative}")
for name in ("loomex","loomex-runner","loomex-lifecycle-bootstrap"):
    binary=root/"bin"/name
    if not binary.is_file() or not (binary.stat().st_mode & 0o111): raise SystemExit(f"runner executable missing: {name}")
metadata=json.loads((root/"metadata/project.json").read_text())
has_build='build' in metadata
build=metadata.pop('build',None)
if metadata!={"project":"loomex-runner","version":args.expected_version,"platform":"darwin-arm64","stateSchema":"app.loomex.runner.state/v1"}: raise SystemExit("runner metadata mismatch")
if has_build and (build != {'profile':'distribution-dev','optimizationLevel':'2','debugAssertions':True,'classification':'development'} or type(build.get('debugAssertions')) is not bool):
    raise SystemExit("runner build metadata mismatch")
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
preview=root/'metadata/preview-origin.json'
if preview.exists():
    value=json.loads(preview.read_text())
    valid_origin=runpy.run_path(str(source_root/'scripts/verify-production-config.py'))['valid_origin']
    origin=value.get('apiOrigin') if isinstance(value,dict) else None
    canonical_origin=None
    if isinstance(origin,str) and valid_origin(origin):
        url=urlsplit(origin); host=url.hostname.encode('idna').decode('ascii').lower()
        if ':' in host: host='['+host+']'
        authority=host+(f':{url.port}' if url.port not in (None,443) else '')
        canonical_origin=urlunsplit(('https',authority,'/','',''))
    if (not isinstance(value,dict) or set(value)!={'schema','apiOrigin','sourceRevision','version'}
            or value['schema']!='app.loomex.runner.preview-origin/v1'
            or value['version']!=args.expected_version
            or not isinstance(value['apiOrigin'],str) or not valid_origin(value['apiOrigin'])
            or not value['apiOrigin'].endswith('/')
            or canonical_origin!=value['apiOrigin']
            or not isinstance(value['sourceRevision'],str) or not re.fullmatch('[0-9a-f]{40}',value['sourceRevision'])
            or preview.read_bytes()!=(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()
            or not has_build):
        raise SystemExit('runner preview origin metadata mismatch')
    source=json.loads(source_manifest.read_text())
    if (source['sourceRevision']!=value['sourceRevision'] or not source['files']
            or any(entry['tracked'] is not True or entry['type']=='missing' for entry in source['files'])):
        raise SystemExit('runner preview requires revision-controlled source')
local=root/'metadata/local-development-origin.json'
if local.exists():
    value=json.loads(local.read_text())
    validator=runpy.run_path(str(source_root/'scripts/release-set.py'))['validate_deployment']
    try: validator({'profile':'local-development','apiOrigin':value.get('apiOrigin'),'webAppOrigin':value.get('webAppOrigin')})
    except (ValueError,TypeError,KeyError): raise SystemExit('runner local development origin metadata mismatch')
    if (preview.exists() or set(value)!={'schema','apiOrigin','webAppOrigin','sourceRevision','version'}
            or value['schema']!='app.loomex.runner.local-development-origin/v1' or value['version']!=args.expected_version
            or not isinstance(value['sourceRevision'],str) or not re.fullmatch('[0-9a-f]{40}',value['sourceRevision'])
            or local.read_bytes()!=(json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode() or not has_build):
        raise SystemExit('runner local development origin metadata mismatch')
    source=json.loads(source_manifest.read_text())
    if (source['sourceRevision']!=value['sourceRevision'] or not source['files']
            or any(entry['tracked'] is not True or entry['type']=='missing' for entry in source['files'])):
        raise SystemExit('runner local profile requires revision-controlled source')
plist=(root/"launchd/app.loomex.runner.template.plist").read_text()
if plist.count("__LOOMEX_DAEMON__")!=1 or plist.count("__LOOMEX_STATE_DIR__")!=3 or plist.count("__LOOMEX_DEV_API_ORIGIN_ENTRY__")!=1 or plist.count("__LOOMEX_PROVIDER_EXECUTABLE_ENTRIES__")!=1: raise SystemExit("LaunchAgent template placeholders are invalid")
