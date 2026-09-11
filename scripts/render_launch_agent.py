#!/usr/bin/env python3
import argparse,html,json,os,stat
from pathlib import Path
from validate_development_origin import canonical_origin
parser=argparse.ArgumentParser(); parser.add_argument("--template",required=True); parser.add_argument("--binary",required=True); parser.add_argument("--state",required=True); parser.add_argument("--development-api-origin"); parser.add_argument("--provider-executables-file"); parser.add_argument("--output",required=True); args=parser.parse_args()
binary=Path(os.path.abspath(args.binary)); state=Path(os.path.abspath(args.state))
if not binary.is_absolute() or not state.is_absolute(): raise SystemExit("LaunchAgent paths must be absolute")
text=Path(args.template).read_text()
if text.count("__LOOMEX_DAEMON__")!=1 or text.count("__LOOMEX_STATE_DIR__")!=3 or text.count("__LOOMEX_DEV_API_ORIGIN_ENTRY__")!=1 or text.count("__LOOMEX_PROVIDER_EXECUTABLE_ENTRIES__")!=1: raise SystemExit("invalid LaunchAgent template")
origin_entry=""
if args.development_api_origin:
    try: origin=canonical_origin(args.development_api_origin)
    except ValueError as error: raise SystemExit(f"invalid development API origin: {error}") from error
    origin_entry=f"<key>LOOMEX_DEV_API_ORIGIN</key><string>{html.escape(origin)}</string>"
provider_entries=""
if args.provider_executables_file:
    providers=json.loads(Path(args.provider_executables_file).read_text())
    if not isinstance(providers,dict) or any(name not in {'codex','claude','gemini','antigravity'} for name in providers): raise SystemExit("invalid provider executable configuration")
    environment={'codex':'LOOMEX_CODEX_EXECUTABLE','claude':'LOOMEX_CLAUDE_EXECUTABLE','gemini':'LOOMEX_GEMINI_EXECUTABLE','antigravity':'LOOMEX_ANTIGRAVITY_EXECUTABLE'}
    entries=[]
    for name in ('codex','claude','gemini','antigravity'):
        if name not in providers: continue
        value=providers[name]
        if not isinstance(value,str): raise SystemExit("invalid provider executable path")
        path=Path(value)
        try: canonical=path.resolve(strict=True); mode=canonical.stat().st_mode
        except OSError as error: raise SystemExit(f"provider executable unavailable: {name}") from error
        if not path.is_absolute() or path != canonical or not stat.S_ISREG(mode) or not os.access(canonical,os.X_OK): raise SystemExit(f"provider executable must be an absolute canonical executable: {name}")
        entries.append(f"<key>{environment[name]}</key><string>{html.escape(str(canonical))}</string>")
    provider_entries=''.join(entries)
text=text.replace("__LOOMEX_DAEMON__",html.escape(str(binary))).replace("__LOOMEX_STATE_DIR__",html.escape(str(state))).replace("__LOOMEX_DEV_API_ORIGIN_ENTRY__",origin_entry).replace("__LOOMEX_PROVIDER_EXECUTABLE_ENTRIES__",provider_entries)
Path(args.output).write_text(text)
