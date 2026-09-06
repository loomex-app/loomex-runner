#!/usr/bin/env python3
import argparse,html,os
from pathlib import Path
from validate_development_origin import canonical_origin
parser=argparse.ArgumentParser(); parser.add_argument("--template",required=True); parser.add_argument("--binary",required=True); parser.add_argument("--state",required=True); parser.add_argument("--development-api-origin"); parser.add_argument("--output",required=True); args=parser.parse_args()
binary=Path(os.path.abspath(args.binary)); state=Path(os.path.abspath(args.state))
if not binary.is_absolute() or not state.is_absolute(): raise SystemExit("LaunchAgent paths must be absolute")
text=Path(args.template).read_text()
if text.count("__LOOMEX_DAEMON__")!=1 or text.count("__LOOMEX_STATE_DIR__")!=3 or text.count("__LOOMEX_DEV_API_ORIGIN_ENTRY__")!=1: raise SystemExit("invalid LaunchAgent template")
origin_entry=""
if args.development_api_origin:
    try: origin=canonical_origin(args.development_api_origin)
    except ValueError as error: raise SystemExit(f"invalid development API origin: {error}") from error
    origin_entry=f"<key>LOOMEX_DEV_API_ORIGIN</key><string>{html.escape(origin)}</string>"
text=text.replace("__LOOMEX_DAEMON__",html.escape(str(binary))).replace("__LOOMEX_STATE_DIR__",html.escape(str(state))).replace("__LOOMEX_DEV_API_ORIGIN_ENTRY__",origin_entry)
Path(args.output).write_text(text)
