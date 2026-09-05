#!/usr/bin/env python3
import argparse,html,os
from pathlib import Path
parser=argparse.ArgumentParser(); parser.add_argument("--template",required=True); parser.add_argument("--binary",required=True); parser.add_argument("--state",required=True); parser.add_argument("--output",required=True); args=parser.parse_args()
binary=Path(os.path.abspath(args.binary)); state=Path(os.path.abspath(args.state))
if not binary.is_absolute() or not state.is_absolute(): raise SystemExit("LaunchAgent paths must be absolute")
text=Path(args.template).read_text()
if text.count("__LOOMEX_DAEMON__")!=1 or text.count("__LOOMEX_STATE_DIR__")!=3: raise SystemExit("invalid LaunchAgent template")
text=text.replace("__LOOMEX_DAEMON__",html.escape(str(binary))).replace("__LOOMEX_STATE_DIR__",html.escape(str(state)))
Path(args.output).write_text(text)
