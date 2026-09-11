#!/bin/bash
# Run the cross-component contract check when callers supply real component exports.
set -euo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd -P)"
plugin_components="${LOOMEX_PLUGIN_COMPONENTS:-}"
backend_routes="${LOOMEX_BACKEND_ROUTES:-}"
plugin_root="${LOOMEX_PLUGIN_ROOT:-}"
backend_root="${LOOMEX_BACKEND_ROOT:-}"
backend_python="${LOOMEX_BACKEND_PYTHON:-}"
plugin_node="${LOOMEX_PLUGIN_NODE:-}"
output=""

usage() {
  echo "usage: $0 [--plugin-components FILE --backend-routes FILE] [--plugin-root DIR --backend-root DIR --plugin-node NODE --backend-python PYTHON] [--output FILE]" >&2
  exit 2
}

while (($#)); do
  case "$1" in
    --plugin-components) plugin_components="${2:?}"; shift 2 ;;
    --backend-routes) backend_routes="${2:?}"; shift 2 ;;
    --plugin-root) plugin_root="${2:?}"; shift 2 ;;
    --backend-root) backend_root="${2:?}"; shift 2 ;;
    --plugin-node) plugin_node="${2:?}"; shift 2 ;;
    --backend-python) backend_python="${2:?}"; shift 2 ;;
    --output) output="${2:?}"; shift 2 ;;
    *) usage ;;
  esac
done

if [[ -z "$plugin_components$backend_routes$plugin_root$backend_root" ]]; then
  echo "integration compatibility gate skipped: no plugin/backend artifacts or checkout roots supplied"
  exit 0
fi

if [[ -n "$plugin_components$backend_routes" ]]; then
  [[ -n "$plugin_components" && -n "$backend_routes" && -z "$plugin_root$backend_root" ]] || usage
  [[ -f "$plugin_components" && -f "$backend_routes" ]] || { echo "integration compatibility gate requires readable component artifact files" >&2; exit 1; }
else
  [[ -n "$plugin_root" && -n "$backend_root" ]] || usage
  [[ -d "$plugin_root" && -d "$backend_root" ]] || { echo "integration compatibility gate requires existing checkout roots" >&2; exit 1; }
  [[ -f "$backend_root/manage.py" ]] || { echo "integration compatibility gate backend root lacks manage.py" >&2; exit 1; }
  temporary="$(mktemp -d)"; trap 'rm -rf "$temporary"' EXIT
  plugin_components="$temporary/plugin-components.json"
  backend_routes="$temporary/backend-routes.json"
  [[ -n "$plugin_node" ]] || plugin_node="node"
  "$plugin_node" --version | python3 -c 'import re,sys; match=re.fullmatch(r"v(\d+)\.(\d+)\.(\d+)\n?", sys.stdin.read()); assert match and (int(match[1]), int(match[2]), int(match[3])) >= (24,20,0) and int(match[1]) < 25, "Loomex integration compatibility requires Node 24.20.x"'
  if [[ -f "$plugin_root/scripts/export-plugin-components.mjs" ]]; then
    "$plugin_node" "$plugin_root/scripts/export-plugin-components.mjs" --package-root "$plugin_root" --output "$plugin_components"
  elif [[ -f "$plugin_root/dist/compatibility-check.mjs" ]]; then
    "$plugin_node" "$plugin_root/dist/compatibility-check.mjs" --package-root "$plugin_root" --output "$plugin_components"
  else
    echo "integration compatibility gate plugin root lacks a source or packaged component exporter" >&2
    exit 1
  fi
  if [[ -z "$backend_python" ]]; then
    backend_python="python3"
    [[ -x "$backend_root/.venv/bin/python" ]] && backend_python="$backend_root/.venv/bin/python"
  fi
  "$backend_python" "$backend_root/manage.py" export_runner_routes --output "$backend_routes" --skip-checks
fi

arguments=(--plugin-components "$plugin_components" --backend-routes "$backend_routes")
[[ -z "$output" ]] || arguments+=(--output "$output")
python3 "$repo/scripts/verify-integration-compatibility.py" "${arguments[@]}"
