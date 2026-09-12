#!/bin/bash
# Run the cross-component contract check when callers supply real component exports.
set -euo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd -P)"
required=false
plugin_components="${LOOMEX_PLUGIN_COMPONENTS:-}"
backend_routes="${LOOMEX_BACKEND_ROUTES:-}"
plugin_root="${LOOMEX_PLUGIN_ROOT:-}"
backend_root="${LOOMEX_BACKEND_ROOT:-}"
backend_python="${LOOMEX_BACKEND_PYTHON:-}"
plugin_node="${LOOMEX_PLUGIN_NODE:-}"
output=""

usage() {
  echo "usage: $0 [--required] [--plugin-components FILE --backend-routes FILE] [--plugin-root DIR --backend-root DIR --plugin-node NODE --backend-python PYTHON] [--output FILE]" >&2
  exit 2
}

clean_checkout_revision() {
  local label="$1"
  local root="$2"
  local revision
  local working_tree
  revision="$(git -C "$root" rev-parse --verify HEAD 2>/dev/null)" \
    || { echo "integration compatibility gate $label root is not a Git checkout with an immutable HEAD revision" >&2; exit 1; }
  [[ "$revision" =~ ^[0-9a-f]{40,64}$ ]] \
    || { echo "integration compatibility gate $label root has an unverifiable HEAD revision" >&2; exit 1; }
  working_tree="$(git -C "$root" status --porcelain=v1 --untracked-files=all 2>/dev/null)" \
    || { echo "integration compatibility gate cannot verify $label root working-tree state" >&2; exit 1; }
  [[ -z "$working_tree" ]] \
    || { echo "integration compatibility gate $label root must have a clean working tree in --required mode" >&2; exit 1; }
  printf '%s\n' "$revision"
}

while (($#)); do
  case "$1" in
    --required) required=true; shift ;;
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

artifact_inputs=false
root_inputs=false
[[ -z "$plugin_components$backend_routes" ]] || artifact_inputs=true
[[ -z "$plugin_root$backend_root" ]] || root_inputs=true

if ! "$artifact_inputs" && ! "$root_inputs"; then
  if "$required"; then
    echo "integration compatibility gate --required mode requires plugin/backend artifact files or checkout roots" >&2
    exit 1
  fi
  echo "integration compatibility gate skipped: no plugin/backend artifacts or checkout roots supplied"
  exit 0
fi

if "$artifact_inputs"; then
  [[ -n "$plugin_components" && -n "$backend_routes" && -z "$plugin_root$backend_root" ]] || usage
  [[ -f "$plugin_components" && -f "$backend_routes" ]] || { echo "integration compatibility gate requires readable component artifact files" >&2; exit 1; }
else
  [[ -n "$plugin_root" && -n "$backend_root" ]] || usage
  [[ -d "$plugin_root" && -d "$backend_root" ]] || { echo "integration compatibility gate requires existing checkout roots" >&2; exit 1; }
  [[ -f "$backend_root/manage.py" ]] || { echo "integration compatibility gate backend root lacks manage.py" >&2; exit 1; }
  plugin_revision=""
  backend_revision=""
  if "$required"; then
    plugin_revision="$(clean_checkout_revision plugin "$plugin_root")"
    backend_revision="$(clean_checkout_revision backend "$backend_root")"
  fi
  temporary="$(mktemp -d)"; trap 'rm -rf "$temporary"' EXIT
  plugin_components="$temporary/plugin-components.json"
  backend_routes="$temporary/backend-routes.json"
  [[ -n "$plugin_node" ]] || plugin_node="node"
  "$plugin_node" --version | python3 -c 'import re,sys; match=re.fullmatch(r"v(\d+)\.(\d+)\.(\d+)\n?", sys.stdin.read()); assert match and (int(match[1]), int(match[2]), int(match[3])) >= (24,20,0) and int(match[1]) < 25, "Loomex integration compatibility requires Node 24.20.x"'
  plugin_export_arguments=(--package-root "$plugin_root" --output "$plugin_components")
  if "$required"; then
    plugin_export_arguments+=(--source-root "$plugin_root")
  fi
  if [[ -f "$plugin_root/scripts/export-plugin-components.mjs" ]]; then
    "$plugin_node" "$plugin_root/scripts/export-plugin-components.mjs" "${plugin_export_arguments[@]}"
  elif [[ -f "$plugin_root/dist/compatibility-check.mjs" ]]; then
    "$plugin_node" "$plugin_root/dist/compatibility-check.mjs" "${plugin_export_arguments[@]}"
  else
    echo "integration compatibility gate plugin root lacks a source or packaged component exporter" >&2
    exit 1
  fi
  if [[ -z "$backend_python" ]]; then
    backend_python="python3"
    [[ -x "$backend_root/.venv/bin/python" ]] && backend_python="$backend_root/.venv/bin/python"
  fi
  # Route export is a pure contract read.  Keep Django's normal command
  # validation enabled: passing an option that the command does not declare
  # would make the coordinated gate fail before it can compare anything.
  "$backend_python" "$backend_root/manage.py" export_runner_routes --output "$backend_routes"
fi

arguments=(--plugin-components "$plugin_components" --backend-routes "$backend_routes")
if "$required"; then
  arguments+=(--require-clean-identities)
  [[ -z "${plugin_revision:-}" ]] || arguments+=(--expected-plugin-revision "$plugin_revision")
  [[ -z "${backend_revision:-}" ]] || arguments+=(--expected-backend-revision "$backend_revision")
fi
[[ -z "$output" ]] || arguments+=(--output "$output")
python3 "$repo/scripts/verify-integration-compatibility.py" "${arguments[@]}"
