#!/bin/bash
# Local iteration only: no package, immutable qualification, installation or signing.
set -euo pipefail
[[ $# == 0 ]] || { echo "usage: $0 (local iteration only)" >&2; exit 2; }
repo="$(cd "$(dirname "$0")/.." && pwd -P)"
echo "FAST LOCAL DEVELOPMENT: incremental dev binaries only; not distribution or release evidence" >&2
cd "$repo"
cargo +1.88.0 build --locked --bin loomex --bin loomex-runner --bin loomex-lifecycle-bootstrap
