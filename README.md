# Loomex runner

Loomex runs AI workflows on your Mac. The runner is a per-user background service
that authenticates with Loomex, executes approved workflow jobs through local
provider CLIs, and delivers results and artifacts. The `loomex` CLI lets you check
and manage the service. The [Loomex Codex plugin](https://github.com/loomex-app/loomex-codex-plugin)
adds workflow browsing, creation, run following, and Personas to Codex chat.

## Install

Install using the instructions in the
[GitHub release](https://github.com/loomex-app/loomex-runner/releases/latest).
The paired installer selects compatible runner and plugin components. Review the
release's platform, backend, and signing prerequisites before installation.

You need a compatible Loomex backend and the provider CLIs required by your
workflows, with their own account access. The release instructions specify the
backend configuration supported by those binaries. Installation does not sign you
into a provider or establish model access. Use Codex desktop or CLI to access the
plugin; the release instructions also cover its registration requirements.

## Get started

After successful installation, check the runner using its stable path:

```sh
loomex="$HOME/Library/Application Support/Loomex/runner/current/bin/loomex"
"$loomex" --version
"$loomex" status
"$loomex" diagnostics
"$loomex" login
```

`login` opens the backend's browser approval flow; the runner completes the
credential exchange. In a fresh Codex chat, use `$loomex:loomex-connect` to check
the connection and select your organization, then `$loomex:loomex-browse` to find
a workflow. Review its required inputs, workspace, provider, and execution policy
before choosing **Start**. See the [plugin README](https://github.com/loomex-app/loomex-codex-plugin#readme)
for all chat entry points.

Jobs run with your OS user's host permissions. A workspace approval is an exact
execution binding, not a filesystem sandbox. Loomex credentials remain with the
runner; provider credentials remain with their provider CLIs. Diagnostics can
identify provider executables without proving account access to a particular model.

## Updates, recovery, and removal

Follow the selected GitHub release's instructions to update. The lifecycle manager
drains execution admission and defers replacement while managed work remains.
Retained versions are eligible for rollback only after compatibility and integrity
checks.

```sh
"$loomex" lifecycle status --rollback-preflight --json
"$loomex" lifecycle --help
```

See [operations](docs/operations.md) and [lifecycle details](docs/release.md) for
resume, rollback, pruning, and uninstall. Uninstall drains work and revokes Loomex
credentials before removing owned files; it preserves provider credentials and
workspace files. Plugin removal and Codex registration are separate steps covered
in the [plugin lifecycle guide](https://github.com/loomex-app/loomex-codex-plugin/blob/main/docs/release.md).

## Development

Source builds require Rust 1.88+ and the locked dependencies:

```sh
cargo test --locked
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
```

Read [architecture](docs/architecture.md), [build and packaging](docs/release.md),
and [distribution](docs/public-distribution.md) for deployment profiles,
compatibility gates, and packaging. Low-level `loomex rpc METHOD JSON` calls use
the [method catalog](contracts/method-catalog.json); ambiguous mutations must be
reconciled with their original UUID idempotency key.
