# Loomex runner

Loomex runs AI workflows on your Mac. The runner is a per-user background service
that authenticates with Loomex, executes approved workflow jobs through local
provider CLIs, and delivers results and artifacts. The `loomex` CLI lets you check
and manage the service. The [Loomex Codex plugin](https://github.com/loomex-app/loomex-codex-plugin)
adds workflow browsing, creation, run following, and Personas to Codex chat.

## Version 1.0.0 preview

[Download the paired 1.0.0 release](https://github.com/loomex-app/loomex-runner/releases/tag/preview-runner-v1.0.0-plugin-v1.0.0).
It contains runner **1.0.0**, plugin **1.0.0**, and their verified installer under
the immutable tag `preview-runner-v1.0.0-plugin-v1.0.0`.

This is an **unsigned local-development prerelease for macOS Apple Silicon**.
It is not Developer ID signed or notarized. Installation requires explicit
unsigned-development consent. It has not been promoted to a latest stable release.

Before installing, you need:

- A Mac with Apple Silicon (`arm64`), using a normal foreground user session.
- A compatible Loomex backend already running at **`http://127.0.0.1:28080/`**.
  The download does not install or start a backend. This release has no configured
  web app origin and cannot be redirected to a hosted cloud backend.
- Codex desktop or CLI for the plugin. The unified installer uses the Codex CLI
  for registration when available; otherwise it reports the local marketplace
  root for supported GUI import.
- The provider CLIs required by your workflows, with their own account access.
  Loomex installation does not sign you into a provider or establish model access.

The plugin bundles its Node runtime; installing these release assets does not
require Rust, npm, Python, or a source checkout.

## Install

Use the paired release above, including when you only want the plugin. Do not
mix assets from different releases or independently select `latest` components.
The default installs both the runner and plugin; `--runner-only` installs the runner
alone.

Download the release-specific launcher to a new directory:

```sh
mkdir loomex-1.0.0-preview
cd loomex-1.0.0-preview
/usr/bin/curl --fail --show-error --location --proto '=https' --proto-redir '=https' \
  --output install-preview.sh \
  https://github.com/loomex-app/loomex-runner/releases/download/preview-runner-v1.0.0-plugin-v1.0.0/install-preview.sh
```

Inspect the script and compare its checksum with the immutable release assets:

```sh
cat install-preview.sh
printf '%s\n' 'dd509a052ec437d5be7362ee29163f0db9cd60170f04d0b2cfad335d010f4d6b  install-preview.sh' \
  | /usr/bin/shasum -a 256 -c -
```

Proceed only after the checksum check succeeds and you accept this unsigned
preview. This is the explicit install step:

```sh
LOOMEX_ALLOW_UNSAFE_DEV_INSTALL=1 /bin/bash ./install-preview.sh --allow-unsigned-preview
```

The launcher pins `release-set.json` to SHA-256
`906cca85109be51819ebe6ba5c3d8de6b4ff9bbe8b427f86f5592f1ce0906cdd`
and verifies the native installer before running it. The native installer verifies
both component archives, nested file inventories, and compatibility evidence
before delegating activation to each component's lifecycle manager. Checksums
establish byte integrity; this unsigned preview has no publisher signature.

The installer does not force login, organization selection, hook trust, or a
workflow run. Review and trust the plugin's lifecycle hooks separately in Codex.
If registration cannot finish, follow the reported Codex prerequisite and retry
the same release set. An interrupted operation must retain its original verified
assets and lifecycle state; do not delete journals or installed versions manually.
A Keychain transition requires separate explicit authorization through the native
owner; see [installation and Keychain policy](docs/release.md).

For the offline archive, custom installation bases, and verification details,
see [public distribution](docs/public-distribution.md).

## Get started

After successful installation, check the installed runner using its stable path:

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
for the chat entry points.

Jobs run with your OS user's host permissions. A workspace approval is an exact
execution binding, not a filesystem sandbox. Loomex credentials remain with the
runner; provider credentials remain with their provider CLIs. Diagnostics can
identify provider executables without proving account access to a particular model.

## Update, recovery, and removal

Review and install a complete new paired release to update. The lifecycle manager
drains execution admission and defers replacement while managed work remains.
Retained versions are eligible for rollback only after compatibility and integrity
checks; retaining their files alone does not establish a safe downgrade.

```sh
"$loomex" lifecycle status --rollback-preflight --json
"$loomex" lifecycle --help
```

Use the documented [operations](docs/operations.md) and
[release lifecycle](docs/release.md) for resume, rollback, pruning, and uninstall.
Uninstall drains work and revokes Loomex credentials before removing owned files;
it preserves provider credentials and workspace files. Plugin removal and Codex
registration are separate steps covered in the
[plugin lifecycle guide](https://github.com/loomex-app/loomex-codex-plugin/blob/main/docs/release.md).

## Development and contracts

Source builds require Rust 1.88+ and the locked dependencies:

```sh
cargo test --locked
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
```

Read [architecture](docs/architecture.md), [release qualification](docs/release.md),
and [public distribution](docs/public-distribution.md) for builds, deployment
profiles, compatibility gates, and packaging. The local-control protocol is
`loomex.local-control/v2`; product versions and protocol versions change
independently. Low-level `loomex rpc METHOD JSON` calls use the
[method catalog](contracts/method-catalog.json); ambiguous mutations must be
reconciled with their original UUID idempotency key.

The published runner was built from
[`031ea7aa612786cb76b24bf98fe3c0644058c71c`](https://github.com/loomex-app/loomex-runner/commit/031ea7aa612786cb76b24bf98fe3c0644058c71c),
paired with plugin
[`349cbbbca34bfe172714088f633bc7bf656b378c`](https://github.com/loomex-app/loomex-codex-plugin/commit/349cbbbca34bfe172714088f633bc7bf656b378c).
Later source or documentation changes do not change those immutable release bytes.
