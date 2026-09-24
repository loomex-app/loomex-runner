# Runner operations

This guide covers the per-user `loomex-runner` daemon and `loomex` CLI. It describes current source behavior; production use still depends on the open release gates.

The daemon creates `presentation.sqlite3` on first startup after durable UI support is installed. No separate migration command is required. The file and its WAL live inside the owner-only runner state directory. Active UI sessions and unresolved operation records are retained across daemon restarts. Inactive and resolved views are swept after 30 days; explicit view deletion removes its journal, and run deletion removes views bound to the deleted execution subtree.

## Runtime layout and basic checks

The default state root is `~/.local/share/loomex/runner`. A test or development instance may use an absolute `LOOMEX_STATE_DIR`. Never point a test daemon at an installed user's state directory.

```sh
loomex status
loomex diagnostics
loomex login
loomex logout
loomex drain
loomex rpc METHOD JSON
```

`status` returns a concise runner version, local protocol, active-job count, drain state, and staged-update view. `diagnostics` is read-only JSON for repair: it reports daemon connectivity, the non-secret installation ID when the daemon can read it, and each provider executable's availability with a safe reason. It never starts a daemon, reads provider authentication, or prints provider paths and checksums. `login` starts browser approval with PKCE and opens the same-origin authorization page. The daemon completes the loopback callback and credential exchange. Organization selection and workspace grant are separate catalogued operations, for example:

```sh
loomex rpc organizations.list '{}'
loomex rpc organizations.select '{"organizationId":"00000000-0000-4000-8000-000000000000","idempotencyKey":"00000000-0000-4000-8000-000000000001"}'
loomex rpc workspaces.grant '{"workspacePath":"/absolute/path/to/workspace","idempotencyKey":"00000000-0000-4000-8000-000000000002"}'
```

Use fresh UUIDs in real requests. Retain each mutation key with its intended operation. If a response is ambiguous, retry the same operation with the same key; do not issue a second logical change with a different key.

The daemon should have exactly one owner per state root. Check that the state directory is owned by the signed-in user and mode `0700`, and that `control.sock` and regular state files are owner-only. Do not relax socket permissions to make another user or service connect.

For provider CLIs installed outside the standard service search paths, pass one option per provider during installation, for example `--provider-executable codex=/absolute/path/to/codex`. The accepted provider names are `codex`, `claude`, `gemini`, and `antigravity`; `antigravity` binds the `agy` executable and does not replace the Gemini CLI adapter. The installer resolves symlinks, requires a regular executable file, stores the canonical path in the installation receipt, and writes the corresponding `LOOMEX_CODEX_EXECUTABLE`, `LOOMEX_CLAUDE_EXECUTABLE`, `LOOMEX_GEMINI_EXECUTABLE`, or `LOOMEX_ANTIGRAVITY_EXECUTABLE` value into this runner's LaunchAgent. Updates preserve these bindings when the flags are omitted, including a deferred update resumed after active jobs finish. This does not read or copy provider authentication.

## Authentication and organizations

Loomex credentials live in macOS Keychain service `app.loomex.runner.v1`, account `installation`. The daemon creates one installation identity, obtains device authority through user approval, and enrolls a separate child credential for each selected organization. Neither the CLI nor plugin prints tokens, keys, refresh material, proofs, or bootstrap grants.

`auth.status` distinguishes unauthenticated, pending recovery, authenticated, logout-pending, invalid store, and unavailable store states. During an ambiguous bootstrap, enrollment, or refresh, the runner may perform the backend's one permitted recovery within 30 seconds using the exact persisted request. If that recovery is spent or rejected, do not repeatedly retry or delete state manually; preserve the Keychain record and investigate the backend authority state.

Logout rejects an active provider job without cancelling it. Otherwise, it temporarily closes lease admission and waits for idle sessions and heartbeats to exit before recording logout intent. It revokes the device and all child credentials at the backend, then clears local Loomex credentials only after the remote result. A network failure leaves logout pending so revocation can be reconciled. The temporary admission gate is released on completion or failure; it is not a durable lifecycle drain. Provider CLI credentials are outside this process and must remain intact.

## Workspace and run admission

A grant is tied to the canonical absolute path, filesystem device/inode, organization, and installation. Moving the directory away and creating another at the same path invalidates the grant. Regrant only after confirming the intended directory.

Before commit, review the exact workflow/version closure, ordinary inputs, organization, installation, canonical workspace, provider configuration, and the warning that `host_user/v1` has the full permissions of the signed-in user. The workspace defines cwd and artifact-reference checks; it does not confine arbitrary child access. Concurrent runs may use the same workspace, and Loomex supplies no per-workspace locking. The user and invoked tools own coordination of overlapping file changes.

The runner admits only a committed local preparation whose digest and confirmation data still match the backend job. A changed provider executable, replaced workspace, different organization, stale installation, or altered provider configuration fails before spawn. Missing providers should be installed or repaired through their normal vendor process; do not copy provider credentials into Loomex.

## Execution, cancellation, and authority loss

Provider and command jobs use explicit argv under `host_user/v1`. There is no product execution deadline or cumulative output/artifact/concurrency quota. Host resource limits still apply: available disk, memory, process limits, provider behavior, network reachability, and backend lease authority can end or impair a run.

Cancellation can arrive from an explicit run request, backend heartbeat or renewal, lease expiry, run deletion, or logout. Graceful SIGINT/SIGTERM drains the daemon and waits for current work; it does not imply cancellation. If the daemon process dies, its guardian detects the closed ownership pipe and terminates the managed group. For a live owned process group the runner sends `SIGTERM`, waits two seconds, then sends `SIGKILL`. It reports whether the managed group stopped. Detached descendants and already-issued external effects cannot be proved reversed and remain explicitly indeterminate.

If a provider or command effect may have started and the daemon loses durable outcome evidence, the runner records `EXECUTION_INDETERMINATE` and never reruns the command automatically. Reconcile the workflow and external system using the run, job, correlation, and artifact identifiers. Do not work around this state by deleting its journal and restarting the same job.

## Failure and recovery guide

| Symptom or state | Meaning and action |
| --- | --- |
| `RUNNER_UNAVAILABLE` | The socket is absent, unsafe, inaccessible, refused a connection, or transport failed before a mutation was known sent. Run `loomex diagnostics`, check LaunchAgent/daemon status, state ownership, and `control.sock`; preserve state. |
| `LIFECYCLE_ERROR` | A lifecycle journal, LaunchAgent, or candidate-health operation could not be completed. Run `loomex lifecycle status --json`; preserve the lifecycle journal and use `resume` or `repair` when it identifies an action. |
| `NETWORK_AMBIGUOUS` | A local mutation may have reached the runner. Retry the same intended mutation with the returned idempotency key or query the resulting resource. |
| `AUTH_REQUIRED` / `AUTH_EXPIRED` | Device or organization authority is missing. Inspect `auth.status`; complete login or repair enrollment rather than supplying tokens manually. |
| `AUTH_RECOVERY_PENDING` / `AUTH_RECOVERY_EXHAUSTED` | A credential mutation has durable uncertain state. Preserve Keychain state and reconcile the backend record; repeated recovery is intentionally blocked. |
| `WORKSPACE_DENIED` | The canonical path, inode, organization, or installation no longer matches the grant. Inspect and explicitly grant the intended existing directory. |
| `PROVIDER_UNAVAILABLE` | `argv[0]` cannot be resolved as an executable, or an explicitly configured provider path is no longer the same canonical executable. Repair the installed path or rerun the installer with the provider's current absolute executable path, without exposing its auth store. |
| `PROVIDER_CONFIGURATION_CHANGED` / `PRECONDITION_FAILED` | Provider bytes/metadata or a prepared binding changed after review. Prepare and review a new binding. |
| `EXECUTION_INDETERMINATE` | Restart or host failure left no trustworthy terminal outcome. The command is not replayed. Reconcile effects manually and keep the journal for evidence. |
| `ARTIFACT_FINALIZATION_FAILED` | Complete local output could not be registered as required artifacts. Inspect backend/storage availability and retained job files; terminal evidence is preserved. |
| `delivery_blocked` journal | Terminal evidence cannot be delivered because authority or referenced server state is no longer valid. Preserve it for operator reconciliation; it has no automatic expiry. |
| Disk exhaustion | Output spooling or atomic state writes can fail and make the outcome indeterminate. Free space without deleting active/undelivered runner evidence, then reconcile. There is no silent truncation fallback. |

The daemon retries retryable terminal and artifact delivery from durable evidence. It may reclaim a backend fence for terminal submission only. It does not replay provider or command execution. Restart recovery redelivers a durable exit/result or converts a nonterminal journal to an indeterminate terminal error.

## Output, artifacts, and retention

Stdout and stderr are complete owner-only job files and are also delivered as checksummed artifacts before terminal success. Event streaming uses durable byte offsets, so a transient backend outage does not impose a total output cap. Declared artifacts are uploaded only after an expected, non-cancelled exit and must be individual regular files at reviewed relative workspace paths.

Large local control results return a `responseRef`. Read every page with `responses.read`, advancing `nextOffset` until null, and verify the whole-response `checksumSha256`. `responses.delete` removes a reference when it is no longer needed and is idempotent.

The automatic 30-day policy removes acknowledged job evidence, idle response spools, and cached operation results. It does not expire running, terminal-pending, or delivery-blocked journals. Expired operation results retain a tombstone that prevents an old mutation key from executing again.

`runs.delete` first applies the backend's existing deletion policy. Only after backend success does the runner tombstone and purge generated local evidence for that run. It never deletes files from the user's workspace or provider credential stores.

## Drain, update, rollback, and uninstall

`loomex drain` stops admission and lets current work finish without a product deadline. The installer durably drains before checking whether managed work remains, records every staged version in `owned-versions.json`, and keeps a pending update while work is active. Retry installation when the runner is idle; the latest pending candidate is selected. The persistent drain marker is cleared only after the old daemon stops and the installed version switches. Live process or journal ownership is never transferred implicitly.

During an upgrade, lifecycle administration negotiates only the stable local `status.get` and `daemon.drain` method capabilities with the previous daemon. It must prove drained, idle work before replacement and still requires the full current capability set for ordinary CLI and plugin operations. This allows a new authentication capability to be introduced without preventing safe retirement of the previous daemon. A rejected drain is never treated as a successful lifecycle response.

Activation uses immutable version directories and a stable `current` symlink. The new daemon must report the expected version and healthy status before previous bytes are retired. If activation fails, rollback first confirms no active work and successfully unloads the candidate. If that cannot be established, installation retains the current service and all relevant files for recovery. Follow [release.md](release.md) for exact verification, rollback, development flags, signing, and notarization behavior.

First installation rejects pre-existing runner-owned state namespaces. Uninstall validates receipted direct SemVer paths, drains before checking activity, and completes remote logout before removing the service and exact owned state names, including `presentation.sqlite3` and its WAL/SHM companions. Unrelated children of a custom state directory remain intact. If revocation, unloading, or credential cleanup fails, removal stops while preserving recovery evidence. Backend data, workspaces, provider authentication, unrelated Keychain accounts, and unrelated files remain outside the uninstall scope.

Follow and recovery state are also owned state: `follow.sqlite3` and
`recovery.sqlite3`, including WAL/SHM sidecars. Uninstall removes them only
after the same completed drain and revocation sequence. A live Stop continues
while its exact event drain, handoff, or terminal-result delivery remains due;
it allows the host to stop once the durable response receipt is present.

## Developer and operator validation

From the runner source tree:

```sh
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
./scripts/test-packaging.sh
```

CI also builds an unsigned development package in isolated temporary directories, installs it without touching the user's LaunchAgent or Keychain, starts the daemon against a non-listening loopback origin, and checks installed CLI status. Unit and fake-backend tests cover state permissions, workspace replacement, signed requests, credential recovery, socket safety, prepare/commit binding, process-group cancellation, output larger than a transport frame, resumable artifact upload, restart without replay, retention, update deferral, rollback, and uninstall boundaries.

These checks do not qualify a production environment. Before release, satisfy the [release gates](../../planning/plugin-runner-clean-slate/release-gates.md), including Developer ID signing, notarization/Gatekeeper, an actually signed clean-host LaunchAgent lifecycle, deployed backend migrations and compatibility, real Desktop UI use, real account and revocation flows, confirmation of historical remote credential revocation, and real Codex, Claude, and Gemini execution. The current planning authority and historical-decision disposition are the [clean-slate baseline](../../planning/plugin-runner-clean-slate/README.md) and [superseded decision index](../../planning/plugin-runner-clean-slate/superseded-decisions-index.md).

## Repairing receipt identity

`loomex lifecycle repair` reconciles a stale installation receipt only after the owned current package, LaunchAgent configuration, and daemon version agree. Receipt repair has its own pending/completed record so interruption after the receipt write can finish without replacing the service. A changed active lifecycle operation or conflicting target/plist fails closed. Repair does not adopt an arbitrary package or transfer execution ownership. Read the lifecycle status before interpreting repair as complete.

Public error recovery rules are exported in `contracts/error-recovery.json`. New local-control clients explicitly negotiate `error.recovery/v1` to receive recovery/outcome fields; older clients retain the original wire envelope. Unknown outcomes require exact reconciliation. A retryable transport hint never permits replay of uncertain command effects.

## Execution ownership diagnostics

When drain remains pending, inspect active/managed work and durable job state
before replacing the daemon. Managed work includes recovery, delivery and
control operations; an exited child alone does not prove quiescence.

After an execution-task failure, preserve the journal and output directory.
A confirmed exit/result is retained for delivery; absence of trustworthy
terminal evidence produces an indeterminate outcome, never automatic command
replay. An unreadable journal is retained and does not prevent reconciliation
of other readable jobs. Repair storage availability before retrying delivery;
do not delete evidence to force another execution.

Source validation and evidence for the modular execution implementation are in
[Phase 5 completion](../../planning/plugin-runner-integration/phase-5-completion.md).
Installed provider and signed-package qualification remain separate gates.
