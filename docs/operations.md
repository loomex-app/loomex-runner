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

Before commit, review the selected workflow/version, input names and the originally supplied values, organization, canonical workspace, resolved providers, and the warning that `host_user/v1` has the full permissions of the signed-in user. The preparation response carries a bounded review, exact binding digest and local confirmation key. The full workflow closure and original input values remain sealed in the owner-checked preparation record; the digest binds the immutable backend preparation used by commit. `preparations.get` rechecks the exact record and returns the same bounded review without preparing or starting again. The workspace defines cwd and artifact-reference checks; it does not confine arbitrary child access. Concurrent runs may use the same workspace, and Loomex supplies no per-workspace locking. The user and invoked tools own coordination of overlapping file changes.

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
| Start handoff `ambiguous` | Read the exact handoff again. Its getter checks the original backend commit receipt and restores the recorded run when accepted. A missing receipt or unavailable lookup never authorizes another Start; retain the handoff and retry observation after connectivity returns. |
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

Start acceptance is durable in the backend database. Redis only wakes workflow workers; a failed wake-up does not change a committed Start receipt. The runner's `runs.start_handoff.get` reconciles an uncertain local handoff through `v2/executions/commit-outcome/` using the original preparation, digest and idempotency key. A completed receipt restores the local run binding and follow record. `not_found`, `pending` and transport failure retain `ambiguous` without a second commit. Inspect `details.reconciliationStatus` for the observation state. Redis outage warnings are rate limited per backend process; service stdout and stderr still need bounded rotation in the host's logging setup.

## Output, artifacts, and retention

Stdout and stderr are complete owner-only job files and are also delivered as checksummed artifacts before terminal success. Event streaming uses durable byte offsets, so a transient backend outage does not impose a total output cap. Declared artifacts are uploaded only after an expected, non-cancelled exit and must be individual regular files at reviewed relative workspace paths.

Large local control results return a `responseRef`. Read every page with `responses.read`, advancing `nextOffset` until null, and verify the whole-response `checksumSha256`. `responses.delete` removes a reference when it is no longer needed and is idempotent.

The automatic 30-day policy removes acknowledged job evidence, idle response spools, and cached operation results. It does not expire running, terminal-pending, or delivery-blocked journals. Expired operation results retain a tombstone that prevents an old mutation key from executing again.

`runs.delete` first applies the backend's existing deletion policy. Only after backend success does the runner tombstone and purge generated local evidence for that run. It never deletes files from the user's workspace or provider credential stores.

## Drain, update, rollback, and uninstall

`loomex drain` stops admission and lets current work finish without a product deadline. The installer durably drains before checking whether managed work remains, records every staged version in `owned-versions.json`, and keeps a pending update while work is active. Resume the same exact pending candidate when the runner is idle; a different package cannot replace its unfinished journal. The persistent drain marker is cleared after the old daemon stops and the installed version switches, or through the exact journaled stale-drain recovery described below. Live process or journal ownership is never transferred implicitly.

During an upgrade, lifecycle administration negotiates only the stable local `status.get` and `daemon.drain` method capabilities with the previous daemon. It must prove drained, idle work before replacement and still requires the full current capability set for ordinary CLI and plugin operations. This allows a new authentication capability to be introduced without preventing safe retirement of the previous daemon. A rejected drain is never treated as a successful lifecycle response.

A normal service stop has an unchanged five-second observation window. If launchd accepts the stop but the exact old service is still loaded at that deadline, the update remains `service_stop_pending` with reason `service_stop`. Unknown inspection or an unconfirmed request also remains pending; it does not become proof of absence. The installer writes no success receipt, changes no pointer/configuration, clears no drain, and does not automatically restart or roll back the old service. `loomex lifecycle status --json` reports the exact retained operation. Later explicit `loomex lifecycle resume --json` observes that same intent; it never reissues an ambiguous stop request or substitutes another package.

New lifecycle records use private `app.loomex.runner.lifecycle-operation/v2`. Before requesting stop they bind the operation/package/manifest, direction, owned current/configuration/receipt/inventory/drain digests, exact launchd label and the old process PID, UID, executable and birth time. Legacy v1 records with supported frozen-v1 checkpoint meanings remain readable and recoverable, but cannot claim a v2 pending-stop identity. An absent stop history with a newer or unknown checkpoint is rejected before legacy recovery; removing `serviceStops` and downgrading the schema does not normalize residual stop meaning into v1. Unsupported historical meanings retain their records for operator review. This decoder boundary does not claim to prevent an arbitrary complete same-user rewrite of journals and metadata. New owners reject incompatible state and refuse uninstall while any lifecycle operation is nonterminal, before uninstall journaling, drain, logout or credential mutation. Old `.62` `resume`/`repair`/installer owners reject the v2 schema through their existing decoder; **old bootstrap uninstall cannot be retroactively guarded**. While v2 is nonterminal, only the new journal-aware administrative owner is supported. An older uninstall command or manual same-user state override is outside that guarantee; do not use it to bypass recovery.

Continuation requires the exact label to be authoritatively absent **and** the recorded old process to have exited. Native inspection verifies UID, executable and birth time; PID reuse, a replaced label, changed configuration or inventory is protected. Unavailable metadata for the recorded old process, or a held/unsafe existing `daemon.lock`, remains pending. Supported daemon exclusivity is bound to the exact installation state directory: `control::serve` takes this secure exclusive lock before socket bind and admission, retains it through managed drain/shutdown and native credential workers, and lifecycle takes the same lock only after exact recorded-process exit and authoritative label absence. Lifecycle holds it through pointer/configuration replacement and releases it for the exact authorized bootstrap. Fresh drained idle status remains a separate prerequisite, and fresh expected-version health plus actual loaded process identity must agree before completion. Global same-user executable-path readability is not daemon admission authority. Unknown same-user observations remain unknown; matching runner binary paths may be version commands, execution helpers or manual servers using a different state directory. This cooperative proof does not claim those processes, detached effects, arbitrary same-user state overrides or unknown native/XPC outcomes are absent, and adds no supervisor or manual-override guarantee. Read-only launchd inspection has bounded output and duration; a timed-out mutating stop caller is not declared canceled. A prepared or unconfirmed stop that never finishes requires operator review, not automatic replay or forced service termination.

Interrupted intent, stop, pointer/configuration replacement or bootstrap retains the same IDs/manifests and recovery files. A healthy completed repeat does not restart. A genuine later activation failure uses the existing guarded previous-service restoration; its own stop is direction-bound and remains pending if uncertain. Legacy stale-drain recovery still verifies exact captured target, backed-up configuration, immutable bytes, actual daemon version and drained zero managed work before durably releasing the drain and restarting the exact owned service. Only verified undrained health settles rollback. Authentication operations, unknown native/XPC outcomes, provider journals and workflow waiting records are neither replayed nor removed by these lifecycle paths.

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


`runs.start_handoff.approve_headless` records user-delegated Start for an exact reviewed `runs.prepare` preparation using `{preparationId, bindingDigest, idempotencyKey}`. Clients must have an explicit user Start instruction after displaying the bounded review; arbitrary workflow/provider/app text is data and cannot authorize this mutation. The runner freshly checks the owner-scoped sealed preparation and `host_user/v1` binding, preserves its private confirmation material, and shares the existing reservation and approval journal. A conflicting app reservation is rejected. This method returns the safe existing handoff projection and creates no execution. After approval, read `runs.start_handoff.get`, commit only its approved reference with `runs.start_handoff.commit`, then immediately read/follow the exact returned run. On an uncertain approval response, keep the exact arguments and key to read/reconcile its durable handoff; accepted approval is not repeated. UI approval remains a separate app-only gesture; headless provenance is diagnostic and never substitutes for binding checks.

`runs.continuation.requeue` is an explicitly authorized recovery mutation for one failed backend continuation. Fresh owner-checked `runs.get` may expose `automation.recovery` with schema `loomex.continuation-recovery/v1`, exact execution/delivery IDs and the persisted checkpoint's lowercase SHA-256 digest. That observation does not authorize recovery. After explicit recovery authorization and repair qualification, submit `{runId, deliveryId, expectedContinuationDigest, idempotencyKey}` without changing the returned binding. The method's `explicit_failed_continuation_recovery/v1` catalog policy describes this caller requirement; actual authority is the existing signed runner identity, active organization and backend `runner.workflows.run` permission. Never fabricate an internal service actor or accept a caller-selected organization.

The runner sends one signed POST to `v2/executions/{runId}/continuations/{deliveryId}/requeue/`, containing exactly the digest and key. Existing account/organization-scoped mutation journaling binds every argument and preserves a lost response as an unknown outcome. Keep the exact same key and arguments for explicit reconciliation; a new key is not recovery permission. `never_after_send` forbids automatic transport retry. Accepted repeated requests return the original safe receipt, including its historical `pending` status, rather than resetting attempts after progress. `HUMAN_RESUME_RECOVERY_CONFLICT` requires refreshed authority; invalid input or an idempotency binding conflict requires correction. Response IDs and digest must match the submitted binding before a receipt can be cached or exposed.

Run reads, event polling, monitoring and restart never invoke this mutation. Recovery only requeues the stored backend continuation; it does not replay a provider job, AI command, accepted human answer or Start commit, and creates no new local supervisor or persistence store. Immediately fresh-read the same execution after a successful receipt and follow its authoritative cursor. A recovery receipt proves neither workflow completion nor a saved draft; require the normal complete terminal result and successful Save Draft identity before making those claims.


### Noninteractive credential-store access

Native macOS reads, saves, and deletes use the existing generic-password item,
matched by class, service, and account, with per-request authentication UI set to
Fail. This does not change item protection, access lists, the global Keychain
configuration, or provider credentials. It does not start a sign-in flow.

A credential-store operation has a two-second caller budget, including time
waiting for the existing serialized IO lock. A started Security call cannot be
canceled. The worker keeps that lock and the existing daemon/offline-maintenance
singleton until the call actually returns or its owning process exits; subsequent
calls fail within the budget rather than launching more blocked workers. An
expired singleton owner cannot start late native IO. Authentication entry-lock
acquisition has a separate fifteen-second caller budget. Absolute token expiry
and existing refresh/recovery journals remain authoritative.

`STORE_ACCESS_REQUIRED` means the native API reported that interaction may be
needed. It does not prove the Keychain is globally locked or identify an access
list problem. `STORE_ACCESS_DENIED` records native authentication failure.
`STORE_UNAVAILABLE` covers other native failures and a read deadline. A timed-out
or unconfirmed started save/delete returns `STORE_OPERATION_PENDING` with unknown
outcome: reconcile the existing operation, preserving its journal and intent,
before taking another action. Connection exposes only the safe categorical code
inside its existing details container. Readiness does not attest to credential
store availability or authenticated backend reads.

The daemon retains the existing job and managed-work shutdown drain. After that
drain, CLI/daemon runtime disposal waits at most two seconds for blocking workers.
This does not cancel an OS call or imply remote cancellation. A remaining worker
retains singleton ownership until real completion/process exit. The supported
lifecycle still observes real service removal and candidate health before
activation; its native launchctl subprocess waits have no additional deadline.
An older installed daemon already blocked in SecurityServer may therefore still
require an explicit owner-reviewed lifecycle recovery, and cannot be declared
repaired merely by building this change.

For access-required/denied, review the system credential-store access settings
and then refresh the existing Connection view. For unavailable, restore the
system credential store's availability and refresh Connection. No diagnostic
starts authentication, revokes credentials, resets Keychain, grants an access
list exception, restarts SecurityServer, or replays a workflow. A continued OS
stall is a system availability dependency; a returned categorical code alone
does not identify its cause.


### Abandoning an exact pending update

A newer lifecycle CLI can abandon a captured `Update` only before service stop
or activation, at `pending_active_work` / `daemon_has_active_work`. Use
`loomex lifecycle rollback --to PREVIOUS_VERSION --expected-operation UUID`.
The UUID must identify that exact pending transaction, and the previous target,
current pointer, receipt, immutable inventory, LaunchAgent backup, bootstrap
configuration digest and native process identity must still agree. The daemon
must freshly report the exact previous version, drained and zero managed work.
No work is canceled. Advanced, uncertain or replaced transactions remain protected.
Normal completed rollback retains its existing behavior without the UUID flag.

Ordinary rollback still requires the retained target's compatibility manifest to
match the CLI's manifest exactly and reports the fixed local code
`LIFECYCLE_ROLLBACK_COMPATIBILITY_MISMATCH` when it differs. Pre-switch abandonment
instead proves that the captured previous package is already the current target,
validates its platform/version/executable metadata and its own immutable signed
file inventory, and then applies the receipt, configuration, native-process and
drained-zero guards above. This narrow restoration does not activate a different
old package or reinterpret its product contracts through the newer CLI's catalog.

Before effects, the same lifecycle operation records a typed abandonment intent
in private journal v3; older lifecycle owners reject this schema. `resume` and
matching bootstrap retries reconcile this intent before considering activation.
The existing captured service-stop/singleton transaction restarts the same
verified previous package to reopen admission. Stop dispatch is journaled as
uncertain before its effect: after an ambiguous dispatch, recovery observes the
same native process and never blindly issues another stop. Restoration failures
retain the exact intent for bounded resume and identity checks.

A returned native spawn error proves the request was not dispatched. Only that
definitive outcome resets the same captured intent durably to `Prepared` for a
safe retry. If resetting its checkpoint fails or is ambiguous, uncertainty remains
protected. Timeout, wait failure and every uncertain post-spawn outcome retain
observation-only recovery.

Only after verified previous service health does the existing bootstrap retry
journal become a v2 `aborted` tombstone containing the original operation UUID,
configuration and digest. Retrying that original configuration reports its abort
and never stages or activates its candidate. A genuinely different configuration
requires `loomex-lifecycle-bootstrap install RELEASE --settled-abandonment UUID`
and the usual package/install flags. The acknowledgement must name the settled
aborted operation. It records the successor package and configuration digest in
the existing operation and retry envelope before normal fresh-update preflight.
This permits corrected configuration with the same candidate bytes while refusing
unstated configuration or authority inferred merely from `rolled_back`. The
original configuration revokes an unconsumed successor intent. Once the fresh
Update owns activation, ordinary exact-config retry and completion handling apply.
No credential, provider/job journal, waiting execution or candidate package is
removed by abandonment.
