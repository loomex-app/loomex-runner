# Runner architecture

The Loomex runner is a macOS arm64 per-user Rust service. `loomex-runner` is the long-lived daemon; `loomex` is a thin local CLI. The runner is the only new product component that holds Loomex credentials, communicates with the backend, discovers provider executables, launches work, controls live process groups, and retains local recovery evidence.

## Components and authority

The runner sits between a credential-free local client and the canonical Loomex backend. Its main modules are:

- `control`: owner-only Unix socket, canonical local method catalog, prepare/commit enforcement, backend route allowlist, response spooling, artifact download, and daemon lifecycle.
- `auth`: device login, organization enrollment, credential rotation, one-time lost-response recovery, logout, and native credential-store persistence.
- `api`: fixed-origin HTTPS client, signed request proofs, bounded HTTP request budgets, no redirects, and backend envelope validation.
- `jobs`: organization sessions, leasing and fencing, local authorization checks, output events, resumable artifact upload, terminal delivery, and restart recovery.
- `executor`: explicit argv launch, durable spawn observations, process-group supervision, cancellation, and complete disk spooling.
- `state` and `retention`: private atomic state, workspace identity grants, operation idempotency records, tombstones, and generated-evidence lifecycle.

The backend owns workflow and run policy and is authoritative for remote identity, organizations, immutable versions, preparations, executions, leases, events, interactions, artifacts, retention, and deletion authorization. The runner enforces local authority in addition to backend checks; it never treats a backend-supplied path alone as a workspace grant.

## Trust boundaries

### Local clients

The daemon binds `${LOOMEX_STATE_DIR}/control.sock`, defaulting to `~/.local/share/loomex/runner/control.sock`. The state path must be absolute. Existing state paths must be non-symlink directories owned by the effective UID; the daemon sets directories to `0700`, state files to `0600`, and the socket to `0600`. A singleton file lock prevents two daemons from owning the same state root. Accepted Unix connections must report the same peer UID.

Local frames are newline-delimited JSON under `loomex.local-control/v2`, with a maximum frame size of 1,048,576 bytes. Requests name one method from the runner-owned catalog. Unknown methods, unknown input fields, schema violations, unsafe paths, and malformed envelopes fail with safe error codes. Mutations serialize through a daemon mutex and use durable idempotency records.

The socket carries no Loomex bearer token or request proof. Same-UID access is the local authentication boundary, so the channel is intended for the signed-in user's plugin and CLI, not for a shared or remote runner.

### Credentials and backend

Loomex device and organization child credentials plus the installation signing key are serialized only into the native macOS Keychain service `app.loomex.runner.v1`, account `installation`. Public workspace and selection state is stored separately. Operational job journals do not contain Loomex credentials. Provider authentication is not copied into Loomex state; Codex, Claude, and Gemini retain their own host stores.

Production builds embed one HTTPS API origin in `LOOMEX_API_ORIGIN`. They reject a runtime development-origin override. Debug builds require an explicit loopback HTTP or HTTPS `LOOMEX_DEV_API_ORIGIN`. The HTTP client follows no redirects and performs no implicit request retry. Device and child requests use scoped bearer credentials and Ed25519 request proofs over the exact method, path/query, body digest, timestamp, nonce, token prefix, and subject.

Credential creation and rotation persist the exact pending operation before transmission. Only the backend-defined one-time recovery may resend bootstrap, enrollment, or refresh material after an ambiguous response, within 30 seconds. Logout marks protected state pending, revokes remotely, and only then clears local Loomex credentials.

## Protocol ownership and versioning

The runner owns `contracts/local-control.schema.json` and `contracts/method-catalog.json`. The local protocol remains `loomex.local-control/v2`. Fixed-text `validationIssueVersion: "v1"` issues are behind the negotiated `error.validation-issues/v1` capability. Durable UI sessions and backend interaction drafts are separately negotiated through `presentation.sessions/v1` and `interactions.drafts/v1`; older runners therefore fail compatibility checks before a new UI can write. `protocol.negotiate` establishes the selected protocol and required capabilities on the same socket before actions; incompatible peers cannot mutate state. `daemon.drain` is internal lifecycle control. The plugin vendors a pinned catalog copy and exposes only its intended model/app surface.

Presentation state is stored in `presentation.sqlite3` inside the existing mode-0700 daemon directory; the database is mode 0600. Rows carry both the selected organization and authenticated child runner subject. The backend binds that subject to one user, organization, and installation, so a later login by another account cannot restore the first account's views while the same owner tuple remains stable across credential rotation. Session state and exact operation arguments use separate tables. SQLite immediate transactions serialize revision updates and atomically journal a UI mutation before its session revision becomes visible. This store is presentation only and is never consulted by workspace, preparation, commit, job admission, or human-request authorization paths.

Protocol input and output changes require synchronized plugin schemas, new digests in the plugin pin, compatibility review, and cross-product validation. Backend response fields outside a local method's declared result are folded into `details`; required local fields must still be present. A local result too large for one frame becomes a checksummed response reference that can be read in 262,144-byte pages.

## Workspace and prepared authority

A workspace grant records the canonical directory path, filesystem device and inode, organization, runner installation, time, and mutation key. Every use canonicalizes the supplied path again and verifies all identities. Replacing a directory at the same spelling invalidates the grant.

Runs and builder/editor sessions use two stages:

1. Prepare verifies a live workspace grant, snapshots installed providers, supplies installation ID and `host_user/v1`, and persists the backend's binding digest with a local confirmation key.
2. Commit verifies the operation kind, organization, installation, binding digest, confirmation key, live workspace identity, and unchanged provider snapshot. It persists local commit authorization before asking the backend to enqueue work.

Each leased job must carry that preparation ID and exact binding. The runner checks its payload digest, organization, installation, workspace, execution policy, provider configuration, and current provider snapshot again before start. A changed or missing provider fails closed.

## Provider and execution policy

Provider discovery is limited to executable `codex`, `claude`, and `gemini` files. An installed service can bind canonical executable paths through `LOOMEX_CODEX_EXECUTABLE`, `LOOMEX_CLAUDE_EXECUTABLE`, and `LOOMEX_GEMINI_EXECUTABLE`; an explicit binding takes precedence and fails closed if its file becomes missing, non-executable, or non-canonical. Providers without an explicit binding retain discovery through the daemon `PATH` plus `/opt/homebrew/bin`, `/usr/local/bin`, `/usr/bin`, and `/bin`. The snapshot binds canonical path, SHA-256, size, modification time, and `host_user/v1`. Jobs support `shell.exec` and `command.run`; the backend supplies explicit argv. The runner resolves argv element zero to an executable and never invokes an implicit shell. An explicitly authored scalar shell command must already have been converted into reviewed `[/bin/sh, -c, ...]` argv by the backend.

For a Codex structured-output job, the runner writes the bound JSON schema to the private job directory and requires exactly one `{loomex:provider-schema}` argv placeholder. It substitutes the private file path after verifying the schema digest. Provider-model, effort, resume, and permission-bypass arguments are backend-owned prepared data; the runner enforces their bound payload and executable snapshot rather than reconstructing provider policy.

`host_user/v1` is full OS-user execution. The child receives selected host identity and locale variables, a provider-capable `PATH`, and explicitly requested environment entries. The workspace constrains cwd validation and declared artifact references. It does not sandbox arbitrary file, network, process, or external-system access.

There is no product execution deadline, total output limit, artifact count or byte limit, global concurrency cap, or per-workspace lock. One session runs for each enrolled organization, and leased jobs spawn concurrent workers. Renewable leases and finite transport chunks bound authority and message size; they do not cap total execution.

## Durable execution and cancellation

The runner journals the lease before spawning. It asks the backend to mark the job started, records spawn intent, launches a guardian as an owned process-group leader, records and syncs the guardian identity, and only then authorizes the guardian to launch the target through a private pipe. A repeated lease cannot spawn again once the journal path exists.

Stdout and stderr are streamed into owner-only files with fixed-size copy buffers and no cumulative truncation. The runner periodically sends 32 KiB event chunks using durable offsets. Lease renewal runs every five seconds, while an independent 200 ms authority watcher requests cancellation when lease authority expires. Backend heartbeat, renewal, explicit run cancellation, deletion, logout, and daemon shutdown can also set the live cancellation token.

Cancellation sends `SIGTERM` to the owned process group, waits up to two seconds, then sends `SIGKILL`. The unreaped guardian reserves process-group identity until observation and cleanup finish. A recovered PID or PGID is evidence only and is never signaled after restart. Full-host descendants may detach or create external effects, so the result reports managed-group status and descendant cleanup as indeterminate rather than claiming reversal.

## Failure, recovery, and terminal delivery

An interrupted job with no durable terminal outcome is never replayed. On restart it becomes `EXECUTION_INDETERMINATE`, and the runner redelivers that terminal error with the existing terminal idempotency key. Jobs that reached durable `exited` or `terminal_pending` resume output/artifact materialization and terminal submission. Failed terminal delivery may obtain a new backend fence solely for redelivery; it never launches the command again.

Authorization, revoked/missing object, and invalid-token failures move evidence to `delivery_blocked`. Other delivery failures retry after a delay. The durable phases provide evidence for leased, start-pending, started, spawn-intent, running, exited, terminal-pending, acknowledged, and blocked outcomes; backend fences and payload digests prevent stale workers from completing another lease.

Both stdout and stderr become complete artifacts before successful terminal submission. Declared outputs are uploaded only for an expected exit code and a non-cancelled outcome. Each declaration is one normal relative path; directories, traversal, missing files, and paths that canonicalize outside the workspace fail. Upload create is idempotent, resumes from the server offset in chunks of at most 262,144 bytes, and completes against a whole-file SHA-256.

Artifact downloads write an owner-only temporary file, verify page offsets, total size, and whole-file SHA-256, then publish into the requested absolute destination without following a destination symlink.

## Retention boundary

Automatic retention applies only to runner-generated evidence. Acknowledged job directories expire 30 days after acknowledgement. Response spools expire 30 days after last access. Cached operation results expire after 30 days but retain an `expired` tombstone, so an old mutation key cannot replay. Running, terminal-pending, and delivery-blocked journals have no automatic expiry.

Backend-confirmed run deletion writes local run and preparation tombstones, cancels a live matching job, purges matching response and cached operation results, and removes matching job evidence when safe. Retention and run deletion never traverse or delete the user's workspace or provider credential stores.

## Current decisions and verification limits

The controlling documents are the [clean-slate baseline](../../planning/plugin-runner-clean-slate/README.md), [runtime contract](../../planning/plugin-runner-clean-slate/runtime-contract.md), [authentication contract](../../planning/plugin-runner-clean-slate/auth-contract.md), [backend contract](../../planning/plugin-runner-clean-slate/backend-contract.md), [requirements matrix](../../planning/plugin-runner-clean-slate/requirements-capability-acceptance.md), and [superseded decision index](../../planning/plugin-runner-clean-slate/superseded-decisions-index.md).

Current unit and fake-backend tests verify many enforcement and recovery paths but do not prove a production release. Apple signing/notarization, an actually signed clean-host LaunchAgent, deployed backend migrations and compatibility, real account flows, real Desktop UI use, real Codex/Claude/Gemini executions, and confirmation of historical remote credential revocation remain open in the [release gates](../../planning/plugin-runner-clean-slate/release-gates.md).
