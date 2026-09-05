# Loomex runner 0.1.0

A fresh macOS per-user execution service. `loomex-runner` is the private daemon;
`loomex` is the public CLI. This project has no old runner imports, state migration,
or legacy command aliases.

## Build and test

Rust 1.85+ is required. Dependency resolution is pinned by `Cargo.lock`.

```sh
cargo test --locked
cargo clippy --all-targets -- -D warnings
cargo fmt --all --check
```

Production artifacts must compile with `LOOMEX_API_ORIGIN` set to the deployment's
HTTPS origin. Runtime origin overrides are rejected for that build. An unsigned
development/debug build may instead set `LOOMEX_DEV_API_ORIGIN` to an explicit
loopback origin. No production origin is guessed.

```sh
LOOMEX_DEV_API_ORIGIN=http://127.0.0.1:8000 cargo run --bin loomex-runner
cargo run --bin loomex -- status
cargo run --bin loomex -- login
```

`login` opens the same-origin approval page and polls the device challenge. The
plugin uses the same local methods. Organization selection and workspace approval
are separate explicit steps. See `contracts/method-catalog.json` for exact inputs
and outputs. `loomex rpc METHOD JSON` makes a credential-free local request.

## Execution and authority

The daemon alone stores Loomex credentials, using native macOS Keychain service
`app.loomex.runner.v1`, account `installation`. Device authority discovers and
enrolls organizations; isolated child credentials sign organization requests.
Refresh expirations are absolute. Protected pending rotation state is persisted
before transmission and permits only the backend's explicit recovery protocol.
Provider login stores remain owned by Codex, Claude, and Gemini (the AGY CLI adapter).

The local newline-JSON socket is `~/.local/share/loomex/runner/control.sock`.
`LOOMEX_STATE_DIR`, when present, names that exact runner state directory. The
socket is owner-only and checks the peer UID; it carries no bearer token or proof.
Every connection first calls `protocol.negotiate` with supported protocols and
required capabilities. The CLI and plugin verify the selected protocol, required
capabilities and frame size before sending an action on that same connection.
Incompatible or unnegotiated connections receive `COMPATIBILITY_ERROR` without
performing the requested action.

A remembered workspace is an exact canonical directory and inode bound to the
organization and installation. It is an execution authorization prerequisite,
not a filesystem sandbox. A separate prepare/commit exchange binds the immutable
workflow, input, workspace, organization, installation, execution policy, and
provider configuration. The daemon writes local commit authorization before the
backend can enqueue work. Every job must present that exact preparation and
binding digest. A backend-supplied workspace path cannot grant authority.

Only `host_user/v1` argv jobs are supported. Processes have the OS user's host
permissions. There are no product concurrency, execution-time, cumulative output,
or cumulative artifact limits. Bounded transport chunks do not truncate totals.
Finite renewable leases represent execution authority, not runtime deadlines.
Loss of authority requests cancellation independently of blocked HTTP requests.

The executor writes output to disk, supervises an owned process group, and records
spawn intent and process identity durably. Restarted commands are never replayed.
Terminal delivery and artifact uploads resume from durable evidence. Cancellation
reports managed-group observation separately from detached descendants or external
effects, which full-host execution cannot prove reversed.

Declared `artifactOutputs` contain explicit relative regular-file paths. The daemon
rejects escapes, uploads complete streams and files in resumable chunks, and only
then submits the terminal result. Artifact downloads verify the complete SHA256
before publishing the destination file.

## Data and service lifecycle

Drain stops new execution admission and defers updates while jobs remain. The
installer never transfers a running job to a replacement binary. Run deletion
first confirms the backend tombstone, then removes generated local evidence for
that run; it never removes workspace files or provider credentials. Successfully
delivered output journals and idle response caches expire after 30 days. Active,
undelivered, and blocked recovery evidence is preserved. Idempotency cache expiry
retains a minimal tombstone so an old key cannot replay a write.

Large local responses are immutable paged references with a complete checksum.
`responses.read` reads bounded pages and refreshes last access; `responses.delete`
removes the reference explicitly. A lost mutation response is ambiguous: use the
same idempotency key to reconcile instead of issuing a new logical operation.

Packaging, signing, installation, and operational acceptance are documented in
[docs/release.md](docs/release.md). Unit and fake-backend tests do not deploy the
backend, apply migrations, exercise real account login, or qualify signed provider
execution from a user's installed LaunchAgent. Those remain explicit release checks.

For the local protocol and trust boundaries, read [architecture](docs/architecture.md). For recovery, cancellation, retention and service operation, read [operations](docs/operations.md).

During ordinary operation `activeJobs` counts managed jobs. While draining, it also includes pending session/admission and helper work, so an idle acknowledgement cannot precede a late journal write. The daemon stops admission before acknowledging drain; update activation waits for this count to reach zero.

Control operations capture their organization when admitted and serialize only requests using the same idempotency key. Drain remains responsive during transfers and includes local control writers and response spooling in its pending work count. Once a persistent drain becomes idle, it rejects new work; cancellation and read requests can join a drain only while existing work remains. Repeated drain requests are read-only after the durable drain marker exists.

Uninstall first drains without cancelling active work, waits for idle, and stops the daemon. It then calls `loomex logout --offline`, which takes the same exclusive daemon lock and performs only native credential revocation and cleanup. Failed revocation preserves files and protected retry state; retrying this command does not restart execution or require a socket.
