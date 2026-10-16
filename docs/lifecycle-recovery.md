# Installation and removal recovery

Updates, clean removal, and recovery are separate operations. Use the verified
release's supported tools; do not delete receipts, native credentials, drain
markers, or journals to make an installer proceed.

## Inspect before changing anything

`loomex lifecycle status --json` works without a running daemon. It reports
bootstrap, native, and historical ownership together. An unfinished uninstall
takes precedence over a historical completed update. `actionRequired: true`
means the indicated owner must finish before another installation transaction.

A completed update can still require metadata recovery. Resume its exact
operation rather than deleting `pending-update.json`. Recovery verifies the
installed inventory, receipt and LaunchAgent/provider configuration, records
the original marker bytes and digests in the existing lifecycle journal, then
retires only that matching marker. Interrupted retirement retains its owner;
unknown markers and competing legacy operations remain protected.

The native release bootstrap supports `preflight RELEASE` with the same release
trust, backend-origin, and installation-path options as `install`. It verifies
artifacts and installation eligibility without draining, authorizing native
credential access, or writing an operation. The paired installer has two
distinct read-only modes: `--verify-only` checks artifact integrity, while
`--preflight-only` also checks both installed owners and host registration
prerequisites. Neither is approval to activate a release.

Preflight is an observation. Every mutating owner repeats its checks under the
existing lifecycle lock. A partial pair is reported as such; a plugin or Codex
registration failure never silently rolls back a healthy runner. Retry the
same verified release set, bases, and component operation identities.

## Current uninstall

Run the installed release's `scripts/uninstall.sh`, retaining any explicitly
selected installation/state/LaunchAgent paths. The native owner records one
operation and drain identity, verifies idle managed work, records stop intent,
and verifies service/process/singleton state. A stopped retry does not require
the dead control socket. Uncertain stop dispatch is observed, never blindly
replayed.

Credential maintenance runs in the verified daemon executable without starting
a service or execution worker. Its destination comes from the validated receipt,
not the shell environment. It confirms remote revocation and checkpoints that
fact before removing the native credential item. Missing local credentials
alone do not prove revocation. A never-signed-in installation is classified as
not requiring revocation only after a matching native absence observation.

Native work retains ownership even when the observer's bounded deadline expires.
Wait for and reconcile that same operation; do not start another cleanup.
Ordinary logout does not bypass an acknowledged idle lifecycle drain. Read-only
authentication observations remain available.

Payload removal uses exact inventories and quarantine checkpoints. Resolved
owned local state is inspected before stopping and again before deletion.
Disposable browsing cards are not execution authority. Pending mutations,
deliveries, schedules, and uncertain job evidence prevent destructive cleanup.
Database inspection includes WAL contents through a private temporary snapshot;
it does not change the original database or discard WAL-only records.

Unknown files, backend workflows/runs, user workspaces and provider CLI login
stores are preserved. Stable non-secret singleton/credential-owner lock inodes
are retained deliberately; unlinking a live lock can permit concurrent owners.
Plugin file removal and Codex marketplace/plugin registration removal are
separate outcomes; remove only the exact Loomex registration through supported
Codex controls.

## Recover an older prepared uninstall

Older tools execute their installed bootstrap. Downloading a newer shell alone
does not repair that executable. Use a newly verified recovery release:

```sh
bash /path/to/new-release/scripts/uninstall.sh recover-uninstall /path/to/new-release \
  --expected-old-journal-sha256 <digest-from-reviewed-status> \
  --allow-unsigned-development
```

Development artifacts additionally require the existing
`LOOMEX_ALLOW_UNSAFE_DEV_INSTALL=1` opt-in. Retain explicit installation path
options. Production releases instead require the verified manifest public key.
Do not substitute a new release, digest, or path on an ambiguous retry.

Recovery independently verifies its package, original receipt/helper/inventories,
historical protected-installation baseline, and current native identity. It
preserves original bytes and writes a private versioned refusal fence before
side effects, so older controllers cannot resume a competing operation.
It never overwrites the old helper or its expected digest.

Recovery refuses when the original installation cannot be bound, when retained
cleanup proof is incomplete, when a competing owner is known, or when a signing
transition is unsupported. In particular an old `revoked` label without bound
confirmation is not sufficient evidence. Keep the original journal and use
permission-checked operator reconciliation; do not invent revocation evidence.

## Signing and concurrency boundary

Public development releases use the explicitly approved persistent self-signed
identity on all three native binaries. This preserves designated requirements;
it is not Developer ID signing, notarization or Apple trust. A matching available
self-signed identity need not appear in `security find-identity -v`'s trusted
list. Missing or different identities fail qualification. Private keys are never
distributed to users and published historical artifacts are never re-signed.

Signed-to-ad-hoc and different-signer upgrades remain refused. The existing
ad-hoc-to-stable transition requires explicit foreground native authorization
and a noninteractive recheck. An authorization probe is not proof of remote
revocation or native deletion capability.

One installed runner per macOS user is supported. Updated credential owners
share user-global exclusion, independently of a custom state path. Unmodified
legacy processes using alternate state directories do not honor that exclusion
and are unsupported concurrently; a process inventory is observation, not a
guarantee against their later startup. Close known competing tools before
recovery. Same-user malicious processes remain within the documented local
trust boundary.

## Qualification boundary

Fixture tests, actual packaged executables, and an observed installed journey
are separate evidence. Destructive faults and native authorization transitions
must use a disposable user/test environment and dedicated backend identity.
Record exact release hashes and operation outcomes. Installation, remote
publication and recovery on another machine require their own authorization.
