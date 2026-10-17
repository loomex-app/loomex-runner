# Installation and removal recovery

Updates, clean removal, and recovery are separate operations. Use the verified
release's supported tools; do not delete receipts, native credentials, drain
markers, caches or journals to make an installer proceed.

## Inspect before changing anything

`loomex lifecycle status --json` works without a running daemon. It reports
bootstrap, native, and historical ownership together. An unfinished uninstall
takes precedence over a historical completed update. Its controlling operation,
phase, journal digest and supported next action determine recovery.

The paired installer has two read-only modes. `--verify-only` checks artifact
integrity. `--preflight-only` also checks installed owners and host registration
prerequisites. Neither drains work, authorizes Keychain access, signs in, enrolls
an organization, approves execution or changes installed state. An ineligible
result includes only validated recovery categories and references; an arbitrary
owner error is never copied into the public result.

Preflight is an observation, not activation authority. Every mutating owner
repeats its checks under its existing locks. Unknown ownership or an unresolved
outcome remains a blocker.

## Ordinary update and deferred activation

Run the reviewed release-specific installer with its sealed release-set digest.
It checks both selected component owners before activation. Healthy partial
installation is preserved: plugin or registration failure does not roll back a
healthy runner. Retry the same release set and component installation bases.

The paired CLI result uses `app.loomex.paired-install-result/v3`. Exit 0 means
completion, exit 3 means a verified pending lifecycle operation, and exit 1 means
blocked or unconfirmed. A known active-work or service-stop pause is not a new
health failure. Inspect the exact operation, finish the indicated native resume,
then retry the same pair. Do not cancel managed work to force an update.

A completed update can still require metadata recovery. Resume its existing
operation rather than deleting `pending-update.json`. Recovery verifies the
installed inventory, receipt and LaunchAgent/provider configuration and retires
only the matching marker. Unknown markers and competing operations stay protected.

## Exact artifact-cache restoration

Pending operations can refer to their original stable release-cache paths.
Read-only preflight reports `cache_restore_required` if those prerequisites are
missing; it never repairs them. Installation can restore missing known bytes
from the same fully verified release set while retaining those exact paths.
It does not replace component journals, issue authority, or silently overwrite
conflicting content. Unexpected files, symlinks and corrupted surviving files
remain refusals. A newly downloaded release is not permission to substitute a
different pending package.

## Current uninstall and stopped retries

Run the verified installed release's `bin/loomex-lifecycle-bootstrap uninstall`,
retaining explicitly selected installation/state/LaunchAgent paths. The native owner records the operation,
drain identity, service-stop evidence, remote revocation and local cleanup stages.

If the service has exited before the first idle acknowledgement, recovery must
verify the recorded installation and native identity, service/process absence,
singleton ownership and managed-work evidence. Socket absence alone proves
nothing. The same operation can then continue through stopped maintenance; it
must not start a daemon or relaunch a command merely to obtain an acknowledgement.
Unresolved children, deliveries, schedules and uncertain outcomes block cleanup.

Operation observations can also block cleanup even when no process is active.
A pending cache records local preparation or uncertainty, not proof that its
backend mutation ran. The immutable response from a completed Start can still
say `queued`; inspect its current execution separately.

Credential maintenance runs in the verified daemon executable without starting
a socket server or worker. Its destination comes from the validated receipt,
not ambient shell variables. Remote revocation confirmation, protected-state
clearing and native item removal are separate outcomes. Missing local credentials
alone do not prove remote revocation. Outstanding native I/O keeps its ownership
even when the observer stops waiting.

Payload removal uses exact inventories and quarantine checkpoints. Partial
removal is resumed against the surviving verified subset. Unknown files,
backend records, user workspaces and provider CLI authentication are preserved.
Stable non-secret singleton and credential-owner lock inodes are retained;
unlinking a live lock could permit concurrent owners. Plugin files and host
registration have separate outcomes; only the exact Loomex registration may be
removed through supported Codex operations.

## Recover a historical interrupted uninstall

Ordinary installation never implicitly completes an uninstall. After reviewing
the exact controlling journal and the intended clean-reinstall operation, use
the verified paired installer with:

```sh
LOOMEX_ALLOW_UNSAFE_DEV_INSTALL=1 /path/to/verified/loomex-install-darwin-arm64 \
  --offline /path/to/verified/release-set \
  --manifest-sha256 REVIEWED_RELEASE_SET_SHA256 \
  --allow-unsigned-development \
  --recover-uninstall \
  --expected-old-journal-sha256 REVIEWED_ORIGINAL_JOURNAL_SHA256
```

Retain the original explicit installation bases. The helper verifies artifacts,
plugin/host prerequisites and recovery eligibility, retains the exact stable
release cache, and delegates to the new release's existing native recovery owner.
It observes cleanup, rechecks both owners, then installs the same pair. A retry
resumes the matching pending operation. If cleanup completed before interruption,
it observes fresh installation eligibility instead of starting another uninstall.
Journal absence is never reported as historical revocation confirmation.

The release-bound recovery route also supports an eligible current-format
`prepared` journal left by an older controller: it verifies the exact original
journal digest and preserves its operation, drain key, fence and old helper.
It must not execute the older helper with unsupported new arguments. Other
current-format phases continue through their recorded supported owner; an
ineligible adoption must provide an explicit refusal before changing state.

The native recovery entrypoint remains available independently:

```sh
LOOMEX_ALLOW_UNSAFE_DEV_INSTALL=1 \
  /path/to/new-release/loomex-lifecycle-bootstrap recover-uninstall /path/to/new-release \
  --expected-old-journal-sha256 REVIEWED_ORIGINAL_JOURNAL_SHA256 \
  --allow-unsigned-development
```

Recovery verifies the original receipt, helper, inventories, historical native
identity and new candidate before committing adoption. The installed helper is
never overwritten. Unsupported historical state, absent identity evidence and
signing downgrades refuse recovery. An old `revoked` label without bound remote
confirmation is not sufficient evidence.

For a recovery already pinned to a rejected candidate by an older implementation,
use the explicit `--replace-pre-adoption-candidate` option together with
`--expected-recovery-intent-sha256 REVIEWED_EXISTING_INTENT_SHA256` and the original
journal digest. This is permitted only before mutating credential maintenance,
with the historical journal unchanged. It retains the original operation, old
intent evidence and old-controller fence. Uncertain or later-stage work cannot
be reset this way. Never edit the saved intent or substitute a digest on an
ambiguous retry.

## Inspect and reconcile retained managed work

A historical prepared uninstall may retain deliveries and follow sessions while
its older daemon is drained. The verified new bootstrap provides a release-bound
maintenance route without starting a daemon or adopting an uninstall. Inspect the
exact historical owner first with the same reviewed paired release:

```sh
LOOMEX_ALLOW_UNSAFE_DEV_INSTALL=1 /path/to/verified/loomex-install-darwin-arm64 \
  --offline /path/to/verified/release-set \
  --manifest-sha256 REVIEWED_RELEASE_SET_SHA256 \
  --allow-unsigned-development \
  --uninstall-work inspect \
  --expected-old-journal-sha256 REVIEWED_ORIGINAL_JOURNAL_SHA256
```

Inspection checks the runner and plugin owners and host prerequisites, then emits
an assessment digest, bounded blocker counts and hashed references. It writes no
persistent cache or installed state. Historical owner references report the journal
schema, digest, phase and whether adoption started; an absent operation ID remains
null. It does not invent a new operation to describe historical ownership.

Use `--uninstall-work reconcile` with the same release and journal binding to ask
the verified owner for supported reconciliation. This mode can inspect eligible
retained work even when deletion is blocked. Remote observations and explicit
delivery evidence determine resolution. Unavailable or ambiguous observations stay
protected; clean-reinstall approval supplies no missing acknowledgement.

When supported reconciliation cannot resolve retained local continuation records,
review the inspect assessment and its scope before explicitly authorizing local
retirement. Preview and retain the current assessment using `inspect`; only after
that review use `--uninstall-work retire-local` with the same arguments plus
`--expected-assessment-sha256 REVIEWED_ASSESSMENT_SHA256`. The native owner rechecks
the exact assessment under its locks and rejects drift. Retirement records local
supersession evidence; it does not claim workflow completion, remote cancellation,
delivery acknowledgement, schedule removal or credential revocation. Uncertain
operations, recovery schedules, response spools and domain mutations remain blockers
under this default `continuations` scope.

### Operation-observation recovery

The newer verified distribution also accepts
`--retirement-scope operation-observations` with `--uninstall-work inspect` or
`--uninstall-work retire-local`. The default remains `continuations`; an older
approval cannot silently select operation observations. Inspect with the exact
release and original journal binding, run supported reconciliation, and inspect
again. The resulting preview identifies the exact eligible records, byte
fingerprints, dependencies and current assessment digest. Obtain explicit
approval of that preview before `retire-local --expected-assessment-sha256`.

Canonical reconciliation reads receipts under the original runner identity.
An exact request fingerprint can prove a submission; a same-key-only match,
missing/expired receipt or unavailable backend leaves its outcome unknown.
Native authoring completion additionally requires current execution observation,
drained events and the full terminal result. Reconciliation never resubmits the
mutation, commits Start, sends a message or launches provider work.

Reviewed retirement closes only local observation/retry tracking. It leaves
remote workflows, accepted answers and draft mutations unchanged, and does not
assert that the original operation succeeded or was never sent. The owner
publishes immutable private denial evidence before making source files eligible
for deletion. Required evidence and its minimum-reader lifecycle fence survive
uninstall and reinstall; incompatible activation/rollback is refused. Old cards
or attempts without a verifiable original installation cannot acquire the new
installation's credentials. A legacy hashed slot whose original key is missing
cannot be correlated universally after an account-subject change.

Protected authentication operations, managed execution, terminal-delivery
evidence, external recovery registrations, unsafe files and unreadable required
evidence remain independent blockers. This scope cannot clear those owners.
`actionCompleted: true` means only the selected maintenance action finished;
`cleanupEligible` and the fresh assessment determine whether cleanup may proceed.

Every `--uninstall-work` invocation ends after the selected maintenance action.
It never uninstalls, installs, activates the plugin, registers it with Codex, or
continues into clean reinstall. After verified resolution, independently retry the
explicit historical recovery command above. Error categories distinguish unresolved
work, unsupported schema, unsafe state, unreadable state and observation drift.

## Signing, concurrency and qualification

Development releases use the approved persistent self-signed identity on all
three native executables. That preserves designated requirements; it is not
Developer ID signing, notarization or Apple trust. Signed-to-ad-hoc and
different-signer upgrades remain refused. The supported ad-hoc-to-stable transition
requires explicit foreground native authorization and a noninteractive recheck;
`--authorize-keychain-transition` is never added automatically. A successful
read probe is not proof of deletion or remote revocation.

One installed runner per macOS user is supported. Current binaries share
user-global credential exclusion, including across custom state paths. Older
binaries that ignore that lock cannot be fenced by it; known competing owners
must be stopped through their supported lifecycle before recovery proceeds.

Fixture, packaged and actual native journeys are separate evidence. Destructive
Keychain, historical uninstall, restart and reinstall tests require a disposable
user/test machine and dedicated backend identity. The original incident's native
rejection cause remains unknown. Publication, installation and other-machine
recovery are separate authorized actions.
