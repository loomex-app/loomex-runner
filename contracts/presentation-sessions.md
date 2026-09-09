# Durable presentation contract

`presentation.sessions/v1` persists optional custom UI state in the runner's existing owner-only state directory. It is a local projection only: no restored value grants a workspace, prepares an execution, commits a preparation, resolves a human request, or invokes a recorded operation.

All methods derive `organizationId` and the authenticated child runner subject from the current runner credential. Clients cannot supply either scope. The backend binds that child identity to one user, organization, and installation and reuses it for the same owner tuple. A session has an immutable `{kind, entityType, entityId}` binding. `entityType` is one of `catalog`, `workflow`, `request`, `execution`, `builderSession`, or `preparation`; `catalog` uses the nil UUID. `kind` is one of `browser`, `authoring`, `prepare`, `monitor`, or `interaction`.

The session methods use these exact inputs:

- `presentation.sessions.create`: `{kind, entityType, entityId, state, idempotencyKey}`
- `presentation.sessions.get`: `{viewSessionId}`
- `presentation.sessions.update`: `{viewSessionId, expectedRevision, state, status?, operation?, idempotencyKey}`
- `presentation.sessions.delete`: `{viewSessionId, idempotencyKey}`

Create, get, and update return the bare projection `{viewSessionId, kind, entityType, entityId, revision, state, status, createdAt, updatedAt, expiresAt, operation}`. `operation` is null or the safe reference `{operationId,status}`. `status` is `active`, `inactive`, or `resolved`. Updates compare `expectedRevision` and fail with `REVISION_CONFLICT` rather than overwriting concurrent state.

Presentation state accepts bounded JSON domain data. Normalized keys containing credential, token, password, secret, confirmation, authorization, API/private/signing key, cookie, or idempotency-key terms are rejected. The filter operates on field names; it does not attempt to infer secrets from arbitrary answer text. Exact mutable requests belong only in an update's optional operation value:

```json
{
  "method": "interactions.respond",
  "params": {"requestId": "...", "answer": {}},
  "idempotencyKey": "...",
  "reconciliation": {"method": "interactions.get", "params": {"requestId": "..."}}
}
```

`reconciliation` is optional because some exact mutations, including a commit with no known resulting run ID, have no authoritative read yet. An omitted value restores as `{}` and permits exact retry only; it must not trigger guessed reconciliation.

The session update and operation journal insert commit in one SQLite transaction. One unresolved operation is allowed per view. `presentation.operations.get {viewSessionId,operationId}` returns its exact method, params, mutation key, reconciliation read (or `{}`), state, timestamps, and result reference to the app bridge. It must not be copied into ordinary session state or model-visible metadata. `presentation.operations.settle {viewSessionId,operationId,status,resultReference?,idempotencyKey}` marks it `completed` or `ambiguous`; an ambiguous record remains available for exact retry/reconciliation.

`interactions.drafts/v1` forwards backend-owned human-answer drafts through:

- `interactions.draft.get {requestId}`
- `interactions.draft.update {requestId,expectedRevision,answers,currentQuestionId,phase,expectedSchemaDigest?,idempotencyKey}`
- `interactions.draft.delete {requestId,expectedRevision,expectedSchemaDigest?,idempotencyKey}`

Update with revision zero creates the draft. `phase` is `answer` or `review`. The backend owns request/account/organization scope and the authoritative schema digest. Pending drafts do not expire. Local active sessions and pending or ambiguous operation records do not expire automatically. Inactive/resolved sessions, completed operations, and idempotency receipts expire after 30 days. Explicit session deletion cascades to its operation records; authoritative run deletion removes local sessions bound to every deleted execution.

## Sealed preparation restore

`preparations.get {preparationId}` reads an existing owner-only sealed preparation without contacting the backend, preparing again, committing, or changing authorization. The runner first verifies the selected organization, authenticated child runner subject, installation, live workspace grant, unchanged provider snapshot, sealed binding identity, expiry, and lack of a prior commit authorization.

A valid read returns `{status:"valid", operation, preparation}`, where `operation` is the exact original `runs.prepare`, `builder.prepare`, or `editor.prepare` method and `preparation` is the exact normalized prepare result, including its binding, limits, null `expiresAt`, and confirmation key. A stale read omits the binding and confirmation and returns `{status:"stale", operation, preparationId, reason, nextAction}`. `commit_started` always directs the caller to `reconcile_operation`; it never recommends preparing again because the original commit may have taken effect. Missing records, legacy records without account scope, and scope mismatches return `PREPARATION_NOT_FOUND` without revealing whether another account owns the supplied ID.
