# Persona contracts and job memory

Persona chat generation stays in the active host model. The runner supplies current owner-checked configuration and memory tools; it does not start a provider job for a host chat. `personas.chat_context.create` is a UUID-keyed mutation, while `personas.chat_context.get` reopens the exact conversation/chat references through the backend's read-only inspection route. Role/person list and detail methods require the current organization's Persona read scope. Memory search/read/write/update use closed typed arguments. No method silently requests additional scopes.

`persona.roles.create` and `personas.create` require an explicit `organizationId`, UUID `idempotencyKey`, and `name`; Persona creation also requires the organization's `roleId`. They use the existing account-bound dispatch, mutation journal and response spool. Requests preserve the exact key in the body and `Idempotency-Key` header. Successful acknowledgements contain exactly `{role}` or `{person}` with the matching organization, resource name and status (and role identity for a Persona). The backend remains the source of authority for permissions, ownership and current role eligibility.

Creation requires the separately requested `runner.personas.manage` scope plus current organization `persons.read` and `persons.write` permission. The existing four Persona scopes remain sufficient for discovery, chat and memory. Management is supported by explicit `auth.scope_upgrade`; it is never automatically requested or implied by those four scopes, and does not imply a new read-scope grant.

Role creation defaults to `active` and permits `active` or `disabled`. Persona creation defaults to `draft` and permits an explicitly selected `active` status. Optional `key`, `description`, and `config` are closed typed fields. Role prompt policy permits `basePrompt`, `responsibility`, `boundaries`, and `safetyRules`; Persona prompt policy permits `personalityPrompt`, `outputStyle`, and `memoryUsageInstruction`. Persona memory policy permits only `maxItems` (1–200) and `writeMemory` (boolean). Omitted memory settings retain domain defaults of 50 items and enabled writes; callers can explicitly set `writeMemory:false`. Skills contain at most 100 nonblank string references or closed objects with `id`, optional boolean `enabled`, and optional integer `priority` (0–1000). Name/key and skill references are bounded at 255 characters, description at 4096, and each prompt field at 32768. Unknown provider, model, tool, general, policy or identity fields are rejected before dispatch.

Creation response loss is reconciled by `personas.operations.get` with operation `role.create` or `person.create` and the original UUID key. Pending and completed local records both read the current backend receipt; neither a local cached result nor `not_found` authorizes another creation POST. Management permission errors retain the backend's fixed error code and require explicit authority repair, never a generic mutation retry. The operation enum remains additive with `chat_context.create`, `memory.write`, and `memory.update` supported.

`auth.scope_upgrade` is an explicit additive grant on the existing device, organization, runner and child delegation. Its protected journal records grant, forced existing-child refresh and identity/scope verification. Response loss retains the same request and key. Denial preserves existing credentials. Legacy child refresh responses with `deviceId:null` remain usable but cannot qualify a device-bound upgrade. Scope status exports identities and scopes, never tokens. Logout clears Persona grant metadata.

Persona mutation recovery checks the backend's current permission-bound receipt for both pending and completed local records; it never repeats a write POST to recover a result. Large account-scoped responses retain organization, runner and child ownership in spool metadata. Reads and deletion require that same current owner before accessing the spool. Persona presentation journals contain references and digests, not prompts, effective configuration or credentials. Delivery inspection verifies the exact current context before returning even an existing delivery record.

A workflow Persona selection is sealed by the backend into the prepared closure. The runner preserves the backend's immutable `configDigest` in the bounded review. New Persona preparations carry the exact negotiated `binding.personaMemoryContract` (`ai.persona-memory/v1` or `ai.persona-memory/v2`). An enabled node seals `_memoryContext.bridge={schemaVersion:selectedContract,required:true}` only after the backend verifies both registered runner and supplied installed-provider capabilities. A later capability upgrade never changes a stored preparation's selected version. Required memory checks the actual selected provider before a review is returned, before commit and again before dispatch. Disabled nodes have no declaration and require no memory provider capability. Historical closures with neither contract nor bridge keep their original behavior and receive no new memory gateway authority. Unknown versions and declarations without a contract fail closed. The canonical negotiation is recorded in `contracts/persona-memory.json`. Nested Persona selections that do not match the root version currently fail explicitly.

Job memory uses the exact required marker for its stored selected version. Each live job has a separate owner-only Unix socket and short-lived capability file. The provider subprocess receives only that socket capability, and exposes search/read plus write/update only when the sealed policy permits writes. The daemon sends the job ID, lease fence and typed arguments to the backend; the backend derives the sealed Persona and policy. Caller-supplied context, identity and policy fields are rejected. Write/update require an explicit retained UUID key; per-call locked receipts reconcile ambiguous or completed writes through the current backend receipt. Cancellation, expired leases, recovery sessions and terminal retirement close the bridge. In-flight results are withheld after cancellation, leaving receipt recovery available.

The provider's final JSON schema and the independently disabled public-status gate are unchanged. Invocation-only Codex MCP configuration preserves the user's prompt and global configuration. See [Codex configuration reference](https://developers.openai.com/codex/config-reference) for `mcp_servers.<id>.default_tools_approval_mode`; only the generated private server receives `auto` approval. Memory content remains untrusted data.

Capability advertisement requires the qualified macOS arm64 Codex 0.157.0 native executable digest. Direct native invocation, including the installer's explicit provider binding, checks that binary. Invocation through its npm launcher additionally checks the qualified launcher digest and the native binary it loads. Missing or changed binaries, other platforms and other providers remain unsupported for required memory. Both paths retain fresh filesystem identity checks. Live disposable qualification evidence, including exact model/executable identities and fixed synthetic tool calls, lives in `planning/personas-2026-10-02/runner/` in the parent workspace. That fixture proves native transport behavior only; backend policy and receipt behavior are covered separately by source tests. It does not prove a real workflow, installation, live grant upgrade or other provider support.

Canonical inputs are `contracts/method-catalog.json`, `contracts/backend-routes.json`, and the mutation/error recovery contracts. The generated compatibility manifest must match those bytes. Backend contracts are documented in the parent backend repository's `docs/ai-persona-chat-contract.md` and `docs/ai-persona-job-memory-contract.md`.

### Renewal and receipt consistency

Each job's existing in-memory journal owns an ephemeral lease-request gate.
Persona calls acquire it before reading their fence; renewal retains it through
publication of the durable renewed journal. Credential waits therefore cannot
race a local renewal. The existing 30-second memory-handler deadline includes
queue time; cancellation and expired ownership still reject results. Different
jobs have independent gates. Restart creates no execution authority from the
gate, and uncertain writes reconcile their original call/key without replay.

The backend authorizes the current lease for each call but binds durable memory
receipts to the stable owner, organization, job, session, node and preparation.
Healthy renewal must not make an accepted receipt inaccessible. Manual memory
candidates require the backend's explicit review, not content validation.

### Negotiated v2 transport and discussions

The local protocol capability `personas.memory-transport/v2` indicates support for
lossless bounded transport. The plugin offers it privately at chat creation only
when the runner negotiates that feature; the runner translates the fixed offer
into `X-Loomex-Persona-Memory-Contract`. An older plugin omits the offer, and an
older runner does not negotiate it. Both combinations retain v1. Context inspection
never upgrades an existing persisted selection. Backend selection and current ACLs
remain authoritative; the offer does not grant memory access.

The process-wide chat read transport accepts an optional cursor, while each
job-scoped MCP catalog uses the exact sealed version: v1 rejects cursors; v2 permits
them. Read-only grants expose only search/read and reject mutations before sending
a backend request. V2 replies preserve the exact backend `data.result` JSON as MCP
text, including insertion order, original Unicode and line-separator escaping.
Transport-only wrappers and a duplicate structured memory document are not added
to that text. The backend's pinned `o200k_base/v1` token accounting therefore
continues to describe the same model-facing text; native validation independently
checks the final UTF-8 byte cap and selected accounting contract.

Explicit v2 reads return JSON fragments with code-point offsets, a stable parent
revision, document checksum and opaque cursor. Native consumers check contiguous
offsets and exact next cursor, writing only explicitly requested fragments into
an owner-only anonymous file unlinked before private content is written. Complete
UTF-8 document SHA-256, full JSON grammar/end and requested root identity/revision
are verified before completion. The canonical backend owns source authorization,
artifact pin and original source-text checksum validation; the native document
checksum covers the exact returned source pins and text. This replaces the earlier
duplicate full source-text checksum check that required a whole document in RAM.
No pages are automatically retrieved or injected, and no snapshot copy is made.

Chat state is owner/org/Persona/conversation/chat scoped. Append/seek/parse and
cleanup run through the existing two-worker filesystem owner; the native child
uses its own bounded instance. Files are 0600, unlinked, and close on completion,
invalid sequence, explicit restart, cancellation/disposal or process exit. RAM
retains bounded cursor/hash/identity state, with 16 documents per context and 64
contexts/64 total open chat documents. Operational disk ceilings are 64 MiB per
document, 256 MiB per context and 512 MiB for the daemon. These are resource limits,
separate from page/source validity: a resource failure returns READ_LIMIT without
claiming completion or a provider failure. Arbitrarily large historical records
are not claimed to fit. Chat reads bind an exact existing auth owner and local
epoch before HTTP. Logout (including pending cleanup), organization selection and
observed identity replacement invalidate retained and pending reads; auth fences
run after HTTP and after the filesystem worker, with a final ticket check before
publication. Per-document generations reject superseded first pages and stale or
duplicate continuations without erasing newer or unrelated partial documents.
Request-driven idle eviction runs after 15 minutes; a new explicit first page may
reclaim the least recently used context at capacity. No timer or scheduler is
added. A continuation of evicted state reports SEQUENCE_INVALID and requires an
explicit read without a cursor. At most 64 chat read requests may hold HTTP
admission, including superseded requests; invalidation does not cancel or replay
remote execution. Logout/organization disposal precedes auth mutation dispatch,
so local disposal cannot replace an accepted remote receipt. A permitted 1 MiB escaped artifact source producing a
6.29 MiB canonical document is covered by native regression evidence.

Discussion preparation validates ordered slot/role/Persona bindings, exact selected
provider and memory version, read-only turn policies, and fresh-context requirements.
Every turn uses the existing managed command execution with its exact provider-input
bytes and digest. Resume arguments and public-status opt-ins are rejected for
these jobs. Fixed backend milestones continue through the existing run-event path;
there is no new polling, scheduling or hook owner. The supplied discussion wrapper
is forwarded unchanged; its budget excludes separate role, memory and provider/tool
protocol scopes. Fresh input delivery is not a host-user filesystem sandbox or a
model disclosure guarantee.

Managed `ai.persona-memory/v2` and `ai.persona-discussion/v1` are separate,
qualification-gated runner/provider capabilities. Source implementation and the
chat transport capability do not qualify a provider or authorize job dispatch.
Phase 5 evidence and remaining provider limits are recorded in the parent workspace
under `planning/plugin-runner-integration/private-memory-discussion/`.

The Phase 5 live qualification uses the separately declared runtime model
`gpt-5.6-sol` from the existing catalog. Initial `gpt-6.1-sol` cases were rejected
as `MODEL_UNAVAILABLE` and remain separate evidence. Adapter capability does not
claim account access to every model. No job changes its selected model or provider
to recover from a failure. Pinned Codex is the only provider qualified for the new
managed versions; other providers remain unsupported.
