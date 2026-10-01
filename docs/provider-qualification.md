# Provider qualification evidence

The runner admits prepared `host_user/v1` provider jobs only when their
`loomex.provider-adapter/v1` contract exactly matches one of these identities:

| Logical provider | Executable | Output transport |
| --- | --- | --- |
| Codex | `codex` | `codex.native-json/v2` or `codex.json-tree/v2` |
| Claude | `claude` | `claude.stream-json/v1` |
| Gemini | `gemini` | `gemini.stream-json/v1` |
| Antigravity | `agy` | `antigravity.json/v1` |

Gemini and Antigravity are deliberately distinct. Historic Gemini jobs keep
the official `gemini` executable; only Antigravity binds `agy`.

The fixture qualification covers missing executable handling, provider snapshot
drift after preparation, exact adapter and output transport matching, Codex
schema digest and single-placeholder materialization, and delivery of safe
provider completion/progress events for all four contracts. Fixtures use only
temporary files and a fake loopback backend. They do not read, write, or invoke
vendor login stores or provider commands.

## External qualification status

Real installed-provider execution is **blocked evidence, not a pass**. It
requires an explicitly authorized clean host with each provider installed and
signed in under its own vendor account. This repository currently also reports
no valid Apple code-signing identity, so signed clean-host LaunchAgent
qualification is blocked. Do not treat fixture results as a provider login,
vendor CLI compatibility, signing, notarization, or production-installation
pass.

When those prerequisites are available, run the approved provider checks
outside this fixture suite and record each provider, executable version,
authentication result, and signed-host result separately. Never copy provider
credentials into Loomex state to satisfy the check.

## Public AI status capability

The runner implements a job-scoped `report_status` MCP tool and durable
`ai.public-status.v1` delivery, but advertises `ai.public-status/v1: false` and
does not inject that tool into provider jobs in this version. The initial live
provider would be Codex only; Claude is unqualified. Fixed, content-free
`ai.progress.v1` milestones remain available for all supported providers.

Activation requires a new pinned runner/provider qualification: an installed
Codex CLI must discover and call the per-invocation tool without replacing the
user's configuration, the exact status must reach the backend with its stable
event ID, and the same job must still produce valid strict final JSON. Record
the CLI and runner binary hashes, bounded call/result evidence, and cleanup
before changing `LIVE_PROVIDER_QUALIFIED` or advertising the capability. The
current direct MCP probe passes, but a Codex run did not reach tool discovery:
the normal configuration has an unrelated missing `fcp` executable and the
isolated attempt timed out refreshing models. Neither qualifies live Codex
status. Backend nodes that request public status continue with fixed progress
when the runner does not advertise the capability.
