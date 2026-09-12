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
