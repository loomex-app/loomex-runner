# Reviewed workspace sets

`execution.workspace-set/v1` is an additive `loomex.local-control/v2` capability. The primary directory remains the active task's actual working directory. `additionalWorkspacePaths` carries explicit extra roots; the runner canonicalizes existing directories, removes canonical duplicates and the primary root, and sorts extras deterministically. Nested and disjoint roots remain separate. Their common ancestor never becomes a grant.

## Caller selection and preparation

Visual entrypoints accept mandatory `taskContext.cwd` and optional `taskContext.projectDirectories`. Only supported host context establishing membership in the current project may populate projectDirectories. Filesystem permission lists and unrelated folders are not project context. Currently the available Codex project API reports only one path, so automatic complete-project discovery remains unqualified.

An explicit `workspacePath` override replaces the host project set. Extra directories then require explicit `additionalWorkspacePaths`. Headless `runs.prepare` and terminal `loomex rpc runs.prepare JSON` use that same explicit array. Register the complete selected set through the existing `workspaces.grant` operation; there is no additional grant card or authorization step. A failed validation sends no preparation.

Preparation requires workspace-set support in the runner registration, local negotiation and every required provider fingerprint in the sealed workflow closure. The backend seals `workspaceSetContract`, canonical `additionalWorkspacePaths` and primary-first `workspaceIdentities` (path/device/inode) in the confirmation digest. The runner also retains the identity snapshot locally. Commit and every job revalidate all roots and the original snapshots after asynchronous work. Regranting a replaced directory cannot revive a previous approval.

Historical records without the contract remain single-root with their original digests and keys; their canonical path aliases are resolved through the existing grant validation. They are not rewritten into multi-root records. Existing executions keep their original roots even if project context later changes.

## Runtime and outputs

Commands, HTTP jobs, provider/Persona jobs and child workflows inherit sealed execution context. Relative command working directories stay inside the primary root. A multi-root command may use an absolute working directory resolving inside a bound root; symlink escapes and an unbound common parent are rejected. These checks do not make host_user/v1 a filesystem sandbox.

The backend exposes `workspace.path`, `workspace.additionalPaths` and `workspace.paths` through existing execution-context mappings. No workflow input is needed for the workspace. Declared artifacts may select a bound canonical path with `workspaceRoot`; omission remains primary-relative. Artifact `path` stays relative. Canonical file lookup must remain inside the selected root, and generated artifacts retain execution scope, transfer identity and existing retention behavior.

## Provider qualification

Additional-directory arguments are per invocation. Codex uses repeated global `--add-dir` options before `exec`, including `exec resume`. Claude and AntiGravity use repeated `--add-dir`; Gemini uses `--include-directories`. Final-output schema, model, reasoning, session, public-status and memory configuration stay on the existing paths.

Only the pinned macOS arm64 Codex CLI 0.157.0 fingerprint is eligible for workspace-set advertisement in this candidate. Claude, Gemini and AntiGravity remain unqualified for this capability and fail preparation rather than omitting roots or changing the selected provider. See the integration report for actual fresh/resume and installed-run evidence. No provider's global configuration is changed.

## Restoration and support

The existing UI lifecycle restores safe selections and exact preparation references, then verifies the sealed set. Restoration never imports current project roots into a previous review. Completed Start cards remain read-only. Run monitoring remains chat-owned. Hidden native create/edit authoring remains current-chat and has no workspace/provider setup card.

Qualification evidence is recorded in `planning/plugin-runner-integration/multi-workspace-2026-10-09/REPORT.md` in the Loomex workspace. Fixture, packaged, installed and actual Codex observations must be distinguished.
