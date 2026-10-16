# Paired public distribution

Public distribution uses development releases for **macOS ARM64** with an unsigned release envelope and all three runner binaries signed by the existing approved persistent local development identity. The repositories retain their existing **Proprietary** license decision. Production Developer ID signing, notarization and manifest signature gates remain required and unchanged; release naming does not supply signing assurance.

The authoritative download is one frozen paired tag in `loomex-app/loomex-runner`, named `runner-v<RUNNER>-plugin-v<PLUGIN>`. Never combine independent `latest` downloads. `release-set.json` uses `app.loomex.release-set/v2` and binds exact component versions, full source SHAs, repository/tag, manifest hash, artifact URL/size/hash, platform, `developmentOnly`, protocol and compatibility evidence. `compatibility.json` wraps the successful existing required clean plugin/backend gate and binds its original component digests plus exact runner/plugin/backend source SHAs. The actual compiled plugin export is compared with the required gate; a stale source export fails packaging.

The v2 manifest seals a deployment profile. `cloud-preview` binds a canonical HTTPS DNS API origin and preserves the existing compiled cloud configuration. `local-development` binds a canonical HTTP loopback API origin and an exact optional loopback frontend origin (`null` means none). These profiles cannot be substituted under one approval digest. The 1.0.0 local development release uses `http://127.0.0.1:28080/` with no frontend origin; it requires an already running compatible local backend. The download does not install or start a backend.

To qualify local development bytes for public download, use the existing builder with `--unsigned-development --local-development-api-origin http://127.0.0.1:28080/`, a clean committed source tree, no `LOOMEX_API_ORIGIN` environment variable, and the existing approved local signing identity. Leave `LOOMEX_WEB_APP_ORIGIN` unset when no frontend is configured. The resulting inventory binds `metadata/local-development-origin.json` to version, source SHA, API and frontend. Public packaging requires `--deployment-profile local-development --api-origin http://127.0.0.1:28080/`; the optional `--web-app-origin` must exactly match the packaged metadata. Ordinary local development builds remain compatible without the new qualification option.

`preview-release.yml` validates full pinned source references and builds the plugin before exporting contracts. Runner and component checkouts are siblings, so a nested component checkout cannot contaminate the required clean runner source gate. The runner preview embeds explicit, validated HTTPS `LOOMEX_API_ORIGIN` and `LOOMEX_WEB_APP_ORIGIN` repository variables. For `cloud-preview`, the manifest-bound `metadata/preview-origin.json` and `--preview-api-origin` installer option use the compiled cloud destination. The cloud workflow remains cloud-only and packages with `--deployment-profile cloud-preview --api-origin` from the exact runner metadata. Local sets use the existing native owner’s `--development-api-origin` option, while cloud sets use `--preview-api-origin`. Empty origins fail before building a candidate. Building a public candidate also requires `LOOMEX_DEVELOPMENT_CODESIGN_IDENTITY` to resolve unambiguously to an already available local code-signing identity; `LOOMEX_DEVELOPMENT_CODESIGN_KEYCHAIN` may select its existing keychain. Availability uses all matching identities, including an approved self-signed certificate reported as `CSSMERR_TP_NOT_TRUSTED`; Apple trust is not a development qualification requirement. Optional `LOOMEX_DEVELOPMENT_CODESIGN_FINGERPRINT` pins the exact approved SHA1 certificate and must match the selected build identity. For artifact packaging or inspection, that explicit fingerprint (or a fingerprint supplied as the identity) is sufficient and requires no private identity/keychain lookup; actual executable signatures and leaf pins are still verified. The pipeline neither creates an identity nor imports or exports private keys. A build job without the approved existing signing identity deliberately fails closed. The workflow never adds certificate trust. An Apple account is unnecessary for the local self-signed identity; Developer ID production signing and notarization remain deferred.

The workflow builds each component and native installer once, packages and inspects the same bytes, then stores an Actions artifact. It does not create tags or a GitHub release. Every edited action is pinned to a reviewed full commit SHA. Python, Node, Cargo and source checkouts are build dependencies only.

## Install the reviewed set

Download and inspect the release-specific `install.sh` and independently review the release-set digest in the immutable release notes. Run the downloaded script with both explicit preview opt-ins:

```sh
LOOMEX_ALLOW_UNSAFE_DEV_INSTALL=1 /bin/bash ./install.sh --allow-unsigned-development
```

Add `--runner-only` to install the runner alone. The native installer verifies its own manifest-bound bytes, both component archives, every nested payload file, source-content bindings, compiled compatibility descriptors and qualification evidence. It then asks both existing lifecycle owners for read-only installed eligibility before persisting any new cache or activating the runner. `--runner-only` asks only the selected runner owner. The owners repeat eligibility checks inside their own mutation locks; a successful preflight does not promise activation if host state changes. Initial download URLs must be exact frozen GitHub release asset URLs; native redirects permit only GitHub's HTTPS asset hosts. Archive traversal, links, devices, duplicate entries, unsafe modes, oversized downloads/expansion and wrong pairs fail closed. The launcher is ordinary transport and never evaluates downloaded configuration.

`--verify-only` checks artifact integrity and compatibility evidence without invoking an owner. `--preflight-only` additionally invokes the native bootstrap `preflight RELEASE` and the packaged plugin manager `preflight --release RELEASE --install-base BASE`, using the same explicit bases and owner options as installation. It may extract temporary artifacts, but creates no persistent cache, lifecycle journal, drain or installed state. A complete existing cache is verified and reused read-only so a pending owner operation retains its exact release path; a different pending manifest, path or base remains an owner rejection. Preflight performs no credential read, authorization prompt or Keychain transition. Any explicitly authorized transition still needs the native owner's foreground probe and noninteractive confirmation during actual installation.

The native paired installer emits sanitized `app.loomex.paired-install-result/v2` JSON: exit 0 means completed, exit 3 means verified pending work, and exit 1 means blocked or unconfirmed. Pending results retain the native operation identity and next action; they skip expected-new-version health and plugin activation. Failure JSON is on stderr; completed and pending JSON is on stdout, with manual instructions in `completion.guidance`. Native activation is accepted only from the bootstrap’s typed `app.loomex.runner.bootstrap-activation/v1` response. Completion records distinguish `not-attempted`, `unconfirmed`, `healthy` runner, installed plugin files and verified/manual host registration. An owner failure after it starts is unconfirmed until authoritative readback. Runner health/version is required before plugin installation. A plugin or registration failure retains the healthy runner, exact cache and owner journals for retry; no cross-owner rollback runs.

Verified prerequisites live under `~/Library/Caches/Loomex/release-sets/<RELEASE-SET-SHA256>`. This immutable artifact cache is independent of the existing runner and plugin lifecycle journals. Its stable paths preserve interrupted plugin prerequisites; retries use the original owner and exact envelope. Do not remove a cache while either component has an unfinished lifecycle operation. If files are missing, preflight verifies staged candidate bytes against the pending owner’s original stable release-path binding and reports `cache_restore_required` with exit 3 without writing. Installation then restores only missing exact files at that original cache path after both owner checks and host eligibility pass. Corrupt or conflicting files, symlinks and unexpected entries are preserved and refused. Interrupted `.incoming` staging remains isolated; cache reconstruction does not authorize activation or authentication.

An interrupted uninstall requires explicit recovery. Ordinary installation never cleans uninstall ownership. Review the old journal digest and the same release-set manifest digest, then add `--recover-uninstall --expected-old-journal-sha256 OLD_SHA256` to the paired invocation. Artifacts, recovery eligibility, plugin eligibility and supported host preflights are checked before the native `recover-uninstall` command runs. After authoritative cleanup completion, the helper repeats ordinary owner and host preflights before installing the same pair. A retry after terminal cleanup uses fresh or exact-current installation eligibility and does not repeat uninstall against the replacement installation; an absent journal alone proves no credential revocation. Replacing a trapped pre-adoption candidate additionally requires `--replace-pre-adoption-candidate --expected-recovery-intent-sha256 INTENT_SHA256`, guarded by the native recovery owner. The transport creates no additional lifecycle journal.

Installation delegates runner activation to the native lifecycle bootstrap and plugin file activation to the packaged compiled lifecycle manager/runtime. The helper checks runner health and expected version before continuing. Existing code identity and Keychain policy stay with the native owner. The default installer never authorizes a Keychain transition. After reviewing the exact verified candidate, an explicit `--authorize-keychain-transition` is passed only to that owner; any rejected signer/downgrade remains rejected by its policy. A failed plugin or Codex registration never uninstalls or rolls back the runner. Retry the same set after resolving the reported owner issue. Existing provider credentials, runner credentials, journals and retained workflow work remain owned by their existing components.

After plugin files are installed, the helper uses supported Codex commands: marketplace list, local marketplace add, plugin add and installed plugin readback. The current marketplace name remains `loomex-private`. An existing marketplace of that name with another root is refused for manual review. The helper does not edit Codex settings or cache files. If the Codex CLI is unavailable, runner and plugin files remain installed and the helper prints the durable local marketplace root for GUI import; if the GUI lacks local import, install the supported Codex CLI and retry the same set. No login, organization choice, hooks or task execution is forced.

## Offline envelope

The optional `<PAIRED-TAG>-offline.tar.gz` contains the same installer, manifest, component bytes and evidence. Inspect the checksum through an independent reviewed source, inspect the archive inventory, and extract it into a disposable directory. The installer accepts a directory rather than executing arbitrary archive contents:

```sh
LOOMEX_ALLOW_UNSAFE_DEV_INSTALL=1 ./loomex-install-darwin-arm64 \
  --offline "$PWD" --manifest-sha256 REVIEWED_RELEASE_SET_SHA256 --allow-unsigned-development
```

Offline execution verifies the current native installer against the exact release-set inventory. A colocated checksum is integrity evidence and does not supply independent authenticity for an unsigned preview. Never copy an installer from another set.

## Operator checkpoints

Inspect the complete build-once directory first:

```sh
python3 scripts/github-preview-release.py inspect --assets /absolute/reviewed-assets
```

After separate explicit operator authorization, create and upload an immutable-ready **draft release**:

```sh
python3 scripts/github-preview-release.py stage-draft --assets /absolute/reviewed-assets \
  --approve-manifest-sha256 REVIEWED_RELEASE_SET_SHA256
```

The tool requires repository immutable releases already enabled and both existing remote paired tags resolving to their exact component source SHAs. It never creates/moves tags, rebuilds bytes, overwrites assets, or enables repository settings. A partial/ambiguous draft upload is inspected and resumed with `resume-draft` using the same assets and digest; identical remote hashes are retained, differing assets fail closed. Inspect all draft assets before separately authorizing `publish` with the same digest. Publication rechecks the inventory and requires a terminal immutable release readback. New regular releases become latest after verified publication; historical preview-tag publication remains non-latest.

The public packager and public release inspector require canonical inventoried `metadata/development-signing.json`, verify each of `loomex`, `loomex-runner` and `loomex-lifecycle-bootstrap` using `codesign --verify --strict`, and match actual designated requirements to the selected persistent certificate fingerprint. Missing metadata, ad-hoc signing, signer substitution and metadata/actual-requirement mismatch all reject public qualification. Generic artifact verification and isolated unsigned test builds remain available. Published 1.2.6 assets remain immutable; these checks apply to newly qualified bytes and do not rewrite historical assets.

The standard production workflow still builds only a signed Actions artifact. Production public release-set policy requires a separately qualified signed distribution path.

GitHub recommends attaching all assets to a draft before immutable publication: [release management](https://docs.github.com/en/repositories/releasing-projects-on-github/managing-releases-in-a-repository), [release APIs](https://docs.github.com/en/rest/releases/releases), [immutable repository check](https://docs.github.com/en/rest/repos/repos#check-if-immutable-releases-are-enabled-for-a-repository). Supported marketplace/plugin commands are documented in [OpenAI plugin packaging](https://developers.openai.com/plugins/build/plugins). The CLI JSON contracts were additionally inspected read-only on the installed Codex CLI on 2026-10-04.

## Release naming and easy installation

New GitHub artifacts use `install.sh`,
`loomex-runner-<VERSION>-darwin-arm64.tar.gz`,
`loomex-plugin-<VERSION>-darwin-arm64.tar.gz`, and
`runner-v<RUNNER>-plugin-v<PLUGIN>-offline.tar.gz`.
The README uses `/releases/latest/download/install.sh` only to download the
launcher. That launcher seals one frozen pair and verifies the native helper
and manifest digests. Release notes provide the version-pinned curl command.
The filenames do not change signing status, backend requirements or execution authority.
Previously published preview-tag releases remain immutable and readable; the
new writer produces only current names. The old unsigned flag is a parser alias
for existing reviewed invocations, not another installation mechanism.
