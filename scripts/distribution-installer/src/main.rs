//! Transport/verifier only. Persistent mutations belong to existing lifecycle owners.
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs,
    io::{Read, Write},
    path::{Component as PathComponent, Path, PathBuf},
    process::Command,
};
use url::Url;

mod namespace_names;

const RUNNER_OWNED_NAMES: &[&str] = &["versions", "current"];
const PLUGIN_OWNED_NAMES: &[&str] = &[
    "versions",
    "current",
    ".lifecycle-runtime",
    ".agents",
    "install-receipt.json",
    "lifecycle.json",
    "lifecycle.terminal.json",
    ".lifecycle.lock",
];
const SCHEMA: &str = "app.loomex.release-set/v2";
const REPOSITORY: &str = "loomex-app/loomex-runner";
const MAX_MANIFEST: u64 = 1024 * 1024;
const MAX_EXPANDED: u64 = 2 * 1024 * 1024 * 1024;
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Asset {
    file: String,
    url: String,
    size: u64,
    sha256: String,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Component {
    version: String,
    source_revision: String,
    repository: String,
    release_tag: String,
    manifest_sha256: String,
    asset: Asset,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Components {
    runner: Component,
    plugin: Component,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Evidence {
    asset: Asset,
    backend_source_revision: String,
    passed: bool,
}
#[derive(Debug, Deserialize)]
#[serde(tag = "profile", rename_all = "kebab-case", deny_unknown_fields)]
enum Deployment {
    CloudPreview {
        #[serde(rename = "apiOrigin")]
        api_origin: String,
    },
    LocalDevelopment {
        #[serde(rename = "apiOrigin")]
        api_origin: String,
        #[serde(rename = "webAppOrigin")]
        web_app_origin: Value,
    },
}
impl Deployment {
    fn api_origin(&self) -> &str {
        match self {
            Self::CloudPreview { api_origin } | Self::LocalDevelopment { api_origin, .. } => {
                api_origin
            }
        }
    }
    fn local(&self) -> bool {
        matches!(self, Self::LocalDevelopment { .. })
    }
    fn web_app_origin(&self) -> Value {
        match self {
            Self::LocalDevelopment { web_app_origin, .. } => web_app_origin.clone(),
            _ => Value::Null,
        }
    }
}
fn deployment_origin(raw: &str, local: bool) -> Result<()> {
    let origin = Url::parse(raw)?;
    ensure!(
        origin.username().is_empty()
            && origin.password().is_none()
            && origin.path() == "/"
            && origin.query().is_none()
            && origin.fragment().is_none()
            && origin.as_str() == raw,
        "canonical deployment root origin required"
    );
    let host = origin.host_str().context("origin host missing")?;
    let ip = host.trim_matches(['[', ']']).parse::<std::net::IpAddr>();
    if local {
        ensure!(
            origin.scheme() == "http"
                && (host == "localhost" || ip.is_ok_and(|ip| ip.is_loopback())),
            "local-development requires HTTP loopback origin"
        );
    } else {
        ensure!(
            origin.scheme() == "https" && host != "localhost" && ip.is_err(),
            "cloud preview requires HTTPS DNS origin"
        );
    }
    Ok(())
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReleaseSet {
    schema: String,
    release_tag: String,
    platform: String,
    development_only: bool,
    protocol_version: String,
    deployment: Deployment,
    components: Components,
    evidence: Evidence,
    installer: Asset,
}
fn canonical_digest(value: &Value) -> Result<String> {
    let mut bytes = serde_json::to_vec(value)?;
    bytes.push(b'\n');
    Ok(hex::encode(Sha256::digest(bytes)))
}
fn hash_file(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path)?;
    let mut state = Sha256::new();
    let mut buf = [0; 65536];
    loop {
        let count = file.read(&mut buf)?;
        if count == 0 {
            break;
        }
        state.update(&buf[..count]);
    }
    Ok(hex::encode(state.finalize()))
}
fn hex_string(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
fn safe_path(s: &str) -> bool {
    !s.is_empty()
        && !s.contains('\\')
        && !s.contains('\0')
        && !s.split('/').any(|p| p.is_empty() || p == "." || p == "..")
        && Path::new(s)
            .components()
            .all(|c| matches!(c, PathComponent::Normal(_)))
}
fn version(s: &str) -> bool {
    let p: Vec<_> = s.split('.').collect();
    p.len() == 3
        && p.iter().all(|p| {
            !p.is_empty()
                && p.bytes().all(|c| c.is_ascii_digit())
                && (p.len() == 1 || !p.starts_with('0'))
        })
}
fn asset(a: &Asset, tag: &str) -> Result<()> {
    ensure!(
        safe_path(&a.file) && !a.file.contains('/'),
        "invalid asset name"
    );
    ensure!(
        hex_string(&a.sha256, 64) && a.size > 0 && a.size <= MAX_EXPANDED,
        "invalid asset digest or size"
    );
    ensure!(
        a.url
            == format!(
                "https://github.com/{REPOSITORY}/releases/download/{tag}/{}",
                a.file
            ),
        "asset URL must identify the frozen paired GitHub release"
    );
    Ok(())
}
fn validate(s: &ReleaseSet) -> Result<()> {
    ensure!(s.schema == SCHEMA, "unsupported release-set schema");
    ensure!(s.platform == "darwin-arm64", "unsupported platform");
    ensure!(
        s.development_only,
        "this installer supports explicitly unsigned development sets only"
    );
    ensure!(
        s.protocol_version == "loomex.local-control/v2",
        "unsupported protocol"
    );
    deployment_origin(s.deployment.api_origin(), s.deployment.local())?;
    if let Deployment::LocalDevelopment { web_app_origin, .. } = &s.deployment {
        if !web_app_origin.is_null() {
            deployment_origin(
                web_app_origin
                    .as_str()
                    .context("web app origin must be string or null")?,
                true,
            )?;
        }
    }
    for (name, c) in [
        ("runner", &s.components.runner),
        ("plugin", &s.components.plugin),
    ] {
        ensure!(
            version(&c.version)
                && hex_string(&c.source_revision, 40)
                && hex_string(&c.manifest_sha256, 64),
            "invalid component identity"
        );
        ensure!(
            c.repository
                == if name == "runner" {
                    REPOSITORY
                } else {
                    "loomex-app/loomex-codex-plugin"
                },
            "unexpected component repository"
        );
        ensure!(
            c.release_tag == s.release_tag,
            "component belongs to a different release set"
        );
        asset(&c.asset, &s.release_tag)?;
    }
    ensure!(
        s.release_tag
            == format!(
                "runner-v{}-plugin-v{}",
                s.components.runner.version, s.components.plugin.version
            )
            || s.release_tag
                == format!(
                    "preview-runner-v{}-plugin-v{}",
                    s.components.runner.version, s.components.plugin.version
                ),
        "release tag/version pair mismatch"
    );
    ensure!(
        s.evidence.passed && hex_string(&s.evidence.backend_source_revision, 40),
        "qualification evidence missing"
    );
    asset(&s.evidence.asset, &s.release_tag)?;
    asset(&s.installer, &s.release_tag)?;
    let files = [
        &s.components.runner.asset.file,
        &s.components.plugin.asset.file,
        &s.evidence.asset.file,
        &s.installer.file,
    ];
    ensure!(
        files.iter().collect::<BTreeSet<_>>().len() == files.len(),
        "duplicate release assets"
    );
    Ok(())
}
fn verify_asset(path: &Path, a: &Asset) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    ensure!(
        m.file_type().is_file() && m.len() == a.size && hash_file(path)? == a.sha256,
        "asset size/digest mismatch: {}",
        a.file
    );
    Ok(())
}
fn extract(archive: &Path, root: &Path) -> Result<()> {
    fs::create_dir(root)?;
    let mut seen = BTreeSet::new();
    let mut expanded = 0u64;
    let stream = flate2::read::GzDecoder::new(fs::File::open(archive)?);
    for entry in tar::Archive::new(stream).entries()? {
        let mut e = entry?;
        let p = e.path()?.into_owned();
        let text = p.to_str().context("non UTF-8 archive path")?;
        // tar commonly encodes directory names with one trailing slash.
        let name = text.strip_suffix('/').unwrap_or(text);
        ensure!(
            safe_path(name) && seen.insert(name.to_owned()),
            "unsafe or duplicate archive path"
        );
        let kind = e.header().entry_type();
        ensure!(
            kind.is_file() || kind.is_dir(),
            "archive links/devices are forbidden"
        );
        let mode = e.header().mode()?;
        ensure!(mode & !0o777 == 0, "unsafe archive mode");
        expanded = expanded
            .checked_add(e.size())
            .context("archive size overflow")?;
        ensure!(expanded <= MAX_EXPANDED, "archive expansion exceeds limit");
        let target = root.join(name);
        if kind.is_dir() {
            fs::create_dir_all(&target)?;
        } else {
            fs::create_dir_all(target.parent().unwrap())?;
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&target)?;
            std::io::copy(&mut e, &mut f)?;
            f.flush()?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&target, fs::Permissions::from_mode(mode))?;
            }
        }
    }
    Ok(())
}
fn verify_envelope(root: &Path, c: &Component, deployment: &Deployment) -> Result<Value> {
    ensure!(
        hash_file(&root.join("manifest.json"))? == c.manifest_sha256,
        "component manifest digest mismatch"
    );
    let manifest_bytes = fs::read(root.join("manifest.json"))?;
    let m: Value = serde_json::from_slice(&manifest_bytes)?;
    ensure!(
        canonical_digest(&m)? == hex::encode(Sha256::digest(&manifest_bytes)),
        "noncanonical component manifest"
    );
    let project = if c.repository == REPOSITORY {
        "loomex-runner"
    } else {
        "loomex-plugin"
    };
    ensure!(
        m["schema"] == "app.loomex.release/v1"
            && m["project"] == project
            && m["version"] == c.version
            && m["sourceRevision"] == c.source_revision
            && m["platform"] == "darwin-arm64"
            && m["developmentOnly"] == true,
        "component envelope/pair mismatch"
    );
    ensure!(
        !root.join("manifest.sig").exists(),
        "unsigned preview envelope unexpectedly signed"
    );
    ensure!(
        m["payload"]["file"] == "payload.tar.gz",
        "unsupported payload filename"
    );
    ensure!(
        hash_file(&root.join("payload.tar.gz"))?
            == m["payload"]["sha256"]
                .as_str()
                .context("payload digest missing")?,
        "payload digest mismatch"
    );
    let staging = tempfile::tempdir()?;
    let payload = staging.path().join("payload");
    extract(&root.join("payload.tar.gz"), &payload)?;
    let mut expected = BTreeSet::new();
    for e in m["payload"]["files"]
        .as_array()
        .context("payload inventory missing")?
    {
        let name = e["path"].as_str().context("inventory path missing")?;
        ensure!(
            safe_path(name) && expected.insert(name.to_owned()),
            "unsafe/duplicate inventory path"
        );
        let p = payload.join(name);
        let metadata = fs::symlink_metadata(&p)?;
        ensure!(
            metadata.is_file()
                && metadata.len() == e["size"].as_u64().context("inventory size missing")?
                && hash_file(&p)? == e["sha256"].as_str().context("inventory digest missing")?,
            "payload inventory mismatch"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            ensure!(
                metadata.permissions().mode() & 0o777
                    == e["mode"].as_u64().context("inventory mode missing")? as u32,
                "payload mode mismatch"
            );
        }
    }
    fn files(root: &Path, base: &Path, result: &mut BTreeSet<String>) -> Result<()> {
        for e in fs::read_dir(root)? {
            let p = e?.path();
            if p.is_dir() {
                files(&p, base, result)?;
            } else {
                result.insert(
                    p.strip_prefix(base)?
                        .to_str()
                        .context("invalid inventory encoding")?
                        .into(),
                );
            }
        }
        Ok(())
    }
    let mut actual = BTreeSet::new();
    files(&payload, &payload, &mut actual)?;
    ensure!(actual == expected, "unexpected payload files");
    // Source provenance is a mandatory inventory-bound payload file.
    let source = &m["sourceContent"];
    let source_path = source["file"]
        .as_str()
        .context("source content binding missing")?;
    let source_root = if project == "loomex-runner" {
        &payload
    } else {
        root
    };
    ensure!(
        safe_path(source_path)
            && hash_file(&source_root.join(source_path))?
                == source["sha256"]
                    .as_str()
                    .context("source content digest missing")?,
        "source content digest mismatch"
    );
    let source_bytes = fs::read(source_root.join(source_path))?;
    let provenance: Value = serde_json::from_slice(&source_bytes)?;
    ensure!(
        canonical_digest(&provenance)? == hex::encode(Sha256::digest(&source_bytes)),
        "noncanonical source provenance"
    );
    ensure!(
        provenance["schema"] == "app.loomex.source-content/v1"
            && provenance["sourceRevision"] == c.source_revision,
        "source content revision mismatch"
    );
    if project == "loomex-runner" {
        let bootstrap = &m["bootstrap"];
        ensure!(
            bootstrap["file"] == "loomex-lifecycle-bootstrap",
            "native bootstrap binding missing"
        );
        verify_bound_file(root, bootstrap)?;
        let local = deployment.local();
        let file = if local {
            "metadata/local-development-origin.json"
        } else {
            "metadata/preview-origin.json"
        };
        let other = if local {
            "metadata/preview-origin.json"
        } else {
            "metadata/local-development-origin.json"
        };
        ensure!(
            !payload.join(other).exists(),
            "runner deployment profile substitution"
        );
        let bytes = fs::read(payload.join(file)).context("runner deployment metadata missing")?;
        let mut preview: Value = serde_json::from_slice(&bytes)?;
        let mut expected = serde_json::json!({"schema":if local {"app.loomex.runner.local-development-origin/v1"} else {"app.loomex.runner.preview-origin/v1"}, "sourceRevision":c.source_revision,"version":c.version,"apiOrigin":deployment.api_origin()});
        if local {
            expected["webAppOrigin"] = deployment.web_app_origin();
        }
        ensure!(
            preview == expected
                && canonical_digest(&preview)? == hex::encode(Sha256::digest(&bytes)),
            "runner deployment metadata differs from reviewed profile/origins/source"
        );
        let contract: Value = serde_json::from_slice(&fs::read(
            payload.join("metadata/compatibility-manifest.json"),
        )?)?;
        ensure!(
            contract["protocol"] == "loomex.local-control/v2",
            "runner protocol mismatch"
        );
        preview["compatibilityDigest"] = canonical_digest(&contract)?.into();
        return Ok(preview);
    }
    let bootstrap = &m["bootstrap"];
    ensure!(
        bootstrap["runtime"]["file"] == "lifecycle-runtime/node"
            && bootstrap["manager"]["file"] == "lifecycle.mjs",
        "compiled plugin lifecycle owner missing"
    );
    verify_bound_file(root, &bootstrap["runtime"])?;
    verify_bound_file(root, &bootstrap["manager"])?;
    let components: Value =
        serde_json::from_slice(&fs::read(root.join("plugin-components.json"))?)?;
    Ok(serde_json::json!({"compatibilityDigest":canonical_digest(&components)?}))
}
fn verify_bound_file(root: &Path, e: &Value) -> Result<()> {
    let name = e["file"].as_str().context("bootstrap file missing")?;
    ensure!(safe_path(name), "unsafe bootstrap path");
    let p = root.join(name);
    let m = fs::symlink_metadata(&p)?;
    ensure!(
        m.file_type().is_file()
            && m.len() == e["size"].as_u64().context("bootstrap size missing")?
            && hash_file(&p)? == e["sha256"].as_str().context("bootstrap digest missing")?,
        "bootstrap digest mismatch"
    );
    Ok(())
}
fn download(url: &str, output: &Path, max: u64) -> Result<()> {
    let client = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(300))
        .build()?;
    let mut current = Url::parse(url)?;
    for _ in 0..5 {
        ensure!(
            current.scheme() == "https"
                && current.username().is_empty()
                && current.password().is_none()
                && matches!(
                    current.host_str(),
                    Some(
                        "github.com"
                            | "release-assets.githubusercontent.com"
                            | "objects.githubusercontent.com"
                    )
                ),
            "unsafe download redirect"
        );
        let response = client.get(current.clone()).send()?;
        if response.status().is_redirection() {
            let next = response
                .headers()
                .get(reqwest::header::LOCATION)
                .context("redirect lacks location")?
                .to_str()?;
            current = current.join(next)?;
            continue;
        }
        let response = response.error_for_status()?;
        if let Some(n) = response.content_length() {
            ensure!(n <= max, "download larger than expected");
        }
        let mut limited = response.take(max + 1);
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output)?;
        let count = std::io::copy(&mut limited, &mut file)?;
        ensure!(count <= max, "download larger than expected");
        return Ok(());
    }
    bail!("too many download redirects")
}
fn evidence(path: &Path, s: &ReleaseSet, runner: &Value, plugin: &Value) -> Result<()> {
    let e: Value = serde_json::from_slice(&fs::read(path)?)?;
    ensure!(
        e["schema"] == "app.loomex.release-qualification/v1"
            && e["compatibility"]["schemaVersion"] == "loomex/compatibility-manifest/v1",
        "compatibility evidence schema mismatch"
    );
    for (name, revision) in [
        ("runner", &s.components.runner.source_revision),
        ("plugin", &s.components.plugin.source_revision),
        ("backend", &s.evidence.backend_source_revision),
    ] {
        ensure!(
            e["sourceRevisions"][name] == *revision,
            "qualification belongs to a different source pair"
        );
        if name != "runner" {
            ensure!(
                e["compatibility"]["verification"]["sourceRevisions"][name] == *revision,
                "required compatibility gate source mismatch"
            );
        }
    }
    for (name, value) in [("runner", runner), ("plugin", plugin)] {
        let actual = value["compatibilityDigest"]
            .as_str()
            .context("component compatibility digest missing")?;
        ensure!(
            e["compatibility"]["components"][name]["digest"] == format!("sha256:{actual}"),
            "gate did not qualify packaged component bytes"
        );
    }
    Ok(())
}
fn run_owner(script: &Path, release: &Path, args: &[String]) -> Result<()> {
    let output = Command::new("/bin/bash")
        .arg(script)
        .arg(release)
        .args(args)
        .env("LOOMEX_ALLOW_UNSAFE_DEV_INSTALL", "1")
        .output()?;
    ensure!(
        output.status.success(),
        "lifecycle owner returned failure; retained state belongs to that owner"
    );
    Ok(())
}
// Keep owner output private: it can contain paths, account details or arbitrary errors.
fn owner_preflight(cmd: &mut Command, schema: &str) -> Result<Value> {
    let value = command_json(cmd)?;
    ensure!(
        value["schema"] == schema
            && value["artifact"]["eligible"] == true
            && value["activation"]["eligible"] == true,
        "unsupported or ineligible owner preflight response"
    );
    Ok(value)
}
fn preflight_owners(
    runner: &Path,
    plugin: Option<&Path>,
    runner_args: &[String],
    plugin_args: &[String],
    completion: &mut Completion,
) -> Result<()> {
    completion.phase = "runner-preflight";
    owner_preflight(
        Command::new(runner.join("loomex-lifecycle-bootstrap"))
            .arg("preflight")
            .arg(runner)
            .args(runner_args),
        "app.loomex.runner.install-preflight/v1",
    )?;
    if let Some(plugin) = plugin {
        completion.phase = "plugin-preflight";
        owner_preflight(
            Command::new(plugin.join("lifecycle-runtime/node"))
                .arg(plugin.join("lifecycle.mjs"))
                .arg("preflight")
                .arg("--release")
                .arg(plugin)
                .args(plugin_args),
            "app.loomex.plugin.install-preflight/v1",
        )?;
    }
    // Never relay the owners' extensible fields or errors through the transport.
    Ok(())
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Completion {
    schema: &'static str,
    phase: &'static str,
    runner: &'static str,
    plugin: &'static str,
    host_registration: &'static str,
}
impl Default for Completion {
    fn default() -> Self {
        Self {
            schema: "app.loomex.paired-install-result/v1",
            phase: "artifact-verification",
            runner: "not-attempted",
            plugin: "not-attempted",
            host_registration: "not-attempted",
        }
    }
}
fn failure_report(completion: &Completion) -> Value {
    let message = match completion.phase {
        "runner-preflight" => {
            "Runner installed eligibility was rejected by the native lifecycle owner. Inspect its preflight result and retry this exact release set."
        }
        "plugin-preflight" => {
            "Plugin installed eligibility was rejected by the plugin lifecycle owner. Inspect its preflight result and retry this exact release set."
        }
        "runner-activation" | "runner-health" => {
            "Runner activation or health is unconfirmed. Resolve the native lifecycle owner before retrying this exact release set."
        }
        "plugin-activation" => {
            "Plugin installation is incomplete; the healthy runner remains installed. Retry this exact release set to resume the plugin owner."
        }
        "host-registration" => {
            "Codex registration is incomplete; the healthy runner and plugin files remain installed. Retry this exact release set."
        }
        "host-preflight" => {
            "Codex marketplace eligibility failed. Review the existing marketplace before retrying this exact release set."
        }
        "namespace-preflight" => {
            "Paired install bases overlap another owner's installed or state namespace. Select distinct bases outside the other owner's managed paths."
        }
        "cache-persistence" => {
            "Verified artifact cache could not be retained. Retry this exact release set after resolving the cache issue."
        }
        _ => {
            "Release-set verification failed. Review the exact artifacts and invocation before retrying."
        }
    };
    serde_json::json!({"schema":completion.schema,"ok":false,"category":"PAIRED_INSTALL_REJECTED","phase":completion.phase,"completion":completion,"message":message})
}
// Resolve existing aliases component by component while retaining normalized
// missing suffixes. This reads metadata only and never creates an install root.
fn normalized_namespace(path: &Path) -> Result<PathBuf> {
    ensure!(path.is_absolute(), "install namespace must be absolute");
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            PathComponent::RootDir => result.push(Path::new("/")),
            PathComponent::CurDir => {}
            PathComponent::ParentDir => {
                result.pop();
            }
            PathComponent::Normal(part) => {
                result.push(part);
                match fs::symlink_metadata(&result) {
                    Ok(_) => result = fs::canonicalize(&result)?,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
            }
            _ => bail!("unsupported install namespace"),
        }
    }
    Ok(result)
}
// Component comparisons consult the actual containing volume only when byte
// spellings differ. Missing suffixes inherit the nearest existing volume.
fn namespace_contains(parent: &Path, child: &Path) -> Result<bool> {
    let mut prefix = PathBuf::new();
    let mut children = child.components();
    for part in parent.components() {
        let Some(other) = children.next() else {
            return Ok(false);
        };
        if part != other {
            let policy = namespace_names::volume_policy(&prefix)?;
            if !namespace_names::equivalent(part.as_os_str(), other.as_os_str(), policy)? {
                return Ok(false);
            }
        }
        prefix.push(part.as_os_str());
    }
    Ok(true)
}
fn plugin_bootstrap_anchor(plugin: &Path) -> Result<PathBuf> {
    let mut name = std::ffi::OsString::from(".");
    name.push(plugin.file_name().context("plugin base name unavailable")?);
    name.push(".lifecycle.bootstrap.lock");
    normalized_namespace(
        &plugin
            .parent()
            .context("plugin parent unavailable")?
            .join(name),
    )
}
fn validate_launch_agent_namespace(
    runner: &Path,
    plugin: &Path,
    runner_state: &Path,
    launch_agent: &Path,
) -> Result<()> {
    let owned = normalized_namespace(launch_agent)?;
    let runner = normalized_namespace(runner)?;
    let plugin = normalized_namespace(plugin)?;
    for base in [&runner, &plugin] {
        ensure!(
            !namespace_contains(&owned, base)?,
            "install base enters the runner LaunchAgent file namespace"
        );
    }
    let mut managed = vec![
        normalized_namespace(runner_state)?,
        plugin_bootstrap_anchor(&plugin)?,
    ];
    for (base, names) in [(&runner, RUNNER_OWNED_NAMES), (&plugin, PLUGIN_OWNED_NAMES)] {
        for name in names {
            managed.push(normalized_namespace(&base.join(name))?);
        }
    }
    for namespace in managed {
        ensure!(
            !namespace_contains(&namespace, &owned)? && !namespace_contains(&owned, &namespace)?,
            "runner LaunchAgent file overlaps an owner-managed namespace"
        );
    }
    Ok(())
}
fn validate_install_namespaces(runner: &Path, plugin: &Path, runner_state: &Path) -> Result<()> {
    let runner = normalized_namespace(runner)?;
    let plugin = normalized_namespace(plugin)?;
    let state = normalized_namespace(runner_state)?;
    ensure!(
        !(namespace_contains(&runner, &plugin)? && namespace_contains(&plugin, &runner)?),
        "paired install bases share one namespace"
    );
    // Only reserve paths actually owned by these lifecycle implementations.
    // Unrelated sibling or nested directories keep their existing policy.
    for (base, other, names) in [
        (&runner, &plugin, RUNNER_OWNED_NAMES),
        (&plugin, &runner, PLUGIN_OWNED_NAMES),
    ] {
        for name in names {
            let owned = normalized_namespace(&base.join(name))?;
            ensure!(
                !namespace_contains(&owned, other)?,
                "paired install base enters another owner's namespace"
            );
        }
    }
    // The plugin owner acquires this narrowly named sibling lock before its
    // root exists, so it is part of the paired namespace plan as well.
    let anchor = plugin_bootstrap_anchor(&plugin)?;
    ensure!(
        !namespace_contains(&anchor, &runner)?,
        "runner base enters the plugin bootstrap lock namespace"
    );
    for base in [&runner, &plugin] {
        ensure!(
            !namespace_contains(&state, base)? && !namespace_contains(base, &state)?,
            "install base overlaps the runner state namespace"
        );
    }
    Ok(())
}
// Existing complete cache bytes may carry a pending owner's exact release-path binding.
// Reading it must not repair, chmod, create, or remove any entry.
fn preflight_root<'a>(stage: &'a Path, cache: &'a Path) -> Result<&'a Path> {
    if !cache.exists() {
        return Ok(stage);
    }
    for ancestor in cache.ancestors() {
        if ancestor.exists() {
            ensure!(
                !fs::symlink_metadata(ancestor)?.file_type().is_symlink(),
                "artifact cache ancestor symlink forbidden"
            );
        }
    }
    let expected = directory_inventory(stage)?;
    let actual = cache_inventory(cache)?;
    ensure!(
        actual.iter().all(|entry| expected.contains(entry)),
        "immutable artifact cache differs from verified release set"
    );
    Ok(if actual == expected { cache } else { stage })
}
fn find_codex() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for directory in std::env::split_paths(&path) {
        let p = directory.join("codex");
        if let Ok(m) = fs::metadata(&p) {
            #[cfg(unix)]
            let executable = {
                use std::os::unix::fs::PermissionsExt;
                m.is_file() && m.permissions().mode() & 0o111 != 0
            };
            #[cfg(not(unix))]
            let executable = m.is_file();
            if executable {
                return fs::canonicalize(p).ok();
            }
        }
    }
    None
}
fn directory_inventory(root: &Path) -> Result<Vec<(String, String, u32)>> {
    directory_inventory_impl(root, false)
}
fn cache_inventory(root: &Path) -> Result<Vec<(String, String, u32)>> {
    directory_inventory_impl(root, true)
}
fn directory_inventory_impl(
    root: &Path,
    ignore_incoming: bool,
) -> Result<Vec<(String, String, u32)>> {
    fn walk(
        root: &Path,
        base: &Path,
        out: &mut Vec<(String, String, u32)>,
        ignore_incoming: bool,
    ) -> Result<()> {
        for e in fs::read_dir(root)? {
            let p = e?.path();
            let m = fs::symlink_metadata(&p)?;
            ensure!(
                !m.file_type().is_symlink(),
                "artifact cache symlinks forbidden"
            );
            if m.is_dir() {
                if !(ignore_incoming && p == base.join(".incoming")) {
                    walk(&p, base, out, ignore_incoming)?;
                }
            } else {
                ensure!(m.is_file(), "artifact cache special file forbidden");
                #[cfg(unix)]
                let mode = {
                    use std::os::unix::fs::PermissionsExt;
                    m.permissions().mode() & 0o777
                };
                #[cfg(not(unix))]
                let mode = 0;
                out.push((
                    p.strip_prefix(base)?
                        .to_str()
                        .context("cache path encoding")?
                        .into(),
                    hash_file(&p)?,
                    mode,
                ));
            }
        }
        Ok(())
    }
    let mut out = Vec::new();
    walk(root, root, &mut out, ignore_incoming)?;
    out.sort();
    Ok(out)
}
fn persist_cache(stage: &Path, cache: &Path) -> Result<()> {
    ensure!(cache.is_absolute(), "artifact cache must be absolute");
    for ancestor in cache.ancestors() {
        if ancestor.exists() {
            ensure!(
                !fs::symlink_metadata(ancestor)?.file_type().is_symlink(),
                "artifact cache ancestor symlink forbidden"
            );
        }
    }
    let expected = directory_inventory(stage)?;
    let parent = cache.parent().context("cache parent unavailable")?;
    fs::create_dir_all(parent)?;
    if !cache.exists() {
        fs::create_dir(cache)?;
    }
    ensure!(
        fs::symlink_metadata(cache)?.is_dir(),
        "artifact cache is not a directory"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        ensure!(
            fs::metadata(cache)?.uid() == fs::metadata(stage)?.uid(),
            "artifact cache has another owner"
        );
        fs::set_permissions(cache, fs::Permissions::from_mode(0o700))?;
    }
    for entry in cache_inventory(cache)? {
        ensure!(
            expected.contains(&entry),
            "immutable artifact cache differs from verified release set"
        );
    }
    let incoming = cache.join(".incoming");
    if !incoming.exists() {
        fs::create_dir(&incoming)?;
    }
    let incoming_metadata = fs::symlink_metadata(&incoming)?;
    ensure!(
        incoming_metadata.is_dir() && !incoming_metadata.file_type().is_symlink(),
        "cache staging must be a regular directory"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        ensure!(
            incoming_metadata.uid() == fs::metadata(stage)?.uid(),
            "cache staging has another owner"
        );
        fs::set_permissions(&incoming, fs::Permissions::from_mode(0o700))?;
    }
    fn copy(root: &Path, dest: &Path, incoming: &Path) -> Result<()> {
        for e in fs::read_dir(root)? {
            let p = e?.path();
            let to = dest.join(p.file_name().unwrap());
            if p.is_dir() {
                if !to.exists() {
                    fs::create_dir(&to)?;
                }
                copy(&p, &to, incoming)?;
            } else if !to.exists() {
                let mut source = fs::File::open(&p)?;
                let mut temporary = tempfile::NamedTempFile::new_in(incoming)?;
                std::io::copy(&mut source, &mut temporary)?;
                temporary.as_file().sync_all()?;
                fs::set_permissions(temporary.path(), fs::metadata(&p)?.permissions())?;
                ensure!(
                    hash_file(temporary.path())? == hash_file(&p)?,
                    "cache staged file changed"
                );
                // Hard-link promotion is atomic and create-only; incomplete staging bytes never occupy a final artifact path.
                if let Err(error) = fs::hard_link(temporary.path(), &to) {
                    if error.kind() != std::io::ErrorKind::AlreadyExists {
                        return Err(error.into());
                    }
                    ensure!(
                        hash_file(&to)? == hash_file(&p)?,
                        "concurrent cache file differs"
                    );
                }
            }
        }
        Ok(())
    }
    copy(stage, cache, &incoming)?;
    ensure!(
        cache_inventory(cache)? == expected,
        "artifact cache readback failed"
    );
    Ok(())
}
fn command_json(cmd: &mut Command) -> Result<Value> {
    let out = cmd.output()?;
    ensure!(
        out.status.success(),
        "supported command failed; retry the same release set after resolving the reported owner issue"
    );
    serde_json::from_slice(&out.stdout).context("unsupported command JSON response")
}
fn runner_health(base: &Path, version: &str) -> Result<()> {
    let value = command_json(Command::new(base.join("current/bin/loomex")).arg("status"))?;
    ensure!(
        value["version"] == version
            && value["protocol"] == "loomex.local-control/v2"
            && value["draining"] == false
            && value["updateDeferred"] == false,
        "runner activation is pending or health/version differs; resolve the native lifecycle owner before plugin install"
    );
    Ok(())
}
fn check_marketplace(codex: &Path, base: &Path) -> Result<bool> {
    let listing =
        command_json(Command::new(codex).args(["plugin", "marketplace", "list", "--json"]))?;
    let marketplaces = listing["marketplaces"]
        .as_array()
        .context("Codex marketplace response missing")?;
    let mut found = false;
    for market in marketplaces {
        if market["name"] == "loomex-private" {
            ensure!(!found, "duplicate Loomex marketplace identity");
            found = true;
            let root = market["root"]
                .as_str()
                .context("marketplace root missing")?;
            ensure!(
                Path::new(root) == base,
                "existing loomex-private marketplace belongs to another root; review it manually before retrying"
            );
            if let Some(source) = market.get("marketplaceSource") {
                ensure!(
                    source["sourceType"] == "local" && source["source"].as_str() == base.to_str(),
                    "existing marketplace source differs"
                );
            }
        }
    }
    Ok(found)
}
fn register_plugin(codex: &Path, base: &Path, version: &str) -> Result<()> {
    if !check_marketplace(codex, base)? {
        command_json(
            Command::new(codex)
                .args(["plugin", "marketplace", "add"])
                .arg(base)
                .arg("--json"),
        )?;
    }
    ensure!(
        check_marketplace(codex, base)?,
        "marketplace registration readback failed"
    );
    command_json(Command::new(codex).args(["plugin", "add", "loomex@loomex-private", "--json"]))?;
    let listing = command_json(Command::new(codex).args([
        "plugin",
        "list",
        "--marketplace",
        "loomex-private",
        "--json",
    ]))?;
    let entries = listing["installed"]
        .as_array()
        .context("Codex installed plugin readback missing")?;
    let matches: Vec<_> = entries
        .iter()
        .filter(|v| v["pluginId"] == "loomex@loomex-private")
        .collect();
    ensure!(
        matches.len() == 1
            && matches[0]["installed"] == true
            && matches[0]["enabled"] == true
            && matches[0]["version"] == version
            && matches[0]["source"]["source"] == "local"
            && matches[0]["source"]["path"].as_str() == base.join("current/plugin").to_str(),
        "Codex plugin source/version/enablement readback differs"
    );
    Ok(())
}
fn install(completion: &mut Completion) -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut manifest = None;
    let mut offline = None;
    let mut expected = None;
    let mut preview = false;
    let mut runner_only = false;
    let mut verify_only = false;
    let mut preflight_only = false;
    let mut authorize_keychain_transition = false;
    let mut bases = Vec::new();
    let mut cache = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--manifest"
            | "--offline"
            | "--manifest-sha256"
            | "--runner-install-base"
            | "--plugin-install-base"
            | "--cache-dir" => {
                let value = args.get(i + 1).context("missing option value")?.clone();
                match args[i].as_str() {
                    "--manifest" => manifest = Some(value),
                    "--offline" => offline = Some(value),
                    "--manifest-sha256" => expected = Some(value),
                    "--cache-dir" => cache = Some(PathBuf::from(value)),
                    key => bases.push((key.to_owned(), value)),
                }
                i += 2;
            }
            "--allow-unsigned-development" | "--allow-unsigned-preview" => {
                preview = true;
                i += 1
            }
            "--authorize-keychain-transition" => {
                authorize_keychain_transition = true;
                i += 1;
            }
            "--preflight-only" => {
                preflight_only = true;
                i += 1;
            }
            "--verify-only" => {
                verify_only = true;
                i += 1;
            }
            "--runner-only" => {
                runner_only = true;
                i += 1
            }
            _ => bail!(
                "usage: loomex-install (--manifest FILE | --offline DIR) --manifest-sha256 SHA256 --allow-unsigned-development [--runner-only] [--runner-install-base DIR] [--plugin-install-base DIR]"
            ),
        }
    }
    ensure!(
        !(verify_only && preflight_only),
        "choose one verification mode"
    );
    ensure!(
        preview && std::env::var("LOOMEX_ALLOW_UNSAFE_DEV_INSTALL").as_deref() == Ok("1"),
        "unsigned distribution requires --allow-unsigned-development and LOOMEX_ALLOW_UNSAFE_DEV_INSTALL=1"
    );
    ensure!(
        std::env::consts::OS == "macos" && std::env::consts::ARCH == "aarch64",
        "supported platform is macOS ARM64 only"
    );
    ensure!(
        manifest.is_some() != offline.is_some(),
        "choose one manifest or offline directory"
    );
    let expected = expected.context("an independently reviewed --manifest-sha256 is required")?;
    ensure!(hex_string(&expected, 64), "invalid manifest digest");
    let offline = offline.map(PathBuf::from);
    let manifest = manifest
        .map(PathBuf::from)
        .unwrap_or_else(|| offline.as_ref().unwrap().join("release-set.json"));
    ensure!(
        fs::metadata(&manifest)?.len() <= MAX_MANIFEST && hash_file(&manifest)? == expected,
        "release-set digest mismatch"
    );
    let manifest_bytes = fs::read(manifest)?;
    let canonical: Value = serde_json::from_slice(&manifest_bytes)?;
    ensure!(
        canonical_digest(&canonical)? == hex::encode(Sha256::digest(&manifest_bytes)),
        "noncanonical release-set"
    );
    let s: ReleaseSet = serde_json::from_slice(&manifest_bytes)?;
    validate(&s)?;
    // Even offline execution is bound to the installer inventory; a colocated hash isn't a trust root.
    verify_asset(&std::env::current_exe()?, &s.installer)?;
    let stage = tempfile::tempdir()?;
    for a in [
        &s.components.runner.asset,
        &s.components.plugin.asset,
        &s.evidence.asset,
    ] {
        let path = stage.path().join(&a.file);
        if let Some(dir) = &offline {
            let source = dir.join(&a.file);
            verify_asset(&source, a)?;
            fs::copy(source, &path)?;
        } else {
            download(&a.url, &path, a.size)?;
        }
        verify_asset(&path, a)?;
    }
    let runner = stage.path().join("runner");
    let plugin = stage.path().join("plugin");
    extract(&stage.path().join(&s.components.runner.asset.file), &runner)?;
    extract(&stage.path().join(&s.components.plugin.asset.file), &plugin)?;
    let origin = verify_envelope(&runner, &s.components.runner, &s.deployment)?;
    ensure!(
        origin["apiOrigin"] == s.deployment.api_origin(),
        "preview origin differs from verified runner payload"
    );
    let plugin_contract = verify_envelope(&plugin, &s.components.plugin, &s.deployment)?;
    evidence(
        &stage.path().join(&s.evidence.asset.file),
        &s,
        &origin,
        &plugin_contract,
    )?;
    if verify_only {
        println!(
            "{}",
            serde_json::json!({"schema":"app.loomex.paired-install-result/v1","ok":true,"mode":"verify-only","artifactIntegrity":true,"installedEligibilityVerified":false})
        );
        return Ok(());
    }
    let home = PathBuf::from(std::env::var_os("HOME").context("HOME unavailable")?);
    ensure!(home.is_absolute(), "HOME must be absolute");
    let cache = cache
        .unwrap_or_else(|| home.join("Library/Caches/Loomex/release-sets"))
        .join(&expected);
    let mut plugin_base = home.join("Library/Application Support/Loomex/plugin");
    let mut runner_base = home.join("Library/Application Support/Loomex/runner");
    let mut runner_args = vec![
        "--allow-unsigned-development".into(),
        (if s.deployment.local() {
            "--development-api-origin"
        } else {
            "--preview-api-origin"
        })
        .into(),
        s.deployment.api_origin().to_owned(),
    ];
    if authorize_keychain_transition {
        runner_args.push("--authorize-keychain-transition".into());
    }
    let mut plugin_args = vec!["--allow-unsigned-development".into()];
    for (key, value) in bases {
        if key == "--runner-install-base" {
            runner_base = PathBuf::from(&value);
        } else {
            plugin_base = PathBuf::from(&value);
        }
    }
    ensure!(
        runner_base.is_absolute() && plugin_base.is_absolute(),
        "install bases must be absolute"
    );
    if !runner_only {
        completion.phase = "namespace-preflight";
        let runner_state = std::env::var_os("LOOMEX_STATE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".local/share/loomex/runner"));
        validate_install_namespaces(&runner_base, &plugin_base, &runner_state)?;
        let launch_agents = std::env::var_os("LOOMEX_LAUNCH_AGENTS_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join("Library/LaunchAgents"));
        validate_launch_agent_namespace(
            &runner_base,
            &plugin_base,
            &runner_state,
            &launch_agents.join("app.loomex.runner.plist"),
        )?;
    }
    runner_args.extend([
        "--install-base".into(),
        runner_base.to_string_lossy().into_owned(),
    ]);
    plugin_args.extend([
        "--install-base".into(),
        plugin_base.to_string_lossy().into_owned(),
    ]);
    let root = preflight_root(stage.path(), &cache)?;
    preflight_owners(
        &root.join("runner"),
        (!runner_only).then(|| root.join("plugin")).as_deref(),
        &runner_args,
        &plugin_args,
        completion,
    )?;
    let codex = find_codex();
    let has_codex = codex.is_some();
    completion.phase = "host-preflight";
    if !runner_only && has_codex {
        check_marketplace(codex.as_deref().unwrap(), &plugin_base)?;
    }
    if preflight_only {
        println!(
            "{}",
            serde_json::json!({"schema":"app.loomex.paired-install-result/v1","ok":true,"mode":"preflight-only","artifactIntegrity":true,"installedEligibilityVerified":true,"runnerOnly":runner_only,"hostRegistrationVerified":false})
        );
        return Ok(());
    }
    completion.phase = "cache-persistence";
    persist_cache(stage.path(), &cache)?;
    let runner = cache.join("runner");
    let plugin = cache.join("plugin");
    completion.phase = "runner-activation";
    completion.runner = "unconfirmed";
    run_owner(&runner.join("scripts/install.sh"), &runner, &runner_args)?;
    completion.phase = "runner-health";
    runner_health(&runner_base, &s.components.runner.version)?;
    completion.runner = "healthy";
    let installed = !runner_only;
    if installed {
        completion.phase = "plugin-activation";
        completion.plugin = "unconfirmed";
        run_owner(&plugin.join("scripts/install.sh"), &plugin, &plugin_args)?;
        completion.plugin = "installed";
        if has_codex {
            completion.phase = "host-registration";
            completion.host_registration = "unconfirmed";
            register_plugin(
                codex.as_deref().unwrap(),
                &plugin_base,
                &s.components.plugin.version,
            )?;
            completion.host_registration = "verified";
        } else {
            completion.host_registration = "manual-action-required";
        }
    }
    if installed && has_codex {
        println!(
            "Runner and Loomex plugin installed and read back through Codex. Restart Codex to load the plugin."
        );
    } else if runner_only {
        println!("Runner lifecycle owner completed (--runner-only).");
    } else {
        println!(
            "Runner and plugin files installed. Codex CLI is unavailable; the healthy runner is preserved. In Codex desktop open Plugins, import the local marketplace at {} and install Loomex from loomex-private. If the GUI cannot import a local marketplace, install the supported Codex CLI, then retry this exact release set. Verified prerequisites retained at {}. No settings/cache edits are required.",
            plugin_base.display(),
            cache.display()
        );
    }

    completion.phase = "complete";
    Ok(())
}

fn main() {
    let mut completion = Completion::default();
    if install(&mut completion).is_err() {
        eprintln!("{}", failure_report(&completion));
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn a(file: &str, tag: &str) -> Asset {
        Asset {
            file: file.into(),
            url: format!("https://github.com/{REPOSITORY}/releases/download/{tag}/{file}"),
            size: 1,
            sha256: "a".repeat(64),
        }
    }
    fn fixture() -> ReleaseSet {
        let tag = "preview-runner-v0.5.1-plugin-v0.16.1";
        ReleaseSet {
            schema: SCHEMA.into(),
            release_tag: tag.into(),
            platform: "darwin-arm64".into(),
            development_only: true,
            protocol_version: "loomex.local-control/v2".into(),
            deployment: Deployment::CloudPreview {
                api_origin: "https://api.example.com/".into(),
            },
            components: Components {
                runner: Component {
                    version: "0.5.1".into(),
                    source_revision: "b".repeat(40),
                    repository: REPOSITORY.into(),
                    release_tag: tag.into(),
                    manifest_sha256: "c".repeat(64),
                    asset: a("runner.tar.gz", tag),
                },
                plugin: Component {
                    version: "0.16.1".into(),
                    source_revision: "d".repeat(40),
                    repository: "loomex-app/loomex-codex-plugin".into(),
                    release_tag: tag.into(),
                    manifest_sha256: "e".repeat(64),
                    asset: a("plugin.tar.gz", tag),
                },
            },
            evidence: Evidence {
                asset: a("compatibility.json", tag),
                backend_source_revision: "f".repeat(40),
                passed: true,
            },
            installer: a("loomex-install", tag),
        }
    }
    #[test]
    fn pair_and_preview_fail_closed() {
        let mut s = fixture();
        assert!(validate(&s).is_ok());
        s.components.plugin.release_tag = "latest".into();
        assert!(validate(&s).is_err());
        s = fixture();
        s.development_only = false;
        assert!(validate(&s).is_err());
        s = fixture();
        s.platform = "linux-x64".into();
        assert!(validate(&s).is_err());
        s = fixture();
        s.components.runner.asset.url = "https://evil.example/x".into();
        assert!(validate(&s).is_err());
        s = fixture();
        s.deployment = Deployment::CloudPreview {
            api_origin: "http://127.0.0.1:8000/".into(),
        };
        assert!(validate(&s).is_err());
    }
    #[test]
    fn current_release_names_preserve_frozen_urls_and_pair_binding() {
        let mut s = fixture();
        s.release_tag = s.release_tag.trim_start_matches("preview-").to_owned();
        for c in [&mut s.components.runner, &mut s.components.plugin] {
            c.release_tag = s.release_tag.clone();
            c.asset.url = format!(
                "https://github.com/{REPOSITORY}/releases/download/{}/{}",
                s.release_tag, c.asset.file
            );
        }
        for a in [&mut s.installer, &mut s.evidence.asset] {
            a.url = format!(
                "https://github.com/{REPOSITORY}/releases/download/{}/{}",
                s.release_tag, a.file
            );
        }
        validate(&s).unwrap();
        s.components.runner.release_tag = "runner-v9.9.9-plugin-v0.16.1".into();
        assert!(validate(&s).is_err());
    }

    #[test]
    fn deployment_profiles_are_discriminated_and_canonical() {
        let mut s = fixture();
        s.deployment = Deployment::LocalDevelopment {
            api_origin: "http://127.0.0.1:28080/".into(),
            web_app_origin: Value::Null,
        };
        assert!(validate(&s).is_ok());
        for raw in [
            "https://api.example.test/",
            "http://external.example/",
            "http://127.0.0.1:28080/path",
            "http://user@127.0.0.1:28080/",
            "http://127.0.0.1:28080",
        ] {
            assert!(deployment_origin(raw, true).is_err());
        }
        for raw in [
            "http://127.0.0.1:28080/",
            "https://127.0.0.1/",
            "https://api.example.test/path",
            "https://API.example.test/",
        ] {
            assert!(deployment_origin(raw, false).is_err());
        }
        for raw in [
            r#"{"profile":"local-development","apiOrigin":"http://127.0.0.1:28080/"}"#,
            r#"{"profile":"cloud-preview","apiOrigin":"https://api.example.test/","webAppOrigin":null}"#,
            r#"{"profile":"other","apiOrigin":"https://api.example.test/"}"#,
        ] {
            assert!(serde_json::from_str::<Deployment>(raw).is_err());
        }
    }
    #[test]
    fn malformed_schema() {
        assert!(
            serde_json::from_str::<ReleaseSet>(
                r#"{"schema":"app.loomex.release-set/v2","unexpected":true}"#
            )
            .is_err()
        );
    }
    #[test]
    fn digest_rejected() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("x");
        fs::write(&p, b"x").unwrap();
        assert!(verify_asset(&p, &a("x", "tag")).is_err());
    }
    #[test]
    fn paths_rejected() {
        for name in ["../x", "/x", "a/../x", "a\\x", "./x", "a//x", ""] {
            assert!(!safe_path(name));
        }
        assert!(safe_path("a/b"));
    }
    #[test]
    fn paired_namespaces_reject_aliases_and_owned_subtrees_without_writes() {
        let t = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(t.path()).unwrap();
        let runner = root.join("runner");
        let plugin = root.join("plugin");
        let state = root.join("runner-state");
        assert!(validate_install_namespaces(&runner, &plugin, &state).is_ok());
        assert!(validate_install_namespaces(&runner, &runner, &state).is_err());
        assert!(
            validate_install_namespaces(&runner, &root.join("missing/../runner"), &state).is_err()
        );
        for name in ["versions", "current"] {
            assert!(
                validate_install_namespaces(&runner, &runner.join(name).join("nested"), &state)
                    .is_err()
            );
        }
        for name in [
            "versions",
            "current",
            ".lifecycle-runtime",
            ".agents",
            "install-receipt.json",
            "lifecycle.json",
            "lifecycle.terminal.json",
            ".lifecycle.lock",
        ] {
            assert!(
                validate_install_namespaces(&plugin.join(name).join("nested"), &plugin, &state)
                    .is_err()
            );
        }
        assert!(validate_install_namespaces(&runner, &state.join("plugin"), &state).is_err());
        assert!(
            validate_install_namespaces(
                &runner,
                &root.join("state-parent"),
                &root.join("state-parent/runner-state")
            )
            .is_err()
        );
        assert!(validate_install_namespaces(&runner, &runner.join("unrelated"), &state).is_ok());
        assert_eq!(fs::read_dir(&root).unwrap().count(), 0);
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&root, root.join("alias")).unwrap();
            assert!(
                validate_install_namespaces(&runner, &root.join("alias/runner"), &state).is_err()
            );
            assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
        }
    }
    #[test]
    fn cache_preflight_reads_complete_exact_cache_without_repair() {
        let t = tempfile::tempdir().unwrap();
        let root = fs::canonicalize(t.path()).unwrap();
        let stage = root.join("stage");
        let cache = root.join("cache");
        fs::create_dir(&stage).unwrap();
        fs::write(stage.join("envelope"), b"same bytes").unwrap();
        assert_eq!(preflight_root(&stage, &cache).unwrap(), stage);
        assert!(!cache.exists());
        fs::create_dir(&cache).unwrap();
        // Incomplete artifacts carry no preflight authority.
        assert_eq!(preflight_root(&stage, &cache).unwrap(), stage);
        fs::copy(stage.join("envelope"), cache.join("envelope")).unwrap();
        let modified = fs::metadata(cache.join("envelope"))
            .unwrap()
            .modified()
            .unwrap();
        assert_eq!(preflight_root(&stage, &cache).unwrap(), cache);
        assert_eq!(
            fs::metadata(cache.join("envelope"))
                .unwrap()
                .modified()
                .unwrap(),
            modified
        );
        assert!(!cache.join(".incoming").exists());
        fs::write(cache.join("envelope"), b"different bytes").unwrap();
        assert!(preflight_root(&stage, &cache).is_err());
    }
    #[test]
    fn partial_completion_never_claims_failed_activation_installed() {
        let mut completion = Completion {
            phase: "runner-health",
            runner: "unconfirmed",
            ..Completion::default()
        };
        let report = failure_report(&completion);
        assert_eq!(report["completion"]["runner"], "unconfirmed");
        assert!(!report.to_string().contains("runner remains installed"));
        completion.phase = "plugin-activation";
        completion.runner = "healthy";
        completion.plugin = "unconfirmed";
        let report = failure_report(&completion);
        assert_eq!(report["completion"]["runner"], "healthy");
        assert_eq!(report["completion"]["plugin"], "unconfirmed");
        assert!(
            report["message"]
                .as_str()
                .unwrap()
                .contains("runner remains installed")
        );
    }
    #[test]
    fn owner_preflight_rejects_missing_or_false_eligibility() {
        for output in [
            r#"{"schema":"fixture","artifact":{"eligible":true},"activation":{"eligible":true}}"#,
            r#"{"schema":"fixture","artifact":{"eligible":true},"activation":{"eligible":false}}"#,
            r#"{"schema":"fixture"}"#,
        ] {
            let mut cmd = Command::new("/bin/sh");
            cmd.arg("-c")
                .arg("printf '%s' \"$1\"")
                .arg("fixture")
                .arg(output);
            assert_eq!(
                owner_preflight(&mut cmd, "fixture").is_ok(),
                output.contains(r#""activation":{"eligible":true}"#)
            );
        }
    }
    #[test]
    fn symlink_archive_rejected() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("evil.tar.gz");
        let gz = flate2::write::GzEncoder::new(
            fs::File::create(&p).unwrap(),
            flate2::Compression::default(),
        );
        let mut tar = tar::Builder::new(gz);
        let mut h = tar::Header::new_gnu();
        h.set_entry_type(tar::EntryType::Symlink);
        h.set_size(0);
        h.set_mode(0o777);
        h.set_link_name("/etc/passwd").unwrap();
        h.set_cksum();
        tar.append_data(&mut h, "link", std::io::empty()).unwrap();
        tar.into_inner().unwrap().finish().unwrap();
        assert!(extract(&p, &t.path().join("out")).is_err());
    }
}
