//! Transport/verifier only. Persistent mutations belong to existing lifecycle owners.
use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;
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

const SCHEMA: &str = "app.loomex.release-set/v1";
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
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReleaseSet {
    schema: String,
    release_tag: String,
    platform: String,
    development_only: bool,
    protocol_version: String,
    cloud_api_origin: String,
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
        "this installer supports explicitly unsigned preview sets only"
    );
    ensure!(
        s.protocol_version == "loomex.local-control/v2",
        "unsupported protocol"
    );
    let origin = Url::parse(&s.cloud_api_origin)?;
    ensure!(
        origin.scheme() == "https"
            && origin.host_str().is_some()
            && origin.username().is_empty()
            && origin.password().is_none()
            && origin.path() == "/"
            && origin.query().is_none()
            && origin.fragment().is_none(),
        "cloud API origin must be HTTPS without credentials, path, query or fragment"
    );
    let host = origin.host_str().unwrap();
    ensure!(
        host != "localhost" && host.parse::<std::net::IpAddr>().is_err(),
        "preview cloud origin must use a DNS host"
    );
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
fn verify_envelope(root: &Path, c: &Component) -> Result<Value> {
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
        let mut preview: Value = serde_json::from_slice(
            &fs::read(payload.join("metadata/preview-origin.json"))
                .context("cloud preview metadata missing")?,
        )?;
        ensure!(
            preview["schema"] == "app.loomex.runner.preview-origin/v1"
                && preview["sourceRevision"] == c.source_revision
                && preview["version"] == c.version,
            "preview metadata identity mismatch"
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
    let status = Command::new("/bin/bash")
        .arg(script)
        .arg(release)
        .args(args)
        .env("LOOMEX_ALLOW_UNSAFE_DEV_INSTALL", "1")
        .status()?;
    ensure!(
        status.success(),
        "lifecycle owner returned failure; retained state belongs to that owner"
    );
    Ok(())
}
fn execute_plan<F, G>(runner: F, plugin: Option<G>) -> Result<bool>
where
    F: FnOnce() -> Result<()>,
    G: FnOnce() -> Result<()>,
{
    runner()?;
    if let Some(install) = plugin {
        install().context("plugin installation incomplete; runner remains installed. Retry this exact release set to resume its lifecycle owner")?;
        return Ok(true);
    }
    Ok(false)
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
fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut manifest = None;
    let mut offline = None;
    let mut expected = None;
    let mut preview = false;
    let mut runner_only = false;
    let mut verify_only = false;
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
            "--allow-unsigned-preview" => {
                preview = true;
                i += 1
            }
            "--authorize-keychain-transition" => {
                authorize_keychain_transition = true;
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
                "usage: loomex-install (--manifest FILE | --offline DIR) --manifest-sha256 SHA256 --allow-unsigned-preview [--runner-only] [--runner-install-base DIR] [--plugin-install-base DIR]"
            ),
        }
    }
    ensure!(
        preview && std::env::var("LOOMEX_ALLOW_UNSAFE_DEV_INSTALL").as_deref() == Ok("1"),
        "unsigned preview requires --allow-unsigned-preview and LOOMEX_ALLOW_UNSAFE_DEV_INSTALL=1"
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
    let origin = verify_envelope(&runner, &s.components.runner)?;
    ensure!(
        origin["apiOrigin"] == s.cloud_api_origin,
        "preview origin differs from verified runner payload"
    );
    let plugin_contract = verify_envelope(&plugin, &s.components.plugin)?;
    evidence(
        &stage.path().join(&s.evidence.asset.file),
        &s,
        &origin,
        &plugin_contract,
    )?;
    if verify_only {
        println!(
            "Verified frozen paired preview artifacts and compatibility evidence; no lifecycle owner invoked."
        );
        return Ok(());
    }
    let home = PathBuf::from(std::env::var_os("HOME").context("HOME unavailable")?);
    ensure!(home.is_absolute(), "HOME must be absolute");
    let cache = cache
        .unwrap_or_else(|| home.join("Library/Caches/Loomex/release-sets"))
        .join(&expected);
    persist_cache(stage.path(), &cache)?;
    let runner = cache.join("runner");
    let plugin = cache.join("plugin");
    let mut plugin_base = home.join("Library/Application Support/Loomex/plugin");
    let mut runner_base = home.join("Library/Application Support/Loomex/runner");
    let mut runner_args = vec![
        "--allow-unsigned-development".into(),
        "--preview-api-origin".into(),
        s.cloud_api_origin.clone(),
    ];
    if authorize_keychain_transition {
        runner_args.push("--authorize-keychain-transition".into());
    }
    let mut plugin_args = vec!["--allow-unsigned-development".into()];
    for (key, value) in bases {
        if key == "--runner-install-base" {
            runner_base = PathBuf::from(&value);
            runner_args.extend(["--install-base".into(), value]);
        } else {
            plugin_base = PathBuf::from(&value);
            plugin_args.extend(["--install-base".into(), value]);
        }
    }
    let codex = find_codex();
    let has_codex = codex.is_some();
    if !runner_only && has_codex {
        check_marketplace(codex.as_deref().unwrap(), &plugin_base)?;
    }
    let plugin_action = if !runner_only {
        Some(|| {
            run_owner(&plugin.join("scripts/install.sh"), &plugin, &plugin_args)?;
            if has_codex {
                register_plugin(
                    codex.as_deref().unwrap(),
                    &plugin_base,
                    &s.components.plugin.version,
                )?;
            }
            Ok(())
        })
    } else {
        None
    };
    let installed = execute_plan(
        || {
            run_owner(&runner.join("scripts/install.sh"), &runner, &runner_args).with_context(||format!("Runner owner prerequisites retained at {}. Review this exact candidate before any explicit --authorize-keychain-transition retry; default installation does not authorize Keychain transitions",runner.display()))?;
            runner_health(&runner_base, &s.components.runner.version)?;
            Ok(())
        },
        plugin_action,
    )?;
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

    Ok(())
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
            cloud_api_origin: "https://api.example.com".into(),
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
        s.cloud_api_origin = "http://127.0.0.1:8000".into();
        assert!(validate(&s).is_err());
    }
    #[test]
    fn malformed_schema() {
        assert!(
            serde_json::from_str::<ReleaseSet>(
                r#"{"schema":"app.loomex.release-set/v1","unexpected":true}"#
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
    fn no_plugin_preserves_runner() {
        let calls = std::cell::Cell::new(0);
        let r = execute_plan(
            || {
                calls.set(calls.get() + 1);
                Ok(())
            },
            None::<fn() -> Result<()>>,
        )
        .unwrap();
        assert!(!r);
        assert_eq!(calls.get(), 1);
    }
    #[test]
    fn plugin_failure_does_not_roll_back_runner() {
        let calls = std::cell::Cell::new(0);
        let r = execute_plan(
            || {
                calls.set(1);
                Ok(())
            },
            Some(|| bail!("fixture failure")),
        );
        assert!(r.is_err());
        assert_eq!(calls.get(), 1);
        assert!(format!("{:#}", r.unwrap_err()).contains("runner remains installed"));
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
