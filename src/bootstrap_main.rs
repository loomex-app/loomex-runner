//! Release-bound installer bootstrap.
//!
//! This program is copied both into a release envelope and into the payload.
//! The shell launchers verify the envelope-bound copy and immediately `exec`
//! it.  It intentionally uses only the signed release bytes, macOS system
//! tools, and the runner's own Rust code; it never locates the source tree or
//! invokes Python, npm, or a provider CLI.
use anyhow::{Context, Result, bail};
use loomex_runner::{control, lifecycle, state};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Stdio,
};
use uuid::Uuid;

fn main() {
    if let Err(error) = entry() {
        eprintln!("{error:#}");
        std::process::exit(1);
    }
}

fn entry() -> Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(run())
}

#[derive(Default)]
struct Arguments {
    release: Option<PathBuf>,
    public_key: Option<PathBuf>,
    allow_unsigned_development: bool,
    development_api_origin: Option<String>,
    providers: Vec<String>,
    install_base: Option<PathBuf>,
    state_dir: Option<PathBuf>,
    launch_agents_dir: Option<PathBuf>,
}

fn usage() -> ! {
    eprintln!(
        "usage: loomex-lifecycle-bootstrap install RELEASE [--public-key FILE | --allow-unsigned-development --development-api-origin LOOPBACK_URL] [--provider-executable PROVIDER=/absolute/path] [--install-base DIR --state-dir DIR --launch-agents-dir DIR]\n       loomex-lifecycle-bootstrap uninstall [--install-base DIR --state-dir DIR --launch-agents-dir DIR]"
    );
    std::process::exit(2)
}

fn parse() -> (String, Arguments) {
    let mut values = std::env::args_os().skip(1);
    let command = values
        .next()
        .unwrap_or_else(|| usage())
        .to_string_lossy()
        .into_owned();
    let mut parsed = Arguments::default();
    if command == "install" {
        parsed.release = Some(PathBuf::from(values.next().unwrap_or_else(|| usage())));
    }
    while let Some(value) = values.next() {
        match value.to_string_lossy().as_ref() {
            "--public-key" => {
                parsed.public_key = Some(PathBuf::from(values.next().unwrap_or_else(|| usage())))
            }
            "--allow-unsigned-development" => parsed.allow_unsigned_development = true,
            "--development-api-origin" => {
                parsed.development_api_origin = Some(
                    values
                        .next()
                        .unwrap_or_else(|| usage())
                        .to_string_lossy()
                        .into_owned(),
                )
            }
            "--provider-executable" => parsed.providers.push(
                values
                    .next()
                    .unwrap_or_else(|| usage())
                    .to_string_lossy()
                    .into_owned(),
            ),
            "--install-base" => {
                parsed.install_base = Some(PathBuf::from(values.next().unwrap_or_else(|| usage())))
            }
            "--state-dir" => {
                parsed.state_dir = Some(PathBuf::from(values.next().unwrap_or_else(|| usage())))
            }
            "--launch-agents-dir" => {
                parsed.launch_agents_dir =
                    Some(PathBuf::from(values.next().unwrap_or_else(|| usage())))
            }
            _ => usage(),
        }
    }
    (command, parsed)
}

fn paths(args: &Arguments) -> Result<lifecycle::Paths> {
    let mut paths = lifecycle::Paths::from_environment()?;
    if let Some(value) = &args.install_base {
        paths.install_base = absolute(value)?;
    }
    if let Some(value) = &args.state_dir {
        paths.state_dir = absolute(value)?;
    }
    if let Some(value) = &args.launch_agents_dir {
        paths.launch_agents_dir = absolute(value)?;
    }
    paths.validate()?;
    Ok(paths)
}

fn absolute(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute() {
        bail!("lifecycle paths must be absolute")
    }
    if path.exists() {
        return Ok(fs::canonicalize(path)?);
    }
    let parent = path.parent().context("lifecycle path has no parent")?;
    Ok(fs::canonicalize(parent)?.join(path.file_name().context("lifecycle path has no name")?))
}

fn read_manifest(release: &Path) -> Result<Value> {
    let release = fs::canonicalize(release)?;
    let metadata = fs::symlink_metadata(&release)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        bail!("unsafe release directory")
    }
    let manifest = release.join("manifest.json");
    let bytes = fs::read(&manifest)?;
    let value: Value = serde_json::from_slice(&bytes)?;
    if value["schema"] != "app.loomex.release/v1"
        || value["project"] != "loomex-runner"
        || value["platform"] != "darwin-arm64"
        || value["version"].as_str().is_none()
        || value["payload"]["file"] != "payload.tar.gz"
        || value["payload"]["sha256"].as_str().is_none()
    {
        bail!("release manifest is invalid")
    }
    // Canonical JSON is part of the signature boundary.  This also prevents
    // accepting a parser-normalized duplicate-key representation.
    let mut canonical = serde_json::to_vec(&value)?;
    canonical.push(b'\n');
    if canonical != bytes {
        bail!("release manifest is not canonical")
    }
    Ok(value)
}

async fn verify_release(release: &Path, manifest: &Value, args: &Arguments) -> Result<()> {
    let development = manifest["developmentOnly"]
        .as_bool()
        .context("release class is invalid")?;
    if development {
        if !args.allow_unsigned_development
            || std::env::var_os("LOOMEX_ALLOW_UNSAFE_DEV_INSTALL").as_deref()
                != Some(std::ffi::OsStr::new("1"))
        {
            bail!("unsigned development release requires explicit opt-in")
        }
    } else {
        if args.allow_unsigned_development || args.development_api_origin.is_some() {
            bail!("production release rejects development options")
        }
        let key = args
            .public_key
            .as_ref()
            .context("production release requires --public-key")?;
        let signature = release.join("manifest.sig");
        if !signature.is_file() {
            bail!("production release signature is missing")
        }
        let status = tokio::process::Command::new("/usr/bin/openssl")
            .args(["dgst", "-sha256", "-verify"])
            .arg(key)
            .args(["-signature"])
            .arg(signature)
            .arg(release.join("manifest.json"))
            .status()
            .await?;
        if !status.success() {
            bail!("release signature verification failed")
        }
    }
    let archive = release.join(manifest["payload"]["file"].as_str().unwrap());
    if state::digest(&fs::read(&archive)?) != manifest["payload"]["sha256"].as_str().unwrap() {
        bail!("release payload digest mismatch")
    }
    Ok(())
}

fn parse_origin(value: &str) -> Result<String> {
    let url = url::Url::parse(value)?;
    if !matches!(url.scheme(), "http" | "https")
        || url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
        || !matches!(
            url.host_str(),
            Some("localhost") | Some("127.0.0.1") | Some("::1")
        )
    {
        bail!("development API origin must be a loopback root URL")
    }
    Ok(url.to_string())
}

fn inventory(root: &Path, expected: &[Value]) -> Result<()> {
    let mut actual = Vec::new();
    fn visit(root: &Path, dir: &Path, output: &mut Vec<Value>) -> Result<()> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let meta = fs::symlink_metadata(&path)?;
            if meta.file_type().is_symlink() {
                bail!("release payload contains a symlink")
            }
            if meta.is_dir() {
                visit(root, &path, output)?;
            } else if meta.is_file() {
                output.push(json!({"path":path.strip_prefix(root)?.to_string_lossy(),"sha256":state::digest(&fs::read(&path)?),"size":meta.len(),"mode":meta.permissions().mode() & 0o777}));
            } else {
                bail!("release payload contains an unsupported entry")
            }
        }
        Ok(())
    }
    visit(root, root, &mut actual)?;
    actual.sort_by(|a, b| a["path"].as_str().cmp(&b["path"].as_str()));
    if actual != expected {
        bail!("release payload inventory mismatch")
    }
    Ok(())
}

async fn extract(release: &Path, manifest: &Value, stage: &Path) -> Result<PathBuf> {
    fs::create_dir(stage)?;
    let archive = release.join(manifest["payload"]["file"].as_str().unwrap());
    let status = tokio::process::Command::new("/usr/bin/tar")
        .args(["-xzf"])
        .arg(archive)
        .arg("-C")
        .arg(stage)
        .stdin(Stdio::null())
        .status()
        .await?;
    if !status.success() {
        bail!("release extraction failed")
    }
    let expected = manifest["payload"]["files"]
        .as_array()
        .context("release inventory is invalid")?;
    inventory(stage, expected)?;
    validate_source_binding(stage, manifest)?;
    Ok(stage.to_path_buf())
}

fn validate_source_binding(payload: &Path, manifest: &Value) -> Result<()> {
    let binding = manifest["sourceContent"]
        .as_object()
        .context("release source provenance is missing")?;
    if binding.get("file").and_then(Value::as_str) != Some("metadata/source-content-manifest.json")
    {
        bail!("release source provenance is invalid")
    }
    let expected = binding
        .get("sha256")
        .and_then(Value::as_str)
        .context("release source provenance digest is missing")?;
    let bytes = fs::read(payload.join("metadata/source-content-manifest.json"))?;
    if state::digest(&bytes) != expected {
        bail!("release source provenance digest mismatch")
    }
    let value: Value = serde_json::from_slice(&bytes)?;
    let mut canonical = serde_json::to_vec(&value)?;
    canonical.push(b'\n');
    if canonical != bytes
        || value["schema"] != "app.loomex.source-content/v1"
        || value["sourceRevision"] != manifest["sourceRevision"]
    {
        bail!("release source provenance is invalid")
    }
    Ok(())
}

fn providers(values: &[String]) -> Result<BTreeMap<String, String>> {
    let mut result = BTreeMap::new();
    for value in values {
        let (name, path) = value
            .split_once('=')
            .context("invalid provider executable")?;
        let variable = match name {
            "codex" | "claude" | "gemini" | "antigravity" => name,
            _ => bail!("unknown provider executable"),
        };
        if result.contains_key(variable) {
            bail!("duplicate provider executable")
        }
        let candidate = PathBuf::from(path);
        let canonical = fs::canonicalize(&candidate)?;
        let meta = fs::metadata(&canonical)?;
        if !candidate.is_absolute()
            || candidate != canonical
            || !meta.is_file()
            || meta.permissions().mode() & 0o111 == 0
        {
            bail!("provider executable must be an absolute canonical executable")
        }
        result.insert(variable.into(), canonical.to_string_lossy().into_owned());
    }
    Ok(result)
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn render_plist(
    template: &Path,
    output: &Path,
    state_dir: &Path,
    daemon: &Path,
    origin: Option<&str>,
    providers: &BTreeMap<String, String>,
) -> Result<()> {
    let mut value = fs::read_to_string(template)?;
    let provider_entries = [
        ("codex", "LOOMEX_CODEX_EXECUTABLE"),
        ("claude", "LOOMEX_CLAUDE_EXECUTABLE"),
        ("gemini", "LOOMEX_GEMINI_EXECUTABLE"),
        ("antigravity", "LOOMEX_ANTIGRAVITY_EXECUTABLE"),
    ]
    .into_iter()
    .filter_map(|(key, env)| {
        providers
            .get(key)
            .map(|path| format!("<key>{env}</key><string>{}</string>", xml_escape(path)))
    })
    .collect::<String>();
    let origin_entry = origin
        .map(|v| {
            format!(
                "<key>LOOMEX_DEV_API_ORIGIN</key><string>{}</string>",
                xml_escape(v)
            )
        })
        .unwrap_or_default();
    for (token, replacement) in [
        ("__LOOMEX_DAEMON__", xml_escape(&daemon.to_string_lossy())),
        (
            "__LOOMEX_STATE_DIR__",
            xml_escape(&state_dir.to_string_lossy()),
        ),
        ("__LOOMEX_DEV_API_ORIGIN_ENTRY__", origin_entry),
        ("__LOOMEX_PROVIDER_EXECUTABLE_ENTRIES__", provider_entries),
    ] {
        value = value.replace(token, &replacement);
    }
    if value.contains("__LOOMEX_") {
        bail!("LaunchAgent template is invalid")
    }
    atomic_write_owned(output, value.as_bytes())
}

fn atomic_write_owned(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("missing output parent")?;
    fs::create_dir_all(parent)?;
    let temporary = parent.join(format!(
        ".{}.{}.new",
        path.file_name().unwrap().to_string_lossy(),
        Uuid::new_v4()
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

async fn install(args: Arguments) -> Result<()> {
    let release = fs::canonicalize(args.release.as_ref().context("release is required")?)?;
    let manifest = read_manifest(&release)?;
    verify_release(&release, &manifest, &args).await?;
    let paths = paths(&args)?;
    let version = manifest["version"].as_str().unwrap();
    let origin = if manifest["developmentOnly"] == true {
        Some(parse_origin(
            args.development_api_origin
                .as_deref()
                .context("development release requires --development-api-origin")?,
        )?)
    } else {
        None
    };
    let mut providers = providers(&args.providers)?;
    // Updating a running installation without provider flags preserves the
    // existing, receipt-bound executable selection.  This prevents a retry or
    // routine update from silently dropping a daemon's provider binding.
    if providers.is_empty() {
        let receipt_path = paths.state_dir.join("install-receipt.json");
        if receipt_path.exists() {
            let receipt: Value = state::read_json(&receipt_path)?;
            if let Some(existing) = receipt["providerExecutables"].as_object() {
                for (name, value) in existing {
                    let path = value
                        .as_str()
                        .context("invalid receipt provider executable")?;
                    if !matches!(name.as_str(), "codex" | "claude" | "gemini" | "antigravity")
                        || !Path::new(path).is_absolute()
                        || fs::canonicalize(path)? != Path::new(path)
                    {
                        bail!("invalid receipt provider executable")
                    }
                    providers.insert(name.clone(), path.into());
                }
            }
        }
    }
    let target = paths.install_base.join("versions").join(version);
    let manifest_digest = state::digest(&fs::read(release.join("manifest.json"))?);
    let bootstrap_journal = paths.state_dir.join("bootstrap-install.json");
    let configuration = json!({"schema":"app.loomex.runner.bootstrap-install/v1","version":version,"target":target,"manifestSha256":manifest_digest,"developmentApiOrigin":origin,"providerExecutables":providers});
    // One guard covers preflight, staging, inventory and service activation.
    // No competing lifecycle writer can change the namespace between those
    // observations and mutations.
    let _lifecycle_lock = lifecycle::LifecycleLock::acquire(&paths)?;
    if bootstrap_journal.exists() && state::read_json::<Value>(&bootstrap_journal)? != configuration
    {
        bail!("LIFECYCLE_OPERATION_CONFIGURATION_MISMATCH")
    }
    let preflight = lifecycle::preflight_package_locked(
        &paths,
        lifecycle::OperationKind::Update,
        lifecycle::PackageIdentity {
            version: version.into(),
            target: target.clone(),
            manifest_sha256: manifest_digest.clone(),
        },
    )
    .await?;
    if preflight["pending"] == true {
        // The matching native transaction retained the staged package and
        // rollback/update intent.  It has not activated, so do not write a
        // receipt or report installation success.
        println!("Loomex runner update is pending until active work completes.");
        return Ok(());
    }
    if preflight["reconciled"] == true {
        // The native transaction already reached verified completion.  Finish
        // only the bootstrap-owned receipt; do not restage or activate a
        // second time.
        let bootstrap = target.join("bin/loomex-lifecycle-bootstrap");
        let metadata = fs::symlink_metadata(&bootstrap)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            bail!("installed lifecycle bootstrap is invalid")
        }
        state::write_json(
            &paths.state_dir.join("install-receipt.json"),
            &json!({"schema":"app.loomex.runner.install-receipt/v2","version":version,"versionPath":target,"launchAgent":paths.launch_agents_dir.join("app.loomex.runner.plist"),"bootstrapSha256":state::digest(&fs::read(bootstrap)?),"developmentOnly":manifest["developmentOnly"],"developmentApiOrigin":origin,"providerExecutables":providers}),
        )?;
        remove_regular(&bootstrap_journal)?;
        println!("Installed and activated Loomex runner {version}");
        return Ok(());
    }
    fs::create_dir_all(paths.install_base.join("versions"))?;
    fs::create_dir_all(&paths.launch_agents_dir)?;
    state::write_json(&bootstrap_journal, &configuration)?;
    let stage = paths
        .install_base
        .join(format!(".stage.{}", Uuid::new_v4()));
    let staged_plist = async {
        let payload = extract(&release, &manifest, &stage).await?;
        let project: Value =
            serde_json::from_slice(&fs::read(payload.join("metadata/project.json"))?)?;
        if project["project"] != "loomex-runner"
            || project["version"] != version
            || project["platform"] != "darwin-arm64"
        {
            bail!("release project metadata mismatch")
        }
        if target.exists() {
            inventory(&target, manifest["payload"]["files"].as_array().unwrap())?;
        } else {
            fs::rename(&payload, &target)?;
            File::open(paths.install_base.join("versions"))?.sync_all()?;
        }
        let owned = paths.state_dir.join("owned-versions.json");
        let mut owned_value = if owned.exists() {
            state::read_json::<Value>(&owned)?
        } else {
            json!({"schema":"app.loomex.runner.owned-versions/v1","paths":[],"inventories":[]})
        };
        let mut entries = owned_value["paths"]
            .as_array()
            .cloned()
            .context("invalid owned versions inventory")?;
        if !entries
            .iter()
            .any(|v| v.as_str() == Some(target.to_string_lossy().as_ref()))
        {
            entries.push(json!(target));
        }
        let inventories = owned_value["inventories"]
            .as_array_mut()
            .context("invalid owned version inventory")?;
        inventories
            .retain(|entry| entry["path"].as_str() != Some(target.to_string_lossy().as_ref()));
        inventories.push(json!({"path":target,"files":manifest["payload"]["files"]}));
        owned_value["paths"] = json!(entries);
        state::write_json(&owned, &owned_value)?;
        let staged_plist = stage.join("app.loomex.runner.plist");
        render_plist(
            &target.join("launchd/app.loomex.runner.template.plist"),
            &staged_plist,
            &paths.state_dir,
            &paths.install_base.join("current/bin/loomex-runner"),
            origin.as_deref(),
            &providers,
        )?;
        Ok(staged_plist)
    }
    .await;
    let result = async {
        let staged_plist = staged_plist?;
        let activation = lifecycle::activate_locked(
            &paths,
            target.clone(),
            version.into(),
            manifest_digest,
            staged_plist,
        )
        .await?;
        if activation["pending"] == true {
            println!("Loomex runner update is pending until active work completes.");
            return Ok::<bool, anyhow::Error>(false);
        }
        let bootstrap = target.join("bin/loomex-lifecycle-bootstrap");
        let bootstrap_metadata = fs::symlink_metadata(&bootstrap)?;
        if !bootstrap_metadata.is_file() || bootstrap_metadata.file_type().is_symlink() {
            bail!("installed lifecycle bootstrap is invalid")
        }
        state::write_json(&paths.state_dir.join("install-receipt.json"), &json!({"schema":"app.loomex.runner.install-receipt/v2","version":version,"versionPath":target,"launchAgent":paths.launch_agents_dir.join("app.loomex.runner.plist"),"bootstrapSha256":state::digest(&fs::read(bootstrap)?),"developmentOnly":manifest["developmentOnly"],"developmentApiOrigin":origin,"providerExecutables":providers}))?;
        remove_regular(&bootstrap_journal)?;
        Ok::<bool, anyhow::Error>(true)
    }.await;
    let _ = fs::remove_dir_all(&stage);
    if result? {
        println!("Installed and activated Loomex runner {version}");
    }
    Ok(())
}

async fn uninstall(args: Arguments) -> Result<()> {
    let paths = paths(&args)?;
    let _lock = lifecycle::LifecycleLock::acquire(&paths)?;
    let journal_path = paths.state_dir.join("bootstrap-uninstall.json");
    let mut journal: Value = if journal_path.exists() {
        let value: Value = state::read_json(&journal_path)?;
        if value["schema"] != "app.loomex.runner.bootstrap-uninstall/v1"
            || !matches!(value["phase"].as_str(), Some("prepared") | Some("revoked"))
            || value["helper"].as_str().is_none()
            || value["helperSha256"].as_str().is_none()
            || !value["inventories"].is_array()
        {
            bail!("invalid bootstrap uninstall journal")
        }
        value
    } else {
        let receipt: Value = state::read_json(&paths.state_dir.join("install-receipt.json"))
            .context("owned installation receipt is required")?;
        let owned: Value = state::read_json(&paths.state_dir.join("owned-versions.json"))
            .context("owned version inventory is required")?;
        validate_owned_installation(&paths, &receipt, &owned, false)?;
        let helper = paths.state_dir.join("bootstrap-uninstall-helper");
        let bootstrap = PathBuf::from(
            receipt["versionPath"]
                .as_str()
                .context("owned installation receipt has no version path")?,
        )
        .join("bin/loomex-lifecycle-bootstrap");
        let expected = receipt["bootstrapSha256"]
            .as_str()
            .context("owned installation receipt has no bootstrap digest")?;
        let metadata = fs::symlink_metadata(&bootstrap)?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || state::digest(&fs::read(&bootstrap)?) != expected
        {
            bail!("installed lifecycle bootstrap is invalid")
        }
        state::atomic_write(&helper, &fs::read(&bootstrap)?)?;
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o700))?;
        let value = json!({
            "schema":"app.loomex.runner.bootstrap-uninstall/v1",
            "phase":"prepared",
            "receipt":receipt,
            "paths":owned["paths"],
            "inventories":owned["inventories"].clone(),
            "helper":helper,
            "helperSha256":expected,
        });
        state::write_json(&journal_path, &value)?;
        value
    };
    let journal_owned = json!({"schema":"app.loomex.runner.owned-versions/v1","paths":journal["paths"],"inventories":journal["inventories"]});
    validate_owned_installation(
        &paths,
        &journal["receipt"],
        &journal_owned,
        journal["phase"] == "revoked",
    )?;
    if journal["phase"] == "revoked" {
        return cleanup_owned_installation(&paths, &journal);
    }
    let test_mode = std::env::var_os("LOOMEX_INSTALL_TEST_MODE").is_some();
    if !test_mode {
        control::client(
            &paths.state_dir,
            "daemon.drain",
            json!({"idempotencyKey":Uuid::new_v4()}),
        )
        .await?;
        let status = control::client(&paths.state_dir, "status.get", json!({})).await?;
        if status["result"]["activeJobs"].as_u64() != Some(0) {
            bail!("uninstall deferred while runner jobs remain")
        }
    }
    if !test_mode {
        let uid = unsafe { libc::geteuid() };
        let status = tokio::process::Command::new("/bin/launchctl")
            .arg("bootout")
            .arg(format!("gui/{uid}/app.loomex.runner"))
            .status()
            .await?;
        if !status.success() && !bootstrap_label_absent().await? {
            bail!("runner LaunchAgent could not be stopped")
        }
        if !bootstrap_label_absent().await? {
            bail!("runner LaunchAgent remains loaded")
        }
    }
    if !test_mode {
        control::offline_logout(&paths.state_dir).await?;
    }
    journal["phase"] = json!("revoked");
    state::write_json(&journal_path, &journal)?;
    cleanup_owned_installation(&paths, &journal)
}

fn validate_owned_installation(
    paths: &lifecycle::Paths,
    receipt: &Value,
    owned: &Value,
    allow_missing: bool,
) -> Result<()> {
    let expected_agent = paths.launch_agents_dir.join("app.loomex.runner.plist");
    if receipt["schema"] != "app.loomex.runner.install-receipt/v2"
        || receipt["launchAgent"].as_str() != Some(expected_agent.to_string_lossy().as_ref())
    {
        bail!("invalid owned installation receipt")
    }
    let versions = fs::canonicalize(paths.install_base.join("versions"))?;
    let entries = owned["paths"]
        .as_array()
        .context("invalid owned version inventory")?;
    if owned["schema"] != "app.loomex.runner.owned-versions/v1" || entries.is_empty() {
        bail!("invalid owned version inventory")
    }
    for value in entries {
        let path = PathBuf::from(value.as_str().context("invalid owned version path")?);
        let file_name = path.file_name().and_then(|v| v.to_str());
        let semver = file_name.is_some_and(|v| {
            let parts: Vec<_> = v.split('.').collect();
            parts.len() == 3
                && parts
                    .iter()
                    .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
        });
        if !path.is_absolute()
            || !semver
            || fs::canonicalize(path.parent().context("invalid owned version path")?)? != versions
        {
            bail!("unsafe owned version path")
        }
        match fs::symlink_metadata(&path) {
            Ok(metadata) if !metadata.file_type().is_symlink() && metadata.is_dir() => {
                lifecycle::verify_owned_version_from_inventory(&path, owned)?;
            }
            Err(error) if allow_missing && error.kind() == std::io::ErrorKind::NotFound => {}
            _ => bail!("unsafe owned version path"),
        }
    }
    Ok(())
}

async fn bootstrap_label_absent() -> Result<bool> {
    let uid = unsafe { libc::geteuid() };
    for _ in 0..20 {
        let status = tokio::process::Command::new("/bin/launchctl")
            .arg("print")
            .arg(format!("gui/{uid}/app.loomex.runner"))
            .status()
            .await?;
        if !status.success() {
            return Ok(true);
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    Ok(false)
}

fn cleanup_owned_installation(paths: &lifecycle::Paths, journal: &Value) -> Result<()> {
    // Resume uses the inventory captured in the revoked journal, rather than
    // reconstructing ownership from mutable state that may already have been
    // removed by an earlier cleanup attempt.
    let owned = json!({
        "schema":"app.loomex.runner.owned-versions/v1",
        "paths":journal["paths"],
        "inventories":journal["inventories"],
    });
    validate_owned_installation(paths, &journal["receipt"], &owned, true)?;
    for value in journal["paths"].as_array().unwrap() {
        // A prior attempt may have removed an owned version and then crashed
        // before checkpointing the rest of cleanup.  The journal remains the
        // authority for the exact deletion set, so an absent path is a
        // reconciled effect; any present path was validated above.
        match fs::remove_dir_all(PathBuf::from(value.as_str().unwrap())) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    if std::env::var_os("LOOMEX_TEST_UNINSTALL_FAIL_AFTER_PAYLOAD").is_some() {
        bail!("injected uninstall failure after payload deletion")
    }
    let agent = paths.launch_agents_dir.join("app.loomex.runner.plist");
    match fs::symlink_metadata(&agent) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            fs::remove_file(&agent)?
        }
        Ok(_) => bail!("unsafe runner LaunchAgent"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    // The uninstall journal is now revoked, so lifecycle recovery resources
    // have reached a verified terminal boundary and may be released.
    lifecycle::remove_operation_resources_after_uninstall(paths)?;
    for name in [
        "drain.json",
        "pending-update.json",
        "control.sock",
        "daemon.lock",
    ] {
        let path = paths.state_dir.join(name);
        if path.exists() && !fs::symlink_metadata(&path)?.file_type().is_symlink() {
            fs::remove_file(path)?;
        }
    }
    // Keep the verified bootstrap reachable through `current` until all
    // journal/state cleanup has succeeded. A failure above is therefore
    // resumable with the same native helper.
    let current = paths.install_base.join("current");
    if current.exists() || current.is_symlink() {
        if !current.is_symlink() {
            bail!("unsafe runner current pointer")
        }
        fs::remove_file(current)?;
    }
    // Receipt and journal deliberately remain available through current/helper
    // validation and removal, so a failure at either boundary has a trusted
    // launcher path on the next invocation.
    let helper = PathBuf::from(
        journal["helper"]
            .as_str()
            .context("uninstall helper is missing")?,
    );
    if helper.parent() != Some(paths.state_dir.as_path())
        || helper.file_name().and_then(|name| name.to_str()) != Some("bootstrap-uninstall-helper")
        || state::digest(&fs::read(&helper)?) != journal["helperSha256"]
    {
        bail!("uninstall helper is invalid")
    }
    for name in ["lifecycle-operation.json", "install-receipt.json"] {
        let path = paths.state_dir.join(name);
        if path.exists() && !fs::symlink_metadata(&path)?.file_type().is_symlink() {
            fs::remove_file(path)?;
        }
    }
    if std::env::var_os("LOOMEX_TEST_UNINSTALL_FAIL_AFTER_RECEIPT_REMOVAL").is_some() {
        bail!("injected uninstall failure after receipt removal")
    }
    let owned = paths.state_dir.join("owned-versions.json");
    if owned.exists() && !fs::symlink_metadata(&owned)?.file_type().is_symlink() {
        fs::remove_file(owned)?;
    }
    // Seal a terminal marker before dropping the resumable journal.  It binds
    // the exact helper digest and operation record for a crash after journal
    // removal but before helper unlink.
    let marker = paths.state_dir.join("bootstrap-uninstall-terminal.json");
    let mut terminal = journal.clone();
    terminal["phase"] = json!("terminal");
    state::write_json(&marker, &terminal)?;
    let journal_path = paths.state_dir.join("bootstrap-uninstall.json");
    if journal_path.exists()
        && !fs::symlink_metadata(&journal_path)?
            .file_type()
            .is_symlink()
    {
        fs::remove_file(journal_path)?;
    }
    if std::env::var_os("LOOMEX_TEST_UNINSTALL_FAIL_AFTER_JOURNAL_REMOVAL").is_some() {
        bail!("injected uninstall failure after journal removal")
    }
    // This is the final fallible mutation. All journal/current metadata is
    // terminal before the out-of-payload helper is unlinked.
    remove_regular(&helper)?;
    if std::env::var_os("LOOMEX_TEST_UNINSTALL_FAIL_AFTER_HELPER_UNLINK").is_some() {
        bail!("injected uninstall failure after terminal helper unlink")
    }
    remove_regular(&marker)?;
    println!("Revoked Loomex credentials and removed only the inventoried runner files and state.");
    Ok(())
}

fn remove_regular(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        bail!("unsafe lifecycle helper")
    }
    fs::remove_file(path)?;
    Ok(())
}

async fn run() -> Result<()> {
    let (command, args) = parse();
    match command.as_str() {
        "install" => install(args).await,
        "uninstall" => uninstall(args).await,
        _ => usage(),
    }
}
