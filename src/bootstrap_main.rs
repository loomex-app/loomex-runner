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
#[path = "bootstrap_preflight.rs"]
mod bootstrap_preflight;
#[path = "bootstrap_uninstall.rs"]
mod bootstrap_uninstall;
#[path = "uninstall_state.rs"]
mod uninstall_state;

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
    preview_api_origin: Option<String>,
    providers: Vec<String>,
    install_base: Option<PathBuf>,
    state_dir: Option<PathBuf>,
    launch_agents_dir: Option<PathBuf>,
    settled_abandonment: Option<Uuid>,
    authorize_keychain_transition: bool,
    expected_old_journal_sha256: Option<String>,
}

fn usage() -> ! {
    eprintln!(
        "usage: loomex-lifecycle-bootstrap install RELEASE [--public-key FILE | --allow-unsigned-development (--development-api-origin LOOPBACK_URL | --preview-api-origin HTTPS_URL)] [--authorize-keychain-transition] [--settled-abandonment UUID] [--provider-executable PROVIDER=/absolute/path] [--install-base DIR --state-dir DIR --launch-agents-dir DIR]\n       loomex-lifecycle-bootstrap uninstall [--install-base DIR --state-dir DIR --launch-agents-dir DIR]\n       loomex-lifecycle-bootstrap preflight RELEASE [install options]\n       loomex-lifecycle-bootstrap recover-uninstall RELEASE --expected-old-journal-sha256 SHA256 [release verification and path options]"
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
    if matches!(
        command.as_str(),
        "install" | "preflight" | "recover-uninstall"
    ) {
        parsed.release = Some(PathBuf::from(values.next().unwrap_or_else(|| usage())));
    }
    while let Some(value) = values.next() {
        match value.to_string_lossy().as_ref() {
            "--settled-abandonment" => {
                if command != "install" || parsed.settled_abandonment.is_some() {
                    usage();
                }
                parsed.settled_abandonment = Some(
                    Uuid::parse_str(&values.next().unwrap_or_else(|| usage()).to_string_lossy())
                        .unwrap_or_else(|_| usage()),
                );
            }
            "--expected-old-journal-sha256" => {
                if command != "recover-uninstall" || parsed.expected_old_journal_sha256.is_some() {
                    usage();
                }
                parsed.expected_old_journal_sha256 = Some(
                    values
                        .next()
                        .unwrap_or_else(|| usage())
                        .to_string_lossy()
                        .into_owned(),
                );
            }
            "--public-key" => {
                parsed.public_key = Some(PathBuf::from(values.next().unwrap_or_else(|| usage())))
            }
            "--allow-unsigned-development" => parsed.allow_unsigned_development = true,
            "--authorize-keychain-transition" => {
                if !matches!(
                    command.as_str(),
                    "install" | "preflight" | "recover-uninstall"
                ) || parsed.authorize_keychain_transition
                {
                    usage();
                }
                parsed.authorize_keychain_transition = true;
            }
            "--development-api-origin" => {
                parsed.development_api_origin = Some(
                    values
                        .next()
                        .unwrap_or_else(|| usage())
                        .to_string_lossy()
                        .into_owned(),
                )
            }
            "--preview-api-origin" => {
                if !matches!(
                    command.as_str(),
                    "install" | "preflight" | "recover-uninstall"
                ) || parsed.preview_api_origin.is_some()
                {
                    usage();
                }
                parsed.preview_api_origin = Some(
                    values
                        .next()
                        .unwrap_or_else(|| usage())
                        .to_string_lossy()
                        .into_owned(),
                );
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
        if args.allow_unsigned_development
            || args.development_api_origin.is_some()
            || args.preview_api_origin.is_some()
            || args.authorize_keychain_transition
        {
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

fn stable_development_requirement(requirement: &str, name: &str) -> bool {
    let prefix = format!("identifier \"app.loomex.runner.{name}\" and ");
    let Some(policy) = requirement.strip_prefix(&prefix) else {
        return false;
    };
    if requirement.contains("cdhash ") {
        return false;
    }
    if policy.starts_with("anchor ") {
        return true;
    }
    // Keychain Access emits this designated requirement for a self-signed
    // Code Signing identity. The certificate hash pins the signer across
    // rebuilds while leaving system and user trust settings unchanged.
    policy
        .strip_prefix("certificate leaf = H\"")
        .and_then(|hash| hash.strip_suffix('"'))
        .is_some_and(|hash| hash.len() == 40 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

fn signing_requirement(binary: &Path) -> Result<Option<String>> {
    let verified = std::process::Command::new("/usr/bin/codesign")
        .args(["--verify", "--strict"])
        .arg(binary)
        .stdin(Stdio::null())
        .output()?;
    if !verified.status.success() {
        bail!("development code signature is invalid")
    }
    let details = std::process::Command::new("/usr/bin/codesign")
        .args(["-dv", "--verbose=4"])
        .arg(binary)
        .stdin(Stdio::null())
        .output()?;
    if !details.status.success() {
        bail!("development code signature is unavailable")
    }
    let ad_hoc = String::from_utf8_lossy(&details.stderr).contains("Signature=adhoc");
    let output = std::process::Command::new("/usr/bin/codesign")
        .args(["-dr", "-"])
        .arg(binary)
        .stdin(Stdio::null())
        .output()?;
    if !output.status.success() {
        bail!("development designated requirement is unavailable")
    }
    let display = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let requirements = display
        .lines()
        .filter_map(|line| {
            line.strip_prefix("designated => ")
                .or_else(|| line.strip_prefix("# designated => "))
        })
        .collect::<Vec<_>>();
    if requirements.len() != 1 {
        bail!("development designated requirement is invalid")
    }
    if ad_hoc {
        return Ok(None);
    }
    let requirement = requirements[0];
    let name = binary
        .file_name()
        .and_then(|name| name.to_str())
        .context("development binary name is invalid")?;
    if !stable_development_requirement(requirement, name) {
        bail!("development designated requirement is not stable")
    }
    Ok(Some(requirement.to_owned()))
}

async fn credential_probe(binary: &Path, interactive: bool) -> Result<()> {
    let flag = if interactive {
        "--credential-store-authorize"
    } else {
        "--credential-store-probe"
    };
    let child = tokio::process::Command::new(binary)
        .arg(flag)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .output();
    let budget = if interactive { 120 } else { 4 };
    let result = tokio::time::timeout(std::time::Duration::from_secs(budget), child)
        .await
        .map_err(|_| anyhow::anyhow!("credential authorization probe timed out"))??;
    if !result.status.success() || result.stdout != b"AUTHORIZED\n" {
        bail!("credential authorization probe did not succeed")
    }
    Ok(())
}

#[derive(PartialEq, Eq, Debug)]
enum SigningTransition {
    Ready,
    ForegroundAuthorizationRequired,
}

fn signing_transition(
    previous: Option<&str>,
    candidate: Option<&str>,
    same_binary: bool,
    authorize_transition: bool,
) -> Result<SigningTransition> {
    match (previous, candidate) {
        (Some(old), Some(new)) if old == new && !authorize_transition => {
            Ok(SigningTransition::Ready)
        }
        (None, None) if same_binary && !authorize_transition => Ok(SigningTransition::Ready),
        (None, Some(_)) if authorize_transition => {
            Ok(SigningTransition::ForegroundAuthorizationRequired)
        }
        _ => bail!("development signing identity changed; upgrade refused"),
    }
}

async fn verify_development_signing(
    payload: &Path,
    paths: &lifecycle::Paths,
    args: &Arguments,
) -> Result<()> {
    let metadata = payload.join("metadata/development-signing.json");
    let candidate = payload.join("bin/loomex-runner");
    let candidate_requirement = signing_requirement(&candidate)?;
    if metadata.exists() {
        let bytes = fs::read(&metadata)?;
        let value: Value = serde_json::from_slice(&bytes)?;
        let mut canonical = serde_json::to_vec(&value)?;
        canonical.push(b'\n');
        if bytes != canonical || value["schema"] != "app.loomex.runner.development-signing/v1" {
            bail!("development signing manifest is invalid")
        }
        let requirements = value["requirements"]
            .as_object()
            .context("development signing requirements are missing")?;
        if requirements.len() != 3 {
            bail!("development signing requirements are incomplete")
        }
        for name in ["loomex", "loomex-runner", "loomex-lifecycle-bootstrap"] {
            let expected = requirements
                .get(name)
                .and_then(Value::as_str)
                .context("development signing requirement is missing")?;
            if signing_requirement(&payload.join("bin").join(name))?.as_deref() != Some(expected)
                || !expected.contains(&format!("identifier \"app.loomex.runner.{name}\""))
            {
                bail!("development signing requirement does not match package")
            }
        }
    } else if candidate_requirement.is_some() {
        bail!("signed development package lacks signing manifest")
    }
    let current = paths.install_base.join("current");
    if fs::symlink_metadata(&current).is_err() {
        if args.authorize_keychain_transition {
            bail!("credential transition requires an installed daemon")
        }
        return Ok(());
    }
    let previous = current.join("bin/loomex-runner");
    let previous_requirement = signing_requirement(&previous)?;
    match signing_transition(
        previous_requirement.as_deref(),
        candidate_requirement.as_deref(),
        fs::read(&previous)? == fs::read(&candidate)?,
        args.authorize_keychain_transition,
    )? {
        SigningTransition::Ready => {}
        SigningTransition::ForegroundAuthorizationRequired => {
            credential_probe(&candidate, true).await?;
            credential_probe(&candidate, false).await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod signing_tests {
    use super::*;

    #[test]
    fn self_signed_requirement_pins_exact_certificate_and_identifier() {
        let hash = "3a552832d7ae3cced399130fe1fa5b0f26a417c5";
        let requirement = format!(
            "identifier \"app.loomex.runner.loomex-runner\" and certificate leaf = H\"{hash}\""
        );
        assert!(stable_development_requirement(
            &requirement,
            "loomex-runner"
        ));
        assert!(!stable_development_requirement(&requirement, "loomex"));
        for invalid in [
            "identifier \"app.loomex.runner.loomex-runner\" and cdhash H\"1234\"",
            "identifier \"app.loomex.runner.loomex-runner\" and certificate leaf = H\"1234\"",
            "identifier \"app.loomex.runner.loomex-runner\" and certificate leaf = H\"3a552832d7ae3cced399130fe1fa5b0f26a417c5\" or true",
            "identifier \"wrong\" and certificate leaf = H\"3a552832d7ae3cced399130fe1fa5b0f26a417c5\"",
        ] {
            assert!(!stable_development_requirement(invalid, "loomex-runner"));
        }
    }

    #[test]
    fn signed_upgrade_requires_the_exact_same_designated_requirement() {
        let pinned = "identifier \"app.loomex.runner.loomex-runner\" and certificate leaf = H\"3a552832d7ae3cced399130fe1fa5b0f26a417c5\"";
        let changed = "identifier \"app.loomex.runner.loomex-runner\" and certificate leaf = H\"4a552832d7ae3cced399130fe1fa5b0f26a417c5\"";
        assert_eq!(
            signing_transition(Some(pinned), Some(pinned), false, false).unwrap(),
            SigningTransition::Ready
        );
        assert!(signing_transition(Some(pinned), Some(changed), false, true).is_err());
        assert_eq!(
            signing_transition(
                Some("identifier daemon and anchor A"),
                Some("identifier daemon and anchor A"),
                false,
                false
            )
            .unwrap(),
            SigningTransition::Ready
        );
        assert!(
            signing_transition(
                Some("identifier daemon and anchor A"),
                Some("identifier daemon and anchor B"),
                false,
                true
            )
            .is_err()
        );
        assert!(
            signing_transition(Some("identifier daemon and anchor A"), None, false, false).is_err()
        );
    }

    #[test]
    fn ad_hoc_upgrade_needs_explicit_foreground_transition() {
        assert!(signing_transition(None, None, false, false).is_err());
        assert_eq!(
            signing_transition(None, None, true, false).unwrap(),
            SigningTransition::Ready
        );
        assert!(
            signing_transition(None, Some("identifier daemon and anchor A"), false, false).is_err()
        );
        assert_eq!(
            signing_transition(None, Some("identifier daemon and anchor A"), false, true).unwrap(),
            SigningTransition::ForegroundAuthorizationRequired
        );
    }
}

fn parse_origin(value: &str) -> Result<String> {
    let url = url::Url::parse(value)?;
    let host = url.host_str();
    if !matches!(url.scheme(), "http" | "https")
        || url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
        || !matches!(host, Some("localhost") | Some("127.0.0.1") | Some("::1"))
            && !host.is_some_and(|hostname| hostname.ends_with(".localhost"))
    {
        bail!("development API origin must be a loopback root URL")
    }
    Ok(url.to_string())
}

fn parse_preview_origin(value: &str) -> Result<String> {
    let url = url::Url::parse(value)?;
    let raw_authority = value
        .strip_prefix("https://")
        .map(|rest| rest.split_once('/').unwrap_or((rest, "")));
    if value.chars().any(char::is_whitespace)
        || value.contains(['\\', '@'])
        || raw_authority.is_none_or(|(_, path)| !path.is_empty())
        || url.scheme() != "https"
        || url.host().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
        || url.port() == Some(0)
    {
        bail!("preview API origin must be an HTTPS root URL without credentials")
    }
    Ok(url.to_string())
}

fn validate_preview_identity(
    manifest: &Value,
    compiled_revision: Option<&str>,
    compiled_version: &str,
) -> Result<()> {
    if manifest["version"] != compiled_version
        || manifest["sourceRevision"].as_str() != compiled_revision
        || compiled_revision.is_none()
    {
        bail!("preview release does not match bootstrap source identity")
    }
    Ok(())
}

// Called only after extracting and verifying the exact envelope inventory and
// source-content binding. A preview uses its compiled service origin, never the
// generic loopback-only runtime development override.
fn development_origin(
    payload: &Path,
    manifest: &Value,
    args: &Arguments,
    compiled_origin: Option<&str>,
) -> Result<Option<String>> {
    let metadata = payload.join("metadata/preview-origin.json");
    if !metadata.exists() {
        if args.preview_api_origin.is_some() {
            bail!("preview release origin metadata is missing")
        }
        return Ok(Some(parse_origin(
            args.development_api_origin
                .as_deref()
                .context("development release requires --development-api-origin")?,
        )?));
    }
    if args.development_api_origin.is_some() {
        bail!("preview release rejects --development-api-origin")
    }
    let requested = parse_preview_origin(
        args.preview_api_origin
            .as_deref()
            .context("preview release requires --preview-api-origin")?,
    )?;
    let bytes = fs::read(metadata)?;
    let value: Value = serde_json::from_slice(&bytes)?;
    let mut canonical = serde_json::to_vec(&value)?;
    canonical.push(b'\n');
    let revision = manifest["sourceRevision"]
        .as_str()
        .context("preview source revision is missing")?;
    if bytes != canonical
        || value.as_object().map(|object| object.len()) != Some(4)
        || value["schema"] != "app.loomex.runner.preview-origin/v1"
        || value["version"] != manifest["version"]
        || value["sourceRevision"] != manifest["sourceRevision"]
        || revision.len() != 40
        || !revision.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        bail!("preview release origin metadata is invalid")
    }
    let bound = value["apiOrigin"]
        .as_str()
        .context("preview API origin binding is missing")?;
    if parse_preview_origin(bound)? != bound
        || bound != requested
        || parse_preview_origin(compiled_origin.context("preview compiled API origin is missing")?)?
            != bound
    {
        bail!("preview API origin does not match release binding")
    }
    let source: Value = serde_json::from_slice(&fs::read(
        payload.join("metadata/source-content-manifest.json"),
    )?)?;
    let files = source["files"]
        .as_array()
        .context("preview source inventory is missing")?;
    if files.is_empty()
        || files
            .iter()
            .any(|file| file["tracked"] != true || file["type"] == "missing")
    {
        bail!("preview release requires revision-controlled source")
    }
    Ok(None)
}

#[cfg(test)]
mod preview_tests {
    use super::*;

    fn write_preview(path: &Path, value: &Value) {
        let mut bytes = serde_json::to_vec(value).unwrap();
        bytes.push(b'\n');
        fs::write(path, bytes).unwrap();
    }

    #[test]
    fn preview_source_revision_and_package_version_match_the_compiled_bootstrap() {
        let manifest = json!({"version":"0.4.9","sourceRevision":"a".repeat(40)});
        assert!(validate_preview_identity(&manifest, Some(&"a".repeat(40)), "0.4.9").is_ok());
        assert!(validate_preview_identity(&manifest, None, "0.4.9").is_err());
        assert!(validate_preview_identity(&manifest, Some(&"b".repeat(40)), "0.4.9").is_err());
        assert!(validate_preview_identity(&manifest, Some(&"a".repeat(40)), "9.9.9").is_err());
    }

    fn fixture() -> (tempfile::TempDir, Value, Arguments) {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("metadata")).unwrap();
        let manifest =
            json!({"developmentOnly":true,"version":"0.4.9","sourceRevision":"a".repeat(40)});
        let metadata = json!({"schema":"app.loomex.runner.preview-origin/v1","apiOrigin":"https://preview.example/","version":manifest["version"],"sourceRevision":manifest["sourceRevision"]});
        write_preview(&dir.path().join("metadata/preview-origin.json"), &metadata);
        state::write_json(
            &dir.path().join("metadata/source-content-manifest.json"),
            &json!({"files":[{"path":"Cargo.toml","tracked":true,"type":"file"}]}),
        )
        .unwrap();
        let args = Arguments {
            preview_api_origin: Some("https://preview.example".into()),
            allow_unsigned_development: true,
            ..Arguments::default()
        };
        (dir, manifest, args)
    }

    #[test]
    fn preview_requires_requested_compiled_and_metadata_origins_to_match() {
        let (dir, manifest, mut args) = fixture();
        assert_eq!(
            development_origin(
                dir.path(),
                &manifest,
                &args,
                Some("https://preview.example")
            )
            .unwrap(),
            None
        );
        assert!(development_origin(dir.path(), &manifest, &args, None).is_err());
        assert!(
            development_origin(dir.path(), &manifest, &args, Some("https://other.example"))
                .is_err()
        );
        args.preview_api_origin = Some("https://other.example".into());
        assert!(
            development_origin(
                dir.path(),
                &manifest,
                &args,
                Some("https://preview.example")
            )
            .is_err()
        );
        args.preview_api_origin = None;
        assert!(
            development_origin(
                dir.path(),
                &manifest,
                &args,
                Some("https://preview.example")
            )
            .is_err()
        );
    }

    #[test]
    fn malformed_preview_origins_and_development_override_are_rejected() {
        for origin in [
            "http://preview.example",
            "https://user:pass@preview.example",
            "https://preview.example/path",
            "https://preview.example/path/../",
            "https://@preview.example/",
            "https://preview.example:0/",
            "https:\\\\preview.example",
            "https://preview.example/?",
            "https://preview.example/#fragment",
            " https://preview.example",
            "https://preview.example\n",
        ] {
            assert!(parse_preview_origin(origin).is_err(), "{origin:?}");
        }
        let (dir, manifest, mut args) = fixture();
        args.development_api_origin = Some("http://127.0.0.1:9".into());
        assert!(
            development_origin(
                dir.path(),
                &manifest,
                &args,
                Some("https://preview.example")
            )
            .is_err()
        );
    }

    #[test]
    fn missing_metadata_preserves_loopback_development_install_policy() {
        let (dir, manifest, mut args) = fixture();
        fs::remove_file(dir.path().join("metadata/preview-origin.json")).unwrap();
        assert!(
            development_origin(
                dir.path(),
                &manifest,
                &args,
                Some("https://preview.example")
            )
            .is_err()
        );
        args.preview_api_origin = None;
        assert!(development_origin(dir.path(), &manifest, &args, None).is_err());
        args.development_api_origin = Some("http://127.0.0.1:9".into());
        assert_eq!(
            development_origin(dir.path(), &manifest, &args, None).unwrap(),
            Some("http://127.0.0.1:9/".into())
        );
        args.development_api_origin = Some("http://api.loomex.localhost:28080".into());
        assert_eq!(
            development_origin(dir.path(), &manifest, &args, None).unwrap(),
            Some("http://api.loomex.localhost:28080/".into())
        );
        args.development_api_origin = Some("https://preview.example".into());
        assert!(development_origin(dir.path(), &manifest, &args, None).is_err());
    }

    #[test]
    fn preview_metadata_and_source_identity_cannot_be_changed() {
        let (dir, manifest, args) = fixture();
        let metadata = dir.path().join("metadata/preview-origin.json");
        let original: Value = state::read_json(&metadata).unwrap();
        for (key, value) in [
            ("schema", json!("wrong")),
            ("version", json!("9.9.9")),
            ("sourceRevision", json!("b".repeat(40))),
            ("apiOrigin", json!("https://other.example/")),
            ("extra", json!(true)),
        ] {
            let mut changed = original.clone();
            changed[key] = value;
            write_preview(&metadata, &changed);
            assert!(
                development_origin(
                    dir.path(),
                    &manifest,
                    &args,
                    Some("https://preview.example")
                )
                .is_err(),
                "{key}"
            );
        }
        write_preview(&metadata, &original);
        for files in [
            json!([]),
            json!([{"tracked":false,"type":"file"}]),
            json!([{"tracked":true,"type":"missing"}]),
        ] {
            state::write_json(
                &dir.path().join("metadata/source-content-manifest.json"),
                &json!({"files":files}),
            )
            .unwrap();
            assert!(
                development_origin(
                    dir.path(),
                    &manifest,
                    &args,
                    Some("https://preview.example")
                )
                .is_err()
            );
        }
    }

    #[test]
    fn changing_bound_preview_bytes_invalidates_payload_inventory() {
        let (dir, _, _) = fixture();
        let mut expected = Vec::new();
        for name in ["preview-origin.json", "source-content-manifest.json"] {
            let path = dir.path().join("metadata").join(name);
            let details = fs::metadata(&path).unwrap();
            expected.push(json!({"path":format!("metadata/{name}"),"sha256":state::digest(&fs::read(&path).unwrap()),"size":details.len(),"mode":details.permissions().mode() & 0o777}));
        }
        inventory(dir.path(), &expected).unwrap();
        fs::write(dir.path().join("metadata/preview-origin.json"), b"tampered").unwrap();
        assert!(inventory(dir.path(), &expected).is_err());
    }

    #[tokio::test]
    async fn production_rejects_preview_or_development_flags_before_signature_work() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = json!({"developmentOnly":false});
        for args in [
            Arguments {
                preview_api_origin: Some("https://preview.example".into()),
                ..Arguments::default()
            },
            Arguments {
                development_api_origin: Some("http://127.0.0.1:9".into()),
                ..Arguments::default()
            },
            Arguments {
                allow_unsigned_development: true,
                ..Arguments::default()
            },
        ] {
            assert!(
                verify_release(dir.path(), &manifest, &args)
                    .await
                    .unwrap_err()
                    .to_string()
                    .contains("production release rejects development options")
            );
        }
    }
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
    if args.preview_api_origin.is_some() {
        validate_preview_identity(
            &manifest,
            option_env!("LOOMEX_PREVIEW_SOURCE_REVISION"),
            env!("CARGO_PKG_VERSION"),
        )?;
    }
    let paths = paths(&args)?;
    let version = manifest["version"].as_str().unwrap();
    let origin = if manifest["developmentOnly"] == true {
        // Verify the inventoried candidate and its exact code identity before
        // any lifecycle intent, drain, pointer change, or version retirement.
        let signing_stage =
            std::env::temp_dir().join(format!("loomex-development-signing-{}", Uuid::new_v4()));
        let result = async {
            let payload = extract(&release, &manifest, &signing_stage).await?;
            let origin =
                development_origin(&payload, &manifest, &args, option_env!("LOOMEX_API_ORIGIN"))?;
            verify_development_signing(&payload, &paths, &args).await?;
            Ok::<_, anyhow::Error>(origin)
        }
        .await;
        let _ = fs::remove_dir_all(&signing_stage);
        result?
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
    if let Some(receipt) = lifecycle::reconcile_bootstrap_abandonment_locked(
        &paths,
        &configuration,
        args.settled_abandonment,
    )
    .await?
    {
        println!("{}", serde_json::to_string(&receipt)?);
        return Ok(());
    }
    let successor_envelope = bootstrap_journal.exists()
        && state::read_json::<Value>(&bootstrap_journal)?["schema"]
            == "app.loomex.runner.bootstrap-install/v2";
    if bootstrap_journal.exists()
        && !successor_envelope
        && state::read_json::<Value>(&bootstrap_journal)? != configuration
    {
        // A bootstrap journal binds retries of an unfinished installation to
        // its exact configuration.  It must not, however, turn a completed
        // installation into a permanent update barrier.  Lifecycle owns the
        // authoritative transaction record; only after it has reached a
        // validated terminal phase may this stale, bootstrap-local retry
        // record be released for a new package transaction.
        let operation_path = paths.state_dir.join("lifecycle-operation.json");
        let terminal = if operation_path.exists() {
            let operation: lifecycle::Operation = state::read_json(&operation_path)?;
            lifecycle::operation_is_terminal(&operation)?
        } else {
            false
        };
        if terminal {
            remove_regular(&bootstrap_journal)?;
        } else {
            bail!("LIFECYCLE_OPERATION_CONFIGURATION_MISMATCH")
        }
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
        println!("{}", pending_update_message(&preflight));
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
    if !successor_envelope {
        state::write_json(&bootstrap_journal, &configuration)?;
    }
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
            println!("{}", pending_update_message(&activation));
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

fn pending_update_message(value: &Value) -> &'static str {
    if value["reason"] == "service_stop" {
        "Loomex runner update is pending verified service stop. Resume the same lifecycle operation after checking its status."
    } else {
        "Loomex runner update is pending until active work completes."
    }
}

async fn uninstall(args: Arguments) -> Result<()> {
    bootstrap_uninstall::run(args, false).await
}
fn validate_owned_installation(
    paths: &lifecycle::Paths,
    receipt: &Value,
    owned: &Value,
    allow_missing: bool,
) -> Result<()> {
    bootstrap_uninstall::validate_owned_installation(paths, receipt, owned, allow_missing)
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
        "recover-uninstall" => bootstrap_uninstall::run(args, true).await,
        "preflight" => bootstrap_preflight::run(args).await,
        _ => usage(),
    }
}

#[cfg(test)]
mod pending_stop_tests {
    use super::*;
    #[test]
    fn pending_stop_copy_distinguishes_service_observation_from_active_work() {
        assert!(
            pending_update_message(&json!({"pending":true,"reason":"service_stop"}))
                .contains("verified service stop")
        );
        assert!(
            pending_update_message(&json!({"pending":true,"reason":"active_work"}))
                .contains("active work")
        );
    }
}

#[cfg(test)]
mod uninstall_regression_tests {
    use super::*;
    #[test]
    fn cleanup_validation_accepts_only_the_remaining_owned_subset_after_interruption() {
        let root = tempfile::tempdir().unwrap();
        let canonical_root = fs::canonicalize(root.path()).unwrap();
        let paths = lifecycle::Paths {
            install_base: canonical_root.join("install"),
            state_dir: canonical_root.join("state"),
            launch_agents_dir: canonical_root.join("agents"),
        };
        let version = paths.install_base.join("versions/1.2.3");
        fs::create_dir_all(version.join("bin")).unwrap();
        fs::write(version.join("bin/remaining"), b"owned").unwrap();
        fs::set_permissions(
            version.join("bin/remaining"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let owned = json!({"schema":"app.loomex.runner.owned-versions/v1","paths":[version],"inventories":[{"path":version,"files":[{"path":"bin/deleted","sha256":state::digest(b"deleted"),"size":7,"mode":384},{"path":"bin/remaining","sha256":state::digest(b"owned"),"size":5,"mode":384}]}]});
        let receipt = json!({"schema":"app.loomex.runner.install-receipt/v2","version":"1.2.3","versionPath":version,"launchAgent":paths.launch_agents_dir.join("app.loomex.runner.plist")});
        assert!(
            validate_owned_installation(&paths, &receipt, &owned, true).is_ok(),
            "an interrupted exact deletion must resume from a verified subset"
        );
        fs::write(version.join("user-file"), b"preserve").unwrap();
        assert!(validate_owned_installation(&paths, &receipt, &owned, true).is_err());
    }
}
