//! Read-only release and installation eligibility inspection. No lifecycle lock,
//! credential access, daemon request, or installed-state mutation belongs here.
use super::*;

struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn version_is_safe(version: &str) -> bool {
    let parts: Vec<_> = version.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
}

fn read_optional_record(path: &Path) -> Result<Option<Value>> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
        Ok(metadata) => {
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                bail!("unsafe installation metadata")
            }
            Ok(Some(state::read_json(path)?))
        }
    }
}

fn transition_eligibility(
    previous: Option<&str>,
    candidate: Option<&str>,
    same_binary: bool,
    authorized: bool,
) -> Result<&'static str> {
    // An opted-in transition still requires foreground authorization during
    // install. A preflight must never represent that authorization as verified.
    match signing_transition(previous, candidate, same_binary, authorized) {
        Ok(SigningTransition::Ready) => Ok("eligible"),
        Ok(SigningTransition::ForegroundAuthorizationRequired) => Ok("needs_explicit_transition"),
        Err(error) if previous.is_none() && candidate.is_some() => {
            if signing_transition(previous, candidate, same_binary, true).is_ok() {
                Ok("needs_explicit_transition")
            } else {
                Err(error)
            }
        }
        Err(error) => Err(error),
    }
}

fn development_signing(payload: &Path) -> Result<Option<String>> {
    let candidate = payload.join("bin/loomex-runner");
    let candidate_requirement = signing_requirement(&candidate)?;
    let metadata = payload.join("metadata/development-signing.json");
    if let Some(value) = read_optional_record(&metadata)? {
        let bytes = fs::read(&metadata)?;
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
            let actual = signing_requirement(&payload.join("bin").join(name))?;
            let expected = requirements
                .get(name)
                .and_then(Value::as_str)
                .context("development signing requirement is missing")?;
            if actual.as_deref() != Some(expected)
                || !expected.contains(&format!("identifier \"app.loomex.runner.{name}\""))
            {
                bail!("development signing requirement does not match package")
            }
        }
    } else {
        if candidate_requirement.is_some() {
            bail!("signed development package lacks signing manifest")
        }
        // Validate every shipped executable even for an ad-hoc package.
        for name in ["loomex", "loomex-lifecycle-bootstrap"] {
            if signing_requirement(&payload.join("bin").join(name))?.is_some() {
                bail!("signed development package lacks signing manifest")
            }
        }
    }
    Ok(candidate_requirement)
}

fn installed_signing(
    payload: &Path,
    paths: &lifecycle::Paths,
    args: &Arguments,
    candidate_requirement: Option<&str>,
) -> Result<&'static str> {
    let candidate = payload.join("bin/loomex-runner");
    let current = paths.install_base.join("current");
    match fs::symlink_metadata(&current) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if args.authorize_keychain_transition {
                bail!("credential transition requires an installed daemon")
            }
            Ok("eligible")
        }
        Err(error) => Err(error.into()),
        Ok(metadata) => {
            if !metadata.file_type().is_symlink() {
                bail!("unsafe runner current pointer")
            }
            let previous = current.join("bin/loomex-runner");
            let requirement = signing_requirement(&previous)?;
            transition_eligibility(
                requirement.as_deref(),
                candidate_requirement,
                fs::read(previous)? == fs::read(candidate)?,
                args.authorize_keychain_transition,
            )
        }
    }
}

fn inherited_providers(
    paths: &lifecycle::Paths,
    args: &Arguments,
) -> Result<BTreeMap<String, String>> {
    let selected = providers(&args.providers)?;
    if !selected.is_empty() {
        return Ok(selected);
    }
    let Some(receipt) = read_optional_record(&paths.state_dir.join("install-receipt.json"))? else {
        return Ok(selected);
    };
    let Some(existing) = receipt["providerExecutables"].as_object() else {
        return Ok(selected);
    };
    let values = existing
        .iter()
        .map(|(name, value)| {
            Ok(format!(
                "{name}={}",
                value
                    .as_str()
                    .context("invalid receipt provider executable")?
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    providers(&values)
}

fn configuration_matches(journal: &Value, expected: &Value) -> bool {
    journal == expected
        || (journal["schema"] == "app.loomex.runner.bootstrap-install/v2"
            && journal.get("successorConfiguration") == Some(expected))
}

fn installed_eligibility(
    paths: &lifecycle::Paths,
    package: &lifecycle::PackageIdentity,
    manifest: &Value,
    configuration: &Value,
) -> Result<Value> {
    let receipt = read_optional_record(&paths.state_dir.join("install-receipt.json"))?;
    let owned = read_optional_record(&paths.state_dir.join("owned-versions.json"))?;
    match (&receipt, &owned) {
        (Some(receipt), Some(owned)) => {
            validate_owned_installation(paths, receipt, owned, false)?;
            let receipt_target = receipt["versionPath"]
                .as_str()
                .context("receipt version path is missing")?;
            if !owned["paths"]
                .as_array()
                .context("invalid owned version inventory")?
                .iter()
                .any(|value| value.as_str() == Some(receipt_target))
            {
                bail!("receipt version is not owned")
            }
        }
        (None, None) => {}
        // A first install may have staged ownership before its receipt. The
        // lifecycle package identity below must authorize that exact retry.
        (None, Some(owned)) => {
            let staged_receipt = json!({"schema":"app.loomex.runner.install-receipt/v2", "launchAgent":paths.launch_agents_dir.join("app.loomex.runner.plist")});
            validate_owned_installation(paths, &staged_receipt, owned, false)?;
        }
        _ => bail!("incomplete owned installation metadata"),
    }
    let current = paths.install_base.join("current");
    match fs::symlink_metadata(&current) {
        Ok(metadata) => {
            if !metadata.file_type().is_symlink() {
                bail!("unsafe runner current pointer")
            }
            let target = fs::canonicalize(&current)?;
            let inventory = owned
                .as_ref()
                .context("current installation is not owned")?;
            if !inventory["paths"]
                .as_array()
                .context("invalid owned version inventory")?
                .iter()
                .any(|value| value.as_str() == Some(target.to_string_lossy().as_ref()))
            {
                bail!("current installation is not owned")
            }
            lifecycle::verify_owned_version_from_inventory(&target, inventory)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let mut result =
        lifecycle::package_preflight(paths, lifecycle::OperationKind::Update, package)?;
    let mut blockers = result["blockers"].as_array().cloned().unwrap_or_default();
    if let Some(journal) = read_optional_record(&paths.state_dir.join("bootstrap-install.json"))? {
        let terminal =
            match read_optional_record(&paths.state_dir.join("lifecycle-operation.json"))? {
                Some(value) => {
                    let operation: lifecycle::Operation = serde_json::from_value(value)?;
                    lifecycle::operation_is_terminal(&operation)?
                }
                None => false,
            };
        if !terminal && !configuration_matches(&journal, configuration) {
            blockers.push(json!("LIFECYCLE_OPERATION_CONFIGURATION_MISMATCH"));
        }
    }
    match fs::symlink_metadata(&package.target) {
        Ok(metadata) => {
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                bail!("unsafe installed candidate version")
            }
            inventory(
                &package.target,
                manifest["payload"]["files"]
                    .as_array()
                    .context("release inventory is invalid")?,
            )?;
            if let Some(owned) = &owned {
                lifecycle::verify_owned_version_from_inventory(&package.target, owned)?;
            } else {
                bail!("candidate version is not owned")
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    if receipt.is_none()
        && owned.is_some()
        && read_optional_record(&paths.state_dir.join("bootstrap-install.json"))?.is_none()
    {
        blockers.push(json!("incomplete_owned_installation"));
    }
    result["blockers"] = json!(blockers);
    result["ready"] = json!(blockers.is_empty());
    Ok(result)
}

fn verify_envelope(release: &Path, payload: &Path, manifest: &Value) -> Result<()> {
    if manifest["bootstrap"]["file"] != "loomex-lifecycle-bootstrap" {
        bail!("release bootstrap binding is invalid")
    }
    let envelope = release.join("loomex-lifecycle-bootstrap");
    let metadata = fs::symlink_metadata(&envelope)?;
    let bytes = fs::read(&envelope)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || manifest["bootstrap"]["size"].as_u64() != Some(metadata.len())
        || manifest["bootstrap"]["sha256"].as_str() != Some(state::digest(&bytes).as_str())
        || bytes != fs::read(payload.join("bin/loomex-lifecycle-bootstrap"))?
    {
        bail!("release bootstrap envelope does not match payload")
    }
    Ok(())
}

// Capture subprocess diagnostics so stdout remains one machine-readable report
// and malformed artifacts cannot expose arbitrary command output.
async fn verify_artifact(release: &Path, manifest: &Value, args: &Arguments) -> Result<()> {
    let development = manifest["developmentOnly"]
        .as_bool()
        .context("release class is invalid")?;
    if development {
        return verify_release(release, manifest, args).await;
    }
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
    let output = tokio::process::Command::new("/usr/bin/openssl")
        .args(["dgst", "-sha256", "-verify"])
        .arg(key)
        .arg("-signature")
        .arg(signature)
        .arg(release.join("manifest.json"))
        .stdin(Stdio::null())
        .output()
        .await?;
    if !output.status.success() {
        bail!("release signature verification failed")
    }
    let archive = release.join(
        manifest["payload"]["file"]
            .as_str()
            .context("release archive is missing")?,
    );
    if state::digest(&fs::read(archive)?)
        != manifest["payload"]["sha256"]
            .as_str()
            .context("release digest is missing")?
    {
        bail!("release payload digest mismatch")
    }
    Ok(())
}

async fn extract_artifact(release: &Path, manifest: &Value, stage: &Path) -> Result<PathBuf> {
    fs::create_dir(stage)?;
    let output = tokio::process::Command::new("/usr/bin/tar")
        .arg("-xzf")
        .arg(release.join("payload.tar.gz"))
        .arg("-C")
        .arg(stage)
        .stdin(Stdio::null())
        .output()
        .await?;
    if !output.status.success() {
        bail!("release extraction failed")
    }
    inventory(
        stage,
        manifest["payload"]["files"]
            .as_array()
            .context("release inventory is invalid")?,
    )?;
    validate_source_binding(stage, manifest)?;
    Ok(stage.to_path_buf())
}

async fn inspect(args: &Arguments, report: &mut Value) -> Result<()> {
    let release = fs::canonicalize(args.release.as_ref().context("release is required")?)?;
    let manifest = read_manifest(&release)?;
    verify_artifact(&release, &manifest, args).await?;
    let version = manifest["version"]
        .as_str()
        .context("release version is missing")?;
    if !version_is_safe(version) {
        bail!("release version is invalid")
    }
    if args.preview_api_origin.is_some() {
        validate_preview_identity(
            &manifest,
            option_env!("LOOMEX_PREVIEW_SOURCE_REVISION"),
            env!("CARGO_PKG_VERSION"),
        )?;
    }
    let paths = paths(args)?;
    let scratch =
        Scratch(std::env::temp_dir().join(format!("loomex-install-preflight-{}", Uuid::new_v4())));
    let payload = extract_artifact(&release, &manifest, &scratch.0).await?;
    verify_envelope(&release, &payload, &manifest)?;
    let project: Value = serde_json::from_slice(&fs::read(payload.join("metadata/project.json"))?)?;
    if project["project"] != "loomex-runner"
        || project["version"] != version
        || project["platform"] != "darwin-arm64"
    {
        bail!("release project metadata mismatch")
    }
    let (origin, requirement) = if manifest["developmentOnly"] == true {
        let origin =
            development_origin(&payload, &manifest, args, option_env!("LOOMEX_API_ORIGIN"))?;
        let signing = development_signing(&payload)?;
        (origin, signing)
    } else {
        for name in ["loomex", "loomex-runner", "loomex-lifecycle-bootstrap"] {
            let output = std::process::Command::new("/usr/bin/codesign")
                .args(["--verify", "--strict"])
                .arg(payload.join("bin").join(name))
                .stdin(Stdio::null())
                .output()?;
            if !output.status.success() {
                bail!("production code signature is invalid")
            }
        }
        (None, None)
    };
    report["artifact"] = json!({"eligible":true,"version":version,"manifestSha256":state::digest(&fs::read(release.join("manifest.json"))?)});
    let signing = if manifest["developmentOnly"] == true {
        installed_signing(&payload, &paths, args, requirement.as_deref())?
    } else {
        "eligible"
    };
    let package = lifecycle::PackageIdentity {
        version: version.into(),
        target: paths.install_base.join("versions").join(version),
        manifest_sha256: report["artifact"]["manifestSha256"]
            .as_str()
            .unwrap()
            .into(),
    };
    let selected = inherited_providers(&paths, args)?;
    let configuration = json!({"schema":"app.loomex.runner.bootstrap-install/v1","version":version,"target":package.target,"manifestSha256":package.manifest_sha256,"developmentApiOrigin":origin,"providerExecutables":selected});
    let pending = installed_eligibility(&paths, &package, &manifest, &configuration)?;
    let mut blockers = pending["blockers"].as_array().cloned().unwrap_or_default();
    if signing != "eligible" && !args.authorize_keychain_transition {
        blockers.push(json!(signing));
    }
    report["credentialPrerequisite"]["requiresExplicitTransition"] = json!(signing != "eligible");
    report["credentialPrerequisite"]["foregroundUserActionRequired"] = json!(signing != "eligible");
    report["credentialPrerequisite"]["transitionAuthorizedForInstall"] =
        json!(signing != "eligible" && args.authorize_keychain_transition);
    report["pendingRecovery"] = pending;
    report["upgradeEligibility"] = json!({"eligible":blockers.is_empty(),"conditional":signing != "eligible", "blockers":blockers,"signingTransition":signing});
    report["activation"] = report["upgradeEligibility"].clone();
    report["eligible"] = report["activation"]["eligible"].clone();
    Ok(())
}

pub(super) async fn run(args: super::Arguments) -> Result<()> {
    let mut report = json!({
        "schema":"app.loomex.runner.install-preflight/v1", "readOnly":true,"eligible":false,
        "artifact":{"eligible":false}, "activation":{"eligible":false},
        "upgradeEligibility":{"eligible":false},"pendingRecovery":{"status":"not_checked"},
        "credentialPrerequisite":{"status":"not_verified","nativeAccessVerified":false,"accessAttempted":false},
        "snapshot":{"lockAcquired":false,"requiresInstallRevalidation":true}
    });
    if inspect(&args, &mut report).await.is_err() {
        let category = if report["artifact"]["eligible"] == true {
            "installation_state_invalid"
        } else {
            "artifact_validation_failed"
        };
        report["error"] = json!({"category":category,"message":"Installation preflight could not verify eligibility."});
        println!("{}", serde_json::to_string(&report)?);
        bail!("installation preflight could not verify eligibility");
    }
    println!("{}", serde_json::to_string(&report)?);
    if report["eligible"] != true {
        bail!("installation preflight blocked")
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn version_cannot_escape_version_namespace() {
        for version in ["1.2.3", "0.0.1"] {
            assert!(version_is_safe(version));
        }
        for version in ["../1", "/1.2.3", "1.2.3/../4", "1.2", "1.2.3-beta", "1..3"] {
            assert!(!version_is_safe(version));
        }
    }
    #[test]
    fn foreground_transition_is_never_reported_authorized() {
        assert_eq!(
            transition_eligibility(None, Some("pinned"), false, true).unwrap(),
            "needs_explicit_transition"
        );
        assert_eq!(
            transition_eligibility(None, Some("pinned"), false, false).unwrap(),
            "needs_explicit_transition"
        );
        assert!(transition_eligibility(Some("old"), Some("changed"), false, true).is_err());
        assert!(transition_eligibility(None, None, false, false).is_err());
        assert_eq!(
            transition_eligibility(Some("same"), Some("same"), false, false).unwrap(),
            "eligible"
        );
    }
    #[test]
    fn pending_retry_requires_exact_configuration_including_origin_and_providers() {
        let expected = json!({"version":"1.2.3","manifestSha256":"a","target":"/versions/1.2.3","developmentApiOrigin":null,"providerExecutables":{}});
        assert!(configuration_matches(&expected, &expected));
        let mut changed = expected.clone();
        changed["manifestSha256"] = json!("b");
        assert!(!configuration_matches(&changed, &expected));
        changed = expected.clone();
        changed["target"] = json!("/other/1.2.3");
        assert!(!configuration_matches(&changed, &expected));
        assert!(configuration_matches(
            &json!({"schema":"app.loomex.runner.bootstrap-install/v2","successorConfiguration":expected}),
            &expected
        ));
    }
    #[test]
    fn fresh_preflight_creates_no_install_or_lock_files() {
        let root = tempfile::tempdir().unwrap();
        let paths = lifecycle::Paths {
            install_base: root.path().join("install"),
            state_dir: root.path().join("state"),
            launch_agents_dir: root.path().join("agents"),
        };
        let package = lifecycle::PackageIdentity {
            version: "1.2.3".into(),
            target: paths.install_base.join("versions/1.2.3"),
            manifest_sha256: "a".repeat(64),
        };
        let value = installed_eligibility(
            &paths,
            &package,
            &json!({"payload":{"files":[]}}),
            &json!({}),
        )
        .unwrap();
        assert_eq!(value["ready"], true);
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
    }
    #[test]
    fn same_version_payload_mismatch_is_blocked_without_mutation() {
        let root = tempfile::tempdir().unwrap();
        let paths = lifecycle::Paths {
            install_base: root.path().join("install"),
            state_dir: root.path().join("state"),
            launch_agents_dir: root.path().join("agents"),
        };
        let target = paths.install_base.join("versions/1.2.3");
        fs::create_dir_all(&target).unwrap();
        fs::write(target.join("changed"), b"preserve").unwrap();
        let package = lifecycle::PackageIdentity {
            version: "1.2.3".into(),
            target: target.clone(),
            manifest_sha256: "a".repeat(64),
        };
        assert!(
            installed_eligibility(
                &paths,
                &package,
                &json!({"payload":{"files":[]}}),
                &json!({})
            )
            .is_err()
        );
        assert_eq!(fs::read(target.join("changed")).unwrap(), b"preserve");
        assert!(!paths.state_dir.exists());
    }
    #[test]
    fn envelope_requires_the_exact_payload_bootstrap_bytes() {
        let root = tempfile::tempdir().unwrap();
        let payload = root.path().join("payload");
        fs::create_dir_all(payload.join("bin")).unwrap();
        fs::write(root.path().join("loomex-lifecycle-bootstrap"), b"envelope").unwrap();
        fs::write(payload.join("bin/loomex-lifecycle-bootstrap"), b"envelope").unwrap();
        let manifest = json!({"bootstrap":{"file":"loomex-lifecycle-bootstrap","size":8,"sha256":state::digest(b"envelope")}});
        verify_envelope(root.path(), &payload, &manifest).unwrap();
        fs::write(payload.join("bin/loomex-lifecycle-bootstrap"), b"different").unwrap();
        assert!(verify_envelope(root.path(), &payload, &manifest).is_err());
    }
    #[test]
    fn optional_metadata_does_not_follow_symlinks_or_create_state() {
        let root = tempfile::tempdir().unwrap();
        let missing = root.path().join("missing");
        assert!(read_optional_record(&missing).unwrap().is_none());
        assert!(!missing.exists());
        fs::write(root.path().join("record"), b"{}").unwrap();
        std::os::unix::fs::symlink(root.path().join("record"), &missing).unwrap();
        assert!(read_optional_record(&missing).is_err());
    }
}
