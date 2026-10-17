//! Read-only release and installation eligibility inspection. No lifecycle lock,
//! credential access, daemon request, or installed-state mutation belongs here.
use super::*;
use std::os::unix::fs::DirBuilderExt;

pub(super) struct Scratch(pub(super) PathBuf);
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
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let before = match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
        Ok(metadata) => metadata,
    };
    let typed = |category| uninstall_state::ManagedStateError::new(category);
    if !before.is_file() || before.file_type().is_symlink() {
        return Err(typed(uninstall_state::BlockerCategory::UnsafeState).into());
    }
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let opened = file.metadata()?;
    if opened.dev() != before.dev() || opened.ino() != before.ino() {
        return Err(typed(uninstall_state::BlockerCategory::ObservationDrift).into());
    }
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut file, &mut bytes)?;
    let after = file.metadata()?;
    let named = fs::symlink_metadata(path)?;
    if before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || opened.dev() != named.dev()
        || opened.ino() != named.ino()
    {
        return Err(typed(uninstall_state::BlockerCategory::ObservationDrift).into());
    }
    let record = serde_json::from_slice(&bytes)
        .map_err(|_| typed(uninstall_state::BlockerCategory::UnsupportedSchema))?;
    Ok(Some(record))
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

pub(super) fn development_signing(payload: &Path) -> Result<Option<String>> {
    let candidate = payload.join("bin/loomex-runner");
    let candidate_requirement = signing_requirement(&candidate)?;
    let metadata = payload.join("metadata/development-signing.json");
    if let Some(value) = read_optional_record(&metadata)? {
        let bytes = fs::read(&metadata)?;
        let mut canonical = serde_json::to_vec(&value)?;
        canonical.push(b'\n');
        if bytes != canonical || value["schema"] != "app.loomex.runner.development-signing/v1" {
            return Err(anyhow::anyhow!("development signing manifest is invalid")
                .context(OwnerDiagnostic::SignatureRejected));
        }
        let requirements = value["requirements"]
            .as_object()
            .context("development signing requirements are missing")?;
        if requirements.len() != 3 {
            return Err(
                anyhow::anyhow!("development signing requirements are incomplete")
                    .context(OwnerDiagnostic::SignatureRejected),
            );
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
                return Err(anyhow::anyhow!(
                    "development signing requirement does not match package"
                )
                .context(OwnerDiagnostic::SignatureRejected));
            }
        }
    } else {
        if candidate_requirement.is_some() {
            return Err(
                anyhow::anyhow!("signed development package lacks signing manifest")
                    .context(OwnerDiagnostic::SignatureRejected),
            );
        }
        // Validate every shipped executable even for an ad-hoc package.
        for name in ["loomex", "loomex-lifecycle-bootstrap"] {
            if signing_requirement(&payload.join("bin").join(name))?.is_some() {
                return Err(
                    anyhow::anyhow!("signed development package lacks signing manifest")
                        .context(OwnerDiagnostic::SignatureRejected),
                );
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
                return Err(uninstall_state::ManagedStateError::new(
                    uninstall_state::BlockerCategory::UnsafeState,
                )
                .into());
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
                return Err(uninstall_state::ManagedStateError::new(
                    uninstall_state::BlockerCategory::UnsafeState,
                )
                .into());
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
                return Err(uninstall_state::ManagedStateError::new(
                    uninstall_state::BlockerCategory::UnsafeState,
                )
                .into());
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

pub(super) fn verify_envelope(release: &Path, payload: &Path, manifest: &Value) -> Result<()> {
    if manifest["bootstrap"]["file"] != "loomex-lifecycle-bootstrap" {
        return Err(anyhow::anyhow!("release bootstrap binding is invalid")
            .context(OwnerDiagnostic::BindingMismatch));
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
        return Err(
            anyhow::anyhow!("release bootstrap envelope does not match payload")
                .context(OwnerDiagnostic::BindingMismatch),
        );
    }
    Ok(())
}

// Capture subprocess diagnostics so stdout remains one machine-readable report
// and malformed artifacts cannot expose arbitrary command output.
pub(super) async fn verify_artifact(
    release: &Path,
    manifest: &Value,
    args: &Arguments,
) -> Result<()> {
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
        return Err(anyhow::anyhow!("production release signature is missing")
            .context(OwnerDiagnostic::SignatureRejected));
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
        return Err(anyhow::anyhow!("release signature verification failed")
            .context(OwnerDiagnostic::SignatureRejected));
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
        return Err(anyhow::anyhow!("release payload digest mismatch")
            .context(OwnerDiagnostic::BindingMismatch));
    }
    Ok(())
}

pub(super) async fn extract_artifact(
    release: &Path,
    manifest: &Value,
    stage: &Path,
) -> Result<PathBuf> {
    fs::DirBuilder::new().mode(0o700).create(stage)?;
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
    let paths = paths(args)?;
    report["recoveryOwnership"] = bootstrap_uninstall::recovery_ownership(&paths);
    report["ownerReference"] = bootstrap_uninstall::work_owner_reference(&paths);
    report["maintenanceReference"] =
        bootstrap_uninstall::work_maintenance_reference(&paths, None, None);
    let release = fs::canonicalize(args.release.as_ref().context("release is required")?)?;
    let manifest = read_manifest(&release)?;
    report["maintenanceReference"] = bootstrap_uninstall::work_maintenance_reference(
        &paths,
        fs::read(release.join("manifest.json"))
            .ok()
            .map(|bytes| state::digest(&bytes))
            .as_deref(),
        Some(args.expected_release_path.as_deref().unwrap_or(&release)),
    );
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
    let scratch =
        Scratch(std::env::temp_dir().join(format!("loomex-install-preflight-{}", Uuid::new_v4())));
    let payload = extract_artifact(&release, &manifest, &scratch.0).await?;
    lifecycle::require_operation_observation_capability(&paths, &payload)?;
    verify_envelope(&release, &payload, &manifest)?;
    let project: Value = serde_json::from_slice(&fs::read(payload.join("metadata/project.json"))?)?;
    if project["project"] != "loomex-runner"
        || project["version"] != version
        || project["platform"] != "darwin-arm64"
    {
        return Err(anyhow::anyhow!("release project metadata mismatch")
            .context(OwnerDiagnostic::BindingMismatch));
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
                return Err(anyhow::anyhow!("production code signature is invalid")
                    .context(OwnerDiagnostic::SignatureRejected));
            }
        }
        (None, None)
    };
    report["artifact"] = json!({"eligible":true,"version":version,"manifestSha256":state::digest(&fs::read(release.join("manifest.json"))?)});
    report["maintenanceReference"] = bootstrap_uninstall::work_maintenance_reference(
        &paths,
        report["artifact"]["manifestSha256"].as_str(),
        Some(args.expected_release_path.as_deref().unwrap_or(&release)),
    );
    if args.work_action.is_some() {
        let work = bootstrap_uninstall::work_preflight(&paths, args, &release, &manifest, &payload)
            .await?;
        report["ownerReference"] = work["ownerReference"].clone();
        report["maintenanceReference"] = work["maintenanceReference"].clone();
        report["retirementScope"] = work["retirementScope"].clone();
        report["assessment"] = work
            .get("assessment")
            .unwrap_or(&work["managedStateAssessment"])
            .clone();
        publish_work_eligibility(report, &work)?;
        report["eligible"] = json!(true);
        return Ok(());
    }
    if args.recovery_uninstall {
        let pending =
            bootstrap_uninstall::recovery_preflight(&paths, args, &release, &manifest, &payload)
                .await?;
        if pending {
            publish_recovery_eligibility(
                report,
                args.expected_release_path
                    .as_deref()
                    .is_some_and(|p| p != release),
            )?;
            return Ok(());
        }
        ensure_no_pending_uninstall(&report["recoveryOwnership"])?;
        report["recoveryEligibility"] = json!({"eligible":true,"readOnly":true});
    }
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
    report["cacheRestoreRequired"] = json!(
        args.expected_release_path
            .as_deref()
            .is_some_and(|p| p != release)
            && pending["ready"] == true
            && report["recoveryOwnership"]["status"] == "pending"
    );
    report["pendingRecovery"] = pending;
    report["upgradeEligibility"] = json!({"eligible":blockers.is_empty(),"conditional":signing != "eligible", "blockers":blockers,"signingTransition":signing});
    report["activation"] = report["upgradeEligibility"].clone();
    report["eligible"] = report["activation"]["eligible"].clone();
    Ok(())
}

fn publish_work_eligibility(report: &mut Value, work: &Value) -> Result<()> {
    let signing = work["signingTransition"].as_str();
    if !matches!(signing, Some("eligible" | "needs_explicit_transition"))
        || work["eligible"] != true
        || work["readOnly"] != true
        || work["accessAttempted"] != false
        || work["nativeAccessVerified"] != false
    {
        return Err(
            anyhow::anyhow!("uninstall work preflight contract is unconfirmed")
                .context(OwnerDiagnostic::BindingMismatch),
        );
    }
    report["uninstallWorkEligibility"] = json!({"eligible":true,"readOnly":true,"retirementScope":work["retirementScope"],"signingTransition":signing,"successorAfterOriginalResult":work["successorAfterOriginalResult"]==true,"accessAttempted":false,"nativeAccessVerified":false});
    Ok(())
}

fn publish_recovery_eligibility(report: &mut Value, cache_restore_required: bool) -> Result<()> {
    // Candidate/historical binding checks cannot override an authoritative
    // ownership refusal. Keep the bounded diagnostic facts unchanged.
    if report["recoveryOwnership"]["status"] != "pending" {
        report["recoveryEligibility"] = json!({"eligible":false,"readOnly":true});
        report["activation"] = json!({"eligible":false,"recovery":true});
        report["eligible"] = json!(false);
        report["cacheRestoreRequired"] = json!(false);
        bail!("recovery ownership is unconfirmed");
    }
    report["recoveryEligibility"] = json!({"eligible":true,"readOnly":true});
    report["activation"] = json!({"eligible":true,"recovery":true});
    report["eligible"] = json!(true);
    report["cacheRestoreRequired"] = json!(cache_restore_required);
    Ok(())
}

fn ensure_no_pending_uninstall(ownership: &Value) -> Result<()> {
    if ownership["status"] == "blocked" || ownership["owner"] == "bootstrap_uninstall" {
        bail!("recovery ownership is unconfirmed");
    }
    Ok(())
}

pub(super) async fn run(args: super::Arguments) -> Result<()> {
    let mut report = json!({
        "schema":"app.loomex.runner.install-preflight/v2", "readOnly":true,"eligible":false,
        "recoveryOwnership":{"status":"blocked","operationId":null,"phase":null,"journalSha256":null,"nextAction":"inspect_protected_ownership","reasonCode":"OWNERSHIP_UNCONFIRMED"},
        "recoveryEligibility":{"eligible":false,"readOnly":true},"cacheRestoreRequired":false,
        "artifact":{"eligible":false}, "activation":{"eligible":false},
        "upgradeEligibility":{"eligible":false},"pendingRecovery":{"status":"not_checked"},
        "credentialPrerequisite":{"status":"not_verified","nativeAccessVerified":false,"accessAttempted":false},
        "snapshot":{"lockAcquired":false,"requiresInstallRevalidation":true}
    });
    if let Err(error) = inspect(&args, &mut report).await {
        let diagnostic = preflight_failure(&error);
        report["error"] = diagnostic.clone();
        report["reasonCode"] = diagnostic["reasonCode"].clone();
        report["nextAction"] = diagnostic["nextAction"].clone();
        // Assessment is diagnostic only; it never substitutes for the owner checks.
        if report["artifact"]["eligible"] == true {
            if let Ok(paths) = paths(&args) {
                if let Ok(assessment) = uninstall_state::assess_state(&paths.state_dir) {
                    report["assessment"] = serde_json::to_value(assessment)?;
                }
            }
        }
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
    fn work_preflight_transition_is_bounded_and_never_claims_native_authorization() {
        for signing in ["eligible", "needs_explicit_transition"] {
            let mut report = json!({});
            let mut work = json!({"eligible":true,"readOnly":true,"signingTransition":signing,"accessAttempted":false,"nativeAccessVerified":false,"private":"SECRET"});
            publish_work_eligibility(&mut report, &work).unwrap();
            assert_eq!(
                report["uninstallWorkEligibility"]["signingTransition"],
                signing
            );
            assert_eq!(
                report["uninstallWorkEligibility"]["nativeAccessVerified"],
                false
            );
            assert_eq!(report["uninstallWorkEligibility"]["accessAttempted"], false);
            assert!(!report.to_string().contains("SECRET"));
            work["nativeAccessVerified"] = json!(true);
            assert!(publish_work_eligibility(&mut report, &work).is_err());
        }
        assert!(publish_work_eligibility(&mut json!({}),&json!({"eligible":true,"readOnly":true,"signingTransition":"unknown","accessAttempted":false,"nativeAccessVerified":false})).is_err());
    }
    #[test]
    fn optional_metadata_preserves_unsafe_schema_and_io_categories() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("metadata.json");
        assert!(read_optional_record(&path).unwrap().is_none());
        fs::write(&path, b"invalid private JSON").unwrap();
        let error = read_optional_record(&path).unwrap_err();
        assert_eq!(
            uninstall_state::error_category(&error),
            uninstall_state::BlockerCategory::UnsupportedSchema
        );
        assert!(
            !serde_json::to_string(&preflight_failure(&error))
                .unwrap()
                .contains("private")
        );
        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(root.path().join("missing"), &path).unwrap();
        let error = read_optional_record(&path).unwrap_err();
        assert_eq!(
            uninstall_state::error_category(&error),
            uninstall_state::BlockerCategory::UnsafeState
        );
        fs::remove_file(&path).unwrap();
        fs::write(&path, b"{}").unwrap();
        assert_eq!(read_optional_record(&path).unwrap(), Some(json!({})));
        let error = std::io::Error::from(std::io::ErrorKind::PermissionDenied).into();
        assert_eq!(
            uninstall_state::error_category(&error),
            uninstall_state::BlockerCategory::UnreadableState
        );
    }
    #[test]
    fn preflight_mapper_keeps_managed_state_failures_separate() {
        for (category, expected) in [
            (
                uninstall_state::BlockerCategory::UnsupportedSchema,
                "OWNER_SCHEMA_UNSUPPORTED",
            ),
            (
                uninstall_state::BlockerCategory::UnsafeState,
                "OWNER_STATE_UNSAFE",
            ),
            (
                uninstall_state::BlockerCategory::UnreadableState,
                "OWNER_STATE_UNREADABLE",
            ),
            (
                uninstall_state::BlockerCategory::ObservationDrift,
                "OWNER_STATE_DRIFT",
            ),
            (
                uninstall_state::BlockerCategory::FollowPending,
                "MANAGED_WORK_UNRESOLVED",
            ),
        ] {
            let error = anyhow::Error::new(uninstall_state::ManagedStateError::new(category))
                .context(ManagedWorkBlocked);
            assert_eq!(preflight_failure(&error)["reasonCode"], expected);
        }
    }
    #[tokio::test]
    async fn ownership_is_reported_before_missing_candidate_validation_without_writes() {
        let root = tempfile::tempdir().unwrap();
        let base = fs::canonicalize(root.path()).unwrap();
        let paths = lifecycle::Paths {
            install_base: base.join("install"),
            state_dir: base.join("state"),
            launch_agents_dir: base.join("agents"),
        };
        fs::create_dir(&paths.state_dir).unwrap();
        let target = paths.install_base.join("versions/1.2.3");
        let journal = json!({"schema":"app.loomex.runner.bootstrap-uninstall/v1","phase":"prepared","receipt":{"version":"1.2.3","versionPath":target},"paths":[target],"inventories":[{"path":target,"files":[{"path":"bin/loomex-runner","sha256":"a".repeat(64),"size":1,"mode":448}]}],"helper":paths.state_dir.join("bootstrap-uninstall-helper"),"helperSha256":"a".repeat(64)});
        let path = paths.state_dir.join("bootstrap-uninstall.json");
        state::write_json(&path, &journal).unwrap();
        let before = fs::read(&path).unwrap();
        let args = Arguments {
            release: Some(root.path().join("missing-release")),
            install_base: Some(paths.install_base.clone()),
            state_dir: Some(paths.state_dir.clone()),
            launch_agents_dir: Some(paths.launch_agents_dir.clone()),
            ..Default::default()
        };
        let mut report = json!({});
        assert!(inspect(&args, &mut report).await.is_err());
        assert_eq!(
            report["recoveryOwnership"]["nextAction"],
            "recover_uninstall"
        );
        assert_eq!(
            report["recoveryOwnership"]["journalSha256"],
            state::digest(&before)
        );
        assert_eq!(fs::read(&path).unwrap(), before);
        assert!(!paths.state_dir.join("lifecycle.lock").exists());
        assert_eq!(fs::read_dir(&paths.state_dir).unwrap().count(), 1);
    }
    #[test]
    fn blocked_ownership_never_publishes_recovery_or_activation_eligibility() {
        let ownership = json!({"status":"blocked","owner":"bootstrap_uninstall","operationId":Uuid::new_v4(),"phase":"prepared","journalSha256":"a".repeat(64),"nextAction":"inspect_protected_ownership","reasonCode":"OWNERSHIP_UNCONFIRMED"});
        let mut report = json!({"artifact":{"eligible":true},"recoveryOwnership":ownership,
            "eligible":false,"activation":{"eligible":false},"recoveryEligibility":{"eligible":false,"readOnly":true},"cacheRestoreRequired":false});
        assert!(publish_recovery_eligibility(&mut report, true).is_err());
        assert_eq!(report["recoveryOwnership"], ownership);
        assert_eq!(report["artifact"]["eligible"], true);
        assert_eq!(report["eligible"], false);
        assert_eq!(report["activation"]["eligible"], false);
        assert_eq!(report["recoveryEligibility"]["eligible"], false);
        assert_eq!(report["cacheRestoreRequired"], false);
    }
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
