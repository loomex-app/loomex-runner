//! Reviewed execution roots, not a filesystem sandbox. Historical records stay single-root.
use crate::state::PublicState;
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

pub const CONTRACT: &str = "execution.workspace-set/v1";

pub fn canonical_set(primary: &Path, additional: &Value) -> Result<(PathBuf, Vec<PathBuf>)> {
    fn canonical(path: &Path) -> Result<PathBuf> {
        ensure!(path.is_absolute(), "WORKSPACE_DENIED");
        let path = path
            .canonicalize()
            .map_err(|_| anyhow::anyhow!("WORKSPACE_DENIED"))?;
        ensure!(path.is_dir(), "WORKSPACE_DENIED");
        Ok(path)
    }
    let primary = canonical(primary)?;
    let mut extras = Vec::new();
    if !additional.is_null() {
        for value in additional.as_array().context("INVALID_REQUEST")? {
            let path = canonical(Path::new(value.as_str().context("INVALID_REQUEST")?))?;
            if path != primary {
                extras.push(path);
            }
        }
    }
    extras.sort();
    extras.dedup();
    Ok((primary, extras))
}

/// No normalization of historical bindings or signed payloads is permitted here.
pub fn bound_extras(binding: &Value) -> Result<Vec<PathBuf>> {
    if binding.get("workspaceSetContract").is_none() {
        ensure!(
            binding.get("additionalWorkspacePaths").is_none(),
            "LOCAL_EXECUTION_AUTHORIZATION_REQUIRED"
        );
        return Ok(Vec::new());
    }
    ensure!(
        binding["workspaceSetContract"] == CONTRACT,
        "UNSUPPORTED_CAPABILITY"
    );
    let primary = PathBuf::from(
        binding["workspacePath"]
            .as_str()
            .context("WORKSPACE_DENIED")?,
    );
    let paths = binding["additionalWorkspacePaths"]
        .as_array()
        .context("WORKSPACE_DENIED")?;
    let mut extras = Vec::new();
    for value in paths {
        let path = PathBuf::from(value.as_str().context("WORKSPACE_DENIED")?);
        ensure!(path.is_absolute() && path != primary, "WORKSPACE_DENIED");
        extras.push(path);
    }
    let mut normalized = extras.clone();
    normalized.sort();
    normalized.dedup();
    ensure!(normalized == extras, "WORKSPACE_DENIED");
    Ok(extras)
}

pub fn require_set(
    public: &PublicState,
    binding: &Value,
    org: &str,
    install: &str,
) -> Result<Value> {
    let primary = Path::new(
        binding["workspacePath"]
            .as_str()
            .context("WORKSPACE_DENIED")?,
    );
    let extras = bound_extras(binding)?;
    let mut identities = Vec::new();
    for root in std::iter::once(primary).chain(extras.iter().map(PathBuf::as_path)) {
        let canonical = public.require_grant(root, org, install)?;
        if binding.get("workspaceSetContract").is_some() {
            ensure!(canonical == root, "WORKSPACE_DENIED");
        }
        let grant = public
            .grants
            .iter()
            .find(|g| {
                g.path == canonical && g.organization_id == org && g.installation_id == install
            })
            .context("WORKSPACE_DENIED")?;
        identities.push(json!({"path":canonical,"device":grant.device,"inode":grant.inode}));
    }
    Ok(json!(identities))
}

pub fn same_set(left: &Value, right: &Value) -> bool {
    left.get("workspaceIdentities") == right.get("workspaceIdentities")
        && left.get("workspaceSetContract") == right.get("workspaceSetContract")
        && left.get("additionalWorkspacePaths") == right.get("additionalWorkspacePaths")
}

pub fn artifact_root(payload: &Value, declaration: &Value) -> Result<PathBuf> {
    let primary = PathBuf::from(
        payload["workspacePath"]
            .as_str()
            .context("WORKSPACE_DENIED")?,
    );
    let Some(root) = declaration.get("workspaceRoot") else {
        return Ok(primary);
    };
    ensure!(
        payload["workspaceSetContract"] == CONTRACT,
        "UNSUPPORTED_CAPABILITY"
    );
    let root = PathBuf::from(root.as_str().context("ARTIFACT_DECLARATION_INVALID")?);
    if root != primary && !bound_extras(payload)?.contains(&root) {
        bail!("ARTIFACT_PATH_DENIED");
    }
    Ok(root)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn canonical_dedup_keeps_disjoint_and_nested_roots() {
        let dir = tempfile::tempdir().unwrap();
        let primary = dir.path().join("a");
        let b = dir.path().join("b");
        std::fs::create_dir_all(primary.join("nested")).unwrap();
        std::fs::create_dir(&b).unwrap();
        let (root, extras) =
            canonical_set(&primary, &json!([b, primary, primary.join("nested"), b])).unwrap();
        assert_eq!(extras.len(), 2);
        assert!(!extras.contains(&root));
        assert!(canonical_set(&primary, &json!(["relative"])).is_err());
        assert!(canonical_set(&primary, &json!([dir.path().join("missing")])).is_err());
    }
    #[test]
    fn reviewed_inode_changes_remain_visible_even_after_regrant() {
        use crate::state::{PublicState, WorkspaceGrant};
        let directory = tempfile::tempdir().unwrap();
        let primary = directory.path().join("a");
        let additional = directory.path().join("b");
        std::fs::create_dir(&primary).unwrap();
        std::fs::create_dir(&additional).unwrap();
        let primary = primary.canonicalize().unwrap();
        let additional = additional.canonicalize().unwrap();
        let binding = json!({"workspacePath":primary,"workspaceSetContract":CONTRACT,"additionalWorkspacePaths":[additional]});
        let mut public = PublicState::default();
        public
            .grants
            .push(WorkspaceGrant::new(&primary, "org", "install", "a").unwrap());
        public
            .grants
            .push(WorkspaceGrant::new(&additional, "org", "install", "b").unwrap());
        let sealed = require_set(&public, &binding, "org", "install").unwrap();
        assert!(require_set(&public, &binding, "other", "install").is_err());
        assert!(require_set(&public, &binding, "org", "other").is_err());
        std::fs::rename(&additional, additional.with_extension("old")).unwrap();
        std::fs::create_dir(&additional).unwrap();
        assert!(require_set(&public, &binding, "org", "install").is_err());
        public.grants.pop();
        public
            .grants
            .push(WorkspaceGrant::new(&additional, "org", "install", "new").unwrap());
        assert_ne!(
            require_set(&public, &binding, "org", "install").unwrap(),
            sealed
        );
    }
    #[test]
    fn old_bindings_stay_single_root_and_artifacts_require_bound_selector() {
        let old = json!({"workspacePath":"/a"});
        assert!(bound_extras(&old).unwrap().is_empty());
        assert_eq!(
            artifact_root(&old, &json!({"path":"x"})).unwrap(),
            PathBuf::from("/a")
        );
        assert!(artifact_root(&old, &json!({"workspaceRoot":"/a"})).is_err());
        let multi = json!({"workspacePath":"/a","workspaceSetContract":CONTRACT,"additionalWorkspacePaths":["/b"]});
        assert_eq!(
            artifact_root(&multi, &json!({"workspaceRoot":"/b"})).unwrap(),
            PathBuf::from("/b")
        );
        assert!(artifact_root(&multi, &json!({"workspaceRoot":"/"})).is_err());
        assert!(!same_set(&old, &multi));
    }
}
