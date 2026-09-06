//! Owner-only durable state. Operational journals never contain Loomex credentials.
use anyhow::{Context, Result, bail};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
use uuid::Uuid;

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
pub fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
pub fn json_digest(v: &Value) -> String {
    digest(&serde_json::to_vec(v).expect("JSON serializes"))
}
pub fn state_dir() -> Result<PathBuf> {
    let path = match std::env::var_os("LOOMEX_STATE_DIR") {
        Some(p) => PathBuf::from(p),
        None => PathBuf::from(std::env::var_os("HOME").context("HOME is missing")?)
            .join(".local/share/loomex/runner"),
    };
    if !path.is_absolute() {
        bail!("state directory must be absolute")
    }
    Ok(path)
}
pub fn private_dir(path: &Path) -> Result<()> {
    if path.exists() {
        let m = fs::symlink_metadata(path)?;
        if !m.is_dir() || m.file_type().is_symlink() || m.uid() != unsafe { libc::geteuid() } {
            bail!("unsafe state directory")
        }
    } else {
        fs::create_dir_all(path)?;
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}
pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("missing state parent")?;
    private_dir(parent)?;
    if let Ok(m) = fs::symlink_metadata(path) {
        if !m.is_file() || m.uid() != unsafe { libc::geteuid() } {
            bail!("unsafe state file")
        }
    }
    let temp = parent.join(format!(".{}.tmp", Uuid::new_v4()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&temp, path)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}
pub fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    atomic_write(path, &serde_json::to_vec(value)?)
}
pub fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

#[derive(Clone, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceGrant {
    pub path: PathBuf,
    pub organization_id: String,
    pub installation_id: String,
    pub device: u64,
    pub inode: u64,
    pub granted_at: u64,
    pub idempotency_key: String,
}
impl WorkspaceGrant {
    pub fn new(path: &Path, org: &str, install: &str, key: &str) -> Result<Self> {
        let p = fs::canonicalize(path)?;
        let m = fs::metadata(&p)?;
        if !m.is_dir() {
            bail!("workspace must be directory")
        }
        Ok(Self {
            path: p,
            organization_id: org.into(),
            installation_id: install.into(),
            device: m.dev(),
            inode: m.ino(),
            granted_at: now(),
            idempotency_key: key.into(),
        })
    }
    pub fn validate(&self, path: &Path, org: &str, install: &str) -> Result<PathBuf> {
        let p = fs::canonicalize(path)?;
        let m = fs::metadata(&p)?;
        if p != self.path
            || org != self.organization_id
            || install != self.installation_id
            || m.dev() != self.device
            || m.ino() != self.inode
        {
            bail!("WORKSPACE_DENIED")
        }
        Ok(p)
    }
}
#[derive(Clone, Default, Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicState {
    pub active_organization: Option<String>,
    pub grants: Vec<WorkspaceGrant>,
}
impl PublicState {
    pub fn load(dir: &Path) -> Result<Self> {
        let p = dir.join("state.json");
        if p.exists() {
            read_json(&p)
        } else {
            Ok(Self::default())
        }
    }
    pub fn save(&self, dir: &Path) -> Result<()> {
        write_json(&dir.join("state.json"), self)
    }
    pub fn require_grant(&self, path: &Path, org: &str, install: &str) -> Result<PathBuf> {
        for g in &self.grants {
            if let Ok(p) = g.validate(path, org, install) {
                return Ok(p);
            }
        }
        bail!("WORKSPACE_DENIED")
    }
}
pub fn safe_error(code: &str, retryable: bool) -> Value {
    json!({"code":code,"message":code.replace('_'," ").to_ascii_lowercase(),"correlationId":Uuid::new_v4(),"retryable":retryable})
}

pub fn safe_error_with_data(code: &str, retryable: bool, data: Option<&Value>) -> Value {
    let mut error = safe_error(code, retryable);
    if let (Some(object), Some(data)) = (error.as_object_mut(), data) {
        object.insert("data".into(), data.clone());
    }
    error
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn grant_rejects_org_and_replaced_directory() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("work");
        fs::create_dir(&p).unwrap();
        let g = WorkspaceGrant::new(&p, "org", "install", "key").unwrap();
        assert!(g.validate(&p, "other", "install").is_err());
        fs::rename(&p, t.path().join("old")).unwrap();
        fs::create_dir(&p).unwrap();
        assert!(g.validate(&p, "org", "install").is_err());
    }
    #[test]
    fn state_is_private_and_atomic() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("s.json");
        write_json(&p, &json!({"a":1})).unwrap();
        assert_eq!(
            fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(read_json::<Value>(&p).unwrap()["a"], 1);
    }
}
