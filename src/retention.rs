//! Local generated evidence lifecycle; workspace files and provider stores are never touched.
use crate::state;
use anyhow::Result;
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
};
use uuid::Uuid;
const RETENTION_SECONDS: u64 = 30 * 24 * 60 * 60;
pub fn mark_deleted_tree(dir: &Path, run: &str, metadata: &Value) -> Result<()> {
    Uuid::parse_str(run)?;
    let deleted_runs = metadata["deletedExecutionIds"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("BACKEND_PROTOCOL_ERROR"))?;
    let runs: Vec<&str> = deleted_runs
        .iter()
        .map(|id| {
            let id = id
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("BACKEND_PROTOCOL_ERROR"))?;
            Uuid::parse_str(id)?;
            Ok(id)
        })
        .collect::<Result<_>>()?;
    anyhow::ensure!(runs.contains(&run), "BACKEND_PROTOCOL_ERROR");
    let root = metadata["preparationRootExecutionId"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("BACKEND_PROTOCOL_ERROR"))?;
    Uuid::parse_str(root)?;
    let preparation = metadata["preparationId"].as_str();
    if let Some(preparation) = preparation {
        Uuid::parse_str(preparation)?;
    }
    // The server returns the exact deleted subtree. A child deletion never revokes
    // sibling authority, even though all children share the same preparation.
    for id in &runs {
        mark_deleted(dir, id)?;
    }
    if root == run {
        if let Some(preparation) = preparation {
            state::write_json(
                &dir.join("preparation-tombstones")
                    .join(format!("{preparation}.json")),
                &json!({"executionId":run,"deletedAt":state::now()}),
            )?;
        }
    }
    Ok(())
}
pub fn mark_deleted(dir: &Path, run: &str) -> Result<()> {
    Uuid::parse_str(run)?;
    state::write_json(
        &dir.join("tombstones").join(format!("{run}.json")),
        &json!({"executionId":run,"deletedAt":state::now()}),
    )?;
    purge_responses(dir, Some(run), state::now())?;
    expire_operation_results(dir, Some(run), state::now())?;
    Ok(())
}
pub fn deleted(dir: &Path, job: &Value) -> bool {
    job["createdByExecutionId"].as_str().is_some_and(|id| {
        Uuid::parse_str(id).is_ok() && dir.join("tombstones").join(format!("{id}.json")).exists()
    }) || job["payload"]["preparationId"].as_str().is_some_and(|id| {
        Uuid::parse_str(id).is_ok()
            && dir
                .join("preparation-tombstones")
                .join(format!("{id}.json"))
                .exists()
    })
}
pub fn purge_job(path: &Path) -> Result<()> {
    let Some(dir) = path.parent() else {
        return Ok(());
    };
    if dir
        .file_name()
        .and_then(|s| s.to_str())
        .is_none_or(|s| Uuid::parse_str(s).is_err())
    {
        return Ok(());
    };
    let metadata = fs::symlink_metadata(dir)?;
    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        fs::remove_dir_all(dir)?;
    }
    Ok(())
}
pub fn sweep(dir: &Path, at: u64) -> Result<()> {
    let jobs = dir.join("jobs");
    if jobs.exists() {
        for entry in fs::read_dir(jobs)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let path = entry.path().join("journal.json");
            if !path.exists() {
                continue;
            };
            let record: Value = state::read_json(&path)?;
            // Undelivered, running and blocked evidence has no automatic expiration.
            if record["phase"] == "acknowledged"
                && record["acknowledgedAt"]
                    .as_u64()
                    .is_some_and(|time| at.saturating_sub(time) >= RETENTION_SECONDS)
            {
                purge_job(&path)?;
            }
        }
    }
    purge_responses(dir, None, at)?;
    expire_operation_results(dir, None, at)?;
    Ok(())
}
fn response_files(dir: &Path, id: &str) -> [PathBuf; 3] {
    [
        dir.join("responses").join(format!("{id}.json")),
        dir.join("responses").join(format!("{id}.sha256")),
        dir.join("responses").join(format!("{id}.meta.json")),
    ]
}
pub fn purge_response(dir: &Path, id: &str) -> Result<()> {
    Uuid::parse_str(id)?;
    for path in response_files(dir, id) {
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
fn purge_responses(dir: &Path, run: Option<&str>, at: u64) -> Result<()> {
    let responses = dir.join("responses");
    if !responses.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(responses)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(id) = name.strip_suffix(".meta.json") else {
            continue;
        };
        if Uuid::parse_str(id).is_err() {
            continue;
        }
        let metadata: Value = state::read_json(&entry.path())?;
        let remove = match run {
            Some(run) => metadata["executionId"] == run,
            None => metadata["lastAccessAt"]
                .as_u64()
                .is_some_and(|last| at.saturating_sub(last) >= RETENTION_SECONDS),
        };
        if remove {
            purge_response(dir, id)?;
        }
    }
    Ok(())
}
fn expire_operation_results(dir: &Path, run: Option<&str>, at: u64) -> Result<()> {
    let root = dir.join("operations");
    if !root.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(root)? {
        let path = entry?.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let mut record: Value = state::read_json(&path)?;
        if record.get("result").is_none() {
            continue;
        }
        let expired = match run {
            Some(run) => record["executionId"] == run,
            None => record["cachedAt"]
                .as_u64()
                .is_some_and(|time| at.saturating_sub(time) >= RETENTION_SECONDS),
        };
        if expired {
            record.as_object_mut().unwrap().remove("result");
            record["expired"] = json!(true);
            state::write_json(&path, &record)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn deletion_without_commit_reply_revokes_only_authoritative_subtree() {
        let t = tempfile::tempdir().unwrap();
        let root = Uuid::new_v4().to_string();
        let child = Uuid::new_v4().to_string();
        let sibling = Uuid::new_v4().to_string();
        let prep = Uuid::new_v4().to_string();
        let job = |id: &str| json!({"createdByExecutionId":id,"payload":{"preparationId":prep}});
        assert!(!t.path().join("run-bindings").exists());
        mark_deleted_tree(t.path(),&child,&json!({"preparationId":prep,"preparationRootExecutionId":root,"deletedExecutionIds":[child]})).unwrap();
        assert!(deleted(t.path(), &job(&child)));
        assert!(!deleted(t.path(), &job(&root)));
        assert!(!deleted(t.path(), &job(&sibling)));
        mark_deleted_tree(t.path(),&root,&json!({"preparationId":prep,"preparationRootExecutionId":root,"deletedExecutionIds":[root,child,sibling]})).unwrap();
        assert!(deleted(t.path(), &job(&root)));
        assert!(deleted(t.path(), &job(&sibling)));
        assert!(deleted(t.path(), &job(&Uuid::new_v4().to_string())));
    }
    #[test]
    fn retention_preserves_active_and_undelivered_evidence() {
        let t = tempfile::tempdir().unwrap();
        let now = RETENTION_SECONDS + 10;
        for (phase, expired) in [
            ("running", false),
            ("terminal_pending", false),
            ("delivery_blocked", false),
            ("acknowledged", true),
        ] {
            let id = Uuid::new_v4();
            let p = t
                .path()
                .join("jobs")
                .join(id.to_string())
                .join("journal.json");
            state::write_json(&p, &json!({"phase":phase,"acknowledgedAt":1})).unwrap();
            sweep(t.path(), now).unwrap();
            assert_eq!(p.exists(), !expired);
        }
        let workspace = t.path().join("workspace");
        fs::create_dir(&workspace).unwrap();
        fs::write(workspace.join("input"), b"owned input").unwrap();
        sweep(t.path(), now).unwrap();
        assert!(workspace.join("input").exists());
    }
    #[test]
    fn tombstone_does_not_touch_other_runs_or_workspace() {
        let t = tempfile::tempdir().unwrap();
        let run = Uuid::new_v4().to_string();
        let other = Uuid::new_v4().to_string();
        let id = Uuid::new_v4().to_string();
        state::write_json(
            &t.path().join("responses").join(format!("{id}.meta.json")),
            &json!({"executionId":run,"lastAccessAt":0}),
        )
        .unwrap();
        state::atomic_write(
            &t.path().join("responses").join(format!("{id}.json")),
            b"generated",
        )
        .unwrap();
        mark_deleted(t.path(), &run).unwrap();
        assert!(deleted(t.path(), &json!({"createdByExecutionId":run})));
        assert!(!deleted(t.path(), &json!({"createdByExecutionId":other})));
        assert!(
            !t.path()
                .join("responses")
                .join(format!("{id}.json"))
                .exists()
        );
    }
}
