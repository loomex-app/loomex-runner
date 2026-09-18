use super::*;

pub(super) async fn stream_events(
    daemon: &Daemon,
    path: &Path,
    journal: &Arc<Mutex<Journal>>,
) -> Result<bool> {
    let sender = snapshot(journal)?.event_sender;
    let _sending = sender.lock().await;
    let mut sent = false;
    for stream in ["stdout", "stderr"] {
        let j = snapshot(journal)?;
        let offset = if stream == "stdout" {
            j.stdout_offset
        } else {
            j.stderr_offset
        };
        let mut file = match tokio::fs::File::open(path.parent().unwrap().join(stream)).await {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        file.seek(std::io::SeekFrom::Start(offset)).await?;
        let pending = if stream == "stdout" {
            j.stdout_pending
        } else {
            j.stderr_pending
        };
        let mut bytes = vec![0; pending.unwrap_or(32768)];
        let size = if let Some(size) = pending {
            file.read_exact(&mut bytes).await?;
            size
        } else {
            file.read(&mut bytes).await?
        };
        if size == 0 {
            continue;
        }
        bytes.truncate(size);
        if pending.is_none() {
            let mut locked = journal.lock().unwrap();
            if stream == "stdout" {
                locked.stdout_pending = Some(size);
                let mut decoder = crate::progress::Decoder::from_state(
                    std::mem::take(&mut locked.progress_buffer),
                    locked.progress_buffer_offset,
                    locked.progress_discarding,
                );
                let context = crate::progress::Context::from_job(&locked.job, now_millis());
                locked.progress_pending = Some(decoder.push(&bytes, offset, &context));
                (
                    locked.progress_buffer,
                    locked.progress_buffer_offset,
                    locked.progress_discarding,
                ) = decoder.state();
            } else {
                locked.stderr_pending = Some(size)
            }
            persist(path, &locked)?;
        }
        let current = snapshot(journal)?;
        let mut events = vec![
            json!({"eventType":"output","stream":stream,"message":"","payload":{"encoding":"base64","data":STANDARD.encode(&bytes),"offset":offset,"chunkId":format!("{stream}:{offset}")}}),
        ];
        if stream == "stdout" {
            for progress in current.progress_pending.clone().unwrap_or_default() {
                events.push(json!({"eventType":"ai.progress.v1","stream":"","message":"","payload":progress}));
            }
        }
        let mut body = fence(&current);
        body["events"] = Value::Array(events);
        daemon
            .backend(
                &j.organization,
                "POST",
                &format!("v1/jobs/{}/events/", j.job["id"].as_str().unwrap()),
                Some(body),
                None,
            )
            .await?;
        let mut locked = journal.lock().unwrap();
        if stream == "stdout" {
            locked.stdout_pending = None;
            locked.progress_pending = None;
            locked.stdout_offset = offset + size as u64
        } else {
            locked.stderr_pending = None;
            locked.stderr_offset = offset + size as u64
        }
        persist(path, &locked)?;
        sent = true;
    }
    Ok(sent)
}
pub(super) fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
pub(super) async fn drain_events(
    daemon: &Daemon,
    path: &Path,
    journal: &Arc<Mutex<Journal>>,
) -> Result<()> {
    while stream_events(daemon, path, journal).await? {}
    Ok(())
}
pub(super) async fn materialize_terminal(
    daemon: &Daemon,
    path: &Path,
    journal: &Arc<Mutex<Journal>>,
) -> Result<()> {
    let j = snapshot(journal)?;
    if crate::retention::deleted(&daemon.dir, &j.job) {
        bail!("RUN_DELETED")
    }
    let Some(mut result) = j.result.clone() else {
        return Ok(());
    };
    if j.phase == "terminal_pending" {
        return Ok(());
    }
    if j.job["kind"] == "http.request" {
        if let Some(local) = result.get("bodyPath").and_then(Value::as_str) {
            let path = PathBuf::from(local);
            let name = format!(
                "{}-http-response.bin",
                j.job["id"].as_str().context("BACKEND_PROTOCOL_ERROR")?
            );
            let content_type = result["bodyContentType"]
                .as_str()
                .filter(|value| !value.is_empty())
                .unwrap_or("application/octet-stream");
            // The local path remains in the durable journal until the
            // transfer's complete endpoint returns its artifact id. If this
            // process stops mid-upload, `upload` resumes from the backend's
            // offset using its stable job/body idempotency key.
            let artifact =
                upload(daemon, &j, &path, &name, content_type, "http-response-body").await?;
            result
                .as_object_mut()
                .context("BACKEND_PROTOCOL_ERROR")?
                .remove("bodyPath");
            result
                .as_object_mut()
                .context("BACKEND_PROTOCOL_ERROR")?
                .remove("bodyContentType");
            result
                .as_object_mut()
                .context("BACKEND_PROTOCOL_ERROR")?
                .remove("bodySizeBytes");
            result["bodyStorage"] = json!("artifact");
            result["bodyRef"] = json!({
                "schemaVersion": HTTP_BODY_REF_SCHEMA,
                "artifactId": artifact["artifactId"],
                "name": artifact["name"],
                "sizeBytes": artifact["sizeBytes"],
                "checksumSha256": artifact["checksumSha256"],
                "contentType": artifact["contentType"],
            });
        }
        let mut locked = journal.lock().unwrap();
        locked.result = Some(result);
        locked.transition(JournalPhase::TerminalPending)?;
        persist(path, &locked)?;
        return Ok(());
    }
    for stream in ["stdout", "stderr"] {
        let local = PathBuf::from(
            result[format!("{stream}Path")]
                .as_str()
                .context("SPOOL_MISSING")?,
        );
        let artifact = upload(
            daemon,
            &j,
            &local,
            &format!("{}-{stream}.log", j.job["id"].as_str().unwrap()),
            "application/octet-stream",
            &format!("stream-{stream}"),
        )
        .await?;
        result[format!("{stream}ArtifactId")] = artifact["artifactId"].clone();
        result
            .as_object_mut()
            .unwrap()
            .remove(&format!("{stream}Path"));
    }
    let expected = j.job["payload"]["expectedExitCodes"]
        .as_array()
        .cloned()
        .unwrap_or_else(|| vec![json!(0)]);
    if expected.contains(&result["exitCode"]) && result["cancelled"] != true {
        let mut artifacts = Vec::new();
        if let Some(declarations) = j.job["payload"]["artifactOutputs"].as_array() {
            let workspace = daemon
                .granted(
                    Path::new(
                        j.job["payload"]["workspacePath"]
                            .as_str()
                            .context("WORKSPACE_DENIED")?,
                    ),
                    &j.organization,
                )
                .await?;
            for (index, item) in declarations.iter().enumerate() {
                let relative = Path::new(
                    item["path"]
                        .as_str()
                        .context("ARTIFACT_DECLARATION_INVALID")?,
                );
                if relative.is_absolute()
                    || relative
                        .components()
                        .any(|c| !matches!(c, std::path::Component::Normal(_)))
                {
                    bail!("ARTIFACT_DECLARATION_INVALID")
                }
                let resolved = std::fs::canonicalize(workspace.join(relative))
                    .map_err(|_| anyhow::anyhow!("DECLARED_ARTIFACT_MISSING"))?;
                if !resolved.starts_with(&workspace) || !std::fs::metadata(&resolved)?.is_file() {
                    bail!("ARTIFACT_PATH_DENIED")
                }
                let name = item["name"]
                    .as_str()
                    .context("ARTIFACT_DECLARATION_INVALID")?;
                let mime = item["contentType"]
                    .as_str()
                    .unwrap_or("application/octet-stream");
                let mut artifact = upload(
                    daemon,
                    &j,
                    &resolved,
                    name,
                    mime,
                    &format!("declared-{index}"),
                )
                .await?;
                artifact["path"] = json!(relative);
                artifacts.push(artifact);
            }
        }
        result["artifacts"] = json!(artifacts);
    }
    let mut locked = journal.lock().unwrap();
    locked.result = Some(result);
    locked.transition(JournalPhase::TerminalPending)?;
    persist(path, &locked)?;
    Ok(())
}
pub(super) async fn upload(
    daemon: &Daemon,
    j: &Journal,
    path: &Path,
    name: &str,
    content_type: &str,
    tag: &str,
) -> Result<Value> {
    use sha2::{Digest, Sha256};
    let mut file = std::fs::File::open(path)?;
    let size = file.metadata()?.len();
    let mut hasher = Sha256::new();
    let mut buf = vec![0; 262144];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let hash = hex::encode(hasher.finalize());
    let id = j.job["id"].as_str().context("BACKEND_PROTOCOL_ERROR")?;
    let key = format!("job-{id}-{tag}");
    let body = json!({"executionId":j.job["createdByExecutionId"],"nodeExecutionId":j.job["createdByNodeExecutionId"],"jobId":id,"name":name,"contentType":content_type,"sizeBytes":size,"checksumSha256":hash,"idempotencyKey":key});
    let response = daemon
        .backend(
            &j.organization,
            "POST",
            "v2/artifact-transfers/",
            Some(body),
            Some(&key),
        )
        .await?;
    let transfer = response["transferId"]
        .as_str()
        .context("BACKEND_PROTOCOL_ERROR")?;
    let mut offset = response["offset"]
        .as_u64()
        .context("BACKEND_PROTOCOL_ERROR")?;
    let mut input = tokio::fs::File::open(path).await?;
    input.seek(std::io::SeekFrom::Start(offset)).await?;
    while offset < size {
        if crate::retention::deleted(&daemon.dir, &j.job) {
            bail!("RUN_DELETED")
        }
        let n = input.read(&mut buf).await?;
        if n == 0 {
            bail!("SPOOL_CHANGED")
        };
        let response = daemon
            .backend(
                &j.organization,
                "PUT",
                &format!("v2/artifact-transfers/{transfer}/"),
                Some(json!({"offset":offset,"dataBase64":STANDARD.encode(&buf[..n])})),
                None,
            )
            .await?;
        let next = response["offset"]
            .as_u64()
            .context("BACKEND_PROTOCOL_ERROR")?;
        if next != offset + n as u64 {
            bail!("BACKEND_PROTOCOL_ERROR")
        };
        offset = next;
    }
    let response = daemon
        .backend(
            &j.organization,
            "POST",
            &format!("v2/artifact-transfers/{transfer}/complete/"),
            Some(json!({})),
            None,
        )
        .await?;
    Ok(
        json!({"artifactId":response["artifactId"].as_str().context("BACKEND_PROTOCOL_ERROR")?,"name":name,"contentType":content_type,"sizeBytes":size,"checksumSha256":hash}),
    )
}
