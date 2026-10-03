//! Job-scoped, explicitly public AI status. The provider's final JSON and
//! diagnostic stdout remain independent of this narrow MCP tool channel.
use super::*;
use serde::{Deserialize, Serialize};
use std::os::unix::fs::PermissionsExt;
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    net::{UnixListener, UnixStream},
    task::JoinHandle,
};
use unicode_general_category::{GeneralCategory, get_general_category};

pub(super) const SCHEMA: &str = "ai.public-status/v1";
pub(super) const EVENT_TYPE: &str = "ai.public-status.v1";
// Source support alone is not a provider qualification. Keep the runner's
// capability off until a pinned real Codex invocation proves tool discovery,
// status delivery, and strict final JSON together. Claude is also unqualified.
pub(super) const LIVE_PROVIDER_QUALIFIED: bool = false;
const MIN_INTERVAL_MS: u64 = 10_000;
const MAX_TEXT_CHARS: usize = 240;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Capability {
    socket: PathBuf,
    token: String,
}

pub(super) fn enabled(job: &Value) -> bool {
    job["payload"]["publicStatus"] == json!({"schemaVersion":SCHEMA,"enabled":true})
}

pub(super) fn codex_opted_in(job: &Value) -> bool {
    job["payload"]["provider"] == "codex" && enabled(job)
}

pub(super) fn dispatch_enabled(job: &Value) -> bool {
    LIVE_PROVIDER_QUALIFIED && codex_opted_in(job)
}

fn validated_text(value: &str) -> Result<String> {
    if value.chars().any(|character| {
        matches!(
            get_general_category(character),
            GeneralCategory::Control
                | GeneralCategory::Format
                | GeneralCategory::PrivateUse
                | GeneralCategory::Unassigned
                | GeneralCategory::Surrogate
        ) || matches!(character, '\u{2028}' | '\u{2029}')
    }) {
        bail!("PUBLIC_STATUS_TEXT_INVALID")
    }
    let text = value.trim();
    if text.is_empty() || text.chars().count() > MAX_TEXT_CHARS {
        bail!("PUBLIC_STATUS_TEXT_INVALID")
    }
    Ok(text.to_owned())
}

pub(super) fn accept_status(
    path: &Path,
    journal: &Arc<Mutex<Journal>>,
    message: &str,
) -> Result<()> {
    let text = validated_text(message)?;
    update_sync(path, journal, |record| {
        let expiry = record.job["leasedUntilEpochMs"].as_u64().unwrap_or(0);
        if record.phase != JournalPhase::Running
            || record.recovery_session.is_some()
            || record.job["status"] == "canceling"
            || expiry <= now_millis()
            || record.job["createdByNodeExecutionId"].as_str().is_none()
            || !enabled(&record.job)
        {
            bail!("PUBLIC_STATUS_NOT_ACTIVE")
        }
        record.public_status_latest = Some(json!({
            "text":text,
            "timestamp":now_millis(),
        }));
        Ok(())
    })
}

pub(super) struct StatusServer {
    pub(super) socket: PathBuf,
    pub(super) capability_file: PathBuf,
    pub(super) gate: Arc<Mutex<bool>>,
    task: JoinHandle<()>,
}

impl StatusServer {
    pub(super) fn start(
        _daemon: &Daemon,
        path: &Path,
        journal: Arc<Mutex<Journal>>,
    ) -> Result<Self> {
        // AF_UNIX paths have a small platform limit. Keep the socket in a
        // short, owner-only temporary directory even when the job state root
        // is nested deeply; the durable job still owns the acceptance check.
        let sockets = Path::new("/tmp").join(format!("loomex-public-status-{}", unsafe {
            libc::geteuid()
        }));
        state::private_dir(&sockets)?;
        let socket = sockets.join(format!("{}.sock", Uuid::new_v4().simple()));
        let listener = UnixListener::bind(&socket)?;
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))?;
        let capability_file = path
            .parent()
            .context("PUBLIC_STATUS_UNAVAILABLE")?
            .join(format!("public-status-{}.json", Uuid::new_v4().simple()));
        // The capability is ephemeral and has no backend credential. A unique
        // file in the owner-only job directory avoids placing the token in
        // process arguments or the provider's final output.
        let token = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        if let Err(error) = state::write_json(
            &capability_file,
            &Capability {
                socket: socket.clone(),
                token: token.clone(),
            },
        ) {
            let _ = std::fs::remove_file(&socket);
            return Err(error);
        }
        let gate = Arc::new(Mutex::new(true));
        let handler_gate = gate.clone();
        let path = path.to_owned();
        let task = tokio::spawn(async move {
            let mut handlers = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else { break };
                        if stream.peer_cred().ok().is_none_or(|peer| peer.uid() != unsafe { libc::geteuid() }) {
                            continue;
                        }
                        if handlers.len() >= 16 { continue; }
                        let path = path.clone();
                        let journal = journal.clone();
                        let token = token.clone();
                        let gate = handler_gate.clone();
                        handlers.spawn(async move {
                            let _ = tokio::time::timeout(
                                Duration::from_secs(3),
                                handle_status_connection(stream, &path, &journal, &token, &gate),
                            ).await;
                        });
                    }
                    _ = handlers.join_next(), if !handlers.is_empty() => {}
                }
            }
        });
        Ok(Self {
            socket,
            capability_file,
            gate,
            task,
        })
    }

    pub(super) fn configure_request(
        &self,
        request: &mut ExecutionRequest,
        provider: &str,
    ) -> Result<()> {
        let binary = std::env::current_exe()?;
        let binary = binary.to_str().context("PUBLIC_STATUS_UNAVAILABLE")?;
        let capability_file = self
            .capability_file
            .to_str()
            .context("PUBLIC_STATUS_UNAVAILABLE")?;
        let args = json!(["--internal-public-status-mcp", capability_file]).to_string();
        match provider {
            "codex" => {
                let name = format!("loomex_progress_{}", Uuid::new_v4().simple());
                let prompt = request.argv.pop().context("PUBLIC_STATUS_UNAVAILABLE")?;
                request.argv.extend([
                    "-c".into(),
                    format!(
                        "mcp_servers.{name}.command={}",
                        serde_json::to_string(binary)?
                    ),
                    "-c".into(),
                    format!("mcp_servers.{name}.args={args}"),
                    "-c".into(),
                    format!("mcp_servers.{name}.enabled_tools=[\"report_status\"]"),
                    prompt,
                ]);
            }
            "claude" => {
                let config = request.output_dir.join("public-status-mcp.json");
                state::write_json(
                    &config,
                    &json!({"mcpServers":{
                        format!("loomex_progress_{}", Uuid::new_v4().simple()):{
                            "command":binary,"args":["--internal-public-status-mcp",capability_file]
                        }
                    }}),
                )?;
                request
                    .argv
                    .extend(["--mcp-config".into(), config.to_string_lossy().into_owned()]);
            }
            _ => bail!("PUBLIC_STATUS_PROVIDER_UNSUPPORTED"),
        }
        Ok(())
    }
}

impl Drop for StatusServer {
    fn drop(&mut self) {
        // Synchronously close acceptance before returning to the executor.
        // A handler already persisting its status finishes before this lock
        // releases; handlers that run afterward observe the closed gate.
        *self
            .gate
            .lock()
            .unwrap_or_else(|poison| poison.into_inner()) = false;
        self.task.abort();
        let _ = std::fs::remove_file(&self.socket);
        let _ = std::fs::remove_file(&self.capability_file);
    }
}

async fn handle_status_connection(
    stream: UnixStream,
    path: &Path,
    journal: &Arc<Mutex<Journal>>,
    expected_token: &str,
    gate: &Arc<Mutex<bool>>,
) -> Result<()> {
    let (read, mut write) = stream.into_split();
    let reader = BufReader::new(read);
    let mut bytes = Vec::new();
    reader.take(4097).read_until(b'\n', &mut bytes).await?;
    let result = if bytes.len() > 4096 || !bytes.ends_with(b"\n") {
        Err(anyhow::anyhow!("PUBLIC_STATUS_TEXT_INVALID"))
    } else {
        match serde_json::from_slice::<Value>(&bytes) {
            Ok(value) if value["token"] == expected_token => match value["message"].as_str() {
                Some(message) => {
                    let path = path.to_owned();
                    let journal = journal.clone();
                    let gate = gate.clone();
                    let message = message.to_owned();
                    let owner = snapshot(&journal)?.durable_writer.own();
                    blocking_io(move || {
                        let _owner = owner;
                        accept_if_open(&gate, &path, &journal, &message)
                    })
                    .await
                }
                None => Err(anyhow::anyhow!("PUBLIC_STATUS_TEXT_INVALID")),
            },
            _ => Err(anyhow::anyhow!("PUBLIC_STATUS_NOT_ACTIVE")),
        }
    };
    let response = json!({"ok":result.is_ok()});
    write.write_all(format!("{response}\n").as_bytes()).await?;
    Ok(())
}

pub(super) fn accept_if_open(
    gate: &Mutex<bool>,
    path: &Path,
    journal: &Arc<Mutex<Journal>>,
    message: &str,
) -> Result<()> {
    let open = gate
        .lock()
        .map_err(|_| anyhow::anyhow!("PUBLIC_STATUS_NOT_ACTIVE"))?;
    if !*open {
        bail!("PUBLIC_STATUS_NOT_ACTIVE")
    }
    accept_status(path, journal, message)
}

pub(super) fn promote_latest(path: &Path, journal: &Arc<Mutex<Journal>>) -> Result<Option<Value>> {
    let current = snapshot(journal)?;
    if let Some(pending) = current.public_status_pending {
        return Ok(Some(pending));
    }
    if current.public_status_latest.is_none()
        || current
            .public_status_last_sent_at_ms
            .saturating_add(MIN_INTERVAL_MS)
            > now_millis()
    {
        return Ok(None);
    }
    update_sync(path, journal, |record| {
        if let Some(pending) = &record.public_status_pending {
            return Ok(Some(pending.clone()));
        }
        if record.public_status_latest.is_none()
            || record
                .public_status_last_sent_at_ms
                .saturating_add(MIN_INTERVAL_MS)
                > now_millis()
        {
            return Ok(None);
        }
        let latest = record.public_status_latest.take().unwrap();
        let previous_seq = record.public_status_next_sequence;
        record.public_status_next_sequence = previous_seq.saturating_add(1);
        let pending = json!({
            "version":1,
            "eventId":format!("{}:public-status:{}",record.job["id"].as_str().unwrap_or(""),record.public_status_next_sequence),
            "jobId":record.job["id"],
            "nodeExecutionId":record.job["createdByNodeExecutionId"],
            "attempt":record.job["producerAttempt"].as_u64().or_else(||record.job["attemptCount"].as_u64()).unwrap_or(1),
            "timestamp":latest["timestamp"],
            "text":latest["text"],
            "provenance":"ai_reported",
        });
        record.public_status_pending = Some(pending.clone());
        Ok(Some(pending))
    })
}

pub(super) async fn send_pending_status(
    daemon: &Daemon,
    path: &Path,
    journal: &Arc<Mutex<Journal>>,
    sender: Arc<tokio::sync::OwnedMutexGuard<()>>,
) -> Result<bool> {
    let quiet = snapshot(journal)?;
    if quiet.public_status_pending.is_none() && quiet.public_status_latest.is_none() {
        return Ok(false);
    }
    let status_path = path.to_owned();
    let status_journal = journal.clone();
    let promotion_sender = sender.clone();
    let Some(pending) = job_io(daemon, journal, move || {
        let _sender = promotion_sender;
        promote_latest(&status_path, &status_journal)
    })
    .await?
    else {
        return Ok(false);
    };
    let current = snapshot(journal)?;
    let mut body = fence(&current);
    body["events"] = json!([{"eventType":EVENT_TYPE,"stream":"","message":"","payload":pending}]);
    backend_job(
        daemon,
        journal,
        &current,
        "POST",
        &format!(
            "v1/jobs/{}/events/",
            current.job["id"].as_str().unwrap_or("")
        ),
        Some(body),
        None,
    )
    .await?;
    update_while_sending(daemon, path, journal, sender, move |record| {
        if record.public_status_pending.as_ref() == Some(&pending) {
            record.public_status_pending = None;
            record.public_status_last_sent_at_ms = now_millis();
        }
        Ok(())
    })
    .await?;
    Ok(true)
}

/// Restricted MCP stdio process: it owns no backend credential and forwards
/// only one validated public message to its job's private runner socket.
pub async fn serve_mcp(capability_file: &Path) -> Result<()> {
    if !capability_file.is_absolute() {
        bail!("PUBLIC_STATUS_UNAVAILABLE")
    }
    let capability: Capability = state::read_json(capability_file)?;
    if !capability.socket.is_absolute() || capability.token.len() != 64 {
        bail!("PUBLIC_STATUS_UNAVAILABLE")
    }
    let mut input = BufReader::new(tokio::io::stdin());
    let mut output = tokio::io::stdout();
    loop {
        let mut line = Vec::new();
        if input.read_until(b'\n', &mut line).await? == 0 {
            return Ok(());
        }
        if line.len() > 16 * 1024 {
            bail!("PUBLIC_STATUS_PROTOCOL_INVALID")
        }
        let request: Value = serde_json::from_slice(&line)
            .map_err(|_| anyhow::anyhow!("PUBLIC_STATUS_PROTOCOL_INVALID"))?;
        let Some(id) = request.get("id") else {
            continue;
        };
        let method = request["method"].as_str().unwrap_or("");
        let result = match method {
            "initialize" => {
                json!({"protocolVersion":request["params"]["protocolVersion"].as_str().unwrap_or("2025-06-18"),"capabilities":{"tools":{"listChanged":false}},"serverInfo":{"name":"loomex-public-status","version":"1.0.0"}})
            }
            "tools/list" => {
                json!({"tools":[{"name":"report_status","description":"Report one short, intentionally public status to the workflow user. Do not include private reasoning, commands, paths, credentials, or secrets. This does not affect the final JSON response.","inputSchema":{"type":"object","properties":{"message":{"type":"string","minLength":1,"maxLength":240}},"required":["message"],"additionalProperties":false}}]})
            }
            "tools/call" => {
                let accepted = if request["params"]["name"] == "report_status" {
                    if let Some(message) = request["params"]["arguments"]["message"].as_str() {
                        if validated_text(message).is_ok() {
                            tokio::time::timeout(Duration::from_secs(3), async {
                                let mut stream = UnixStream::connect(&capability.socket).await?;
                                let wire =
                                    json!({"message":message,"token":capability.token}).to_string();
                                stream.write_all(format!("{wire}\n").as_bytes()).await?;
                                let mut answer = String::new();
                                BufReader::new(stream).read_line(&mut answer).await?;
                                Ok::<_, std::io::Error>(
                                    serde_json::from_str::<Value>(&answer)
                                        .ok()
                                        .is_some_and(|value| value["ok"] == true),
                                )
                            })
                            .await
                            .ok()
                            .and_then(Result::ok)
                            .unwrap_or(false)
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                } else {
                    false
                };
                json!({"content":[{"type":"text","text":if accepted {"Status reported."} else {"Status not accepted."}}],"isError":!accepted})
            }
            "ping" => json!({}),
            "prompts/list" => json!({"prompts":[]}),
            "resources/list" => json!({"resources":[]}),
            _ => {
                let response = json!({"jsonrpc":"2.0","id":id,"error":{"code":-32601,"message":"Method not found"}});
                output.write_all(format!("{response}\n").as_bytes()).await?;
                output.flush().await?;
                continue;
            }
        };
        let response = json!({"jsonrpc":"2.0","id":id,"result":result});
        output.write_all(format!("{response}\n").as_bytes()).await?;
        output.flush().await?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_validation_matches_public_contract() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/public-status-text-v1.json"
        ))
        .unwrap();
        for case in fixture["cases"].as_array().unwrap() {
            let input = case["input"].as_str().unwrap();
            let expected = case["normalized"].as_str();
            assert_eq!(
                validated_text(input).ok().as_deref(),
                expected,
                "{}",
                case["name"]
            );
        }
        assert!(validated_text(&"x".repeat(241)).is_err());
        assert_eq!(
            validated_text(&"😀".repeat(240)).unwrap().chars().count(),
            240
        );
    }
}
