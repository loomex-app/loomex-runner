//! Safe, provider-neutral activity signals derived from provider stdout.
//!
//! Provider stdout remains the durable diagnostic spool.  This module only
//! recognizes a small documented subset of JSONL activity envelopes and never
//! forwards provider text, commands, tool input, or reasoning content.
use serde_json::{Value, json};

const MAX_LINE_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Default)]
pub struct Decoder {
    bytes: Vec<u8>,
    line_offset: u64,
    discarding: bool,
}

impl Decoder {
    pub fn from_state(bytes: Vec<u8>, line_offset: u64, discarding: bool) -> Self {
        Self {
            bytes,
            line_offset,
            discarding,
        }
    }

    pub fn state(&self) -> (Vec<u8>, u64, bool) {
        (self.bytes.clone(), self.line_offset, self.discarding)
    }

    /// Consume one stdout chunk. Invalid, unknown, or overlong lines are
    /// deliberately ignored: progress is advisory and cannot affect a job.
    pub fn push(&mut self, bytes: &[u8], offset: u64, context: &Context) -> Vec<Value> {
        if self.bytes.is_empty() && !self.discarding {
            self.line_offset = offset;
        }
        let mut events = Vec::new();
        for (index, byte) in bytes.iter().enumerate() {
            let next_offset = offset.saturating_add(index as u64).saturating_add(1);
            if self.discarding {
                if *byte == b'\n' {
                    self.discarding = false;
                    self.line_offset = next_offset;
                }
                continue;
            }
            self.bytes.push(*byte);
            if *byte == b'\n' {
                let line_offset = self.line_offset;
                let line = std::mem::take(&mut self.bytes);
                self.line_offset = next_offset;
                if let Some(event) = parse_line(&line, line_offset, context) {
                    events.push(event);
                }
            } else if self.bytes.len() > MAX_LINE_BYTES {
                // Keep no unbounded private copy of malformed output. Ignore
                // the rest of this physical line, even across chunk/restart.
                self.bytes.clear();
                self.discarding = true;
                self.line_offset = next_offset;
            }
        }
        events
    }
}

#[derive(Clone, Debug)]
pub struct Context {
    pub job_id: String,
    pub node_execution_id: Option<String>,
    pub attempt: u64,
    pub provider: String,
    pub timestamp: u64,
}

impl Context {
    pub fn from_job(job: &Value, timestamp: u64) -> Self {
        let payload = &job["payload"];
        Self {
            job_id: job["id"].as_str().unwrap_or_default().to_owned(),
            node_execution_id: job["createdByNodeExecutionId"].as_str().map(str::to_owned),
            attempt: job["producerAttempt"]
                .as_u64()
                .or_else(|| job["attemptCount"].as_u64())
                .unwrap_or(1),
            provider: payload["provider"]
                .as_str()
                .unwrap_or_default()
                .to_ascii_lowercase(),
            timestamp,
        }
    }
}

fn parse_line(line: &[u8], offset: u64, context: &Context) -> Option<Value> {
    let line = std::str::from_utf8(line).ok()?.trim();
    if line.is_empty() {
        return None;
    }
    let value: Value = serde_json::from_str(line).ok()?;
    let (kind, summary) = match context.provider.as_str() {
        "codex" => codex_activity(&value),
        "claude" => claude_activity(&value),
        "gemini" => gemini_activity(&value),
        "antigravity" => antigravity_activity(&value),
        _ => None,
    }?;
    // Offset plus the parsed envelope is stable across a lost response and
    // retry.  It is deliberately independent of wall-clock time.
    let source = serde_json::to_vec(&value).ok()?;
    let digest = crate::state::digest(&source);
    Some(json!({
        "version": 1,
        "eventId": format!("{}:stdout:{}:{}", context.job_id, offset, &digest[..16]),
        "jobId": context.job_id,
        "nodeExecutionId": context.node_execution_id,
        "attempt": context.attempt,
        "timestamp": context.timestamp,
        "kind": kind,
        "summary": summary,
        "provenance": "provider_reported",
    }))
}

fn codex_activity(value: &Value) -> Option<(&'static str, &'static str)> {
    let event_type = value.get("type")?.as_str()?;
    match event_type {
        "thread.started" | "turn.started" => Some(("activity.started", "Provider started work")),
        "turn.completed" => Some(("activity.completed", "Provider completed work")),
        "turn.failed" => Some(("activity.failed", "Provider reported a failure")),
        "item.started" => codex_item(value, true),
        "item.completed" => codex_item(value, false),
        "item.updated" => {
            let item_type = value.get("item")?.get("type")?.as_str()?;
            match item_type {
                "reasoning" => Some(("activity.updated", "Provider is reasoning")),
                "command_execution" | "mcp_tool_call" | "tool_call" => {
                    Some(("tool.updated", "Provider is using a tool"))
                }
                "file_change" => Some(("activity.updated", "Provider is updating files")),
                _ => None,
            }
        }
        _ => None,
    }
}

fn codex_item(value: &Value, started: bool) -> Option<(&'static str, &'static str)> {
    let item_type = value.get("item")?.get("type")?.as_str()?;
    match (item_type, started) {
        ("reasoning", true) => Some(("activity.started", "Provider is reasoning")),
        ("reasoning", false) => Some(("activity.updated", "Provider finished reasoning")),
        ("command_execution" | "mcp_tool_call" | "tool_call", true) => {
            Some(("tool.started", "Provider is using a tool"))
        }
        ("command_execution" | "mcp_tool_call" | "tool_call", false) => {
            Some(("tool.completed", "Provider finished using a tool"))
        }
        ("file_change", true) => Some(("activity.started", "Provider is updating files")),
        ("file_change", false) => Some(("activity.updated", "Provider finished updating files")),
        ("agent_message", _) => Some(("activity.updated", "Provider is preparing a response")),
        _ => None,
    }
}

fn claude_activity(value: &Value) -> Option<(&'static str, &'static str)> {
    let event_type = value.get("type")?.as_str()?;
    match event_type {
        "system" => claude_system_activity(value),
        "result" => match value.get("is_error").and_then(Value::as_bool) {
            Some(true) => Some(("activity.failed", "Provider reported a failure")),
            _ => Some(("activity.completed", "Provider completed work")),
        },
        "error" => Some(("activity.failed", "Provider reported a failure")),
        "rate_limit_event" => Some(("waiting", "Provider is waiting to continue")),
        "tool_progress" | "tool_use_summary" => Some(("tool.updated", "Provider is using a tool")),
        "stream_event" => claude_stream_event(value.get("event")?),
        "assistant" => claude_assistant(value),
        _ => None,
    }
}

fn claude_system_activity(value: &Value) -> Option<(&'static str, &'static str)> {
    match value.get("subtype")?.as_str()? {
        "init" => Some(("activity.started", "Provider started work")),
        "status" => Some(("activity.updated", "Provider reported status")),
        "task_started" | "task_updated" | "task_progress" | "task_notification" => {
            Some(("activity.updated", "Provider reported activity"))
        }
        "api_retry" => Some(("waiting", "Provider is waiting to continue")),
        _ => None,
    }
}

fn claude_stream_event(event: &Value) -> Option<(&'static str, &'static str)> {
    match event.get("type")?.as_str()? {
        "content_block_start" => match event.get("content_block")?.get("type")?.as_str()? {
            "tool_use" => Some(("tool.started", "Provider is using a tool")),
            "thinking" => Some(("activity.started", "Provider is reasoning")),
            "text" => Some(("activity.updated", "Provider is preparing a response")),
            _ => None,
        },
        "content_block_stop" => Some(("activity.updated", "Provider completed an activity")),
        "message_start" => Some(("activity.started", "Provider started work")),
        _ => None,
    }
}

fn claude_assistant(value: &Value) -> Option<(&'static str, &'static str)> {
    let content = value.get("message")?.get("content")?.as_array()?;
    if content
        .iter()
        .any(|block| block.get("type").and_then(Value::as_str) == Some("tool_use"))
    {
        return Some(("tool.started", "Provider is using a tool"));
    }
    if content
        .iter()
        .any(|block| block.get("type").and_then(Value::as_str) == Some("thinking"))
    {
        return Some(("activity.started", "Provider is reasoning"));
    }
    Some(("activity.updated", "Provider is preparing a response"))
}

fn gemini_activity(value: &Value) -> Option<(&'static str, &'static str)> {
    let event_type = value.get("type")?.as_str()?;
    match event_type {
        "init" => Some(("activity.started", "Provider started work")),
        // Gemini emits partial assistant text as delta messages. Keeping each
        // token/chunk out of the durable event stream avoids waking followers
        // once per generated fragment.
        "message" if value.get("delta").and_then(Value::as_bool) == Some(true) => None,
        "message" => match value.get("role").and_then(Value::as_str) {
            Some("assistant") => Some(("activity.updated", "Provider is preparing a response")),
            Some("user") => Some(("activity.updated", "Provider is continuing work")),
            _ => None,
        },
        "tool_use" => Some(("tool.started", "Provider is using a tool")),
        "tool_result" => Some(("tool.completed", "Provider finished using a tool")),
        "error" if value.get("severity").and_then(Value::as_str) == Some("warning") => {
            Some(("warning", "Provider reported a warning"))
        }
        "error" => Some(("activity.failed", "Provider reported a failure")),
        "result" => match value.get("status").and_then(Value::as_str) {
            Some("success") if value.get("error").is_none() || value["error"].is_null() => {
                Some(("activity.completed", "Provider completed work"))
            }
            _ => Some(("activity.failed", "Provider reported a failure")),
        },
        _ => None,
    }
}

/// AGY's legacy response envelope is distinct from Gemini CLI JSONL. Keeping
/// the parser separate prevents historic Gemini journals from changing meaning.
fn antigravity_activity(value: &Value) -> Option<(&'static str, &'static str)> {
    if value.get("error").is_some_and(|error| !error.is_null()) {
        return Some(("activity.failed", "Provider reported a failure"));
    }
    if value
        .get("conversation_id")
        .and_then(Value::as_str)
        .is_some()
        && (value.get("response").is_some() || value.get("structured_output").is_some())
    {
        return Some(("activity.completed", "Provider completed work"));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context(provider: &str) -> Context {
        Context {
            job_id: "job-1".into(),
            node_execution_id: Some("node-1".into()),
            attempt: 2,
            provider: provider.into(),
            timestamp: 123,
        }
    }

    #[test]
    fn recognizes_documented_provider_activity_without_private_content() {
        let cases = [
            (
                "codex",
                r#"{"type":"item.started","item":{"type":"command_execution","command":"rm -rf private"}}"#,
                "tool.started",
            ),
            (
                "claude",
                r#"{"type":"stream_event","event":{"type":"content_block_start","content_block":{"type":"thinking","thinking":"private"}}}"#,
                "activity.started",
            ),
            (
                "gemini",
                r#"{"type":"tool_use","tool_name":"private command","parameters":{"secret":"nope"}}"#,
                "tool.started",
            ),
            (
                "antigravity",
                r#"{"conversation_id":"private-session","response":{"structured_output":{"secret":"nope"}}}"#,
                "activity.completed",
            ),
        ];
        for (provider, line, kind) in cases {
            let mut decoder = Decoder::default();
            let events = decoder.push(format!("{line}\n").as_bytes(), 0, &context(provider));
            assert_eq!(events.len(), 1);
            assert_eq!(events[0]["kind"], kind);
            assert_eq!(events[0]["provenance"], "provider_reported");
            assert!(!events[0].to_string().contains("private"));
            assert!(!events[0].to_string().contains("nope"));
        }
    }

    #[test]
    fn claude_unwraps_documented_partial_event_envelopes() {
        let cases = [
            (
                r#"{"type":"stream_event","event":{"type":"content_block_start","content_block":{"type":"tool_use","name":"private-tool"}}}"#,
                "tool.started",
            ),
            (
                r#"{"type":"stream_event","event":{"type":"content_block_stop"}}"#,
                "activity.updated",
            ),
        ];
        for (line, kind) in cases {
            let mut decoder = Decoder::default();
            let events = decoder.push(format!("{line}\n").as_bytes(), 0, &context("claude"));
            assert_eq!(events.len(), 1);
            assert_eq!(events[0]["kind"], kind);
            assert!(!events[0].to_string().contains("private"));
        }
    }

    #[test]
    fn claude_token_deltas_do_not_create_durable_progress_events() {
        let mut decoder = Decoder::default();
        let deltas = [
            r#"{"type":"stream_event","event":{"type":"content_block_delta","delta":{"type":"thinking_delta","thinking":"private"}}}"#,
            r#"{"type":"stream_event","event":{"type":"content_block_delta","delta":{"type":"text_delta","text":"private"}}}"#,
            r#"{"type":"stream_event","event":{"type":"message_delta","delta":{"stop_reason":null}}}"#,
        ];
        let stream = deltas.join("\n") + "\n";
        assert!(
            decoder
                .push(stream.as_bytes(), 0, &context("claude"))
                .is_empty()
        );
    }

    #[test]
    fn gemini_token_deltas_do_not_create_durable_progress_events() {
        let mut decoder = Decoder::default();
        let deltas = [
            r#"{"type":"message","role":"assistant","delta":true,"text":"private"}"#,
            r#"{"type":"message","role":"assistant","delta":true,"text":"more private"}"#,
            r#"{"type":"message","role":"assistant","delta":true,"text":"still private"}"#,
        ];
        let stream = deltas.join("\n") + "\n";
        assert!(
            decoder
                .push(stream.as_bytes(), 0, &context("gemini"))
                .is_empty()
        );
    }

    #[test]
    fn antigravity_does_not_reinterpret_gemini_stream_events() {
        let mut decoder = Decoder::default();
        assert!(
            decoder
                .push(
                    b"{\"type\":\"init\",\"session_id\":\"gemini-session\"}\n",
                    0,
                    &context("antigravity")
                )
                .is_empty()
        );
    }

    #[test]
    fn claude_system_init_is_the_only_provider_start_signal() {
        let cases = [
            (r#"{"type":"system","subtype":"init"}"#, "activity.started"),
            (
                r#"{"type":"system","subtype":"status"}"#,
                "activity.updated",
            ),
            (
                r#"{"type":"system","subtype":"task_progress"}"#,
                "activity.updated",
            ),
            (r#"{"type":"system","subtype":"api_retry"}"#, "waiting"),
            (r#"{"type":"rate_limit_event"}"#, "waiting"),
            (
                r#"{"type":"tool_progress","tool_id":"private"}"#,
                "tool.updated",
            ),
            (r#"{"type":"system","subtype":"unrecognized"}"#, ""),
        ];
        for (line, expected_kind) in cases {
            let mut decoder = Decoder::default();
            let events = decoder.push(format!("{line}\n").as_bytes(), 0, &context("claude"));
            if expected_kind.is_empty() {
                assert!(events.is_empty(), "{line}");
            } else {
                assert_eq!(events[0]["kind"], expected_kind, "{line}");
            }
        }
    }

    #[test]
    fn chunk_splits_keep_one_stable_event_identity() {
        let line = br#"{"type":"init","session_id":"session-secret"}"#;
        let mut split = Decoder::default();
        assert!(split.push(&line[..12], 0, &context("gemini")).is_empty());
        let events = split.push(&[&line[12..], b"\n"].concat(), 12, &context("gemini"));
        let mut whole = Decoder::default();
        let expected = whole.push(&[line.as_slice(), b"\n"].concat(), 0, &context("gemini"));
        assert_eq!(events[0]["eventId"], expected[0]["eventId"]);
    }

    #[test]
    fn only_turn_completion_marks_the_provider_complete() {
        let cases = [
            (
                r#"{"type":"item.completed","item":{"type":"reasoning"}}"#,
                "activity.updated",
            ),
            (
                r#"{"type":"item.completed","item":{"type":"file_change"}}"#,
                "activity.updated",
            ),
            (r#"{"type":"turn.completed"}"#, "activity.completed"),
        ];
        for (line, kind) in cases {
            let mut decoder = Decoder::default();
            let events = decoder.push(format!("{line}\n").as_bytes(), 0, &context("codex"));
            assert_eq!(events[0]["kind"], kind, "{line}");
        }
    }

    #[test]
    fn malformed_unknown_silence_and_oversized_line_are_ignored() {
        let mut decoder = Decoder::default();
        assert!(
            decoder
                .push(b"{bad}\n\n{\"type\":\"unknown\"}\n", 0, &context("codex"))
                .is_empty()
        );
        // A JSON-looking suffix is still part of the oversized physical line
        // and must not be accepted after the bounded buffer is discarded.
        assert!(
            decoder
                .push(&vec![b'x'; MAX_LINE_BYTES + 1], 30, &context("codex"))
                .is_empty()
        );
        let (buffer, line_offset, discarding) = decoder.state();
        assert!(discarding && buffer.is_empty());
        let mut decoder = Decoder::from_state(buffer, line_offset, discarding);
        let suffix = [br#"{"type":"turn.completed"}"#.as_slice(), b"\n"].concat();
        assert!(
            decoder
                .push(&suffix, 30 + MAX_LINE_BYTES as u64 + 1, &context("codex"))
                .is_empty()
        );
        let next_line = [br#"{"type":"turn.started"}"#.as_slice(), b"\n"].concat();
        let events = decoder.push(
            &next_line,
            30 + MAX_LINE_BYTES as u64 + 1 + suffix.len() as u64,
            &context("codex"),
        );
        assert_eq!(events[0]["kind"], "activity.started");
    }
}
