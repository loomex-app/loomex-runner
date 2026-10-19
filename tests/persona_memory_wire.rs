//! Native MCP process boundary tests. No daemon, provider, credential store or
//! backend starts; the only socket is an owner-owned synthetic fixture.
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Write},
    os::unix::net::UnixListener,
    process::{Command, Stdio},
};

fn request(
    input: &mut impl Write,
    output: &mut impl BufRead,
    id: u64,
    method: &str,
    params: Value,
) -> Option<Value> {
    writeln!(
        input,
        "{}",
        json!({"jsonrpc":"2.0","id":id,"method":method,"params":params})
    )
    .unwrap();
    input.flush().unwrap();
    let mut line = String::new();
    if output.read_line(&mut line).unwrap() == 0 {
        return None;
    }
    Some(serde_json::from_str(&line).unwrap())
}
#[test]
fn v2_bad_checksum_returns_tool_error_and_keeps_mcp_session_alive() {
    let temp = tempfile::tempdir().unwrap();
    let socket = temp.path().join("memory.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let capability = temp.path().join("capability.json");
    std::fs::write(&capability,json!({"socket":socket,"token":"f".repeat(64),"schemaVersion":"ai.persona-memory/v2","writeMemory":false}).to_string()).unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut line = String::new();
        BufReader::new(stream.try_clone().unwrap())
            .read_line(&mut line)
            .unwrap();
        let call: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(call["operation"], "read");
        let document =
            json!({"id":"10000000-0000-4000-8000-000000000001","revision":1,"content":"فارسی🙂é"})
                .to_string();
        let result = json!({"ok":true,"tool":"person_memory.read","schemaVersion":"ai.persona-memory/v2","memoryId":"10000000-0000-4000-8000-000000000001","revision":1,"budget":{"accountingContract":"o200k_base/v1","maxTokens":2048,"maxBytes":16384},"page":{"text":document,"encoding":"application/json; fragment=unicode-codepoints","start":0,"end":document.chars().count(),"totalChars":document.chars().count(),"documentSha256":"0".repeat(64),"complete":true,"nextCursor":null}});
        writeln!(
            stream,
            "{}",
            json!({"ok":true,"result":{"canonicalText":result.to_string(),"result":result}})
        )
        .unwrap();
    });
    let mut child = Command::new(env!("CARGO_BIN_EXE_loomex-runner"))
        .arg("--internal-persona-memory-mcp")
        .arg(capability)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    let listed = request(&mut input, &mut output, 1, "tools/list", json!({})).unwrap();
    let tools = listed["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 2);
    assert!(
        tools[1]["inputSchema"]["properties"]
            .get("cursor")
            .is_some()
    );
    let response = request(
        &mut input,
        &mut output,
        2,
        "tools/call",
        json!({"name":"read","arguments":{"memoryId":"10000000-0000-4000-8000-000000000001"}}),
    );
    let ping = if response.is_some() {
        request(&mut input, &mut output, 3, "ping", json!({}))
    } else {
        None
    };
    drop(input);
    let status = child.wait().unwrap();
    server.join().unwrap();
    assert!(
        response
            .as_ref()
            .is_some_and(|r| r["result"]["isError"] == true),
        "invalid pages must be explicit tool errors"
    );
    assert!(
        ping.is_some() && status.success(),
        "MCP must survive an invalid memory result"
    );
}

#[test]
fn v2_explicit_unicode_pages_preserve_canonical_text_and_read_only_catalog() {
    use sha2::{Digest, Sha256};
    let temp = tempfile::tempdir().unwrap();
    let socket = temp.path().join("memory.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let capability = temp.path().join("capability.json");
    std::fs::write(&capability,json!({"socket":socket,"token":"f".repeat(64),"schemaVersion":"ai.persona-memory/v2","writeMemory":false}).to_string()).unwrap();
    let id = "10000000-0000-4000-8000-000000000001";
    let document = format!(r#"{{"id":"{id}","revision":1,"content":"فارسی🙂é\u2028\\\""}}"#);
    let chars: Vec<char> = document.chars().collect();
    let split = 75;
    let mut pages = Vec::new();
    for (start, end) in [(0, split), (split, chars.len())] {
        // Intentionally retain a backend insertion order unlike serde Value's
        // sorted key order. The model receives precisely this text.
        let fragment =
            serde_json::to_string(&chars[start..end].iter().collect::<String>()).unwrap();
        pages.push(format!(r#"{{"schemaVersion":"ai.persona-memory/v2","ok":true,"tool":"person_memory.read","memoryId":"{id}","revision":1,"page":{{"text":{fragment},"encoding":"application/json; fragment=unicode-codepoints","start":{start},"end":{end},"totalChars":{},"documentSha256":"{}","complete":{},"nextCursor":{}}},"budget":{{"accountingContract":"o200k_base/v1","maxTokens":2048,"maxBytes":16384}}}}"#,chars.len(),hex::encode(Sha256::digest(document.as_bytes())),end==chars.len(),if end==chars.len(){"null"}else{"\"opaque-next\""}));
    }
    let expected = pages.clone();
    let server = std::thread::spawn(move || {
        for (index, canonical) in pages.into_iter().enumerate() {
            let (mut stream, _) = listener.accept().unwrap();
            let mut line = String::new();
            BufReader::new(stream.try_clone().unwrap())
                .read_line(&mut line)
                .unwrap();
            let call: Value = serde_json::from_str(&line).unwrap();
            assert_eq!(call["operation"], "read");
            if index == 1 {
                assert_eq!(call["arguments"]["cursor"], "opaque-next");
            }
            let result: Value = serde_json::from_str(&canonical).unwrap();
            writeln!(
                stream,
                "{}",
                json!({"ok":true,"result":{"canonicalText":canonical,"result":result}})
            )
            .unwrap();
        }
    });
    let mut child = Command::new(env!("CARGO_BIN_EXE_loomex-runner"))
        .arg("--internal-persona-memory-mcp")
        .arg(capability)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    for (index, text) in expected.iter().enumerate() {
        let mut args = json!({"memoryId":id});
        if index == 1 {
            args["cursor"] = json!("opaque-next");
        }
        let response = request(
            &mut input,
            &mut output,
            index as u64 + 1,
            "tools/call",
            json!({"name":"read","arguments":args}),
        )
        .unwrap();
        assert_eq!(response["result"]["content"][0]["text"], *text);
        assert_eq!(response["result"]["isError"], false);
        assert!(response["result"].get("structuredContent").is_none());
    }
    let denied=request(&mut input,&mut output,3,"tools/call",json!({"name":"write","arguments":{"content":"synthetic","type":"fact","idempotencyKey":"10000000-0000-4000-8000-000000000002"}})).unwrap();
    assert_eq!(denied["result"]["isError"], true);
    drop(input);
    assert!(child.wait().unwrap().success());
    server.join().unwrap();
}

#[test]
fn all_actual_backend_http_results_cross_native_mcp_without_reserialization() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/persona-memory-v2-producer.json")).unwrap();
    let cases = fixture["cases"].as_array().unwrap().clone();
    let temp = tempfile::tempdir().unwrap();
    let socket = temp.path().join("memory.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let capability = temp.path().join("capability.json");
    std::fs::write(&capability,json!({"socket":socket,"token":"f".repeat(64),"schemaVersion":"ai.persona-memory/v2","writeMemory":true}).to_string()).unwrap();
    let replies = cases.clone();
    let server = std::thread::spawn(move || {
        for case in replies {
            let (mut stream, _) = listener.accept().unwrap();
            let mut line = String::new();
            BufReader::new(stream.try_clone().unwrap())
                .read_line(&mut line)
                .unwrap();
            let call: Value = serde_json::from_str(&line).unwrap();
            assert_eq!(call["operation"], case["method"]);
            writeln!(stream,"{}",json!({"ok":true,"result":{"canonicalText":case["canonicalText"],"result":case["result"]}})).unwrap();
        }
    });
    let mut child = Command::new(env!("CARGO_BIN_EXE_loomex-runner"))
        .arg("--internal-persona-memory-mcp")
        .arg(capability)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut input = child.stdin.take().unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    for (index, case) in cases.iter().enumerate() {
        let method = case["method"].as_str().unwrap();
        let id = case["result"]["memoryId"]
            .as_str()
            .or_else(|| case["result"]["memory"]["id"].as_str())
            .unwrap_or("10000000-0000-4000-8000-000000000001");
        let args = match method {
            "search" => json!({"query":"fixed producer fixture"}),
            "read" => json!({"memoryId":id}),
            "write" => {
                json!({"content":"Fixed producer fixture.","type":"fact","idempotencyKey":uuid::Uuid::new_v4()})
            }
            "update" => {
                json!({"memoryId":id,"content":"Updated producer fixture.","idempotencyKey":uuid::Uuid::new_v4()})
            }
            _ => unreachable!(),
        };
        let response = request(
            &mut input,
            &mut output,
            index as u64 + 1,
            "tools/call",
            json!({"name":method,"arguments":args}),
        )
        .unwrap();
        assert_eq!(
            response["result"]["content"][0]["text"], case["canonicalText"],
            "{}",
            case["name"]
        );
        assert_eq!(
            response["result"]["isError"],
            case["result"]["ok"] != true,
            "{}",
            case["name"]
        );
    }
    drop(input);
    assert!(child.wait().unwrap().success());
    server.join().unwrap();
}
