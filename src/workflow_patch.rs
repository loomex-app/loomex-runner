//! Bounded node-field edits against an exact canonical draft snapshot.
//!
//! This deliberately does not implement arbitrary JSON Patch. A caller may
//! change fields within an existing node selected by its unique key, but may
//! not change the graph's node identities or top-level authority fields.
use anyhow::{Context, Result, bail, ensure};
use serde_json::Value;
use std::collections::HashSet;

pub const MAX_OPERATIONS: usize = 32;
pub const MAX_PATH_BYTES: usize = 256;
pub const MAX_NODE_KEY_BYTES: usize = 160;

pub fn verified_definition<'a>(
    detail: &'a Value,
    workflow_id: &str,
    expected_revision: u64,
    expected_checksum: &str,
) -> Result<&'a Value> {
    let selected = &detail["selectedVersion"];
    ensure!(
        selected["workflowId"] == workflow_id && selected["status"] == "draft",
        "WORKFLOW_PATCH_STALE"
    );
    ensure!(
        selected["revision"].as_u64() == Some(expected_revision)
            && selected["definitionChecksum"] == expected_checksum,
        "WORKFLOW_PATCH_STALE"
    );
    ensure!(selected["definition"].is_object(), "BACKEND_PROTOCOL_ERROR");
    Ok(&selected["definition"])
}

fn pointer_parts(path: &str) -> Result<Vec<String>> {
    ensure!(
        path.starts_with('/') && path.len() <= MAX_PATH_BYTES,
        "WORKFLOW_PATCH_INVALID"
    );
    let mut result = Vec::new();
    for raw in path[1..].split('/') {
        ensure!(!raw.is_empty(), "WORKFLOW_PATCH_INVALID");
        let mut part = String::new();
        let mut chars = raw.chars();
        while let Some(ch) = chars.next() {
            if ch == '~' {
                part.push(match chars.next() {
                    Some('0') => '~',
                    Some('1') => '/',
                    _ => bail!("WORKFLOW_PATCH_INVALID"),
                });
            } else {
                part.push(ch);
            }
        }
        ensure!(
            !part.is_empty() && !matches!(part.as_str(), "__proto__" | "prototype" | "constructor"),
            "WORKFLOW_PATCH_INVALID"
        );
        result.push(part);
    }
    ensure!(
        !matches!(result[0].as_str(), "key" | "id" | "kind" | "type"),
        "WORKFLOW_PATCH_INVALID"
    );
    Ok(result)
}

fn array_index(part: &str, len: usize, add: bool) -> Result<usize> {
    ensure!(
        !part.is_empty()
            && part.bytes().all(|b| b.is_ascii_digit())
            && (part == "0" || !part.starts_with('0')),
        "WORKFLOW_PATCH_INVALID"
    );
    let index = part
        .parse::<usize>()
        .map_err(|_| anyhow::anyhow!("WORKFLOW_PATCH_INVALID"))?;
    ensure!(
        index < len || (add && index == len),
        "WORKFLOW_PATCH_INVALID"
    );
    Ok(index)
}

fn child_mut<'a>(parent: &'a mut Value, part: &str) -> Result<&'a mut Value> {
    match parent {
        Value::Object(map) => map.get_mut(part).context("WORKFLOW_PATCH_INVALID"),
        Value::Array(items) => {
            let index = array_index(part, items.len(), false)?;
            items.get_mut(index).context("WORKFLOW_PATCH_INVALID")
        }
        _ => bail!("WORKFLOW_PATCH_INVALID"),
    }
}

fn edit(node: &mut Value, op: &Value) -> Result<()> {
    let path = op["path"].as_str().context("WORKFLOW_PATCH_INVALID")?;
    let parts = pointer_parts(path)?;
    let action = op["op"].as_str().context("WORKFLOW_PATCH_INVALID")?;
    let supplied = op.get("value");
    ensure!(
        match action {
            "add" | "replace" => supplied.is_some(),
            "remove" => supplied.is_none(),
            _ => false,
        },
        "WORKFLOW_PATCH_INVALID"
    );
    let mut parent = node;
    for part in &parts[..parts.len() - 1] {
        parent = child_mut(parent, part)?;
    }
    let last = &parts[parts.len() - 1];
    match parent {
        Value::Object(map) => match action {
            "add" => {
                ensure!(!map.contains_key(last), "WORKFLOW_PATCH_INVALID");
                map.insert(last.clone(), supplied.unwrap().clone());
            }
            "replace" => {
                let current = map.get_mut(last).context("WORKFLOW_PATCH_INVALID")?;
                *current = supplied.unwrap().clone();
            }
            "remove" => {
                ensure!(map.remove(last).is_some(), "WORKFLOW_PATCH_INVALID");
            }
            _ => unreachable!(),
        },
        Value::Array(items) => {
            let index = array_index(last, items.len(), action == "add")?;
            match action {
                "add" => items.insert(index, supplied.unwrap().clone()),
                "replace" => items[index] = supplied.unwrap().clone(),
                "remove" => {
                    items.remove(index);
                }
                _ => unreachable!(),
            }
        }
        _ => bail!("WORKFLOW_PATCH_INVALID"),
    }
    Ok(())
}

/// Return a new definition. No caller-owned definition is changed on failure.
pub fn apply(definition: &Value, operations: &[Value]) -> Result<Value> {
    ensure!(
        !operations.is_empty() && operations.len() <= MAX_OPERATIONS,
        "WORKFLOW_PATCH_INVALID"
    );
    let mut result = definition.clone();
    let nodes = result["nodes"]
        .as_array_mut()
        .context("WORKFLOW_PATCH_INVALID")?;
    let mut keys = HashSet::new();
    for node in nodes.iter() {
        let key = node["key"].as_str().context("WORKFLOW_PATCH_INVALID")?;
        ensure!(keys.insert(key.to_owned()), "WORKFLOW_PATCH_INVALID");
    }
    let mut targets: Vec<(String, Vec<String>)> = Vec::new();
    for op in operations {
        let node_key = op["nodeKey"].as_str().context("WORKFLOW_PATCH_INVALID")?;
        ensure!(
            !node_key.is_empty() && node_key.len() <= MAX_NODE_KEY_BYTES,
            "WORKFLOW_PATCH_INVALID"
        );
        let path = op["path"].as_str().context("WORKFLOW_PATCH_INVALID")?;
        // Repeated or overlapping paths have order-sensitive meaning and make
        // independent review of the edit set ambiguous.
        let parts = pointer_parts(path)?;
        ensure!(
            targets.iter().all(|(existing_node, existing_path)| {
                existing_node != node_key
                    || !(existing_path.starts_with(&parts) || parts.starts_with(existing_path))
            }),
            "WORKFLOW_PATCH_INVALID"
        );
        targets.push((node_key.to_owned(), parts));
        let node = nodes
            .iter_mut()
            .find(|node| node["key"] == node_key)
            .context("WORKFLOW_PATCH_INVALID")?;
        edit(node, op)?;
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn graph() -> Value {
        json!({"nodes":(0..21).map(|index|json!({"key":format!("n{index}"),"kind":"ai","config":{"prompt":format!("prompt {index}")},"outputSchema":{"required":["name","definition"]}})).collect::<Vec<_>>(),"transitions":[{"source":"n0","target":"n1"}],"executionPolicy":"host_user/v1"})
    }

    #[test]
    fn changes_only_selected_fields_in_large_graph() {
        let original = graph();
        let ops = vec![
            json!({"op":"replace","nodeKey":"n13","path":"/config/prompt","value":"new prompt"}),
            json!({"op":"replace","nodeKey":"n13","path":"/outputSchema/required","value":["definition"]}),
        ];
        let patched = apply(&original, &ops).unwrap();
        assert_eq!(patched["nodes"][13]["config"]["prompt"], "new prompt");
        assert_eq!(
            patched["nodes"][13]["outputSchema"]["required"],
            json!(["definition"])
        );
        assert_eq!(patched["nodes"][12], original["nodes"][12]);
        assert_eq!(patched["nodes"][14], original["nodes"][14]);
        assert_eq!(patched["transitions"], original["transitions"]);
        assert_eq!(patched["executionPolicy"], original["executionPolicy"]);
        assert_eq!(original["nodes"][13]["config"]["prompt"], "prompt 13");
    }

    #[test]
    fn rejects_unsafe_paths_and_ambiguous_edits() {
        let original = graph();
        for path in [
            "",
            "/key",
            "/kind",
            "/__proto__/x",
            "/config/constructor",
            "/config/~2",
            "/outputSchema/required/00",
            "/missing/x",
        ] {
            assert!(
                apply(
                    &original,
                    &[json!({"op":"replace","nodeKey":"n13","path":path,"value":1})]
                )
                .is_err(),
                "{path}"
            );
        }
        assert!(
            apply(
                &original,
                &[json!({"op":"remove","nodeKey":"unknown","path":"/config/prompt"})]
            )
            .is_err()
        );
        let mut duplicate_keys = original.clone();
        duplicate_keys["nodes"][14]["key"] = json!("n13");
        assert!(
            apply(
                &duplicate_keys,
                &[json!({"op":"replace","nodeKey":"n13","path":"/config/prompt","value":"x"})]
            )
            .is_err()
        );
        let duplicate = json!({"op":"replace","nodeKey":"n13","path":"/config/prompt","value":"x"});
        assert!(apply(&original, &[duplicate.clone(), duplicate]).is_err());
        assert!(
            apply(
                &original,
                &[
                    json!({"op":"replace","nodeKey":"n13","path":"/config","value":{"prompt":"x"}}),
                    json!({"op":"replace","nodeKey":"n13","path":"/config/prompt","value":"y"}),
                ]
            )
            .is_err()
        );
        assert!(
            apply(
                &original,
                &[json!({"op":"replace","nodeKey":"n13","path":"/config/prompt"})]
            )
            .is_err()
        );
        assert!(
            apply(
                &original,
                &[json!({"op":"remove","nodeKey":"n13","path":"/config/prompt","value":null})]
            )
            .is_err()
        );
    }

    #[test]
    fn draft_identity_requires_both_revision_and_checksum() {
        let detail = json!({"selectedVersion":{"workflowId":"w","status":"draft","revision":5,"definitionChecksum":"a".repeat(64),"definition":graph()}});
        assert!(verified_definition(&detail, "w", 5, &"a".repeat(64)).is_ok());
        assert_eq!(
            verified_definition(&detail, "w", 4, &"a".repeat(64))
                .unwrap_err()
                .to_string(),
            "WORKFLOW_PATCH_STALE"
        );
        assert_eq!(
            verified_definition(&detail, "w", 5, &"b".repeat(64))
                .unwrap_err()
                .to_string(),
            "WORKFLOW_PATCH_STALE"
        );
        assert_eq!(
            verified_definition(&detail, "other", 5, &"a".repeat(64))
                .unwrap_err()
                .to_string(),
            "WORKFLOW_PATCH_STALE"
        );
    }
}
