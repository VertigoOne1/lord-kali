// JSONL logging. Best-effort: any failure here is swallowed so a gate decision already
// printed to Claude Code is never blocked or altered by a logging problem.

use crate::config::{expand_tilde, LogConfig};
use crate::decision::{deciding_index, InvocationTrace};

pub(crate) const DEFAULT_LOG_PATH: &str = "~/.local/state/lord-kali/hook.jsonl";

fn append_log_line(log_config: &LogConfig, line: String) {
    let path_str = log_config.path.as_deref().unwrap_or(DEFAULT_LOG_PATH);
    let expanded = expand_tilde(path_str);

    if let Some(parent) = expanded.parent() {
        if std::fs::create_dir_all(parent).is_err() {
            return;
        }
    }

    use std::io::Write;
    let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&expanded)
    else {
        return;
    };

    let _ = writeln!(file, "{}", line);
}

pub(crate) fn log_invocation(log_config: &LogConfig, input: &str, trace: &InvocationTrace) {
    append_log_line(log_config, timestamped_log_line(input, trace));
}

// PostToolUse fires only after a tool actually executed (auto-allowed or user-approved
// at the prompt). It cannot gate, so this path only logs, with no decision and no stdout.
pub(crate) fn log_post_tool_use(log_config: &LogConfig, input: &str) {
    append_log_line(log_config, post_tool_use_log_line(input));
}

pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// Parse the hook input into an object, stamp ts_ms + lk_event, then let the caller add
// event-specific fields. Non-object input is passed through trimmed.
fn shape_log_line(
    input: &str,
    event: &str,
    add_fields: impl FnOnce(&mut serde_json::Map<String, serde_json::Value>),
) -> String {
    match serde_json::from_str::<serde_json::Value>(input) {
        Ok(serde_json::Value::Object(mut map)) => {
            map.insert("ts_ms".to_string(), serde_json::json!(now_ms()));
            map.insert("lk_event".to_string(), serde_json::json!(event));
            add_fields(&mut map);
            serde_json::Value::Object(map).to_string()
        }
        _ => input.trim().to_string(),
    }
}

fn post_tool_use_log_line(input: &str) -> String {
    shape_log_line(input, "post_tool_use", |map| {
        map.remove("tool_response");
    })
}

fn decision_breakdown(trace: &InvocationTrace) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    let final_str = match &trace.final_decision {
        Some((d, _)) => d.as_str(),
        None => "passthrough",
    };
    obj.insert("final".into(), serde_json::json!(final_str));
    obj.insert("kind".into(), serde_json::json!(trace.kind));
    if let Some((_, reason)) = &trace.final_decision {
        obj.insert("reason".into(), serde_json::json!(reason));
    }

    match deciding_index(&trace.nodes) {
        Some(i) => obj.insert("deciding".into(), trace.nodes[i].to_json()),
        None => obj.insert("deciding".into(), serde_json::Value::Null),
    };

    let nodes: Vec<serde_json::Value> = trace.nodes.iter().map(|n| n.to_json()).collect();
    obj.insert("nodes".into(), serde_json::Value::Array(nodes));
    serde_json::Value::Object(obj)
}

fn timestamped_log_line(input: &str, trace: &InvocationTrace) -> String {
    shape_log_line(input, "pre_tool_use", |map| {
        map.insert("lk_decision".to_string(), decision_breakdown(trace));
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::{empty_trace, InvocationTrace};

    fn empty_invocation_trace() -> InvocationTrace {
        InvocationTrace {
            final_decision: None,
            kind: "command_chain",
            nodes: Vec::new(),
        }
    }

    #[test]
    fn timestamped_log_line_injects_ts_and_preserves_fields() {
        let line = timestamped_log_line(
            r#"{"tool_name":"Bash","tool_input":{"command":"ls"},"cwd":"/x"}"#,
            &empty_invocation_trace(),
        );
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["tool_name"], "Bash");
        assert_eq!(v["tool_input"]["command"], "ls");
        assert_eq!(v["cwd"], "/x");
        assert!(v["ts_ms"].as_u64().unwrap() > 0);
        assert_eq!(v["lk_decision"]["final"], "passthrough");
    }

    #[test]
    fn timestamped_log_line_passes_through_non_object() {
        assert_eq!(
            timestamped_log_line("not json", &empty_invocation_trace()),
            "not json"
        );
    }

    #[test]
    fn post_tool_use_line_marks_event_and_strips_response() {
        let input = r#"{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{"command":"ls"},"cwd":"/x","session_id":"s1","tool_response":{"stdout":"a","stderr":""}}"#;
        let line = post_tool_use_log_line(input);
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["lk_event"], serde_json::json!("post_tool_use"));
        assert_eq!(v["tool_name"], serde_json::json!("Bash"));
        assert_eq!(v["tool_input"]["command"], serde_json::json!("ls"));
        assert_eq!(v["session_id"], serde_json::json!("s1"));
        assert!(v.get("tool_response").is_none());
        assert!(v.get("ts_ms").is_some());
        assert!(v.get("lk_decision").is_none());
    }

    #[test]
    fn pre_tool_use_line_marks_event() {
        let input = r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"},"cwd":"/x"}"#;
        let trace = empty_trace("command_chain");
        let line = timestamped_log_line(input, &trace);
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["lk_event"], serde_json::json!("pre_tool_use"));
        assert!(v.get("lk_decision").is_some());
    }
}
