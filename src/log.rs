// JSONL logging. Best-effort: any failure here is swallowed so a gate decision already
// printed to Claude Code is never blocked or altered by a logging problem.

use crate::config::{expand_tilde, load_config, LogConfig};
use crate::decision::{deciding_index, InvocationTrace};
use crate::queue::write_atomic;
use std::path::{Path, PathBuf};

pub(crate) const DEFAULT_LOG_PATH: &str = "~/.local/state/lord-kali/hook.jsonl";
// Log entries older than this are dropped by `prune-logs` and the watch housekeeper.
pub(crate) const DEFAULT_RETAIN_DAYS: u64 = 3;

fn append_log_line(log_config: &LogConfig, line: String) {
    let path_str = log_config.path.as_deref().unwrap_or(DEFAULT_LOG_PATH);
    append_line_to_path(&expand_tilde(path_str), line);
}

// Best-effort append to an explicit log path. Any IO failure is swallowed (logging never
// blocks a gate or, here, an auto-approval).
fn append_line_to_path(path: &Path, line: String) {
    if let Some(parent) = path.parent() {
        if std::fs::create_dir_all(parent).is_err() {
            return;
        }
    }
    use std::io::Write;
    let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    else {
        return;
    };
    let _ = writeln!(file, "{}", line);
}

// Append an LLM auto-approval observability event to the log, stamped with ts_ms + lk_event.
// The watch builds the field set (so this stays a thin, generic sink), letting it record the
// full lifecycle — `llm_consult` (model asked), `llm_result` (what it replied + latency), and
// `llm_auto_approve` (applied) — so `watch --tail` and audits can see if/what/when it decided.
// Best-effort: a logging failure never blocks an auto-approval.
pub(crate) fn log_event(path: &Path, event: &str, fields: serde_json::Value) {
    let mut fields = fields;
    if let Some(obj) = fields.as_object_mut() {
        obj.insert("ts_ms".to_string(), serde_json::json!(now_ms()));
        obj.insert("lk_event".to_string(), serde_json::json!(event));
    }
    append_line_to_path(path, fields.to_string());
}

// A gate invocation. `hook_event` distinguishes the two events that can gate, so a
// PermissionRequest decision is not filed as though it were a PreToolUse one.
pub(crate) fn log_invocation(
    log_config: &LogConfig,
    input: &str,
    trace: &InvocationTrace,
    hook_event: &str,
    timing: GateTiming,
) {
    append_log_line(
        log_config,
        timestamped_log_line(input, trace, hook_event, timing),
    );
}

// How long the gate took, and how much of that was waiting on the approval queue. Recorded
// because neither is recoverable afterwards: the hook process is gone, and a wait that
// timed out looks identical to one that was never made.
#[derive(Clone, Copy, Default)]
pub(crate) struct GateTiming {
    pub(crate) duration_ms: u64,
    // None when the call never reached the queue.
    pub(crate) queue_wait_ms: Option<u64>,
}

// Events lord-kali observes but never gates — PostToolUse, PostToolUseFailure,
// PermissionDenied, session and subagent boundaries. They cannot change an outcome, so this
// path only logs, with no decision and no stdout.
pub(crate) fn log_observed_event(log_config: &LogConfig, input: &str, hook_event: &str) {
    append_log_line(log_config, observed_log_line(input, hook_event));
}

// "PostToolUseFailure" -> "post_tool_use_failure". Derived rather than tabulated, so an event
// Claude Code adds later gets a sensible key without a code change.
pub(crate) fn event_key(hook_event: &str) -> String {
    let mut out = String::with_capacity(hook_event.len() + 4);
    for (i, c) in hook_event.chars().enumerate() {
        if c.is_ascii_uppercase() {
            if i > 0 {
                out.push('_');
            }
            out.push(c.to_ascii_lowercase());
        } else {
            out.push(c);
        }
    }
    out
}

pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// Resolve the active log path: an explicit override (tilde-expanded), else the configured
// `[log] path`, else the default. Shared by the watcher and `prune-logs` so both agree.
pub(crate) fn resolve_log_path(explicit: Option<&str>) -> PathBuf {
    if let Some(p) = explicit {
        return expand_tilde(p);
    }
    let config = load_config(None);
    let path_str = config
        .log
        .as_ref()
        .and_then(|l| l.path.as_deref())
        .unwrap_or(DEFAULT_LOG_PATH);
    expand_tilde(path_str)
}

fn entry_ts_ms(line: &str) -> Option<u64> {
    serde_json::from_str::<serde_json::Value>(line)
        .ok()?
        .get("ts_ms")?
        .as_u64()
}

// Drop entries older than `max_age_days`, rewriting the file atomically. Lines whose ts_ms
// can't be parsed are kept (we never silently discard data we can't date). A missing file
// is a no-op. Returns (kept, removed). Best-effort callers (the watcher) ignore the result.
pub(crate) fn prune_log_file(
    path: &Path,
    max_age_days: u64,
    now_ms: u64,
) -> std::io::Result<(usize, usize)> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((0, 0)),
        Err(e) => return Err(e),
    };
    let cutoff = now_ms.saturating_sub(max_age_days.saturating_mul(86_400_000));
    let mut kept: Vec<&str> = Vec::new();
    let mut removed = 0usize;
    for line in content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        if entry_ts_ms(line).is_none_or(|ts| ts >= cutoff) {
            kept.push(line);
        } else {
            removed += 1;
        }
    }
    if removed > 0 {
        let mut out = kept.join("\n");
        if !out.is_empty() {
            out.push('\n');
        }
        write_atomic(path, &out)?;
    }
    Ok((kept.len(), removed))
}

// `lord-kali prune-logs [--days N] [path]`: drop log entries older than N days (default 7).
pub(crate) fn prune_logs_cli(args: &[String]) {
    let mut days = DEFAULT_RETAIN_DAYS;
    let mut path_arg: Option<&str> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--days" => {
                days = match it.next().and_then(|d| d.parse().ok()) {
                    Some(n) => n,
                    None => {
                        eprintln!("lord-kali prune-logs: --days requires a number");
                        std::process::exit(2);
                    }
                };
            }
            s if s.starts_with("--") => {
                eprintln!("lord-kali prune-logs: unknown flag {s}");
                std::process::exit(2);
            }
            s => path_arg = Some(s),
        }
    }
    let path = resolve_log_path(path_arg);
    match prune_log_file(&path, days, now_ms()) {
        Ok((kept, removed)) => println!(
            "lord-kali prune-logs: removed {removed}, kept {kept} (retained < {days}d) in {}",
            path.display()
        ),
        Err(e) => {
            eprintln!("lord-kali prune-logs: {}: {e}", path.display());
            std::process::exit(1);
        }
    }
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

fn observed_log_line(input: &str, hook_event: &str) -> String {
    shape_log_line(input, &event_key(hook_event), |map| {
        // Tool payloads and assistant messages are unbounded; the gate never reads them back
        // and a log that grows by whole tool outputs is a log nobody keeps.
        map.remove("tool_response");
        map.remove("tool_output");
        map.remove("updatedOutput");
        map.remove("last_assistant_message");
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

fn timestamped_log_line(
    input: &str,
    trace: &InvocationTrace,
    hook_event: &str,
    timing: GateTiming,
) -> String {
    shape_log_line(input, &event_key(hook_event), |map| {
        map.insert("lk_decision".to_string(), decision_breakdown(trace));
        map.insert(
            "lk_duration_ms".to_string(),
            serde_json::json!(timing.duration_ms),
        );
        if let Some(w) = timing.queue_wait_ms {
            map.insert("lk_queue_wait_ms".to_string(), serde_json::json!(w));
        }
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
            "PreToolUse",
            GateTiming::default(),
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
            timestamped_log_line(
                "not json",
                &empty_invocation_trace(),
                "PreToolUse",
                GateTiming::default()
            ),
            "not json"
        );
    }

    #[test]
    fn post_tool_use_line_marks_event_and_strips_response() {
        let input = r#"{"hook_event_name":"PostToolUse","tool_name":"Bash","tool_input":{"command":"ls"},"cwd":"/x","session_id":"s1","tool_response":{"stdout":"a","stderr":""}}"#;
        let line = observed_log_line(input, "PostToolUse");
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
    fn event_key_snake_cases_every_hook_event_name() {
        assert_eq!(event_key("PostToolUse"), "post_tool_use");
        assert_eq!(event_key("PostToolUseFailure"), "post_tool_use_failure");
        assert_eq!(event_key("PermissionDenied"), "permission_denied");
        assert_eq!(event_key("PermissionRequest"), "permission_request");
        assert_eq!(event_key("SessionStart"), "session_start");
        assert_eq!(event_key("Stop"), "stop");
        // An event Claude Code adds later still gets a usable key.
        assert_eq!(event_key("SomeFutureEvent"), "some_future_event");
    }

    // A failure carries `error`, not `tool_response`; the error text is the whole point of
    // the record, so it must survive the strip.
    #[test]
    fn post_tool_use_failure_keeps_the_error() {
        let input = r#"{"hook_event_name":"PostToolUseFailure","tool_name":"Bash","tool_input":{"command":"ls /nope"},"error":"No such file or directory","tool_use_id":"toolu_1"}"#;
        let v: serde_json::Value =
            serde_json::from_str(&observed_log_line(input, "PostToolUseFailure")).unwrap();
        assert_eq!(v["lk_event"], "post_tool_use_failure");
        assert_eq!(v["error"], "No such file or directory");
        assert_eq!(v["tool_use_id"], "toolu_1");
    }

    // Auto mode's classifier denies calls lord-kali passed through; `denied_by` and
    // `classifier_verdict` are the only record that it happened.
    #[test]
    fn permission_denied_keeps_the_denial_provenance() {
        let input = r#"{"hook_event_name":"PermissionDenied","tool_name":"Bash","tool_input":{"command":"rm -rf /"},"denied_by":"classifier","classifier_verdict":"destructive"}"#;
        let v: serde_json::Value =
            serde_json::from_str(&observed_log_line(input, "PermissionDenied")).unwrap();
        assert_eq!(v["lk_event"], "permission_denied");
        assert_eq!(v["denied_by"], "classifier");
        assert_eq!(v["classifier_verdict"], "destructive");
    }

    // Session and subagent events carry no tool at all; they must still log cleanly.
    #[test]
    fn non_tool_events_log_without_a_tool() {
        let input = r#"{"hook_event_name":"SessionStart","session_mode":"startup","session_id":"s9","last_assistant_message":"chatty"}"#;
        let v: serde_json::Value =
            serde_json::from_str(&observed_log_line(input, "SessionStart")).unwrap();
        assert_eq!(v["lk_event"], "session_start");
        assert_eq!(v["session_mode"], "startup");
        assert!(v.get("last_assistant_message").is_none());
    }

    #[test]
    fn pre_tool_use_line_marks_event() {
        let input = r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"ls"},"cwd":"/x"}"#;
        let trace = empty_trace("command_chain");
        let line = timestamped_log_line(input, &trace, "PreToolUse", GateTiming::default());
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["lk_event"], serde_json::json!("pre_tool_use"));
        assert!(v.get("lk_decision").is_some());
    }

    // --- prune_log_file ---

    const NOW: u64 = 1_000_000_000_000;
    const DAY_MS: u64 = 86_400_000;

    #[test]
    fn prune_drops_old_keeps_recent() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("hook.jsonl");
        let old = format!(r#"{{"ts_ms":{},"x":"old"}}"#, NOW - 8 * DAY_MS);
        let recent = format!(r#"{{"ts_ms":{},"x":"recent"}}"#, NOW - DAY_MS);
        std::fs::write(&path, format!("{old}\n{recent}\n")).unwrap();

        assert_eq!(prune_log_file(&path, 7, NOW).unwrap(), (1, 1));
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("recent"));
        assert!(!content.contains("old"));
        assert!(content.ends_with('\n'));
    }

    // Lines we can't date are kept — pruning never silently discards unparseable data.
    #[test]
    fn prune_keeps_lines_without_ts() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("hook.jsonl");
        std::fs::write(&path, "not json\n{\"no\":\"ts\"}\n").unwrap();
        assert_eq!(prune_log_file(&path, 7, NOW).unwrap(), (2, 0));
    }

    #[test]
    fn prune_missing_file_is_noop() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("absent.jsonl");
        assert_eq!(prune_log_file(&path, 7, NOW).unwrap(), (0, 0));
        assert!(!path.exists());
    }

    #[test]
    fn prune_without_removals_leaves_file_untouched() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("hook.jsonl");
        let recent = format!("{{\"ts_ms\":{},\"x\":\"r\"}}\n", NOW - 1000);
        std::fs::write(&path, &recent).unwrap();
        assert_eq!(prune_log_file(&path, 7, NOW).unwrap(), (1, 0));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), recent);
    }
}
