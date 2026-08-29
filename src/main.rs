mod config;
mod decision;
mod eval;
mod live_rules;
mod llm;
mod log;
mod otel;
mod parse;
mod queue;
mod scope;
mod settings;
mod watch;
mod worktree;

use config::{load_config, Config};
use decision::{dispatch, Decision, InvocationTrace};
use log::{log_invocation, log_observed_event, GateTiming};
use queue::QueueRequest;
use serde::Deserialize;
use std::io::Read;

#[derive(Deserialize)]
pub(crate) struct HookInput {
    // Defaulted because lord-kali now also sees events that carry no tool at all
    // (session and subagent boundaries, Stop). Those must log cleanly, not fail to parse.
    #[serde(default)]
    pub(crate) tool_name: String,
    #[serde(default)]
    pub(crate) tool_input: ToolInput,
    pub(crate) cwd: Option<String>,
    #[serde(default)]
    pub(crate) hook_event_name: Option<String>,
    #[serde(default)]
    pub(crate) session_id: Option<String>,
    // Claude Code sends these on every tool event; lord-kali logged them verbatim without
    // ever reading them. Only the ones the gate itself acts on are parsed here — the rest
    // (agent_id, prompt_id, effort) stay in the raw record for the log and OTel to read.
    //
    // `tool_use_id` is the only exact key for correlating one call across the events it
    // fires, and is what stops PreToolUse and PermissionRequest asking the same question
    // twice.
    #[serde(default)]
    pub(crate) tool_use_id: Option<String>,
    // Shown on a queued call: the same command means something different under `plan` than
    // under `bypassPermissions`.
    #[serde(default)]
    pub(crate) permission_mode: Option<String>,
    #[serde(default)]
    pub(crate) agent_type: Option<String>,
}

#[derive(Deserialize, Default)]
pub(crate) struct ToolInput {
    pub(crate) command: Option<String>,
    pub(crate) url: Option<String>,
    pub(crate) query: Option<String>,
    pub(crate) file_path: Option<String>,
    pub(crate) path: Option<String>,
    // Any remaining input keys (e.g. an MCP tool's structured arguments), captured for the
    // MCP summary. The typed fields above are pulled out first, so they are NOT here.
    #[serde(flatten)]
    pub(crate) extra: serde_json::Map<String, serde_json::Value>,
}

impl ToolInput {
    // A compact, truncated one-line view of the structured input, shown to the operator on
    // MCP nodes. Display only — MCP gating matches the tool name, never this. The typed
    // fields are folded back in so a tool whose arg is named `url`/`path` still shows it.
    pub(crate) fn summary(&self) -> String {
        let mut obj = self.extra.clone();
        for (k, v) in [
            ("command", &self.command),
            ("url", &self.url),
            ("file_path", &self.file_path),
            ("path", &self.path),
        ] {
            if let Some(val) = v {
                obj.insert(k.into(), serde_json::Value::String(val.clone()));
            }
        }
        let s = serde_json::Value::Object(obj).to_string();
        const MAX: usize = 80;
        if s.chars().count() > MAX {
            format!("{}…", s.chars().take(MAX).collect::<String>())
        } else {
            s
        }
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("watch") => watch::watch(&args.collect::<Vec<_>>()),
        Some("prune-logs") => log::prune_logs_cli(&args.collect::<Vec<_>>()),
        Some("eval") => eval::eval_cli(&args.collect::<Vec<_>>()),
        _ => run_hook(),
    }
}

// The two events that can change an outcome. Everything else lord-kali registers for is
// observation only — it cannot alter what happens, so it never writes to stdout.
#[derive(Clone, Copy, PartialEq)]
pub(crate) enum GateEvent {
    PreToolUse,
    PermissionRequest,
}

impl GateEvent {
    fn name(self) -> &'static str {
        match self {
            GateEvent::PreToolUse => "PreToolUse",
            GateEvent::PermissionRequest => "PermissionRequest",
        }
    }
}

fn run_hook() {
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .expect("Failed to read stdin");

    let hook_input: HookInput = serde_json::from_str(&input).expect("Failed to parse hook input");
    let config = load_config(hook_input.cwd.as_deref());

    match hook_input.hook_event_name.as_deref() {
        // An absent event name means a direct invocation (tests, manual piping); gating is
        // the behaviour that has always applied there.
        None | Some("PreToolUse") => gate(&config, &hook_input, &input, GateEvent::PreToolUse),
        // Fires when Claude Code is about to prompt. Its value is the calls lord-kali never
        // sees otherwise — tools it has no handler for, and prompts raised by Claude Code's
        // own permission rules.
        Some("PermissionRequest") => {
            gate(&config, &hook_input, &input, GateEvent::PermissionRequest)
        }
        Some(observed) => {
            if let Some(log) = &config.log {
                if log.enabled {
                    log_observed_event(log, &input, observed);
                }
            }
        }
    }
}

fn gate(config: &Config, hook_input: &HookInput, raw: &str, event: GateEvent) {
    let started = std::time::Instant::now();
    let cwd = hook_input.cwd.as_deref();
    let trace = dispatch(config, hook_input, cwd);
    let (trace, queue_wait_ms) = maybe_route_to_approval(config, hook_input, trace, event);

    // Print before logging: the decision is what Claude Code is waiting on, and logging is
    // best-effort by design.
    if let Some((decision, reason)) = &trace.final_decision {
        print_decision(event, decision.clone(), reason);
    }

    if let Some(log) = &config.log {
        if log.enabled {
            log_invocation(
                log,
                raw,
                &trace,
                event.name(),
                GateTiming {
                    duration_ms: started.elapsed().as_millis() as u64,
                    queue_wait_ms,
                },
            );
        }
    }
}

// When approval is enabled and a TUI is alive, route ask/pass-through verdicts through
// the central queue instead of Claude Code's own prompt. Any of: feature off, no live
// TUI, nothing actionable, or operator timeout — falls back to the original trace, i.e.
// today's behavior. The deny/allow paths never reach here.
fn maybe_route_to_approval(
    config: &Config,
    hook_input: &HookInput,
    trace: InvocationTrace,
    event: GateEvent,
) -> (InvocationTrace, Option<u64>) {
    if !config.approval.enabled {
        return (trace, None);
    }
    if !matches!(&trace.final_decision, None | Some((Decision::Ask, _))) {
        return (trace, None);
    }

    let dir = queue::state_dir(&config.approval);
    if !queue::is_tui_live_in(&dir, config.approval.heartbeat_fresh_ms()) {
        return (trace, None);
    }

    let nodes = trace.actionable_nodes();
    if nodes.is_empty() {
        return (trace, None);
    }

    // One tool call reaches the gate twice when Claude Code goes on to prompt for it. The
    // PreToolUse pass marks what it queued so the PermissionRequest pass does not ask the
    // operator the same question again.
    let qdir = queue::queue_dir_in(&dir);
    let marker_age = config.approval.self_timeout_ms() * 2;
    match (event, hook_input.tool_use_id.as_deref()) {
        (GateEvent::PermissionRequest, Some(id)) if queue::was_queued_in(&qdir, id, marker_age) => {
            return (trace, None);
        }
        (GateEvent::PreToolUse, Some(id)) => queue::mark_queued_in(&qdir, id),
        _ => {}
    }

    let target = request_target(hook_input);
    let request = QueueRequest {
        id: queue::request_id(hook_input.session_id.as_deref().unwrap_or("")),
        ts_ms: log::now_ms(),
        cwd: hook_input.cwd.clone(),
        tool: hook_input.tool_name.clone(),
        target,
        hook_event: event.name().to_string(),
        agent_type: hook_input.agent_type.clone(),
        permission_mode: hook_input.permission_mode.clone(),
        nodes,
    };

    let waited = std::time::Instant::now();
    match queue::submit_and_wait_in(
        &dir,
        &request,
        config.approval.self_timeout_ms(),
        config.approval.poll_ms(),
    ) {
        Some(verdict) => {
            let mut trace = trace;
            trace.final_decision = queue::combine_verdict(&verdict.nodes);
            (trace, Some(waited.elapsed().as_millis() as u64))
        }
        // A timeout is still a wait, and the one worth seeing — it means the operator never
        // ruled and the call fell back to Claude Code's own prompt.
        None => (trace, Some(waited.elapsed().as_millis() as u64)),
    }
}

// The one-line label shown for a queued call: its command, URL, search query, or target
// path — falling back to the tool name when the call carries none of those.
fn request_target(hook_input: &HookInput) -> String {
    hook_input
        .tool_input
        .command
        .clone()
        .or_else(|| hook_input.tool_input.url.clone())
        .or_else(|| hook_input.tool_input.query.clone())
        .or_else(|| hook_input.tool_input.file_path.clone())
        .or_else(|| hook_input.tool_input.path.clone())
        .unwrap_or_else(|| hook_input.tool_name.clone())
}

// The two gate events name their decision differently: PreToolUse carries
// `permissionDecision` (allow/deny/ask), while PermissionRequest carries `decision` and
// accepts only allow/deny — it fires *because* a prompt is about to happen, so "ask" there is
// simply letting that prompt proceed, which is what emitting nothing does.
fn decision_output(
    event: GateEvent,
    decision: Decision,
    reason: &str,
) -> Option<serde_json::Value> {
    let decision_str = match decision {
        Decision::Allow => "allow",
        Decision::Deny => "deny",
        // PermissionRequest fires *because* a prompt is about to happen, so "ask" there means
        // letting that prompt proceed — which is what emitting nothing does.
        Decision::Ask if event == GateEvent::PermissionRequest => return None,
        Decision::Ask => "ask",
    };

    Some(match event {
        GateEvent::PreToolUse => serde_json::json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": decision_str,
                "permissionDecisionReason": reason,
            }
        }),
        GateEvent::PermissionRequest => serde_json::json!({
            "hookSpecificOutput": {
                "hookEventName": "PermissionRequest",
                "decision": decision_str,
                "reason": reason,
            }
        }),
    })
}

fn print_decision(event: GateEvent, decision: Decision, reason: &str) {
    if let Some(out) = decision_output(event, decision, reason) {
        println!("{out}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hook_input_with_cwd() {
        let json =
            r#"{"tool_name":"Bash","tool_input":{"command":"ls"},"cwd":"/home/user/projects"}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.cwd.as_deref(), Some("/home/user/projects"));
    }

    #[test]
    fn hook_input_without_cwd() {
        let json = r#"{"tool_name":"Bash","tool_input":{"command":"ls"}}"#;
        let input: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(input.cwd, None);
    }

    #[test]
    fn summary_folds_typed_url_field() {
        let ti: ToolInput = serde_json::from_str(r#"{"url":"https://x.test/page"}"#).unwrap();
        let s = ti.summary();
        assert!(s.contains("url"));
        assert!(s.contains("https://x.test/page"));
    }

    #[test]
    fn summary_keeps_structured_keys() {
        let ti: ToolInput =
            serde_json::from_str(r#"{"fields":[{"name":"Username"},{"name":"Password"}]}"#)
                .unwrap();
        assert!(ti.summary().contains("fields"));
        assert!(ti.summary().contains("Username"));
    }

    #[test]
    fn summary_truncates_long_input() {
        let big = "x".repeat(500);
        let ti: ToolInput = serde_json::from_str(&format!("{{\"blob\":\"{big}\"}}")).unwrap();
        let s = ti.summary();
        assert!(s.chars().count() <= 81, "len was {}", s.chars().count());
        assert!(s.ends_with('…'));
    }

    #[test]
    fn request_target_prefers_command_then_url_then_path() {
        let mut hi = bash_hook_input("ls -la");
        assert_eq!(request_target(&hi), "ls -la");

        hi.tool_input.command = None;
        hi.tool_input.url = Some("https://x.test".into());
        assert_eq!(request_target(&hi), "https://x.test");

        hi = HookInput {
            tool_name: "Edit".into(),
            tool_input: ToolInput {
                command: None,
                url: None,
                query: None,
                file_path: Some("/p/Startup.cs".into()),
                path: None,
                extra: Default::default(),
            },
            cwd: None,
            hook_event_name: None,
            session_id: None,
            tool_use_id: None,
            permission_mode: None,
            agent_type: None,
        };
        assert_eq!(request_target(&hi), "/p/Startup.cs");
    }

    fn bash_hook_input(command: &str) -> HookInput {
        HookInput {
            tool_name: "Bash".into(),
            tool_input: ToolInput {
                command: Some(command.into()),
                url: None,
                query: None,
                file_path: None,
                path: None,
                extra: Default::default(),
            },
            cwd: None,
            hook_event_name: None,
            session_id: None,
            tool_use_id: None,
            permission_mode: None,
            agent_type: None,
        }
    }

    // Parity guard: with approval disabled (the default), routing is a no-op — the
    // original verdict is returned verbatim, so the gate behaves exactly as before.
    #[test]
    fn approval_disabled_is_noop() {
        let config = Config::default();
        assert!(!config.approval.enabled);
        let trace = InvocationTrace {
            final_decision: Some((Decision::Ask, "rm is dangerous".into())),
            kind: "command_chain",
            nodes: Vec::new(),
        };
        let (out, waited) = maybe_route_to_approval(
            &config,
            &bash_hook_input("rm foo"),
            trace,
            GateEvent::PreToolUse,
        );
        assert_eq!(waited, None, "a disabled gate never waits");
        assert_eq!(
            out.final_decision.map(|(d, _)| d),
            Some(Decision::Ask),
            "disabled approval must not alter the verdict"
        );
    }

    // ---- Hook event coverage (docs/D-hook-coverage.md) ---------------------------------

    #[test]
    fn pre_tool_use_output_keeps_its_established_shape() {
        let v = decision_output(GateEvent::PreToolUse, Decision::Deny, "no").unwrap();
        assert_eq!(v["hookSpecificOutput"]["hookEventName"], "PreToolUse");
        assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "deny");
        assert_eq!(v["hookSpecificOutput"]["permissionDecisionReason"], "no");
        let v = decision_output(GateEvent::PreToolUse, Decision::Ask, "confirm").unwrap();
        assert_eq!(v["hookSpecificOutput"]["permissionDecision"], "ask");
    }

    // PermissionRequest names its decision `decision`/`reason`, not
    // `permissionDecision`/`permissionDecisionReason`. Getting this wrong fails schema
    // validation silently, with the tool call simply proceeding.
    #[test]
    fn permission_request_uses_its_own_field_names() {
        let v = decision_output(GateEvent::PermissionRequest, Decision::Allow, "ok").unwrap();
        assert_eq!(
            v["hookSpecificOutput"]["hookEventName"],
            "PermissionRequest"
        );
        assert_eq!(v["hookSpecificOutput"]["decision"], "allow");
        assert_eq!(v["hookSpecificOutput"]["reason"], "ok");
        assert!(v["hookSpecificOutput"]["permissionDecision"].is_null());
    }

    // PermissionRequest accepts only allow/deny; "ask" means let the prompt it fired for
    // happen, which is expressed by emitting nothing at all.
    #[test]
    fn permission_request_ask_emits_nothing() {
        assert!(decision_output(GateEvent::PermissionRequest, Decision::Ask, "confirm").is_none());
    }

    // Session, subagent and Stop events carry no tool_name/tool_input at all. Before this,
    // parsing them would have panicked on a missing field.
    #[test]
    fn non_tool_events_parse_without_a_tool() {
        for json in [
            r#"{"hook_event_name":"SessionStart","session_mode":"startup","session_id":"s1"}"#,
            r#"{"hook_event_name":"Stop","last_assistant_message":"done"}"#,
            r#"{"hook_event_name":"SubagentStop","agent_id":"a1","agent_type":"Explore"}"#,
            r#"{"hook_event_name":"SessionEnd","exit_reason":"clear"}"#,
        ] {
            let hi: HookInput =
                serde_json::from_str(json).unwrap_or_else(|e| panic!("{json} failed: {e}"));
            assert!(hi.tool_name.is_empty());
            assert!(hi.tool_input.command.is_none());
        }
    }

    #[test]
    fn tool_events_parse_the_correlation_fields() {
        let json = r#"{"hook_event_name":"PreToolUse","tool_name":"Bash",
            "tool_input":{"command":"ls"},"tool_use_id":"toolu_01A",
            "permission_mode":"auto","agent_type":"crafter","agent_id":"x","prompt_id":"p"}"#;
        let hi: HookInput = serde_json::from_str(json).unwrap();
        assert_eq!(hi.tool_use_id.as_deref(), Some("toolu_01A"));
        assert_eq!(hi.permission_mode.as_deref(), Some("auto"));
        assert_eq!(hi.agent_type.as_deref(), Some("crafter"));
    }
}
