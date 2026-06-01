mod config;
mod decision;
mod log;
mod parse;
mod watch;
mod worktree;

use config::load_config;
use decision::{dispatch, Decision};
use log::{log_invocation, log_post_tool_use};
use serde::Deserialize;
use std::io::Read;

#[derive(Deserialize)]
pub(crate) struct HookInput {
    pub(crate) tool_name: String,
    pub(crate) tool_input: ToolInput,
    pub(crate) cwd: Option<String>,
    #[serde(default)]
    pub(crate) hook_event_name: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct ToolInput {
    pub(crate) command: Option<String>,
    pub(crate) url: Option<String>,
    pub(crate) file_path: Option<String>,
    pub(crate) path: Option<String>,
}

fn main() {
    let mut args = std::env::args().skip(1);
    if args.next().as_deref() == Some("watch") {
        watch::watch(args.next().as_deref());
        return;
    }
    run_hook();
}

fn run_hook() {
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .expect("Failed to read stdin");

    let hook_input: HookInput = serde_json::from_str(&input).expect("Failed to parse hook input");
    let cwd = hook_input.cwd.as_deref();

    let config = load_config(cwd);

    if hook_input.hook_event_name.as_deref() == Some("PostToolUse") {
        if let Some(log) = &config.log {
            if log.enabled {
                log_post_tool_use(log, &input);
            }
        }
        return;
    }

    let trace = dispatch(&config, &hook_input, cwd);

    if let Some((decision, reason)) = &trace.final_decision {
        print_decision(decision.clone(), reason);
    }

    if let Some(log) = &config.log {
        if log.enabled {
            log_invocation(log, &input, &trace);
        }
    }
}

fn print_decision(decision: Decision, reason: &str) {
    let decision_str = match decision {
        Decision::Allow => "allow",
        Decision::Deny => "deny",
        Decision::Ask => "ask",
    };

    println!(
        "{}",
        serde_json::json!({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": decision_str,
                "permissionDecisionReason": reason,
            }
        })
    );
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
}
