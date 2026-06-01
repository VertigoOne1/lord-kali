// The gating core: resolve each extracted command/URL against its rules, then combine
// per-node decisions into one verdict for the tool call. `dispatch` also builds a
// parallel per-node trace (for logging) that never affects the decision.

use crate::config::{CommandRule, CommandRules, Config, Pattern, RuleMeta, WebFetchConfig};
use crate::parse::{extract_commands, extract_commands_powershell, inner_powershell_script};
use crate::worktree::check_worktree_protection;
use crate::HookInput;

#[derive(Debug, PartialEq, Clone)]
pub(crate) enum Decision {
    Allow,
    Deny,
    Ask,
}

impl Decision {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Decision::Allow => "allow",
            Decision::Deny => "deny",
            Decision::Ask => "ask",
        }
    }
}

// Per-command-node trace, built alongside the gating decision (never affects it).
pub(crate) struct NodeTrace {
    shell: &'static str,
    command: String,
    args: String,
    matched: Option<(Decision, String, RuleMeta)>,
}

impl NodeTrace {
    fn decision_str(&self) -> &'static str {
        match &self.matched {
            Some((d, _, _)) => d.as_str(),
            None => "passthrough",
        }
    }

    pub(crate) fn to_json(&self) -> serde_json::Value {
        let mut obj = serde_json::Map::new();
        obj.insert("shell".into(), serde_json::json!(self.shell));
        obj.insert("command".into(), serde_json::json!(self.command));
        obj.insert("args".into(), serde_json::json!(self.args));
        obj.insert("decision".into(), serde_json::json!(self.decision_str()));
        match &self.matched {
            Some((_, reason, meta)) => {
                obj.insert("matched".into(), serde_json::json!(true));
                obj.insert("reason".into(), serde_json::json!(reason));
                obj.insert(
                    "rule_kind".into(),
                    serde_json::json!(meta.rule_kind.as_str()),
                );
                obj.insert("rule_command".into(), serde_json::json!(meta.rule_command));
                obj.insert("rule_args".into(), serde_json::json!(meta.rule_args));
                obj.insert(
                    "source_file".into(),
                    serde_json::json!(meta.source_file.as_deref()),
                );
            }
            None => {
                obj.insert("matched".into(), serde_json::json!(false));
            }
        }
        serde_json::Value::Object(obj)
    }
}

// Holds everything the gate decided this invocation, for logging only. The
// final_decision drives what is printed to Claude Code; nodes/kind are observability.
pub(crate) struct InvocationTrace {
    pub(crate) final_decision: Option<(Decision, String)>,
    pub(crate) kind: &'static str,
    pub(crate) nodes: Vec<NodeTrace>,
}

impl NodeTrace {
    // A node the operator must rule on: it matched no rule (passthrough) or matched an
    // ask rule. Deny/allow nodes are already resolved and never reach the queue.
    fn is_actionable(&self) -> bool {
        matches!(self.matched, None | Some((Decision::Ask, _, _)))
    }
}

impl InvocationTrace {
    pub(crate) fn actionable_nodes(&self) -> Vec<crate::queue::QueueNode> {
        self.nodes
            .iter()
            .filter(|n| n.is_actionable())
            .map(|n| crate::queue::QueueNode {
                shell: n.shell.to_string(),
                command: n.command.clone(),
                args: n.args.clone(),
                decision: match &n.matched {
                    Some((Decision::Ask, _, _)) => "ask".to_string(),
                    _ => "passthrough".to_string(),
                },
            })
            .collect()
    }
}

// Purpose: compute the gate decision and a parallel per-node trace for one tool call.
// Requires: config loaded; hook_input parsed.
// Guarantees: returned final_decision is byte-identical to the legacy handlers; nodes
//             mirror the same extraction used for the decision.
pub(crate) fn dispatch(
    config: &Config,
    hook_input: &HookInput,
    cwd: Option<&str>,
) -> InvocationTrace {
    if config.worktree_protection.enabled {
        if let Some(cwd) = cwd {
            if let Some((decision, reason)) =
                check_worktree_protection(cwd, &hook_input.tool_name, &hook_input.tool_input)
            {
                return InvocationTrace {
                    final_decision: Some((decision, reason)),
                    kind: "worktree_protection",
                    nodes: Vec::new(),
                };
            }
        }
    }

    match hook_input.tool_name.as_str() {
        "Bash" => match &hook_input.tool_input.command {
            Some(command) => {
                let nodes = trace_bash_tool(&config.bash, &config.powershell, cwd, command);
                InvocationTrace {
                    final_decision: handle_bash_tool(
                        &config.bash,
                        &config.powershell,
                        cwd,
                        command,
                    ),
                    kind: "command_chain",
                    nodes,
                }
            }
            None => empty_trace("command_chain"),
        },
        "PowerShell" => match &hook_input.tool_input.command {
            Some(command) => InvocationTrace {
                final_decision: handle_powershell(&config.powershell, cwd, command),
                kind: "command_chain",
                nodes: trace_powershell(&config.powershell, cwd, command),
            },
            None => empty_trace("command_chain"),
        },
        "WebFetch" => match &hook_input.tool_input.url {
            Some(url) => InvocationTrace {
                final_decision: handle_web_fetch(&config.web_fetch, cwd, url),
                kind: "web_fetch",
                nodes: vec![trace_web_fetch(&config.web_fetch, cwd, url)],
            },
            None => empty_trace("web_fetch"),
        },
        _ => empty_trace("unknown"),
    }
}

pub(crate) fn empty_trace(kind: &'static str) -> InvocationTrace {
    InvocationTrace {
        final_decision: None,
        kind,
        nodes: Vec::new(),
    }
}

pub(crate) fn rule_matches_cwd(projects: &[std::path::PathBuf], cwd: Option<&str>) -> bool {
    projects.is_empty()
        || cwd.is_some_and(|c| {
            let cwd_path = std::path::PathBuf::from(c);
            projects.iter().any(|p| cwd_path.starts_with(p))
        })
}

pub(crate) fn handle_web_fetch(
    config: &WebFetchConfig,
    cwd: Option<&str>,
    url: &str,
) -> Option<(Decision, String)> {
    for rule in &config.rules {
        if rule_matches_cwd(&rule.projects, cwd) && rule.pattern.is_match(url) {
            return Some((rule.decision.clone(), rule.reason.clone()));
        }
    }
    None
}

fn trace_web_fetch(config: &WebFetchConfig, cwd: Option<&str>, url: &str) -> NodeTrace {
    let matched = config
        .rules
        .iter()
        .find(|rule| rule_matches_cwd(&rule.projects, cwd) && rule.pattern.is_match(url))
        .map(|rule| {
            (
                rule.decision.clone(),
                rule.reason.clone(),
                rule.meta.clone(),
            )
        });
    NodeTrace {
        shell: "web-fetch",
        command: url.to_string(),
        args: String::new(),
        matched,
    }
}

fn resolve_in(
    rules: &CommandRules,
    cwd: Option<&str>,
    commands: &[(String, String)],
) -> Vec<Option<(Decision, String)>> {
    commands
        .iter()
        .map(|(name, args)| {
            let rs: Vec<&CommandRule> = rules
                .rules
                .get(name.as_str())
                .map(|r| r.iter().collect())
                .unwrap_or_default();
            resolve_command(&rs, args, cwd)
        })
        .collect()
}

fn combine(resolved: Vec<Option<(Decision, String)>>) -> Option<(Decision, String)> {
    if resolved.is_empty() {
        return None;
    }

    let mut deny_reason: Option<String> = None;
    let mut ask_reason: Option<String> = None;
    let mut all_allowed = true;

    for r in resolved {
        match r {
            Some((Decision::Deny, reason)) => {
                deny_reason.get_or_insert(reason);
            }
            Some((Decision::Ask, reason)) => {
                ask_reason.get_or_insert(reason);
            }
            Some((Decision::Allow, _)) => {}
            None => {
                all_allowed = false;
            }
        }
    }

    if let Some(reason) = deny_reason {
        Some((Decision::Deny, reason))
    } else if let Some(reason) = ask_reason {
        Some((Decision::Ask, reason))
    } else if all_allowed {
        Some((Decision::Allow, "ok".into()))
    } else {
        None
    }
}

fn resolve_command_traced(
    rules: &[&CommandRule],
    args: &str,
    cwd: Option<&str>,
) -> Option<(Decision, String, RuleMeta)> {
    for rule in rules {
        if rule_matches_cwd(&rule.projects, cwd) && matches_args(&rule.args, args) {
            return Some((
                rule.decision.clone(),
                rule.reason.clone(),
                rule.meta.clone(),
            ));
        }
    }
    None
}

fn trace_in(
    rules: &CommandRules,
    cwd: Option<&str>,
    commands: &[(String, String)],
    shell: &'static str,
) -> Vec<NodeTrace> {
    commands
        .iter()
        .map(|(name, args)| {
            let rs: Vec<&CommandRule> = rules
                .rules
                .get(name.as_str())
                .map(|r| r.iter().collect())
                .unwrap_or_default();
            NodeTrace {
                shell,
                command: name.clone(),
                args: args.clone(),
                matched: resolve_command_traced(&rs, args, cwd),
            }
        })
        .collect()
}

// Identifies the node whose decision set the final verdict: the first deny if any
// denied, else the first ask, else the first matched allow.
pub(crate) fn deciding_index(nodes: &[NodeTrace]) -> Option<usize> {
    let pick = |want: &Decision| {
        nodes
            .iter()
            .position(|n| n.matched.as_ref().is_some_and(|(d, _, _)| d == want))
    };
    pick(&Decision::Deny)
        .or_else(|| pick(&Decision::Ask))
        .or_else(|| pick(&Decision::Allow))
}

// Pure bash resolution, retained for the bash regression tests; production dispatch
// goes through handle_bash_tool, which also escalates inner pwsh -Command scripts.
fn handle_powershell(
    rules: &CommandRules,
    cwd: Option<&str>,
    command: &str,
) -> Option<(Decision, String)> {
    combine(resolve_in(
        rules,
        cwd,
        &extract_commands_powershell(command),
    ))
}

fn handle_bash_tool(
    bash: &CommandRules,
    powershell: &CommandRules,
    cwd: Option<&str>,
    command: &str,
) -> Option<(Decision, String)> {
    let bash_cmds = extract_commands(command);
    let mut resolved = resolve_in(bash, cwd, &bash_cmds);

    for (name, args) in &bash_cmds {
        if let Some(script) = inner_powershell_script(name, args) {
            let inner = extract_commands_powershell(&script);
            resolved.extend(resolve_in(powershell, cwd, &inner));
        }
    }

    combine(resolved)
}

fn trace_bash_tool(
    bash: &CommandRules,
    powershell: &CommandRules,
    cwd: Option<&str>,
    command: &str,
) -> Vec<NodeTrace> {
    let bash_cmds = extract_commands(command);
    let mut nodes = trace_in(bash, cwd, &bash_cmds, "bash");

    for (name, args) in &bash_cmds {
        if let Some(script) = inner_powershell_script(name, args) {
            let inner = extract_commands_powershell(&script);
            nodes.extend(trace_in(powershell, cwd, &inner, "powershell"));
        }
    }

    nodes
}

fn trace_powershell(rules: &CommandRules, cwd: Option<&str>, command: &str) -> Vec<NodeTrace> {
    trace_in(
        rules,
        cwd,
        &extract_commands_powershell(command),
        "powershell",
    )
}

#[cfg(test)]
pub(crate) fn handle_bash(
    rules: &CommandRules,
    cwd: Option<&str>,
    command: &str,
) -> Option<(Decision, String)> {
    handle_bash_tool(
        rules,
        &CommandRules {
            rules: std::collections::HashMap::new(),
        },
        cwd,
        command,
    )
}

fn resolve_command(
    rules: &[&CommandRule],
    args: &str,
    cwd: Option<&str>,
) -> Option<(Decision, String)> {
    for rule in rules {
        if rule_matches_cwd(&rule.projects, cwd) && matches_args(&rule.args, args) {
            return Some((rule.decision.clone(), rule.reason.clone()));
        }
    }
    None
}

fn matches_args(pattern: &Option<Pattern>, args: &str) -> bool {
    match pattern {
        None => true,
        Some(re) => re.is_match(args),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{compile_pattern, CommandRules, RawCommandConfig, RawCommandRule};
    use std::collections::HashMap;
    use std::path::PathBuf;

    fn test_bash_config() -> CommandRules {
        let mut rules: HashMap<String, Vec<CommandRule>> = HashMap::new();

        for cmd in ["tail", "grep", "ls", "find", "cat", "head", "wc"] {
            rules.entry(cmd.to_string()).or_default().push(CommandRule {
                decision: Decision::Allow,
                args: None,
                reason: "ok".into(),
                projects: vec![],
                meta: RuleMeta::default(),
            });
        }

        rules
            .entry("npm".to_string())
            .or_default()
            .push(CommandRule {
                decision: Decision::Deny,
                args: None,
                reason: "Use pnpm instead of npm.".into(),
                projects: vec![],
                meta: RuleMeta::default(),
            });

        rules
            .entry("rm".to_string())
            .or_default()
            .push(CommandRule {
                decision: Decision::Ask,
                args: None,
                reason: "rm can be dangerous, please ask.".into(),
                projects: vec![],
                meta: RuleMeta::default(),
            });

        rules
            .entry("rmdir".to_string())
            .or_default()
            .push(CommandRule {
                decision: Decision::Ask,
                args: None,
                reason: "rmdir can be dangerous, please ask.".into(),
                projects: vec![],
                meta: RuleMeta::default(),
            });

        CommandRules { rules }
    }

    fn decision_of(cmd: &str) -> Option<Decision> {
        handle_bash(&test_bash_config(), None, cmd).map(|(d, _)| d)
    }

    // --- deny: detected anywhere ---

    #[test]
    fn deny_simple() {
        assert_eq!(decision_of("npm install"), Some(Decision::Deny));
    }

    #[test]
    fn deny_after_pipe() {
        assert_eq!(decision_of("ls | npm install"), Some(Decision::Deny));
    }

    #[test]
    fn deny_after_and() {
        assert_eq!(decision_of("ls && npm install"), Some(Decision::Deny));
    }

    #[test]
    fn deny_after_semicolon() {
        assert_eq!(decision_of("ls; npm install"), Some(Decision::Deny));
    }

    #[test]
    fn deny_in_command_substitution() {
        assert_eq!(decision_of("echo $(npm install)"), Some(Decision::Deny));
    }

    #[test]
    fn deny_in_subshell() {
        assert_eq!(decision_of("(npm install)"), Some(Decision::Deny));
    }

    #[test]
    fn deny_via_xargs() {
        assert_eq!(decision_of("find . | xargs npm"), Some(Decision::Deny));
    }

    #[test]
    fn deny_with_full_path() {
        assert_eq!(
            decision_of("/usr/local/bin/npm install"),
            Some(Decision::Deny)
        );
    }

    // --- ask: detected anywhere ---

    #[test]
    fn ask_simple() {
        assert_eq!(decision_of("rm foo"), Some(Decision::Ask));
    }

    #[test]
    fn ask_after_pipe() {
        assert_eq!(decision_of("ls | rm foo"), Some(Decision::Ask));
    }

    #[test]
    fn ask_after_and() {
        assert_eq!(decision_of("ls && rm -rf /"), Some(Decision::Ask));
    }

    #[test]
    fn ask_in_command_substitution() {
        assert_eq!(decision_of("echo $(rm foo)"), Some(Decision::Ask));
    }

    #[test]
    fn ask_in_subshell() {
        assert_eq!(decision_of("(rm foo)"), Some(Decision::Ask));
    }

    #[test]
    fn ask_via_xargs() {
        assert_eq!(decision_of("find . | xargs rm"), Some(Decision::Ask));
    }

    #[test]
    fn ask_via_xargs_with_flags() {
        assert_eq!(
            decision_of("find . | xargs -I {} rm {}"),
            Some(Decision::Ask)
        );
    }

    #[test]
    fn ask_with_full_path() {
        assert_eq!(decision_of("/usr/bin/rm foo"), Some(Decision::Ask));
    }

    // --- deny beats ask ---

    #[test]
    fn deny_beats_ask_deny_first() {
        assert_eq!(decision_of("npm install && rm foo"), Some(Decision::Deny));
    }

    #[test]
    fn deny_beats_ask_ask_first() {
        assert_eq!(decision_of("rm foo && npm install"), Some(Decision::Deny));
    }

    #[test]
    fn deny_beats_ask_in_pipeline() {
        assert_eq!(decision_of("rm foo | npm install"), Some(Decision::Deny));
    }

    // --- allow: all commands in allow list ---

    #[test]
    fn allow_single() {
        assert_eq!(decision_of("ls"), Some(Decision::Allow));
    }

    #[test]
    fn allow_with_flags() {
        assert_eq!(decision_of("ls -la"), Some(Decision::Allow));
    }

    #[test]
    fn allow_pipeline() {
        assert_eq!(decision_of("ls -la | grep foo"), Some(Decision::Allow));
    }

    #[test]
    fn allow_chain() {
        assert_eq!(decision_of("find . && ls"), Some(Decision::Allow));
    }

    #[test]
    fn allow_three_piped() {
        assert_eq!(
            decision_of("find . -name '*.rs' | grep test | wc -l"),
            Some(Decision::Allow)
        );
    }

    // --- pass-through: no output (None) ---

    #[test]
    fn passthrough_unknown_command() {
        assert_eq!(decision_of("cargo build"), None);
    }

    #[test]
    fn passthrough_mixed_unknown_and_allowed() {
        assert_eq!(decision_of("find . | ls $(echo poo)"), None);
    }

    #[test]
    fn passthrough_single_unknown() {
        assert_eq!(decision_of("python script.py"), None);
    }

    #[test]
    fn passthrough_multiple_unknown() {
        assert_eq!(decision_of("cargo build && cargo test"), None);
    }

    // --- args matching ---

    #[test]
    fn deny_with_args_match() {
        let mut rules: HashMap<String, Vec<CommandRule>> = HashMap::new();
        rules
            .entry("rm".to_string())
            .or_default()
            .push(CommandRule {
                decision: Decision::Deny,
                args: Some(compile_pattern("-rf **")),
                reason: "No recursive force deletes".into(),
                projects: vec![],
                meta: RuleMeta::default(),
            });
        rules
            .entry("rm".to_string())
            .or_default()
            .push(CommandRule {
                decision: Decision::Ask,
                args: None,
                reason: "rm can be dangerous".into(),
                projects: vec![],
                meta: RuleMeta::default(),
            });
        let config = CommandRules { rules };

        assert_eq!(
            handle_bash(&config, None, "rm -rf /").map(|(d, _)| d),
            Some(Decision::Deny)
        );
    }

    #[test]
    fn ask_fallback_when_args_dont_match_deny() {
        let mut rules: HashMap<String, Vec<CommandRule>> = HashMap::new();
        rules
            .entry("rm".to_string())
            .or_default()
            .push(CommandRule {
                decision: Decision::Deny,
                args: Some(compile_pattern("-rf **")),
                reason: "No recursive force deletes".into(),
                projects: vec![],
                meta: RuleMeta::default(),
            });
        rules
            .entry("rm".to_string())
            .or_default()
            .push(CommandRule {
                decision: Decision::Ask,
                args: None,
                reason: "rm can be dangerous".into(),
                projects: vec![],
                meta: RuleMeta::default(),
            });
        let config = CommandRules { rules };

        assert_eq!(
            handle_bash(&config, None, "rm foo.txt").map(|(d, _)| d),
            Some(Decision::Ask)
        );
    }

    #[test]
    fn allow_with_args_match() {
        let mut rules: HashMap<String, Vec<CommandRule>> = HashMap::new();
        rules
            .entry("git".to_string())
            .or_default()
            .push(CommandRule {
                decision: Decision::Allow,
                args: Some(compile_pattern("status")),
                reason: "ok".into(),
                projects: vec![],
                meta: RuleMeta::default(),
            });
        let config = CommandRules { rules };

        assert_eq!(
            handle_bash(&config, None, "git status").map(|(d, _)| d),
            Some(Decision::Allow)
        );
    }

    #[test]
    fn args_no_match_falls_through() {
        let mut rules: HashMap<String, Vec<CommandRule>> = HashMap::new();
        rules
            .entry("git".to_string())
            .or_default()
            .push(CommandRule {
                decision: Decision::Allow,
                args: Some(compile_pattern("status")),
                reason: "ok".into(),
                projects: vec![],
                meta: RuleMeta::default(),
            });
        let config = CommandRules { rules };

        assert_eq!(handle_bash(&config, None, "git push").map(|(d, _)| d), None);
    }

    #[test]
    fn glob_args_pattern() {
        let mut rules: HashMap<String, Vec<CommandRule>> = HashMap::new();
        rules
            .entry("git".to_string())
            .or_default()
            .push(CommandRule {
                decision: Decision::Allow,
                args: Some(compile_pattern("log *")),
                reason: "ok".into(),
                projects: vec![],
                meta: RuleMeta::default(),
            });
        let config = CommandRules { rules };

        assert_eq!(
            handle_bash(&config, None, "git log --oneline").map(|(d, _)| d),
            Some(Decision::Allow)
        );
    }

    #[test]
    fn regex_args_pattern() {
        let mut rules: HashMap<String, Vec<CommandRule>> = HashMap::new();
        rules
            .entry("git".to_string())
            .or_default()
            .push(CommandRule {
                decision: Decision::Allow,
                args: Some(compile_pattern("/^(status|diff|log)$/")),
                reason: "ok".into(),
                projects: vec![],
                meta: RuleMeta::default(),
            });
        let config = CommandRules { rules };

        assert_eq!(
            handle_bash(&config, None, "git diff").map(|(d, _)| d),
            Some(Decision::Allow)
        );
        assert_eq!(handle_bash(&config, None, "git push").map(|(d, _)| d), None);
    }

    // --- allowed_commands appended after rules ---

    #[test]
    fn rules_take_priority_over_allowed_commands() {
        let raw = RawCommandConfig {
            allowed_commands: vec!["rm".into()],
            rules: vec![RawCommandRule {
                command: "rm".into(),
                args: None,
                decision: "ask".into(),
                reason: Some("rm is dangerous".into()),
                projects: vec![],
            }],
        };
        let config = CommandRules::from_raw(raw, &[], None);

        assert_eq!(
            handle_bash(&config, None, "rm foo").map(|(d, _)| d),
            Some(Decision::Ask)
        );
    }

    #[test]
    fn allowed_commands_used_when_no_rule_matches() {
        let raw = RawCommandConfig {
            allowed_commands: vec!["git".into()],
            rules: vec![RawCommandRule {
                command: "git".into(),
                args: Some("push *".into()),
                decision: "deny".into(),
                reason: Some("no pushing".into()),
                projects: vec![],
            }],
        };
        let config = CommandRules::from_raw(raw, &[], None);

        assert_eq!(
            handle_bash(&config, None, "git push origin main").map(|(d, _)| d),
            Some(Decision::Deny)
        );
        assert_eq!(
            handle_bash(&config, None, "git status").map(|(d, _)| d),
            Some(Decision::Allow)
        );
    }

    // --- handle_web_fetch ---

    fn test_web_fetch_config() -> WebFetchConfig {
        WebFetchConfig {
            rules: vec![
                crate::config::WebFetchRule {
                    decision: Decision::Deny,
                    pattern: compile_pattern("https://evil.com/**"),
                    reason: "Blocked domain".into(),
                    projects: vec![],
                    meta: RuleMeta::default(),
                },
                crate::config::WebFetchRule {
                    decision: Decision::Ask,
                    pattern: compile_pattern("/.*\\.internal\\..*/"),
                    reason: "Internal URL, please confirm".into(),
                    projects: vec![],
                    meta: RuleMeta::default(),
                },
                crate::config::WebFetchRule {
                    decision: Decision::Allow,
                    pattern: compile_pattern("https://docs.rs/**"),
                    reason: "ok".into(),
                    projects: vec![],
                    meta: RuleMeta::default(),
                },
                crate::config::WebFetchRule {
                    decision: Decision::Allow,
                    pattern: compile_pattern("https://crates.io/**"),
                    reason: "ok".into(),
                    projects: vec![],
                    meta: RuleMeta::default(),
                },
            ],
        }
    }

    fn web_fetch_decision(url: &str) -> Option<Decision> {
        handle_web_fetch(&test_web_fetch_config(), None, url).map(|(d, _)| d)
    }

    #[test]
    fn web_fetch_allow_glob() {
        assert_eq!(
            web_fetch_decision("https://docs.rs/regex/latest"),
            Some(Decision::Allow)
        );
    }

    #[test]
    fn web_fetch_deny_glob() {
        assert_eq!(
            web_fetch_decision("https://evil.com/malware"),
            Some(Decision::Deny)
        );
    }

    #[test]
    fn web_fetch_ask_regex() {
        assert_eq!(
            web_fetch_decision("https://wiki.internal.corp/page"),
            Some(Decision::Ask)
        );
    }

    #[test]
    fn web_fetch_passthrough() {
        assert_eq!(web_fetch_decision("https://unknown.com/page"), None);
    }

    #[test]
    fn web_fetch_first_match_wins() {
        let config = WebFetchConfig {
            rules: vec![
                crate::config::WebFetchRule {
                    decision: Decision::Deny,
                    pattern: compile_pattern("https://bad.internal.corp/**"),
                    reason: "Denied".into(),
                    projects: vec![],
                    meta: RuleMeta::default(),
                },
                crate::config::WebFetchRule {
                    decision: Decision::Ask,
                    pattern: compile_pattern("/.*\\.internal\\..*/"),
                    reason: "Ask".into(),
                    projects: vec![],
                    meta: RuleMeta::default(),
                },
            ],
        };
        assert_eq!(
            handle_web_fetch(&config, None, "https://bad.internal.corp/secret").map(|(d, _)| d),
            Some(Decision::Deny)
        );
        assert_eq!(
            handle_web_fetch(&config, None, "https://other.internal.corp/page").map(|(d, _)| d),
            Some(Decision::Ask)
        );
    }

    // --- rule_matches_cwd ---

    #[test]
    fn rule_matches_cwd_empty_projects_matches_all() {
        assert!(rule_matches_cwd(&[], None));
        assert!(rule_matches_cwd(&[], Some("/any/path")));
    }

    #[test]
    fn rule_matches_cwd_exact_match() {
        let projects = vec![PathBuf::from("/home/user/projects/test")];
        assert!(rule_matches_cwd(
            &projects,
            Some("/home/user/projects/test")
        ));
    }

    #[test]
    fn rule_matches_cwd_subdirectory_match() {
        let projects = vec![PathBuf::from("/home/user/projects/test")];
        assert!(rule_matches_cwd(
            &projects,
            Some("/home/user/projects/test/src")
        ));
    }

    #[test]
    fn rule_matches_cwd_no_match() {
        let projects = vec![PathBuf::from("/home/user/projects/test")];
        assert!(!rule_matches_cwd(
            &projects,
            Some("/home/user/projects/other")
        ));
    }

    #[test]
    fn rule_matches_cwd_no_cwd_with_projects() {
        let projects = vec![PathBuf::from("/home/user/projects/test")];
        assert!(!rule_matches_cwd(&projects, None));
    }

    #[test]
    fn rule_matches_cwd_multiple_projects() {
        let projects = vec![
            PathBuf::from("/home/user/projects/a"),
            PathBuf::from("/home/user/projects/b"),
        ];
        assert!(rule_matches_cwd(
            &projects,
            Some("/home/user/projects/b/src")
        ));
        assert!(!rule_matches_cwd(&projects, Some("/home/user/projects/c")));
    }

    // --- per-rule project scoping ---

    #[test]
    fn bash_rule_with_projects_matches_when_cwd_inside() {
        let mut rules: HashMap<String, Vec<CommandRule>> = HashMap::new();
        rules
            .entry("cargo".to_string())
            .or_default()
            .push(CommandRule {
                decision: Decision::Deny,
                args: Some(compile_pattern("publish{, **}")),
                reason: "No publishing from this project".into(),
                projects: vec![PathBuf::from("/home/user/projects/test")],
                meta: RuleMeta::default(),
            });
        rules
            .entry("cargo".to_string())
            .or_default()
            .push(CommandRule {
                decision: Decision::Allow,
                args: None,
                reason: "ok".into(),
                projects: vec![],
                meta: RuleMeta::default(),
            });
        let config = CommandRules { rules };

        assert_eq!(
            handle_bash(&config, Some("/home/user/projects/test"), "cargo publish").map(|(d, _)| d),
            Some(Decision::Deny)
        );
    }

    #[test]
    fn bash_rule_with_projects_skipped_when_cwd_outside() {
        let mut rules: HashMap<String, Vec<CommandRule>> = HashMap::new();
        rules
            .entry("cargo".to_string())
            .or_default()
            .push(CommandRule {
                decision: Decision::Deny,
                args: Some(compile_pattern("publish{, **}")),
                reason: "No publishing from this project".into(),
                projects: vec![PathBuf::from("/home/user/projects/test")],
                meta: RuleMeta::default(),
            });
        rules
            .entry("cargo".to_string())
            .or_default()
            .push(CommandRule {
                decision: Decision::Allow,
                args: None,
                reason: "ok".into(),
                projects: vec![],
                meta: RuleMeta::default(),
            });
        let config = CommandRules { rules };

        assert_eq!(
            handle_bash(&config, Some("/home/user/projects/other"), "cargo publish")
                .map(|(d, _)| d),
            Some(Decision::Allow)
        );
    }

    #[test]
    fn web_fetch_rule_with_projects_matches_when_cwd_inside() {
        let config = WebFetchConfig {
            rules: vec![
                crate::config::WebFetchRule {
                    decision: Decision::Deny,
                    pattern: compile_pattern("https://internal.example.com/**"),
                    reason: "Blocked for this project".into(),
                    projects: vec![PathBuf::from("/home/user/projects/test")],
                    meta: RuleMeta::default(),
                },
                crate::config::WebFetchRule {
                    decision: Decision::Allow,
                    pattern: compile_pattern("https://internal.example.com/**"),
                    reason: "ok".into(),
                    projects: vec![],
                    meta: RuleMeta::default(),
                },
            ],
        };

        assert_eq!(
            handle_web_fetch(
                &config,
                Some("/home/user/projects/test"),
                "https://internal.example.com/api"
            )
            .map(|(d, _)| d),
            Some(Decision::Deny)
        );
    }

    #[test]
    fn web_fetch_rule_with_projects_skipped_when_cwd_outside() {
        let config = WebFetchConfig {
            rules: vec![
                crate::config::WebFetchRule {
                    decision: Decision::Deny,
                    pattern: compile_pattern("https://internal.example.com/**"),
                    reason: "Blocked for this project".into(),
                    projects: vec![PathBuf::from("/home/user/projects/test")],
                    meta: RuleMeta::default(),
                },
                crate::config::WebFetchRule {
                    decision: Decision::Allow,
                    pattern: compile_pattern("https://internal.example.com/**"),
                    reason: "ok".into(),
                    projects: vec![],
                    meta: RuleMeta::default(),
                },
            ],
        };

        assert_eq!(
            handle_web_fetch(
                &config,
                Some("/home/user/projects/other"),
                "https://internal.example.com/api"
            )
            .map(|(d, _)| d),
            Some(Decision::Allow)
        );
    }

    // --- handle_powershell ---

    fn test_powershell_config() -> CommandRules {
        let mut rules: HashMap<String, Vec<CommandRule>> = HashMap::new();
        rules
            .entry("Remove-Item".to_string())
            .or_default()
            .push(CommandRule {
                decision: Decision::Deny,
                args: None,
                reason: "Remove-Item is dangerous.".into(),
                projects: vec![],
                meta: RuleMeta::default(),
            });
        rules
            .entry("Get-ChildItem".to_string())
            .or_default()
            .push(CommandRule {
                decision: Decision::Allow,
                args: None,
                reason: "ok".into(),
                projects: vec![],
                meta: RuleMeta::default(),
            });
        CommandRules { rules }
    }

    #[test]
    fn handle_powershell_deny() {
        assert_eq!(
            handle_powershell(&test_powershell_config(), None, "Remove-Item -Recurse x")
                .map(|(d, _)| d),
            Some(Decision::Deny)
        );
    }

    #[test]
    fn handle_powershell_allow() {
        assert_eq!(
            handle_powershell(&test_powershell_config(), None, "Get-ChildItem").map(|(d, _)| d),
            Some(Decision::Allow)
        );
    }

    #[test]
    fn handle_powershell_passthrough() {
        assert_eq!(
            handle_powershell(&test_powershell_config(), None, "Get-Date").map(|(d, _)| d),
            None
        );
    }

    #[test]
    fn handle_powershell_deny_inside_script_block() {
        assert_eq!(
            handle_powershell(
                &test_powershell_config(),
                None,
                "Get-Process | Where-Object { Remove-Item -Recurse C:\\ }"
            )
            .map(|(d, _)| d),
            Some(Decision::Deny)
        );
    }

    // --- handle_bash_tool inner PowerShell ---

    #[test]
    fn bash_tool_inner_powershell_escalates_to_deny() {
        let bash = CommandRules::default();
        let powershell = test_powershell_config();
        assert_eq!(
            handle_bash_tool(&bash, &powershell, None, "pwsh -Command \"Remove-Item x\"")
                .map(|(d, _)| d),
            Some(Decision::Deny)
        );
    }

    #[test]
    fn bash_tool_powershell_file_unaffected_by_ps_rules() {
        let bash = CommandRules::default();
        let powershell = test_powershell_config();
        assert_eq!(
            handle_bash_tool(&bash, &powershell, None, "pwsh -File x.ps1").map(|(d, _)| d),
            None
        );
    }
}
