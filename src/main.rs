use regex::Regex;
use serde::Deserialize;
use std::collections::HashMap;
use std::io::Read;
use std::path::PathBuf;

#[derive(Deserialize)]
struct Config {
    #[serde(default)]
    bash: BashConfig,
    #[serde(default, rename = "web-fetch")]
    web_fetch: WebFetchConfig,
    log: Option<LogConfig>,
}

#[derive(Default)]
struct BashConfig {
    rules: HashMap<String, Vec<BashRule>>,
}

struct BashRule {
    decision: Decision,
    args: Option<Regex>,
    reason: String,
}

#[derive(Default, Deserialize)]
struct RawBashConfig {
    #[serde(default)]
    allowed_commands: Vec<String>,
    #[serde(default)]
    rules: Vec<RawBashRule>,
}

#[derive(Deserialize)]
struct RawBashRule {
    command: String,
    args: Option<String>,
    decision: String,
    reason: Option<String>,
}

impl From<RawBashConfig> for BashConfig {
    fn from(raw: RawBashConfig) -> Self {
        let mut rules: HashMap<String, Vec<BashRule>> = HashMap::new();

        for r in raw.rules {
            let decision = match r.decision.as_str() {
                "allow" => Decision::Allow,
                "deny" => Decision::Deny,
                "ask" => Decision::Ask,
                other => panic!("Invalid decision '{}' for command '{}'", other, r.command),
            };
            rules.entry(r.command).or_default().push(BashRule {
                decision,
                args: r.args.map(|a| compile_pattern(&a)),
                reason: r.reason.unwrap_or_else(|| "ok".into()),
            });
        }

        for cmd in raw.allowed_commands {
            rules.entry(cmd).or_default().push(BashRule {
                decision: Decision::Allow,
                args: None,
                reason: "ok".into(),
            });
        }

        BashConfig { rules }
    }
}

impl<'de> Deserialize<'de> for BashConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        RawBashConfig::deserialize(deserializer).map(BashConfig::from)
    }
}

#[derive(Default)]
struct WebFetchConfig {
    rules: Vec<WebFetchRule>,
}

struct WebFetchRule {
    decision: Decision,
    pattern: Regex,
    reason: String,
}

#[derive(Default, Deserialize)]
struct RawWebFetchConfig {
    #[serde(default)]
    rules: Vec<RawWebFetchRule>,
}

#[derive(Deserialize)]
struct RawWebFetchRule {
    url: String,
    decision: String,
    reason: Option<String>,
}

impl From<RawWebFetchConfig> for WebFetchConfig {
    fn from(raw: RawWebFetchConfig) -> Self {
        WebFetchConfig {
            rules: raw
                .rules
                .into_iter()
                .map(|r| {
                    let decision = match r.decision.as_str() {
                        "allow" => Decision::Allow,
                        "deny" => Decision::Deny,
                        "ask" => Decision::Ask,
                        other => panic!("Invalid decision '{}' for url '{}'", other, r.url),
                    };
                    WebFetchRule {
                        decision,
                        pattern: compile_pattern(&r.url),
                        reason: r.reason.unwrap_or_else(|| "ok".into()),
                    }
                })
                .collect(),
        }
    }
}

impl<'de> Deserialize<'de> for WebFetchConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        RawWebFetchConfig::deserialize(deserializer).map(WebFetchConfig::from)
    }
}

fn glob_to_regex(glob: &str) -> String {
    let mut result = String::from("^");
    for c in glob.chars() {
        match c {
            '*' => result.push_str(".*"),
            '?' => result.push('.'),
            '.' | '+' | '(' | ')' | '{' | '}' | '[' | ']' | '|' | '^' | '$' | '\\' => {
                result.push('\\');
                result.push(c);
            }
            _ => result.push(c),
        }
    }
    result.push('$');
    result
}

fn compile_pattern(s: &str) -> Regex {
    let pattern = if let Some(inner) = s.strip_prefix('/').and_then(|s| s.strip_suffix('/')) {
        format!("^{inner}$")
    } else {
        glob_to_regex(s)
    };
    Regex::new(&pattern).unwrap_or_else(|e| panic!("Invalid pattern '{s}': {e}"))
}

#[derive(Deserialize)]
struct LogConfig {
    #[serde(default)]
    enabled: bool,
    path: Option<String>,
}

#[derive(Deserialize)]
struct HookInput {
    tool_name: String,
    tool_input: ToolInput,
}

#[derive(Deserialize)]
struct ToolInput {
    command: Option<String>,
    url: Option<String>,
}

#[derive(Debug, PartialEq, Clone)]
enum Decision {
    Allow,
    Deny,
    Ask,
}

fn main() {
    let config = load_config();

    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .expect("Failed to read stdin");

    let hook_input: HookInput = serde_json::from_str(&input).expect("Failed to parse hook input");

    if let Some(log) = &config.log {
        if log.enabled {
            log_invocation(log, &input);
        }
    }

    if hook_input.tool_name == "Bash" {
        if let Some(command) = &hook_input.tool_input.command {
            if let Some((decision, reason)) = handle_bash(&config.bash, command) {
                print_decision(decision, &reason);
            }
        }
    } else if hook_input.tool_name == "WebFetch" {
        if let Some(url) = &hook_input.tool_input.url {
            if let Some((decision, reason)) = handle_web_fetch(&config.web_fetch, url) {
                print_decision(decision, &reason);
            }
        }
    }
}

fn handle_web_fetch(config: &WebFetchConfig, url: &str) -> Option<(Decision, String)> {
    for rule in &config.rules {
        if rule.pattern.is_match(url) {
            return Some((rule.decision.clone(), rule.reason.clone()));
        }
    }
    None
}

fn load_config() -> Config {
    let config_path = dirs::config_dir()
        .expect("Could not determine config directory")
        .join("lord-kali")
        .join("config.toml");

    let content = std::fs::read_to_string(&config_path)
        .unwrap_or_else(|e| panic!("Failed to read config at {}: {}", config_path.display(), e));

    toml::from_str(&content)
        .unwrap_or_else(|e| panic!("Failed to parse config at {}: {}", config_path.display(), e))
}

fn handle_bash(bash: &BashConfig, command: &str) -> Option<(Decision, String)> {
    let commands = extract_commands(command);

    if commands.is_empty() {
        return None;
    }

    let mut deny_reason: Option<String> = None;
    let mut ask_reason: Option<String> = None;
    let mut all_allowed = true;

    for (name, args) in &commands {
        match resolve_command(bash, name, args) {
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

fn resolve_command(bash: &BashConfig, name: &str, args: &str) -> Option<(Decision, String)> {
    for rule in bash.rules.get(name)? {
        if matches_args(&rule.args, args) {
            return Some((rule.decision.clone(), rule.reason.clone()));
        }
    }
    None
}

fn matches_args(pattern: &Option<Regex>, args: &str) -> bool {
    match pattern {
        None => true,
        Some(re) => re.is_match(args),
    }
}

fn extract_commands(source: &str) -> Vec<(String, String)> {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_bash::LANGUAGE.into())
        .expect("Failed to set bash language");

    let tree = parser
        .parse(source, None)
        .expect("Failed to parse bash command");

    let mut commands = Vec::new();
    let mut cursor = tree.root_node().walk();
    walk_node(&mut cursor, source.as_bytes(), &mut commands);
    commands
}

fn extract_args(node: &tree_sitter::Node, source: &[u8]) -> String {
    const REDIRECT_KINDS: &[&str] = &["file_redirect", "heredoc_redirect", "herestring_redirect"];

    let mut parts = Vec::new();
    let mut past_name = false;
    let count = node.child_count();

    for i in 0..count {
        let child = node.child(i).unwrap();
        if !past_name {
            if child.kind() == "command_name" {
                past_name = true;
            }
            continue;
        }
        if REDIRECT_KINDS.contains(&child.kind()) {
            continue;
        }
        if let Ok(text) = child.utf8_text(source) {
            parts.push(text);
        }
    }

    parts.join(" ")
}

fn walk_node(
    cursor: &mut tree_sitter::TreeCursor,
    source: &[u8],
    commands: &mut Vec<(String, String)>,
) {
    let node = cursor.node();

    if node.kind() == "command" {
        if let Some(name_node) = node.child_by_field_name("name") {
            if let Ok(name) = name_node.utf8_text(source) {
                let basename = name.rsplit('/').next().unwrap_or(name);
                if !basename.is_empty() {
                    let args = extract_args(&node, source);
                    commands.push((basename.to_string(), args));

                    if basename == "xargs" {
                        if let Some(sub) = extract_xargs_subcommand(&node, source) {
                            commands.push(sub);
                        }
                    }
                }
            }
        }
    }

    if cursor.goto_first_child() {
        loop {
            walk_node(cursor, source, commands);
            if !cursor.goto_next_sibling() {
                break;
            }
        }
        cursor.goto_parent();
    }
}

fn extract_xargs_subcommand(node: &tree_sitter::Node, source: &[u8]) -> Option<(String, String)> {
    const VALUE_FLAGS: &[&str] = &["-d", "-E", "-I", "-L", "-n", "-P", "-s"];

    let mut skip_next = false;
    let mut past_command_name = false;

    let mut cursor = node.walk();
    if !cursor.goto_first_child() {
        return None;
    }

    loop {
        let child = cursor.node();
        let text = child.utf8_text(source).unwrap_or("");

        if !past_command_name {
            if child.kind() == "command_name" {
                past_command_name = true;
            }
            if !cursor.goto_next_sibling() {
                break;
            }
            continue;
        }

        if skip_next {
            skip_next = false;
            if !cursor.goto_next_sibling() {
                break;
            }
            continue;
        }

        if text.starts_with("--") {
            if !cursor.goto_next_sibling() {
                break;
            }
            continue;
        }

        if text.starts_with('-') {
            if VALUE_FLAGS.contains(&text) {
                skip_next = true;
            }
            if !cursor.goto_next_sibling() {
                break;
            }
            continue;
        }

        let basename = text.rsplit('/').next().unwrap_or(text);
        if !basename.is_empty() {
            let mut sub_args = Vec::new();
            while cursor.goto_next_sibling() {
                let sibling = cursor.node();
                if let Ok(t) = sibling.utf8_text(source) {
                    sub_args.push(t.to_string());
                }
            }
            return Some((basename.to_string(), sub_args.join(" ")));
        }

        if !cursor.goto_next_sibling() {
            break;
        }
    }

    None
}

fn log_invocation(log_config: &LogConfig, input: &str) {
    let default_path = "~/.local/state/lord-kali/hook.jsonl";
    let path_str = log_config.path.as_deref().unwrap_or(default_path);

    let expanded = if let Some(rest) = path_str.strip_prefix("~/") {
        dirs::home_dir()
            .expect("Could not determine home directory")
            .join(rest)
    } else {
        PathBuf::from(path_str)
    };

    if let Some(parent) = expanded.parent() {
        std::fs::create_dir_all(parent).expect("Failed to create log directory");
    }

    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&expanded)
        .unwrap_or_else(|e| panic!("Failed to open log file at {}: {}", expanded.display(), e));

    writeln!(file, "{}", input.trim())
        .unwrap_or_else(|e| panic!("Failed to write to log file: {}", e));
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

    fn test_bash_config() -> BashConfig {
        let mut rules: HashMap<String, Vec<BashRule>> = HashMap::new();

        for cmd in ["tail", "grep", "ls", "find", "cat", "head", "wc"] {
            rules.entry(cmd.to_string()).or_default().push(BashRule {
                decision: Decision::Allow,
                args: None,
                reason: "ok".into(),
            });
        }

        rules.entry("npm".to_string()).or_default().push(BashRule {
            decision: Decision::Deny,
            args: None,
            reason: "Use pnpm instead of npm.".into(),
        });

        rules.entry("rm".to_string()).or_default().push(BashRule {
            decision: Decision::Ask,
            args: None,
            reason: "rm can be dangerous, please ask.".into(),
        });

        rules
            .entry("rmdir".to_string())
            .or_default()
            .push(BashRule {
                decision: Decision::Ask,
                args: None,
                reason: "rmdir can be dangerous, please ask.".into(),
            });

        BashConfig { rules }
    }

    fn decision_of(cmd: &str) -> Option<Decision> {
        handle_bash(&test_bash_config(), cmd).map(|(d, _)| d)
    }

    fn command_names(cmd: &str) -> Vec<String> {
        extract_commands(cmd)
            .into_iter()
            .map(|(name, _)| name)
            .collect()
    }

    // --- extract_commands ---

    #[test]
    fn extract_simple_command() {
        assert_eq!(command_names("ls -la"), vec!["ls"]);
    }

    #[test]
    fn extract_pipeline() {
        assert_eq!(command_names("ls | grep foo"), vec!["ls", "grep"]);
    }

    #[test]
    fn extract_and_chain() {
        assert_eq!(command_names("ls && cat foo"), vec!["ls", "cat"]);
    }

    #[test]
    fn extract_or_chain() {
        assert_eq!(command_names("ls || cat foo"), vec!["ls", "cat"]);
    }

    #[test]
    fn extract_semicolon_chain() {
        assert_eq!(command_names("ls; cat foo"), vec!["ls", "cat"]);
    }

    #[test]
    fn extract_command_substitution() {
        assert_eq!(command_names("echo $(rm foo)"), vec!["echo", "rm"]);
    }

    #[test]
    fn extract_subshell() {
        assert_eq!(command_names("(rm foo)"), vec!["rm"]);
    }

    #[test]
    fn extract_path_normalization() {
        assert_eq!(command_names("/usr/bin/rm foo"), vec!["rm"]);
    }

    #[test]
    fn extract_xargs_simple() {
        assert_eq!(
            command_names("find . | xargs rm"),
            vec!["find", "xargs", "rm"]
        );
    }

    #[test]
    fn extract_xargs_with_short_value_flag() {
        assert_eq!(
            command_names("find . | xargs -I {} rm {}"),
            vec!["find", "xargs", "rm"]
        );
    }

    #[test]
    fn extract_xargs_with_multiple_flags() {
        assert_eq!(
            command_names("find . | xargs -n 1 -I {} rm {}"),
            vec!["find", "xargs", "rm"]
        );
    }

    #[test]
    fn extract_xargs_with_long_flag_equals() {
        assert_eq!(
            command_names("find . | xargs --max-procs=4 rm"),
            vec!["find", "xargs", "rm"]
        );
    }

    #[test]
    fn extract_xargs_with_boolean_short_flag() {
        assert_eq!(
            command_names("find . | xargs -0 rm"),
            vec!["find", "xargs", "rm"]
        );
    }

    #[test]
    fn extract_xargs_subcommand_with_path() {
        assert_eq!(
            command_names("find . | xargs /usr/bin/rm"),
            vec!["find", "xargs", "rm"]
        );
    }

    #[test]
    fn extract_nested_substitution_in_pipeline() {
        let cmds = command_names("find . | ls $(echo poo)");
        assert!(cmds.contains(&"find".to_string()));
        assert!(cmds.contains(&"ls".to_string()));
        assert!(cmds.contains(&"echo".to_string()));
    }

    // --- extract_args ---

    #[test]
    fn extract_args_simple() {
        let cmds = extract_commands("rm -rf /tmp/foo");
        assert_eq!(cmds, vec![("rm".into(), "-rf /tmp/foo".into())]);
    }

    #[test]
    fn extract_args_no_args() {
        let cmds = extract_commands("ls");
        assert_eq!(cmds, vec![("ls".into(), "".into())]);
    }

    #[test]
    fn extract_args_pipeline() {
        let cmds = extract_commands("ls -la | grep foo");
        assert_eq!(
            cmds,
            vec![("ls".into(), "-la".into()), ("grep".into(), "foo".into())]
        );
    }

    #[test]
    fn extract_env_prefix_command() {
        let cmds = extract_commands("PGPASSWORD=secret psql -h localhost mydb");
        assert_eq!(cmds, vec![("psql".into(), "-h localhost mydb".into())]);
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
        let mut rules: HashMap<String, Vec<BashRule>> = HashMap::new();
        rules.entry("rm".to_string()).or_default().push(BashRule {
            decision: Decision::Deny,
            args: Some(compile_pattern("-rf *")),
            reason: "No recursive force deletes".into(),
        });
        rules.entry("rm".to_string()).or_default().push(BashRule {
            decision: Decision::Ask,
            args: None,
            reason: "rm can be dangerous".into(),
        });
        let config = BashConfig { rules };

        assert_eq!(
            handle_bash(&config, "rm -rf /").map(|(d, _)| d),
            Some(Decision::Deny)
        );
    }

    #[test]
    fn ask_fallback_when_args_dont_match_deny() {
        let mut rules: HashMap<String, Vec<BashRule>> = HashMap::new();
        rules.entry("rm".to_string()).or_default().push(BashRule {
            decision: Decision::Deny,
            args: Some(compile_pattern("-rf *")),
            reason: "No recursive force deletes".into(),
        });
        rules.entry("rm".to_string()).or_default().push(BashRule {
            decision: Decision::Ask,
            args: None,
            reason: "rm can be dangerous".into(),
        });
        let config = BashConfig { rules };

        assert_eq!(
            handle_bash(&config, "rm foo.txt").map(|(d, _)| d),
            Some(Decision::Ask)
        );
    }

    #[test]
    fn allow_with_args_match() {
        let mut rules: HashMap<String, Vec<BashRule>> = HashMap::new();
        rules.entry("git".to_string()).or_default().push(BashRule {
            decision: Decision::Allow,
            args: Some(compile_pattern("status")),
            reason: "ok".into(),
        });
        let config = BashConfig { rules };

        assert_eq!(
            handle_bash(&config, "git status").map(|(d, _)| d),
            Some(Decision::Allow)
        );
    }

    #[test]
    fn args_no_match_falls_through() {
        let mut rules: HashMap<String, Vec<BashRule>> = HashMap::new();
        rules.entry("git".to_string()).or_default().push(BashRule {
            decision: Decision::Allow,
            args: Some(compile_pattern("status")),
            reason: "ok".into(),
        });
        let config = BashConfig { rules };

        assert_eq!(handle_bash(&config, "git push").map(|(d, _)| d), None);
    }

    #[test]
    fn glob_args_pattern() {
        let mut rules: HashMap<String, Vec<BashRule>> = HashMap::new();
        rules.entry("git".to_string()).or_default().push(BashRule {
            decision: Decision::Allow,
            args: Some(compile_pattern("log *")),
            reason: "ok".into(),
        });
        let config = BashConfig { rules };

        assert_eq!(
            handle_bash(&config, "git log --oneline").map(|(d, _)| d),
            Some(Decision::Allow)
        );
    }

    #[test]
    fn regex_args_pattern() {
        let mut rules: HashMap<String, Vec<BashRule>> = HashMap::new();
        rules.entry("git".to_string()).or_default().push(BashRule {
            decision: Decision::Allow,
            args: Some(compile_pattern("/^(status|diff|log)$/")),
            reason: "ok".into(),
        });
        let config = BashConfig { rules };

        assert_eq!(
            handle_bash(&config, "git diff").map(|(d, _)| d),
            Some(Decision::Allow)
        );
        assert_eq!(handle_bash(&config, "git push").map(|(d, _)| d), None);
    }

    // --- allowed_commands appended after rules ---

    #[test]
    fn rules_take_priority_over_allowed_commands() {
        let raw = RawBashConfig {
            allowed_commands: vec!["rm".into()],
            rules: vec![RawBashRule {
                command: "rm".into(),
                args: None,
                decision: "ask".into(),
                reason: Some("rm is dangerous".into()),
            }],
        };
        let config = BashConfig::from(raw);

        assert_eq!(
            handle_bash(&config, "rm foo").map(|(d, _)| d),
            Some(Decision::Ask)
        );
    }

    #[test]
    fn allowed_commands_used_when_no_rule_matches() {
        let raw = RawBashConfig {
            allowed_commands: vec!["git".into()],
            rules: vec![RawBashRule {
                command: "git".into(),
                args: Some("push *".into()),
                decision: "deny".into(),
                reason: Some("no pushing".into()),
            }],
        };
        let config = BashConfig::from(raw);

        assert_eq!(
            handle_bash(&config, "git push origin main").map(|(d, _)| d),
            Some(Decision::Deny)
        );
        assert_eq!(
            handle_bash(&config, "git status").map(|(d, _)| d),
            Some(Decision::Allow)
        );
    }

    // --- glob_to_regex ---

    #[test]
    fn glob_star_wildcard() {
        let re = Regex::new(&glob_to_regex("https://docs.rs/*")).unwrap();
        assert!(re.is_match("https://docs.rs/regex/latest"));
        assert!(!re.is_match("https://crates.io/foo"));
    }

    #[test]
    fn glob_question_mark() {
        let re = Regex::new(&glob_to_regex("https://a.com/ab?")).unwrap();
        assert!(re.is_match("https://a.com/abc"));
        assert!(!re.is_match("https://a.com/abcd"));
    }

    #[test]
    fn glob_metachar_escaping() {
        let re = Regex::new(&glob_to_regex("https://example.com/path")).unwrap();
        assert!(re.is_match("https://example.com/path"));
        assert!(!re.is_match("https://exampleXcom/path"));
    }

    // --- compile_pattern ---

    #[test]
    fn compile_pattern_glob() {
        let re = compile_pattern("https://docs.rs/*");
        assert!(re.is_match("https://docs.rs/foo"));
        assert!(!re.is_match("https://evil.com/foo"));
    }

    #[test]
    fn compile_pattern_regex() {
        let re = compile_pattern("/https://docs\\.rs/.+/");
        assert!(re.is_match("https://docs.rs/regex/latest"));
        assert!(!re.is_match("https://docs.rs/"));
    }

    // --- handle_web_fetch ---

    fn test_web_fetch_config() -> WebFetchConfig {
        WebFetchConfig {
            rules: vec![
                WebFetchRule {
                    decision: Decision::Deny,
                    pattern: compile_pattern("https://evil.com/*"),
                    reason: "Blocked domain".into(),
                },
                WebFetchRule {
                    decision: Decision::Ask,
                    pattern: compile_pattern("/.*\\.internal\\..*/"),
                    reason: "Internal URL, please confirm".into(),
                },
                WebFetchRule {
                    decision: Decision::Allow,
                    pattern: compile_pattern("https://docs.rs/*"),
                    reason: "ok".into(),
                },
                WebFetchRule {
                    decision: Decision::Allow,
                    pattern: compile_pattern("https://crates.io/*"),
                    reason: "ok".into(),
                },
            ],
        }
    }

    fn web_fetch_decision(url: &str) -> Option<Decision> {
        handle_web_fetch(&test_web_fetch_config(), url).map(|(d, _)| d)
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
                WebFetchRule {
                    decision: Decision::Deny,
                    pattern: compile_pattern("https://bad.internal.corp/*"),
                    reason: "Denied".into(),
                },
                WebFetchRule {
                    decision: Decision::Ask,
                    pattern: compile_pattern("/.*\\.internal\\..*/"),
                    reason: "Ask".into(),
                },
            ],
        };
        assert_eq!(
            handle_web_fetch(&config, "https://bad.internal.corp/secret").map(|(d, _)| d),
            Some(Decision::Deny)
        );
        assert_eq!(
            handle_web_fetch(&config, "https://other.internal.corp/page").map(|(d, _)| d),
            Some(Decision::Ask)
        );
    }
}
