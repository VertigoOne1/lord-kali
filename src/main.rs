use regex::Regex;
use serde::Deserialize;
use std::collections::HashMap;
use std::io::Read;
use std::path::PathBuf;

#[derive(Default)]
struct Config {
    bash: BashConfig,
    web_fetch: WebFetchConfig,
    log: Option<LogConfig>,
}

impl Config {
    fn merge(mut self, other: Config) -> Config {
        for (cmd, rules) in other.bash.rules {
            self.bash.rules.entry(cmd).or_default().extend(rules);
        }
        self.web_fetch.rules.extend(other.web_fetch.rules);
        if other.log.is_some() {
            self.log = other.log;
        }
        self
    }
}

#[derive(Default)]
struct BashConfig {
    rules: HashMap<String, Vec<BashRule>>,
}

impl BashConfig {
    fn from_raw(raw: RawBashConfig, group_projects: &[String]) -> Self {
        let mut rules: HashMap<String, Vec<BashRule>> = HashMap::new();

        for r in raw.rules {
            let decision = match r.decision.as_str() {
                "allow" => Decision::Allow,
                "deny" => Decision::Deny,
                "ask" => Decision::Ask,
                other => panic!("Invalid decision '{}' for command '{}'", other, r.command),
            };
            let projects = merge_and_expand_projects(group_projects, &r.projects);
            rules.entry(r.command).or_default().push(BashRule {
                decision,
                args: r.args.map(|a| compile_pattern(&a)),
                reason: r.reason.unwrap_or_else(|| "ok".into()),
                projects,
            });
        }

        for cmd in raw.allowed_commands {
            let projects = group_projects.iter().map(|p| expand_tilde(p)).collect();
            rules.entry(cmd).or_default().push(BashRule {
                decision: Decision::Allow,
                args: None,
                reason: "ok".into(),
                projects,
            });
        }

        BashConfig { rules }
    }
}

struct BashRule {
    decision: Decision,
    args: Option<Pattern>,
    reason: String,
    projects: Vec<PathBuf>,
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
    #[serde(default)]
    projects: Vec<String>,
}

#[derive(Default)]
struct WebFetchConfig {
    rules: Vec<WebFetchRule>,
}

impl WebFetchConfig {
    fn from_raw(raw: RawWebFetchConfig, group_projects: &[String]) -> Self {
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
                    let projects = merge_and_expand_projects(group_projects, &r.projects);
                    WebFetchRule {
                        decision,
                        pattern: compile_pattern(&r.url),
                        reason: r.reason.unwrap_or_else(|| "ok".into()),
                        projects,
                    }
                })
                .collect(),
        }
    }
}

struct WebFetchRule {
    decision: Decision,
    pattern: Pattern,
    reason: String,
    projects: Vec<PathBuf>,
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
    #[serde(default)]
    projects: Vec<String>,
}

#[derive(Default, Deserialize)]
struct RawConfig {
    #[serde(default)]
    bash: RawBashConfig,
    #[serde(default, rename = "web-fetch")]
    web_fetch: RawWebFetchConfig,
    log: Option<LogConfig>,
    #[serde(default)]
    group: Vec<RawGroupConfig>,
}

#[derive(Default, Deserialize)]
struct RawGroupConfig {
    #[serde(default)]
    projects: Vec<String>,
    #[serde(default)]
    bash: RawBashConfig,
    #[serde(default, rename = "web-fetch")]
    web_fetch: RawWebFetchConfig,
}

impl From<RawConfig> for Config {
    fn from(raw: RawConfig) -> Self {
        let mut bash = BashConfig::from_raw(raw.bash, &[]);
        let mut web_fetch = WebFetchConfig::from_raw(raw.web_fetch, &[]);

        for group in raw.group {
            let group_bash = BashConfig::from_raw(group.bash, &group.projects);
            for (cmd, rules) in group_bash.rules {
                bash.rules.entry(cmd).or_default().extend(rules);
            }

            let group_web_fetch = WebFetchConfig::from_raw(group.web_fetch, &group.projects);
            web_fetch.rules.extend(group_web_fetch.rules);
        }

        Config {
            bash,
            web_fetch,
            log: raw.log,
        }
    }
}

fn merge_and_expand_projects(group_projects: &[String], rule_projects: &[String]) -> Vec<PathBuf> {
    let mut seen = Vec::new();
    for p in group_projects.iter().chain(rule_projects.iter()) {
        let expanded = expand_tilde(p);
        if !seen.contains(&expanded) {
            seen.push(expanded);
        }
    }
    seen
}

enum Pattern {
    Glob(String),
    Regex(Regex),
}

impl Pattern {
    fn is_match(&self, text: &str) -> bool {
        match self {
            Pattern::Glob(g) => glob_match_ultra::glob_match(g, text),
            Pattern::Regex(r) => r.is_match(text),
        }
    }
}

fn compile_pattern(s: &str) -> Pattern {
    if let Some(inner) = s.strip_prefix('/').and_then(|s| s.strip_suffix('/')) {
        Pattern::Regex(
            Regex::new(&format!("^{inner}$"))
                .unwrap_or_else(|e| panic!("Invalid pattern '{s}': {e}")),
        )
    } else {
        Pattern::Glob(s.to_string())
    }
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
    cwd: Option<String>,
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

    let cwd = hook_input.cwd.as_deref();

    if hook_input.tool_name == "Bash" {
        if let Some(command) = &hook_input.tool_input.command {
            if let Some((decision, reason)) = handle_bash(&config.bash, cwd, command) {
                print_decision(decision, &reason);
            }
        }
    } else if hook_input.tool_name == "WebFetch" {
        if let Some(url) = &hook_input.tool_input.url {
            if let Some((decision, reason)) = handle_web_fetch(&config.web_fetch, cwd, url) {
                print_decision(decision, &reason);
            }
        }
    }
}

fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        dirs::home_dir()
            .expect("Could not determine home directory")
            .join(rest)
    } else {
        PathBuf::from(path)
    }
}

fn rule_matches_cwd(projects: &[PathBuf], cwd: Option<&str>) -> bool {
    projects.is_empty()
        || cwd.is_some_and(|c| {
            let cwd_path = PathBuf::from(c);
            projects.iter().any(|p| cwd_path.starts_with(p))
        })
}

fn handle_web_fetch(
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

fn load_config() -> Config {
    let config_dir = dirs::config_dir()
        .expect("Could not determine config directory")
        .join("lord-kali");

    let entries = std::fs::read_dir(&config_dir)
        .unwrap_or_else(|e| panic!("Failed to read config dir {}: {}", config_dir.display(), e));

    let mut paths: Vec<PathBuf> = entries
        .filter_map(|entry| {
            let path = entry.ok()?.path();
            if path.extension().and_then(|e| e.to_str()) == Some("toml") {
                Some(path)
            } else {
                None
            }
        })
        .collect();
    paths.sort();

    paths
        .into_iter()
        .map(|path| {
            let content = std::fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("Failed to read config at {}: {}", path.display(), e));
            let raw: RawConfig = toml::from_str(&content)
                .unwrap_or_else(|e| panic!("Failed to parse config at {}: {}", path.display(), e));
            Config::from(raw)
        })
        .fold(Config::default(), Config::merge)
}

fn handle_bash(
    config: &BashConfig,
    cwd: Option<&str>,
    command: &str,
) -> Option<(Decision, String)> {
    let commands = extract_commands(command);

    if commands.is_empty() {
        return None;
    }

    let mut deny_reason: Option<String> = None;
    let mut ask_reason: Option<String> = None;
    let mut all_allowed = true;

    for (name, args) in &commands {
        let rules: Vec<&BashRule> = config
            .rules
            .get(name.as_str())
            .map(|r| r.iter().collect())
            .unwrap_or_default();

        match resolve_command(&rules, args, cwd) {
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

fn resolve_command(
    rules: &[&BashRule],
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
    let expanded = expand_tilde(path_str);

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
                projects: vec![],
            });
        }

        rules.entry("npm".to_string()).or_default().push(BashRule {
            decision: Decision::Deny,
            args: None,
            reason: "Use pnpm instead of npm.".into(),
            projects: vec![],
        });

        rules.entry("rm".to_string()).or_default().push(BashRule {
            decision: Decision::Ask,
            args: None,
            reason: "rm can be dangerous, please ask.".into(),
            projects: vec![],
        });

        rules
            .entry("rmdir".to_string())
            .or_default()
            .push(BashRule {
                decision: Decision::Ask,
                args: None,
                reason: "rmdir can be dangerous, please ask.".into(),
                projects: vec![],
            });

        BashConfig { rules }
    }

    fn decision_of(cmd: &str) -> Option<Decision> {
        handle_bash(&test_bash_config(), None, cmd).map(|(d, _)| d)
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
            args: Some(compile_pattern("-rf **")),
            reason: "No recursive force deletes".into(),
            projects: vec![],
        });
        rules.entry("rm".to_string()).or_default().push(BashRule {
            decision: Decision::Ask,
            args: None,
            reason: "rm can be dangerous".into(),
            projects: vec![],
        });
        let config = BashConfig { rules };

        assert_eq!(
            handle_bash(&config, None, "rm -rf /").map(|(d, _)| d),
            Some(Decision::Deny)
        );
    }

    #[test]
    fn ask_fallback_when_args_dont_match_deny() {
        let mut rules: HashMap<String, Vec<BashRule>> = HashMap::new();
        rules.entry("rm".to_string()).or_default().push(BashRule {
            decision: Decision::Deny,
            args: Some(compile_pattern("-rf **")),
            reason: "No recursive force deletes".into(),
            projects: vec![],
        });
        rules.entry("rm".to_string()).or_default().push(BashRule {
            decision: Decision::Ask,
            args: None,
            reason: "rm can be dangerous".into(),
            projects: vec![],
        });
        let config = BashConfig { rules };

        assert_eq!(
            handle_bash(&config, None, "rm foo.txt").map(|(d, _)| d),
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
            projects: vec![],
        });
        let config = BashConfig { rules };

        assert_eq!(
            handle_bash(&config, None, "git status").map(|(d, _)| d),
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
            projects: vec![],
        });
        let config = BashConfig { rules };

        assert_eq!(handle_bash(&config, None, "git push").map(|(d, _)| d), None);
    }

    #[test]
    fn glob_args_pattern() {
        let mut rules: HashMap<String, Vec<BashRule>> = HashMap::new();
        rules.entry("git".to_string()).or_default().push(BashRule {
            decision: Decision::Allow,
            args: Some(compile_pattern("log *")),
            reason: "ok".into(),
            projects: vec![],
        });
        let config = BashConfig { rules };

        assert_eq!(
            handle_bash(&config, None, "git log --oneline").map(|(d, _)| d),
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
            projects: vec![],
        });
        let config = BashConfig { rules };

        assert_eq!(
            handle_bash(&config, None, "git diff").map(|(d, _)| d),
            Some(Decision::Allow)
        );
        assert_eq!(handle_bash(&config, None, "git push").map(|(d, _)| d), None);
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
                projects: vec![],
            }],
        };
        let config = BashConfig::from_raw(raw, &[]);

        assert_eq!(
            handle_bash(&config, None, "rm foo").map(|(d, _)| d),
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
                projects: vec![],
            }],
        };
        let config = BashConfig::from_raw(raw, &[]);

        assert_eq!(
            handle_bash(&config, None, "git push origin main").map(|(d, _)| d),
            Some(Decision::Deny)
        );
        assert_eq!(
            handle_bash(&config, None, "git status").map(|(d, _)| d),
            Some(Decision::Allow)
        );
    }

    // --- glob patterns ---

    #[test]
    fn glob_star_single_segment() {
        let p = compile_pattern("https://docs.rs/*");
        assert!(p.is_match("https://docs.rs/foo"));
        assert!(!p.is_match("https://docs.rs/foo/bar"));
        assert!(!p.is_match("https://crates.io/foo"));
    }

    #[test]
    fn glob_doublestar_crosses_segments() {
        let p = compile_pattern("https://docs.rs/**");
        assert!(p.is_match("https://docs.rs/foo"));
        assert!(p.is_match("https://docs.rs/foo/bar/baz"));
        assert!(!p.is_match("https://crates.io/foo"));
    }

    #[test]
    fn glob_question_mark() {
        let p = compile_pattern("ab?");
        assert!(p.is_match("abc"));
        assert!(!p.is_match("abcd"));
    }

    #[test]
    fn glob_character_class() {
        let p = compile_pattern("[a-z]*");
        assert!(p.is_match("hello"));
        assert!(!p.is_match("123"));
    }

    #[test]
    fn glob_brace_expansion() {
        let p = compile_pattern("{allow,deny}");
        assert!(p.is_match("allow"));
        assert!(p.is_match("deny"));
        assert!(!p.is_match("ask"));
    }

    #[test]
    fn glob_brace_with_space_star() {
        let p = compile_pattern("{ls,why,info} *");
        assert!(p.is_match("ls react"));
        assert!(p.is_match("why lodash"));
        assert!(!p.is_match("ls"));
        assert!(!p.is_match("install react"));
    }

    #[test]
    fn glob_doublestar_matches_empty() {
        let p = compile_pattern("**");
        assert!(p.is_match(""));
        assert!(p.is_match("anything"));
        assert!(p.is_match("a/b/c"));
    }

    #[test]
    fn glob_brace_with_space_doublestar() {
        let p = compile_pattern("{fmt,build,test} **");
        assert!(p.is_match("fmt --check"));
        assert!(p.is_match("test /some/path"));
        assert!(!p.is_match("fmt"));
        assert!(!p.is_match("run --release"));
    }

    #[test]
    fn glob_empty_brace_alternation() {
        let p = compile_pattern("{fmt,build,test}{, **}");
        assert!(p.is_match("fmt"));
        assert!(p.is_match("fmt --check"));
        assert!(!p.is_match("run --release"));
    }

    #[test]
    fn glob_doublestar_inside_brace() {
        let p = compile_pattern("{foo, **}");
        assert!(p.is_match("foo"));
        assert!(p.is_match(" a/b/c"));

        let p2 = compile_pattern("test{, **}");
        assert!(p2.is_match("test"));
        assert!(p2.is_match("test --flag"));
        assert!(p2.is_match("test /some/path"));
    }

    #[test]
    fn glob_literal_dot() {
        let p = compile_pattern("example.com");
        assert!(p.is_match("example.com"));
        assert!(!p.is_match("exampleXcom"));
    }

    // --- compile_pattern ---

    #[test]
    fn compile_pattern_glob() {
        let p = compile_pattern("https://docs.rs/**");
        assert!(p.is_match("https://docs.rs/foo"));
        assert!(!p.is_match("https://evil.com/foo"));
    }

    #[test]
    fn compile_pattern_regex() {
        let p = compile_pattern("/https://docs\\.rs/.+/");
        assert!(p.is_match("https://docs.rs/regex/latest"));
        assert!(!p.is_match("https://docs.rs/"));
    }

    // --- handle_web_fetch ---

    fn test_web_fetch_config() -> WebFetchConfig {
        WebFetchConfig {
            rules: vec![
                WebFetchRule {
                    decision: Decision::Deny,
                    pattern: compile_pattern("https://evil.com/**"),
                    reason: "Blocked domain".into(),
                    projects: vec![],
                },
                WebFetchRule {
                    decision: Decision::Ask,
                    pattern: compile_pattern("/.*\\.internal\\..*/"),
                    reason: "Internal URL, please confirm".into(),
                    projects: vec![],
                },
                WebFetchRule {
                    decision: Decision::Allow,
                    pattern: compile_pattern("https://docs.rs/**"),
                    reason: "ok".into(),
                    projects: vec![],
                },
                WebFetchRule {
                    decision: Decision::Allow,
                    pattern: compile_pattern("https://crates.io/**"),
                    reason: "ok".into(),
                    projects: vec![],
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
                WebFetchRule {
                    decision: Decision::Deny,
                    pattern: compile_pattern("https://bad.internal.corp/**"),
                    reason: "Denied".into(),
                    projects: vec![],
                },
                WebFetchRule {
                    decision: Decision::Ask,
                    pattern: compile_pattern("/.*\\.internal\\..*/"),
                    reason: "Ask".into(),
                    projects: vec![],
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
        let mut rules: HashMap<String, Vec<BashRule>> = HashMap::new();
        rules
            .entry("cargo".to_string())
            .or_default()
            .push(BashRule {
                decision: Decision::Deny,
                args: Some(compile_pattern("publish{, **}")),
                reason: "No publishing from this project".into(),
                projects: vec![PathBuf::from("/home/user/projects/test")],
            });
        rules
            .entry("cargo".to_string())
            .or_default()
            .push(BashRule {
                decision: Decision::Allow,
                args: None,
                reason: "ok".into(),
                projects: vec![],
            });
        let config = BashConfig { rules };

        assert_eq!(
            handle_bash(&config, Some("/home/user/projects/test"), "cargo publish").map(|(d, _)| d),
            Some(Decision::Deny)
        );
    }

    #[test]
    fn bash_rule_with_projects_skipped_when_cwd_outside() {
        let mut rules: HashMap<String, Vec<BashRule>> = HashMap::new();
        rules
            .entry("cargo".to_string())
            .or_default()
            .push(BashRule {
                decision: Decision::Deny,
                args: Some(compile_pattern("publish{, **}")),
                reason: "No publishing from this project".into(),
                projects: vec![PathBuf::from("/home/user/projects/test")],
            });
        rules
            .entry("cargo".to_string())
            .or_default()
            .push(BashRule {
                decision: Decision::Allow,
                args: None,
                reason: "ok".into(),
                projects: vec![],
            });
        let config = BashConfig { rules };

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
                WebFetchRule {
                    decision: Decision::Deny,
                    pattern: compile_pattern("https://internal.example.com/**"),
                    reason: "Blocked for this project".into(),
                    projects: vec![PathBuf::from("/home/user/projects/test")],
                },
                WebFetchRule {
                    decision: Decision::Allow,
                    pattern: compile_pattern("https://internal.example.com/**"),
                    reason: "ok".into(),
                    projects: vec![],
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
                WebFetchRule {
                    decision: Decision::Deny,
                    pattern: compile_pattern("https://internal.example.com/**"),
                    reason: "Blocked for this project".into(),
                    projects: vec![PathBuf::from("/home/user/projects/test")],
                },
                WebFetchRule {
                    decision: Decision::Allow,
                    pattern: compile_pattern("https://internal.example.com/**"),
                    reason: "ok".into(),
                    projects: vec![],
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

    // --- group flattening ---

    #[test]
    fn group_projects_applied_to_rules() {
        let raw = RawConfig {
            bash: RawBashConfig::default(),
            web_fetch: RawWebFetchConfig::default(),
            log: None,
            group: vec![RawGroupConfig {
                projects: vec!["/home/user/projects/test".into()],
                bash: RawBashConfig {
                    allowed_commands: vec![],
                    rules: vec![RawBashRule {
                        command: "cargo".into(),
                        args: Some("publish{, **}".into()),
                        decision: "deny".into(),
                        reason: Some("No publishing".into()),
                        projects: vec![],
                    }],
                },
                web_fetch: RawWebFetchConfig::default(),
            }],
        };
        let config = Config::from(raw);

        assert_eq!(
            handle_bash(
                &config.bash,
                Some("/home/user/projects/test"),
                "cargo publish"
            )
            .map(|(d, _)| d),
            Some(Decision::Deny)
        );
        assert_eq!(
            handle_bash(
                &config.bash,
                Some("/home/user/projects/other"),
                "cargo publish"
            )
            .map(|(d, _)| d),
            None
        );
    }

    #[test]
    fn group_projects_union_with_rule_projects() {
        let raw = RawConfig {
            bash: RawBashConfig::default(),
            web_fetch: RawWebFetchConfig::default(),
            log: None,
            group: vec![RawGroupConfig {
                projects: vec!["/home/user/projects/a".into()],
                bash: RawBashConfig {
                    allowed_commands: vec![],
                    rules: vec![RawBashRule {
                        command: "cargo".into(),
                        args: Some("publish{, **}".into()),
                        decision: "deny".into(),
                        reason: Some("No publishing".into()),
                        projects: vec!["/home/user/projects/b".into()],
                    }],
                },
                web_fetch: RawWebFetchConfig::default(),
            }],
        };
        let config = Config::from(raw);

        assert_eq!(
            handle_bash(&config.bash, Some("/home/user/projects/a"), "cargo publish")
                .map(|(d, _)| d),
            Some(Decision::Deny)
        );
        assert_eq!(
            handle_bash(&config.bash, Some("/home/user/projects/b"), "cargo publish")
                .map(|(d, _)| d),
            Some(Decision::Deny)
        );
        assert_eq!(
            handle_bash(&config.bash, Some("/home/user/projects/c"), "cargo publish")
                .map(|(d, _)| d),
            None
        );
    }

    #[test]
    fn group_allowed_commands_get_group_projects() {
        let raw = RawConfig {
            bash: RawBashConfig::default(),
            web_fetch: RawWebFetchConfig::default(),
            log: None,
            group: vec![RawGroupConfig {
                projects: vec!["/home/user/projects/test".into()],
                bash: RawBashConfig {
                    allowed_commands: vec!["rustup".into()],
                    rules: vec![],
                },
                web_fetch: RawWebFetchConfig::default(),
            }],
        };
        let config = Config::from(raw);

        assert_eq!(
            handle_bash(
                &config.bash,
                Some("/home/user/projects/test"),
                "rustup show"
            )
            .map(|(d, _)| d),
            Some(Decision::Allow)
        );
        assert_eq!(
            handle_bash(
                &config.bash,
                Some("/home/user/projects/other"),
                "rustup show"
            )
            .map(|(d, _)| d),
            None
        );
    }

    #[test]
    fn group_web_fetch_rules_get_group_projects() {
        let raw = RawConfig {
            bash: RawBashConfig::default(),
            web_fetch: RawWebFetchConfig::default(),
            log: None,
            group: vec![RawGroupConfig {
                projects: vec!["/home/user/projects/test".into()],
                bash: RawBashConfig::default(),
                web_fetch: RawWebFetchConfig {
                    rules: vec![RawWebFetchRule {
                        url: "https://internal.example.com/**".into(),
                        decision: "allow".into(),
                        reason: Some("ok".into()),
                        projects: vec![],
                    }],
                },
            }],
        };
        let config = Config::from(raw);

        assert_eq!(
            handle_web_fetch(
                &config.web_fetch,
                Some("/home/user/projects/test"),
                "https://internal.example.com/api"
            )
            .map(|(d, _)| d),
            Some(Decision::Allow)
        );
        assert_eq!(
            handle_web_fetch(
                &config.web_fetch,
                Some("/home/user/projects/other"),
                "https://internal.example.com/api"
            )
            .map(|(d, _)| d),
            None
        );
    }

    #[test]
    fn top_level_rules_before_group_rules() {
        let raw = RawConfig {
            bash: RawBashConfig {
                allowed_commands: vec![],
                rules: vec![RawBashRule {
                    command: "cargo".into(),
                    args: Some("publish{, **}".into()),
                    decision: "deny".into(),
                    reason: Some("Global deny".into()),
                    projects: vec![],
                }],
            },
            web_fetch: RawWebFetchConfig::default(),
            log: None,
            group: vec![RawGroupConfig {
                projects: vec!["/home/user/projects/test".into()],
                bash: RawBashConfig {
                    allowed_commands: vec![],
                    rules: vec![RawBashRule {
                        command: "cargo".into(),
                        args: Some("publish{, **}".into()),
                        decision: "allow".into(),
                        reason: Some("Group allow".into()),
                        projects: vec![],
                    }],
                },
                web_fetch: RawWebFetchConfig::default(),
            }],
        };
        let config = Config::from(raw);

        assert_eq!(
            handle_bash(
                &config.bash,
                Some("/home/user/projects/test"),
                "cargo publish"
            )
            .map(|(d, r)| (d, r)),
            Some((Decision::Deny, "Global deny".into()))
        );
    }

    // --- Config::merge ---

    #[test]
    fn merge_bash_rules() {
        let mut rules_a: HashMap<String, Vec<BashRule>> = HashMap::new();
        rules_a
            .entry("git".to_string())
            .or_default()
            .push(BashRule {
                decision: Decision::Allow,
                args: Some(compile_pattern("status")),
                reason: "ok".into(),
                projects: vec![],
            });
        let a = Config {
            bash: BashConfig { rules: rules_a },
            ..Config::default()
        };

        let mut rules_b: HashMap<String, Vec<BashRule>> = HashMap::new();
        rules_b
            .entry("git".to_string())
            .or_default()
            .push(BashRule {
                decision: Decision::Deny,
                args: Some(compile_pattern("push{, **}")),
                reason: "no pushing".into(),
                projects: vec![],
            });
        rules_b
            .entry("cargo".to_string())
            .or_default()
            .push(BashRule {
                decision: Decision::Allow,
                args: None,
                reason: "ok".into(),
                projects: vec![],
            });
        let b = Config {
            bash: BashConfig { rules: rules_b },
            ..Config::default()
        };

        let merged = a.merge(b);
        let git_rules = &merged.bash.rules["git"];
        assert_eq!(git_rules.len(), 2);
        assert_eq!(git_rules[0].reason, "ok");
        assert_eq!(git_rules[1].reason, "no pushing");
        assert_eq!(merged.bash.rules["cargo"].len(), 1);
    }

    #[test]
    fn merge_web_fetch_rules() {
        let a = Config {
            web_fetch: WebFetchConfig {
                rules: vec![WebFetchRule {
                    decision: Decision::Deny,
                    pattern: compile_pattern("https://evil.com/**"),
                    reason: "blocked".into(),
                    projects: vec![],
                }],
            },
            ..Config::default()
        };
        let b = Config {
            web_fetch: WebFetchConfig {
                rules: vec![WebFetchRule {
                    decision: Decision::Allow,
                    pattern: compile_pattern("https://docs.rs/**"),
                    reason: "ok".into(),
                    projects: vec![],
                }],
            },
            ..Config::default()
        };

        let merged = a.merge(b);
        assert_eq!(merged.web_fetch.rules.len(), 2);
        assert_eq!(merged.web_fetch.rules[0].reason, "blocked");
        assert_eq!(merged.web_fetch.rules[1].reason, "ok");
    }

    #[test]
    fn merge_log_last_wins() {
        let a = Config {
            log: Some(LogConfig {
                enabled: true,
                path: Some("/a.log".into()),
            }),
            ..Config::default()
        };
        let b = Config {
            log: Some(LogConfig {
                enabled: false,
                path: Some("/b.log".into()),
            }),
            ..Config::default()
        };
        let c = Config {
            log: None,
            ..Config::default()
        };

        let merged = a.merge(b);
        assert_eq!(merged.log.as_ref().unwrap().enabled, false);
        assert_eq!(merged.log.as_ref().unwrap().path.as_deref(), Some("/b.log"));

        let merged2 = merged.merge(c);
        assert_eq!(
            merged2.log.as_ref().unwrap().path.as_deref(),
            Some("/b.log")
        );
    }

    // --- TOML deserialization ---

    #[test]
    fn toml_top_level_rule_with_projects() {
        let toml_str = r#"
[[bash.rules]]
command = "cargo"
args = "publish{, **}"
decision = "deny"
projects = ["/home/user/projects/test"]
"#;
        let raw: RawConfig = toml::from_str(toml_str).unwrap();
        let config = Config::from(raw);

        assert_eq!(
            handle_bash(
                &config.bash,
                Some("/home/user/projects/test"),
                "cargo publish"
            )
            .map(|(d, _)| d),
            Some(Decision::Deny)
        );
        assert_eq!(
            handle_bash(
                &config.bash,
                Some("/home/user/projects/other"),
                "cargo publish"
            )
            .map(|(d, _)| d),
            None
        );
    }

    #[test]
    fn toml_group_with_bash_rules() {
        let toml_str = r#"
[[group]]
projects = ["/home/user/projects/test"]

[group.bash]
allowed_commands = ["rustup"]

[[group.bash.rules]]
command = "cargo"
args = "test{, **}"
decision = "allow"
"#;
        let raw: RawConfig = toml::from_str(toml_str).unwrap();
        let config = Config::from(raw);

        assert_eq!(
            handle_bash(&config.bash, Some("/home/user/projects/test"), "cargo test")
                .map(|(d, _)| d),
            Some(Decision::Allow)
        );
        assert_eq!(
            handle_bash(
                &config.bash,
                Some("/home/user/projects/other"),
                "cargo test"
            )
            .map(|(d, _)| d),
            None
        );
        assert_eq!(
            handle_bash(
                &config.bash,
                Some("/home/user/projects/test"),
                "rustup show"
            )
            .map(|(d, _)| d),
            Some(Decision::Allow)
        );
    }

    #[test]
    fn toml_group_rule_with_extra_projects() {
        let toml_str = r#"
[[group]]
projects = ["/home/user/projects/a"]

[[group.bash.rules]]
command = "make"
decision = "allow"
projects = ["/home/user/projects/b"]
"#;
        let raw: RawConfig = toml::from_str(toml_str).unwrap();
        let config = Config::from(raw);

        assert_eq!(
            handle_bash(&config.bash, Some("/home/user/projects/a"), "make").map(|(d, _)| d),
            Some(Decision::Allow)
        );
        assert_eq!(
            handle_bash(&config.bash, Some("/home/user/projects/b"), "make").map(|(d, _)| d),
            Some(Decision::Allow)
        );
        assert_eq!(
            handle_bash(&config.bash, Some("/home/user/projects/c"), "make").map(|(d, _)| d),
            None
        );
    }

    #[test]
    fn toml_group_web_fetch_rules() {
        let toml_str = r#"
[[group]]
projects = ["/home/user/projects/test"]

[[group.web-fetch.rules]]
url = "https://internal.example.com/**"
decision = "allow"
"#;
        let raw: RawConfig = toml::from_str(toml_str).unwrap();
        let config = Config::from(raw);

        assert_eq!(
            handle_web_fetch(
                &config.web_fetch,
                Some("/home/user/projects/test"),
                "https://internal.example.com/api"
            )
            .map(|(d, _)| d),
            Some(Decision::Allow)
        );
        assert_eq!(
            handle_web_fetch(
                &config.web_fetch,
                Some("/home/user/projects/other"),
                "https://internal.example.com/api"
            )
            .map(|(d, _)| d),
            None
        );
    }

    // --- HookInput parsing ---

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
