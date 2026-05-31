use regex::Regex;
use serde::Deserialize;
use std::collections::HashMap;
use std::io::{IsTerminal, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Default)]
struct Config {
    bash: CommandRules,
    powershell: CommandRules,
    web_fetch: WebFetchConfig,
    log: Option<LogConfig>,
    worktree_protection: WorktreeProtectionConfig,
}

impl Config {
    fn merge(mut self, other: Config) -> Config {
        for (cmd, rules) in other.bash.rules {
            self.bash.rules.entry(cmd).or_default().extend(rules);
        }
        for (cmd, rules) in other.powershell.rules {
            self.powershell.rules.entry(cmd).or_default().extend(rules);
        }
        self.web_fetch.rules.extend(other.web_fetch.rules);
        if other.log.is_some() {
            self.log = other.log;
        }
        self.worktree_protection = other.worktree_protection.merge(self.worktree_protection);
        self
    }
}

#[derive(Default)]
struct CommandRules {
    rules: HashMap<String, Vec<CommandRule>>,
}

impl CommandRules {
    fn from_raw(raw: RawCommandConfig, group_projects: &[String], source: Source) -> Self {
        let mut rules: HashMap<String, Vec<CommandRule>> = HashMap::new();

        for r in raw.rules {
            let decision = match r.decision.as_str() {
                "allow" => Decision::Allow,
                "deny" => Decision::Deny,
                "ask" => Decision::Ask,
                other => panic!("Invalid decision '{}' for command '{}'", other, r.command),
            };
            let projects = merge_and_expand_projects(group_projects, &r.projects);
            let command = r.command;
            let meta = RuleMeta {
                source_file: source.clone(),
                rule_kind: RuleKind::Explicit,
                rule_command: Some(command.clone()),
                rule_args: r.args.clone(),
            };
            rules.entry(command).or_default().push(CommandRule {
                decision,
                args: r.args.map(|a| compile_pattern(&a)),
                reason: r.reason.unwrap_or_else(|| "ok".into()),
                projects,
                meta,
            });
        }

        for cmd in raw.allowed_commands {
            let projects = group_projects.iter().map(|p| expand_tilde(p)).collect();
            let meta = RuleMeta {
                source_file: source.clone(),
                rule_kind: RuleKind::AllowedCommands,
                rule_command: Some(cmd.clone()),
                rule_args: None,
            };
            rules.entry(cmd).or_default().push(CommandRule {
                decision: Decision::Allow,
                args: None,
                reason: "ok".into(),
                projects,
                meta,
            });
        }

        CommandRules { rules }
    }
}

type Source = Option<Arc<str>>;

#[derive(Clone, Copy, Default, PartialEq)]
enum RuleKind {
    #[default]
    Explicit,
    AllowedCommands,
}

impl RuleKind {
    fn as_str(&self) -> &'static str {
        match self {
            RuleKind::Explicit => "explicit",
            RuleKind::AllowedCommands => "allowed_commands",
        }
    }
}

#[derive(Clone, Default)]
struct RuleMeta {
    source_file: Source,
    rule_kind: RuleKind,
    rule_command: Option<String>,
    rule_args: Option<String>,
}

struct CommandRule {
    decision: Decision,
    args: Option<Pattern>,
    reason: String,
    projects: Vec<PathBuf>,
    meta: RuleMeta,
}

#[derive(Default, Deserialize)]
struct RawCommandConfig {
    #[serde(default)]
    allowed_commands: Vec<String>,
    #[serde(default)]
    rules: Vec<RawCommandRule>,
}

#[derive(Deserialize)]
struct RawCommandRule {
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
    fn from_raw(raw: RawWebFetchConfig, group_projects: &[String], source: Source) -> Self {
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
                    let meta = RuleMeta {
                        source_file: source.clone(),
                        rule_kind: RuleKind::Explicit,
                        rule_command: Some(r.url.clone()),
                        rule_args: Some(r.url.clone()),
                    };
                    WebFetchRule {
                        decision,
                        pattern: compile_pattern(&r.url),
                        reason: r.reason.unwrap_or_else(|| "ok".into()),
                        projects,
                        meta,
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
    meta: RuleMeta,
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
    bash: RawCommandConfig,
    #[serde(default)]
    powershell: RawCommandConfig,
    #[serde(default, rename = "web-fetch")]
    web_fetch: RawWebFetchConfig,
    log: Option<LogConfig>,
    #[serde(default, rename = "worktree-protection")]
    worktree_protection: RawWorktreeProtectionConfig,
    #[serde(default)]
    group: Vec<RawGroupConfig>,
}

#[derive(Default, Deserialize)]
struct RawGroupConfig {
    #[serde(default)]
    projects: Vec<String>,
    #[serde(default)]
    bash: RawCommandConfig,
    #[serde(default)]
    powershell: RawCommandConfig,
    #[serde(default, rename = "web-fetch")]
    web_fetch: RawWebFetchConfig,
}

impl From<RawConfig> for Config {
    fn from(raw: RawConfig) -> Self {
        Config::from_raw(raw, None)
    }
}

impl Config {
    fn from_raw(raw: RawConfig, source: Source) -> Self {
        let mut bash = CommandRules::from_raw(raw.bash, &[], source.clone());
        let mut powershell = CommandRules::from_raw(raw.powershell, &[], source.clone());
        let mut web_fetch = WebFetchConfig::from_raw(raw.web_fetch, &[], source.clone());

        for group in raw.group {
            let group_bash = CommandRules::from_raw(group.bash, &group.projects, source.clone());
            for (cmd, rules) in group_bash.rules {
                bash.rules.entry(cmd).or_default().extend(rules);
            }

            let group_powershell =
                CommandRules::from_raw(group.powershell, &group.projects, source.clone());
            for (cmd, rules) in group_powershell.rules {
                powershell.rules.entry(cmd).or_default().extend(rules);
            }

            let group_web_fetch =
                WebFetchConfig::from_raw(group.web_fetch, &group.projects, source.clone());
            web_fetch.rules.extend(group_web_fetch.rules);
        }

        Config {
            bash,
            powershell,
            web_fetch,
            log: raw.log,
            worktree_protection: WorktreeProtectionConfig {
                enabled: raw.worktree_protection.enabled,
            },
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

struct WorktreeProtectionConfig {
    enabled: bool,
}

impl Default for WorktreeProtectionConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

impl WorktreeProtectionConfig {
    fn merge(self, other: Self) -> Self {
        if !self.enabled || !other.enabled {
            Self { enabled: false }
        } else {
            Self { enabled: true }
        }
    }
}

#[derive(Deserialize)]
struct RawWorktreeProtectionConfig {
    #[serde(default = "default_true")]
    enabled: bool,
}

fn default_true() -> bool {
    true
}

impl Default for RawWorktreeProtectionConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

#[derive(Deserialize)]
struct HookInput {
    tool_name: String,
    tool_input: ToolInput,
    cwd: Option<String>,
    #[serde(default)]
    hook_event_name: Option<String>,
}

#[derive(Deserialize)]
struct ToolInput {
    command: Option<String>,
    url: Option<String>,
    file_path: Option<String>,
    path: Option<String>,
}

#[derive(Debug, PartialEq, Clone)]
enum Decision {
    Allow,
    Deny,
    Ask,
}

impl Decision {
    fn as_str(&self) -> &'static str {
        match self {
            Decision::Allow => "allow",
            Decision::Deny => "deny",
            Decision::Ask => "ask",
        }
    }
}

// Per-command-node trace, built alongside the gating decision (never affects it).
struct NodeTrace {
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

    fn to_json(&self) -> serde_json::Value {
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

fn main() {
    let mut args = std::env::args().skip(1);
    if args.next().as_deref() == Some("watch") {
        watch(args.next().as_deref());
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

// Holds everything the gate decided this invocation, for logging only. The
// final_decision drives what is printed to Claude Code; nodes/kind are observability.
struct InvocationTrace {
    final_decision: Option<(Decision, String)>,
    kind: &'static str,
    nodes: Vec<NodeTrace>,
}

// Purpose: compute the gate decision and a parallel per-node trace for one tool call.
// Requires: config loaded; hook_input parsed.
// Guarantees: returned final_decision is byte-identical to the legacy handlers; nodes
//             mirror the same extraction used for the decision.
fn dispatch(config: &Config, hook_input: &HookInput, cwd: Option<&str>) -> InvocationTrace {
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

fn empty_trace(kind: &'static str) -> InvocationTrace {
    InvocationTrace {
        final_decision: None,
        kind,
        nodes: Vec::new(),
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

fn find_project_config(cwd: &str) -> Option<PathBuf> {
    let mut dir = Path::new(cwd);
    loop {
        let candidate = dir.join(".claude/lord-kali.toml");
        if candidate.is_file() {
            return Some(candidate);
        }
        if dir.join(".git").exists() {
            return None;
        }
        dir = dir.parent()?;
    }
}

fn parse_config_file(path: &Path) -> Config {
    let content = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("Failed to read config at {}: {}", path.display(), e));
    let raw: RawConfig = toml::from_str(&content)
        .unwrap_or_else(|e| panic!("Failed to parse config at {}: {}", path.display(), e));
    Config::from_raw(raw, Some(Arc::from(path.display().to_string().as_str())))
}

fn load_config(cwd: Option<&str>) -> Config {
    let initial = cwd
        .and_then(find_project_config)
        .map(|p| parse_config_file(&p))
        .unwrap_or_default();

    let config_dir = dirs::config_dir()
        .expect("Could not determine config directory")
        .join("lord-kali");

    let entries = match std::fs::read_dir(&config_dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return initial,
        Err(e) => panic!("Failed to read config dir {}: {}", config_dir.display(), e),
    };

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
        .map(|path| parse_config_file(&path))
        .fold(initial, Config::merge)
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
fn deciding_index(nodes: &[NodeTrace]) -> Option<usize> {
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
fn handle_bash(
    rules: &CommandRules,
    cwd: Option<&str>,
    command: &str,
) -> Option<(Decision, String)> {
    handle_bash_tool(
        rules,
        &CommandRules {
            rules: HashMap::new(),
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

fn command_basename(name: &str) -> &str {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    match base.len().checked_sub(4) {
        Some(cut)
            if cut > 0
                && base
                    .get(cut..)
                    .is_some_and(|ext| ext.eq_ignore_ascii_case(".exe")) =>
        {
            &base[..cut]
        }
        _ => base,
    }
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
                let basename = command_basename(name);
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

        let basename = command_basename(text);
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

fn strip_surrounding_quotes(token: &str) -> &str {
    let bytes = token.as_bytes();
    if bytes.len() >= 2 {
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];
        if (first == b'\'' || first == b'"') && first == last {
            return &token[1..token.len() - 1];
        }
    }
    token
}

fn quote_aware_tokens(segment: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut started = false;

    for c in segment.chars() {
        if let Some(q) = quote {
            current.push(c);
            if c == q {
                quote = None;
            }
            continue;
        }

        match c {
            '\'' | '"' => {
                quote = Some(c);
                current.push(c);
                started = true;
            }
            c if c.is_whitespace() => {
                if started {
                    tokens.push(std::mem::take(&mut current));
                    started = false;
                }
            }
            _ => {
                current.push(c);
                started = true;
            }
        }
    }
    if started {
        tokens.push(current);
    }
    tokens
}

fn extract_commands_powershell(source: &str) -> Vec<(String, String)> {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_powershell::LANGUAGE.into())
        .expect("Failed to set powershell language");

    let tree = parser
        .parse(source, None)
        .expect("Failed to parse powershell command");

    let mut commands = Vec::new();
    let mut cursor = tree.root_node().walk();
    walk_powershell_node(&mut cursor, source.as_bytes(), &mut commands);
    commands
}

fn powershell_command_name(node: &tree_sitter::Node, source: &[u8]) -> Option<String> {
    let mut cursor = node.walk();
    let name_node = node
        .children(&mut cursor)
        .find(|c| c.kind() == "command_name" || c.kind() == "command_name_expr")?;
    let raw = name_node.utf8_text(source).ok()?;
    let unquoted = strip_surrounding_quotes(raw);
    let basename = command_basename(unquoted);
    if basename.is_empty() {
        None
    } else {
        Some(basename.to_string())
    }
}

fn powershell_command_args(node: &tree_sitter::Node, source: &[u8]) -> String {
    let mut cursor = node.walk();
    let Some(elements) = node
        .children(&mut cursor)
        .find(|c| c.kind() == "command_elements")
    else {
        return String::new();
    };

    let mut arg_cursor = elements.walk();
    elements
        .children(&mut arg_cursor)
        .filter(|c| c.kind() != "command_argument_sep")
        .filter_map(|c| c.utf8_text(source).ok())
        .collect::<Vec<_>>()
        .join(" ")
}

fn walk_powershell_node(
    cursor: &mut tree_sitter::TreeCursor,
    source: &[u8],
    commands: &mut Vec<(String, String)>,
) {
    let node = cursor.node();

    if node.kind() == "command" {
        if let Some(name) = powershell_command_name(&node, source) {
            commands.push((name, powershell_command_args(&node, source)));
        }
    }

    if cursor.goto_first_child() {
        loop {
            walk_powershell_node(cursor, source, commands);
            if !cursor.goto_next_sibling() {
                break;
            }
        }
        cursor.goto_parent();
    }
}

const POWERSHELL_EXECUTABLES: &[&str] = &["pwsh", "pwsh.exe", "powershell", "powershell.exe"];

fn inner_powershell_script(name: &str, args: &str) -> Option<String> {
    if !POWERSHELL_EXECUTABLES
        .iter()
        .any(|e| e.eq_ignore_ascii_case(name))
    {
        return None;
    }

    let tokens = quote_aware_tokens(args);
    let idx = tokens
        .iter()
        .position(|t| t.eq_ignore_ascii_case("-command") || t.eq_ignore_ascii_case("-c"))?;

    let rest = &tokens[idx + 1..];
    if rest.is_empty() {
        return None;
    }

    let joined = rest.join(" ");
    Some(strip_surrounding_quotes(&joined).to_string())
}

// Best-effort observability: any failure here is swallowed so a gate decision already
// printed to Claude Code is never blocked or altered by a logging problem.
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

fn log_invocation(log_config: &LogConfig, input: &str, trace: &InvocationTrace) {
    append_log_line(log_config, timestamped_log_line(input, trace));
}

// PostToolUse fires only after a tool actually executed (auto-allowed or user-approved
// at the prompt). It cannot gate, so this path only logs, with no decision and no stdout.
fn log_post_tool_use(log_config: &LogConfig, input: &str) {
    append_log_line(log_config, post_tool_use_log_line(input));
}

fn now_ms() -> u64 {
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

    let nodes: Vec<serde_json::Value> = trace.nodes.iter().map(NodeTrace::to_json).collect();
    obj.insert("nodes".into(), serde_json::Value::Array(nodes));
    serde_json::Value::Object(obj)
}

fn timestamped_log_line(input: &str, trace: &InvocationTrace) -> String {
    shape_log_line(input, "pre_tool_use", |map| {
        map.insert("lk_decision".to_string(), decision_breakdown(trace));
    })
}

const WORKTREE_SEGMENT: &str = "/.claude/worktrees/";

fn detect_worktree(cwd: &str) -> Option<(&str, &str)> {
    let idx = cwd.find(WORKTREE_SEGMENT)?;
    let parent_root = &cwd[..idx];
    let after = &cwd[idx + WORKTREE_SEGMENT.len()..];
    if after.is_empty() || after.ends_with('/') {
        return None;
    }
    Some((parent_root, cwd))
}

const FILE_TOOLS: &[&str] = &[
    "Read",
    "Write",
    "Edit",
    "Glob",
    "Grep",
    "NotebookEdit",
    "MultiEdit",
];

fn check_worktree_protection(
    cwd: &str,
    tool_name: &str,
    tool_input: &ToolInput,
) -> Option<(Decision, String)> {
    if !FILE_TOOLS.contains(&tool_name) {
        return None;
    }

    let (parent_root, worktree_root) = detect_worktree(cwd)?;

    let file_path = tool_input
        .file_path
        .as_deref()
        .or(tool_input.path.as_deref())?;

    if file_path.starts_with(worktree_root) {
        return None;
    }

    if !file_path.starts_with(parent_root) {
        return None;
    }

    let relative = &file_path[parent_root.len()..];
    let corrected = format!("{worktree_root}{relative}");

    Some((
        Decision::Deny,
        format!(
            "You are in a worktree. Do not read/write the parent project at {parent_root}. \
             Use the worktree path instead: {corrected}"
        ),
    ))
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

const DEFAULT_LOG_PATH: &str = "~/.local/state/lord-kali/hook.jsonl";
const WATCH_POLL_MS: u64 = 200;
const PENDING_TIMEOUT_MS: u64 = 60_000;

struct Palette {
    color: bool,
}

impl Palette {
    fn paint(&self, code: &str, s: &str) -> String {
        if self.color {
            format!("\x1b[{}m{}\x1b[0m", code, s)
        } else {
            s.to_string()
        }
    }
}

// A PreToolUse decision awaiting its matching PostToolUse. The absence of that match past
// the timeout is the only (noisy) trace a rejection leaves, so we surface it explicitly.
struct PendingPre {
    ts_ms: u64,
    final_decision: String,
    tool: String,
    target: String,
    // For an `ask`, the node in the chain that drove the verdict (`command args — reason`).
    // None for `passthrough` (nothing matched, so nothing "triggered" the rejection).
    deciding: Option<String>,
}

fn resolve_log_path(explicit: Option<&str>) -> PathBuf {
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

fn event_target(v: &serde_json::Value) -> String {
    let ti = &v["tool_input"];
    for key in ["command", "url", "file_path", "path"] {
        if let Some(s) = ti.get(key).and_then(|x| x.as_str()) {
            return s.to_string();
        }
    }
    String::new()
}

fn correlation_key(v: &serde_json::Value, tool: &str, target: &str) -> String {
    let session = v["session_id"].as_str().unwrap_or("");
    format!("{session}\u{1}{tool}\u{1}{target}")
}

// The specific command node that set the verdict, as `command args — reason`, read from
// lk_decision.deciding. Returns None when nothing matched (deciding is null/absent).
fn format_deciding(lk_decision: &serde_json::Value) -> Option<String> {
    let d = lk_decision.get("deciding")?;
    if d.is_null() {
        return None;
    }
    let cmd = d.get("command").and_then(|x| x.as_str()).unwrap_or("");
    let args = d.get("args").and_then(|x| x.as_str()).unwrap_or("");
    let mut node = cmd.to_string();
    if !args.is_empty() {
        node.push(' ');
        node.push_str(args);
    }
    if let Some(r) = d.get("reason").and_then(|x| x.as_str()) {
        node.push_str(&format!("  — {r}"));
    }
    Some(node)
}

// Command nodes in the chain that matched no rule (`matched: false`) — the gap candidates
// for the allow/deny lists. Empty for an `allow` verdict (every node matched by definition);
// can be non-empty under passthrough/ask/deny. Deduplicated, order preserved.
fn unmatched_nodes(lk_decision: &serde_json::Value) -> Vec<String> {
    let Some(nodes) = lk_decision.get("nodes").and_then(|n| n.as_array()) else {
        return Vec::new();
    };
    let mut out: Vec<String> = Vec::new();
    for n in nodes {
        if n.get("matched").and_then(|m| m.as_bool()) == Some(false) {
            if let Some(cmd) = n.get("command").and_then(|c| c.as_str()) {
                if !cmd.is_empty() && !out.iter().any(|e| e == cmd) {
                    out.push(cmd.to_string());
                }
            }
        }
    }
    out
}

fn render_pre(p: &Palette, tool: &str, target: &str, final_: &str, reason: Option<&str>) -> String {
    let (code, label) = match final_ {
        "allow" => ("32", "ALLOW"),
        "deny" => ("31", "DENY"),
        "ask" => ("33", "ASK"),
        "passthrough" => ("36", "PASS"),
        other => ("0", other),
    };
    let badge = p.paint(code, &format!("{label:<5}"));
    let mut line = format!("{badge}  {tool}: {target}");
    if matches!(final_, "deny" | "ask") {
        if let Some(r) = reason {
            line.push_str(&p.paint("2", &format!("  — {r}")));
        }
    }
    line
}

fn handle_line(p: &Palette, line: &str, pending: &mut HashMap<String, PendingPre>) {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
        return;
    };
    let tool = v["tool_name"].as_str().unwrap_or("?").to_string();
    let target = event_target(&v);
    let key = correlation_key(&v, &tool, &target);

    match v["lk_event"].as_str().unwrap_or("") {
        "pre_tool_use" => {
            let final_ = v["lk_decision"]["final"]
                .as_str()
                .unwrap_or("?")
                .to_string();
            let reason = v["lk_decision"]["reason"].as_str();
            let mut out = render_pre(p, &tool, &target, &final_, reason);
            let gaps = unmatched_nodes(&v["lk_decision"]);
            if !gaps.is_empty() {
                out.push_str(&p.paint("36", &format!("   (no rule: {})", gaps.join(", "))));
            }
            println!("{out}");
            let ts_ms = v["ts_ms"].as_u64().unwrap_or_else(now_ms);
            let deciding = format_deciding(&v["lk_decision"]);
            pending.insert(
                key,
                PendingPre {
                    ts_ms,
                    final_decision: final_,
                    tool,
                    target,
                    deciding,
                },
            );
        }
        "post_tool_use" => match pending.remove(&key) {
            // A passthrough/ask that ran is the high-confidence "you approved this" signal.
            Some(pre) if pre.final_decision == "passthrough" || pre.final_decision == "ask" => {
                println!(
                    "{}",
                    p.paint(
                        "32;1",
                        &format!("       └ approved & ran  {tool}: {target}")
                    )
                );
            }
            // An allow always runs; no need to restate it. Drop silently.
            Some(_) => {}
            None => println!(
                "{}",
                p.paint("2", &format!("       · ran  {tool}: {target}"))
            ),
        },
        _ => {}
    }
}

fn sweep_pending(p: &Palette, pending: &mut HashMap<String, PendingPre>) {
    let now = now_ms();
    let expired: Vec<String> = pending
        .iter()
        .filter(|(_, pre)| now.saturating_sub(pre.ts_ms) > PENDING_TIMEOUT_MS)
        .map(|(k, _)| k.clone())
        .collect();
    for k in expired {
        let pre = pending.remove(&k).unwrap();
        if pre.final_decision == "passthrough" || pre.final_decision == "ask" {
            let mut msg = format!(
                "       └ no execution in {}s — rejected or abandoned?  {}: {}",
                PENDING_TIMEOUT_MS / 1000,
                pre.tool,
                pre.target
            );
            if let Some(node) = &pre.deciding {
                msg.push_str(&format!(
                    "   ({} triggered by: {})",
                    pre.final_decision, node
                ));
            }
            println!("{}", p.paint("35", &msg));
        }
    }
}

fn watch(explicit_path: Option<&str>) {
    use std::io::{Seek, SeekFrom};

    let path = resolve_log_path(explicit_path);
    let palette = Palette {
        color: std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none(),
    };

    eprintln!("lord-kali watch — tailing {}", path.display());
    eprintln!(
        "PASS/ASK go to approval; an indented line shows whether they ran. Ctrl-C to stop.\n"
    );

    let mut offset = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
    let mut carry = String::new();
    let mut pending: HashMap<String, PendingPre> = HashMap::new();

    loop {
        let len = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        if len < offset {
            offset = 0;
            carry.clear();
        }
        if len > offset {
            if let Ok(mut f) = std::fs::File::open(&path) {
                if f.seek(SeekFrom::Start(offset)).is_ok() {
                    let mut buf = String::new();
                    if let Ok(n) = f.read_to_string(&mut buf) {
                        offset += n as u64;
                        carry.push_str(&buf);
                        while let Some(idx) = carry.find('\n') {
                            let line: String = carry.drain(..=idx).collect();
                            let trimmed = line.trim_end();
                            if !trimmed.is_empty() {
                                handle_line(&palette, trimmed, &mut pending);
                            }
                        }
                    }
                }
            }
        }
        sweep_pending(&palette, &mut pending);
        std::thread::sleep(std::time::Duration::from_millis(WATCH_POLL_MS));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
                    meta: RuleMeta::default(),
                },
                WebFetchRule {
                    decision: Decision::Ask,
                    pattern: compile_pattern("/.*\\.internal\\..*/"),
                    reason: "Internal URL, please confirm".into(),
                    projects: vec![],
                    meta: RuleMeta::default(),
                },
                WebFetchRule {
                    decision: Decision::Allow,
                    pattern: compile_pattern("https://docs.rs/**"),
                    reason: "ok".into(),
                    projects: vec![],
                    meta: RuleMeta::default(),
                },
                WebFetchRule {
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
                WebFetchRule {
                    decision: Decision::Deny,
                    pattern: compile_pattern("https://bad.internal.corp/**"),
                    reason: "Denied".into(),
                    projects: vec![],
                    meta: RuleMeta::default(),
                },
                WebFetchRule {
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
                WebFetchRule {
                    decision: Decision::Deny,
                    pattern: compile_pattern("https://internal.example.com/**"),
                    reason: "Blocked for this project".into(),
                    projects: vec![PathBuf::from("/home/user/projects/test")],
                    meta: RuleMeta::default(),
                },
                WebFetchRule {
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
                WebFetchRule {
                    decision: Decision::Deny,
                    pattern: compile_pattern("https://internal.example.com/**"),
                    reason: "Blocked for this project".into(),
                    projects: vec![PathBuf::from("/home/user/projects/test")],
                    meta: RuleMeta::default(),
                },
                WebFetchRule {
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

    // --- group flattening ---

    #[test]
    fn group_projects_applied_to_rules() {
        let raw = RawConfig {
            bash: RawCommandConfig::default(),
            powershell: RawCommandConfig::default(),
            web_fetch: RawWebFetchConfig::default(),
            log: None,
            worktree_protection: RawWorktreeProtectionConfig::default(),
            group: vec![RawGroupConfig {
                projects: vec!["/home/user/projects/test".into()],
                bash: RawCommandConfig {
                    allowed_commands: vec![],
                    rules: vec![RawCommandRule {
                        command: "cargo".into(),
                        args: Some("publish{, **}".into()),
                        decision: "deny".into(),
                        reason: Some("No publishing".into()),
                        projects: vec![],
                    }],
                },
                powershell: RawCommandConfig::default(),
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
            bash: RawCommandConfig::default(),
            powershell: RawCommandConfig::default(),
            web_fetch: RawWebFetchConfig::default(),
            log: None,
            worktree_protection: RawWorktreeProtectionConfig::default(),
            group: vec![RawGroupConfig {
                projects: vec!["/home/user/projects/a".into()],
                bash: RawCommandConfig {
                    allowed_commands: vec![],
                    rules: vec![RawCommandRule {
                        command: "cargo".into(),
                        args: Some("publish{, **}".into()),
                        decision: "deny".into(),
                        reason: Some("No publishing".into()),
                        projects: vec!["/home/user/projects/b".into()],
                    }],
                },
                powershell: RawCommandConfig::default(),
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
            bash: RawCommandConfig::default(),
            powershell: RawCommandConfig::default(),
            web_fetch: RawWebFetchConfig::default(),
            log: None,
            worktree_protection: RawWorktreeProtectionConfig::default(),
            group: vec![RawGroupConfig {
                projects: vec!["/home/user/projects/test".into()],
                bash: RawCommandConfig {
                    allowed_commands: vec!["rustup".into()],
                    rules: vec![],
                },
                powershell: RawCommandConfig::default(),
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
            bash: RawCommandConfig::default(),
            powershell: RawCommandConfig::default(),
            web_fetch: RawWebFetchConfig::default(),
            log: None,
            worktree_protection: RawWorktreeProtectionConfig::default(),
            group: vec![RawGroupConfig {
                projects: vec!["/home/user/projects/test".into()],
                bash: RawCommandConfig::default(),
                powershell: RawCommandConfig::default(),
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
            bash: RawCommandConfig {
                allowed_commands: vec![],
                rules: vec![RawCommandRule {
                    command: "cargo".into(),
                    args: Some("publish{, **}".into()),
                    decision: "deny".into(),
                    reason: Some("Global deny".into()),
                    projects: vec![],
                }],
            },
            powershell: RawCommandConfig::default(),
            web_fetch: RawWebFetchConfig::default(),
            log: None,
            worktree_protection: RawWorktreeProtectionConfig::default(),
            group: vec![RawGroupConfig {
                projects: vec!["/home/user/projects/test".into()],
                bash: RawCommandConfig {
                    allowed_commands: vec![],
                    rules: vec![RawCommandRule {
                        command: "cargo".into(),
                        args: Some("publish{, **}".into()),
                        decision: "allow".into(),
                        reason: Some("Group allow".into()),
                        projects: vec![],
                    }],
                },
                powershell: RawCommandConfig::default(),
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
        let mut rules_a: HashMap<String, Vec<CommandRule>> = HashMap::new();
        rules_a
            .entry("git".to_string())
            .or_default()
            .push(CommandRule {
                decision: Decision::Allow,
                args: Some(compile_pattern("status")),
                reason: "ok".into(),
                projects: vec![],
                meta: RuleMeta::default(),
            });
        let a = Config {
            bash: CommandRules { rules: rules_a },
            ..Config::default()
        };

        let mut rules_b: HashMap<String, Vec<CommandRule>> = HashMap::new();
        rules_b
            .entry("git".to_string())
            .or_default()
            .push(CommandRule {
                decision: Decision::Deny,
                args: Some(compile_pattern("push{, **}")),
                reason: "no pushing".into(),
                projects: vec![],
                meta: RuleMeta::default(),
            });
        rules_b
            .entry("cargo".to_string())
            .or_default()
            .push(CommandRule {
                decision: Decision::Allow,
                args: None,
                reason: "ok".into(),
                projects: vec![],
                meta: RuleMeta::default(),
            });
        let b = Config {
            bash: CommandRules { rules: rules_b },
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
                    meta: RuleMeta::default(),
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
                    meta: RuleMeta::default(),
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

    // --- find_project_config ---

    #[test]
    fn find_project_config_in_cwd() {
        let tmp = tempfile::tempdir().unwrap();
        let claude_dir = tmp.path().join(".claude");
        std::fs::create_dir_all(&claude_dir).unwrap();
        std::fs::write(claude_dir.join("lord-kali.toml"), "").unwrap();
        std::fs::create_dir_all(tmp.path().join(".git")).unwrap();

        let result = find_project_config(tmp.path().to_str().unwrap());
        assert_eq!(result, Some(claude_dir.join("lord-kali.toml")));
    }

    #[test]
    fn find_project_config_from_subdirectory() {
        let tmp = tempfile::tempdir().unwrap();
        let claude_dir = tmp.path().join(".claude");
        std::fs::create_dir_all(&claude_dir).unwrap();
        std::fs::write(claude_dir.join("lord-kali.toml"), "").unwrap();
        std::fs::create_dir_all(tmp.path().join(".git")).unwrap();

        let sub = tmp.path().join("src/deep");
        std::fs::create_dir_all(&sub).unwrap();

        let result = find_project_config(sub.to_str().unwrap());
        assert_eq!(result, Some(claude_dir.join("lord-kali.toml")));
    }

    #[test]
    fn find_project_config_stops_at_git_root() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join(".git")).unwrap();

        let result = find_project_config(tmp.path().to_str().unwrap());
        assert_eq!(result, None);
    }

    #[test]
    fn find_project_config_none_when_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let sub = tmp.path().join("some/path");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::create_dir_all(tmp.path().join(".git")).unwrap();

        let result = find_project_config(sub.to_str().unwrap());
        assert_eq!(result, None);
    }

    // --- project-local config priority ---

    #[test]
    fn project_config_rules_take_priority_over_global() {
        let project_toml = r#"
[[bash.rules]]
command = "rm"
decision = "deny"
reason = "Project denies rm"
"#;
        let global_toml = r#"
[[bash.rules]]
command = "rm"
decision = "allow"
reason = "Global allows rm"
"#;
        let project_config = {
            let raw: RawConfig = toml::from_str(project_toml).unwrap();
            Config::from(raw)
        };
        let global_config = {
            let raw: RawConfig = toml::from_str(global_toml).unwrap();
            Config::from(raw)
        };

        let merged = project_config.merge(global_config);
        let result = handle_bash(&merged.bash, None, "rm foo");
        assert_eq!(
            result.map(|(d, r)| (d, r)),
            Some((Decision::Deny, "Project denies rm".into()))
        );
    }

    // --- detect_worktree ---

    #[test]
    fn detect_worktree_valid() {
        let (parent, worktree) =
            detect_worktree("/home/user/projects/myapp/.claude/worktrees/feature-x").unwrap();
        assert_eq!(parent, "/home/user/projects/myapp");
        assert_eq!(
            worktree,
            "/home/user/projects/myapp/.claude/worktrees/feature-x"
        );
    }

    #[test]
    fn detect_worktree_not_a_worktree() {
        assert!(detect_worktree("/home/user/projects/myapp").is_none());
    }

    #[test]
    fn detect_worktree_trailing_slash_in_worktrees_dir() {
        assert!(detect_worktree("/home/user/projects/myapp/.claude/worktrees/").is_none());
    }

    #[test]
    fn detect_worktree_multi_segment_name() {
        let (parent, worktree) =
            detect_worktree("/home/user/projects/myapp/.claude/worktrees/fix/PJ-1234").unwrap();
        assert_eq!(parent, "/home/user/projects/myapp");
        assert_eq!(
            worktree,
            "/home/user/projects/myapp/.claude/worktrees/fix/PJ-1234"
        );
    }

    // --- check_worktree_protection ---

    fn worktree_tool_input(file_path: Option<&str>, path: Option<&str>) -> ToolInput {
        ToolInput {
            command: None,
            url: None,
            file_path: file_path.map(String::from),
            path: path.map(String::from),
        }
    }

    #[test]
    fn worktree_denies_read_from_parent() {
        let cwd = "/home/user/project/.claude/worktrees/feat";
        let input = worktree_tool_input(Some("/home/user/project/src/main.rs"), None);
        let result = check_worktree_protection(cwd, "Read", &input);
        assert!(result.is_some());
        let (decision, reason) = result.unwrap();
        assert_eq!(decision, Decision::Deny);
        assert!(reason.contains("/home/user/project/.claude/worktrees/feat/src/main.rs"));
    }

    #[test]
    fn worktree_denies_write_from_parent() {
        let cwd = "/home/user/project/.claude/worktrees/feat";
        let input = worktree_tool_input(Some("/home/user/project/Cargo.toml"), None);
        let result = check_worktree_protection(cwd, "Write", &input);
        assert!(result.is_some());
        let (decision, reason) = result.unwrap();
        assert_eq!(decision, Decision::Deny);
        assert!(reason.contains("/home/user/project/.claude/worktrees/feat/Cargo.toml"));
    }

    #[test]
    fn worktree_denies_edit_from_parent() {
        let cwd = "/home/user/project/.claude/worktrees/feat";
        let input = worktree_tool_input(Some("/home/user/project/src/lib.rs"), None);
        let result = check_worktree_protection(cwd, "Edit", &input);
        assert!(result.is_some());
    }

    #[test]
    fn worktree_denies_grep_path_from_parent() {
        let cwd = "/home/user/project/.claude/worktrees/feat";
        let input = worktree_tool_input(None, Some("/home/user/project/src"));
        let result = check_worktree_protection(cwd, "Grep", &input);
        assert!(result.is_some());
        let (_, reason) = result.unwrap();
        assert!(reason.contains("/home/user/project/.claude/worktrees/feat/src"));
    }

    #[test]
    fn worktree_allows_file_within_worktree() {
        let cwd = "/home/user/project/.claude/worktrees/feat";
        let input = worktree_tool_input(
            Some("/home/user/project/.claude/worktrees/feat/src/main.rs"),
            None,
        );
        let result = check_worktree_protection(cwd, "Read", &input);
        assert!(result.is_none());
    }

    #[test]
    fn worktree_allows_file_outside_parent() {
        let cwd = "/home/user/project/.claude/worktrees/feat";
        let input = worktree_tool_input(Some("/tmp/something.txt"), None);
        let result = check_worktree_protection(cwd, "Read", &input);
        assert!(result.is_none());
    }

    #[test]
    fn worktree_ignores_non_file_tools() {
        let cwd = "/home/user/project/.claude/worktrees/feat";
        let input = worktree_tool_input(Some("/home/user/project/src/main.rs"), None);
        assert!(check_worktree_protection(cwd, "Bash", &input).is_none());
        assert!(check_worktree_protection(cwd, "WebFetch", &input).is_none());
    }

    #[test]
    fn worktree_no_file_path_passthrough() {
        let cwd = "/home/user/project/.claude/worktrees/feat";
        let input = worktree_tool_input(None, None);
        assert!(check_worktree_protection(cwd, "Read", &input).is_none());
    }

    #[test]
    fn worktree_protection_disabled_via_config() {
        let toml_str = r#"
[worktree-protection]
enabled = false
"#;
        let raw: RawConfig = toml::from_str(toml_str).unwrap();
        let config = Config::from(raw);
        assert!(!config.worktree_protection.enabled);
    }

    #[test]
    fn worktree_protection_enabled_by_default() {
        let toml_str = "";
        let raw: RawConfig = toml::from_str(toml_str).unwrap();
        let config = Config::from(raw);
        assert!(config.worktree_protection.enabled);
    }

    #[test]
    fn worktree_protection_merge_disabled_wins() {
        let a = Config {
            worktree_protection: WorktreeProtectionConfig { enabled: true },
            ..Config::default()
        };
        let b = Config {
            worktree_protection: WorktreeProtectionConfig { enabled: false },
            ..Config::default()
        };
        let merged = a.merge(b);
        assert!(!merged.worktree_protection.enabled);
    }

    // --- extract_commands_powershell ---

    fn ps_command_names(cmd: &str) -> Vec<String> {
        extract_commands_powershell(cmd)
            .into_iter()
            .map(|(name, _)| name)
            .collect()
    }

    #[test]
    fn ps_extract_simple() {
        assert_eq!(
            extract_commands_powershell("Get-ChildItem"),
            vec![("Get-ChildItem".into(), "".into())]
        );
    }

    #[test]
    fn ps_extract_pipeline() {
        assert_eq!(
            ps_command_names("Get-Process | Stop-Process"),
            vec!["Get-Process", "Stop-Process"]
        );
    }

    #[test]
    fn ps_extract_semicolon() {
        assert_eq!(
            ps_command_names("Get-Foo; Remove-Item x"),
            vec!["Get-Foo", "Remove-Item"]
        );
    }

    #[test]
    fn ps_extract_and_chain() {
        assert_eq!(
            extract_commands_powershell("git status && git push"),
            vec![
                ("git".into(), "status".into()),
                ("git".into(), "push".into())
            ]
        );
    }

    #[test]
    fn ps_extract_call_operator_quoted_path() {
        assert_eq!(
            extract_commands_powershell("& 'C:\\Program Files\\app.exe' --flag"),
            vec![("app".into(), "--flag".into())]
        );
    }

    #[test]
    fn ps_extract_assignment() {
        assert_eq!(
            extract_commands_powershell("$x = Get-Date"),
            vec![("Get-Date".into(), "".into())]
        );
    }

    #[test]
    fn ps_extract_forward_slash_path() {
        assert_eq!(
            extract_commands_powershell("C:/tools/foo.exe bar"),
            vec![("foo".into(), "bar".into())]
        );
    }

    #[test]
    fn ps_extract_comment() {
        assert_eq!(extract_commands_powershell("# comment"), vec![]);
    }

    #[test]
    fn ps_extract_no_split_inside_quotes() {
        assert_eq!(
            ps_command_names("Write-Output 'a | b'"),
            vec!["Write-Output"]
        );
    }

    #[test]
    fn ps_extract_newline_split() {
        assert_eq!(
            ps_command_names("Get-ChildItem\nRemove-Item x"),
            vec!["Get-ChildItem", "Remove-Item"]
        );
    }

    #[test]
    fn ps_extract_script_block() {
        assert_eq!(
            ps_command_names("Get-ChildItem | Where-Object { Remove-Item foo }"),
            vec!["Get-ChildItem", "Where-Object", "Remove-Item"]
        );
    }

    #[test]
    fn ps_extract_command_substitution() {
        assert_eq!(
            ps_command_names("Invoke-Something $(Remove-Item bar)"),
            vec!["Invoke-Something", "Remove-Item"]
        );
    }

    #[test]
    fn ps_extract_assignment_literal_no_command() {
        assert_eq!(
            ps_command_names("$env:NODE_ENV='production'; npm run build"),
            vec!["npm"]
        );
    }

    #[test]
    fn ps_extract_path_args_preserved() {
        assert_eq!(
            extract_commands_powershell("Get-ChildItem -Path C:\\temp"),
            vec![("Get-ChildItem".into(), "-Path C:\\temp".into())]
        );
    }

    #[test]
    fn command_basename_normalizes_separators_and_exe() {
        assert_eq!(command_basename("rm"), "rm");
        assert_eq!(command_basename("/usr/bin/rm"), "rm");
        assert_eq!(command_basename(r"C:\tools\rm.exe"), "rm");
        assert_eq!(command_basename("git.exe"), "git");
        assert_eq!(command_basename("FOO.EXE"), "FOO");
        assert_eq!(command_basename("Get-ChildItem"), "Get-ChildItem");
        assert_eq!(command_basename(".exe"), ".exe");
    }

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

    // --- inner_powershell_script ---

    #[test]
    fn inner_ps_command_with_flags() {
        assert_eq!(
            inner_powershell_script("pwsh", "-NoProfile -Command \"Remove-Item x\""),
            Some("Remove-Item x".into())
        );
    }

    #[test]
    fn inner_ps_short_command_flag() {
        assert_eq!(
            inner_powershell_script("powershell", "-c Get-Process"),
            Some("Get-Process".into())
        );
    }

    #[test]
    fn inner_ps_file_returns_none() {
        assert_eq!(inner_powershell_script("pwsh", "-File scripts/x.ps1"), None);
    }

    #[test]
    fn inner_ps_non_powershell_returns_none() {
        assert_eq!(inner_powershell_script("npm", "-Command x"), None);
    }

    #[test]
    fn inner_ps_encoded_command_returns_none() {
        assert_eq!(
            inner_powershell_script("pwsh", "-EncodedCommand UmVtb3ZlLUl0ZW0="),
            None
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

    // --- PostToolUse log shaping ---

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

    // --- watcher node helpers ---

    #[test]
    fn unmatched_nodes_lists_dedup_in_order() {
        let d = serde_json::json!({
            "nodes": [
                {"command": "ls", "matched": true},
                {"command": "cargo", "matched": false},
                {"command": "frob", "matched": false},
                {"command": "cargo", "matched": false},
            ]
        });
        assert_eq!(unmatched_nodes(&d), vec!["cargo", "frob"]);
    }

    #[test]
    fn unmatched_nodes_empty_when_all_matched() {
        let d = serde_json::json!({
            "nodes": [
                {"command": "ls", "matched": true},
                {"command": "cat", "matched": true},
            ]
        });
        assert!(unmatched_nodes(&d).is_empty());
    }

    #[test]
    fn format_deciding_renders_node_and_reason() {
        let d = serde_json::json!({
            "deciding": {"command": "rm", "args": "-rf foo", "reason": "Recursive/force delete — confirm."}
        });
        assert_eq!(
            format_deciding(&d).as_deref(),
            Some("rm -rf foo  — Recursive/force delete — confirm.")
        );
    }

    #[test]
    fn format_deciding_null_is_none() {
        let d = serde_json::json!({ "deciding": serde_json::Value::Null });
        assert_eq!(format_deciding(&d), None);
    }
}
