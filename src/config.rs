// Configuration model and loading. Rules come from a project-local
// `.claude/lord-kali.toml` (highest priority) merged with all `~/.config/lord-kali/*.toml`
// files in lexicographic order. Patterns are glob by default, regex when wrapped in `//`.

use crate::decision::Decision;
use regex::Regex;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Default)]
pub(crate) struct Config {
    pub(crate) bash: CommandRules,
    pub(crate) powershell: CommandRules,
    pub(crate) web_fetch: WebFetchConfig,
    pub(crate) mcp: McpConfig,
    pub(crate) log: Option<LogConfig>,
    pub(crate) worktree_protection: WorktreeProtectionConfig,
    pub(crate) approval: ApprovalConfig,
}

impl Config {
    pub(crate) fn merge(mut self, other: Config) -> Config {
        for (cmd, rules) in other.bash.rules {
            self.bash.rules.entry(cmd).or_default().extend(rules);
        }
        for (cmd, rules) in other.powershell.rules {
            self.powershell.rules.entry(cmd).or_default().extend(rules);
        }
        self.web_fetch.rules.extend(other.web_fetch.rules);
        self.mcp.rules.extend(other.mcp.rules);
        if other.log.is_some() {
            self.log = other.log;
        }
        self.worktree_protection = other.worktree_protection.merge(self.worktree_protection);
        self.approval = self.approval.merge(other.approval);
        self
    }
}

#[derive(Default)]
pub(crate) struct CommandRules {
    pub(crate) rules: HashMap<String, Vec<CommandRule>>,
}

impl CommandRules {
    pub(crate) fn from_raw(
        raw: RawCommandConfig,
        group_projects: &[String],
        source: Source,
    ) -> Self {
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

pub(crate) type Source = Option<Arc<str>>;

#[derive(Clone, Copy, Default, PartialEq)]
pub(crate) enum RuleKind {
    #[default]
    Explicit,
    AllowedCommands,
}

impl RuleKind {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            RuleKind::Explicit => "explicit",
            RuleKind::AllowedCommands => "allowed_commands",
        }
    }
}

#[derive(Clone, Default)]
pub(crate) struct RuleMeta {
    pub(crate) source_file: Source,
    pub(crate) rule_kind: RuleKind,
    pub(crate) rule_command: Option<String>,
    pub(crate) rule_args: Option<String>,
}

pub(crate) struct CommandRule {
    pub(crate) decision: Decision,
    pub(crate) args: Option<Pattern>,
    pub(crate) reason: String,
    pub(crate) projects: Vec<PathBuf>,
    pub(crate) meta: RuleMeta,
}

#[derive(Default, Deserialize)]
pub(crate) struct RawCommandConfig {
    #[serde(default)]
    pub(crate) allowed_commands: Vec<String>,
    #[serde(default)]
    pub(crate) rules: Vec<RawCommandRule>,
}

#[derive(Deserialize)]
pub(crate) struct RawCommandRule {
    pub(crate) command: String,
    pub(crate) args: Option<String>,
    pub(crate) decision: String,
    pub(crate) reason: Option<String>,
    #[serde(default)]
    pub(crate) projects: Vec<String>,
}

#[derive(Default)]
pub(crate) struct WebFetchConfig {
    pub(crate) rules: Vec<WebFetchRule>,
}

impl WebFetchConfig {
    pub(crate) fn from_raw(
        raw: RawWebFetchConfig,
        group_projects: &[String],
        source: Source,
    ) -> Self {
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

pub(crate) struct WebFetchRule {
    pub(crate) decision: Decision,
    pub(crate) pattern: Pattern,
    pub(crate) reason: String,
    pub(crate) projects: Vec<PathBuf>,
    pub(crate) meta: RuleMeta,
}

#[derive(Default, Deserialize)]
pub(crate) struct RawWebFetchConfig {
    #[serde(default)]
    pub(crate) rules: Vec<RawWebFetchRule>,
}

#[derive(Deserialize)]
pub(crate) struct RawWebFetchRule {
    pub(crate) url: String,
    pub(crate) decision: String,
    pub(crate) reason: Option<String>,
    #[serde(default)]
    pub(crate) projects: Vec<String>,
}

// MCP tool-call gating, keyed on the full `mcp__<server>__<tool>` name (glob or /regex/).
// A flat rule list like web-fetch — no args matching; the tool name is the whole key.
#[derive(Default)]
pub(crate) struct McpConfig {
    pub(crate) rules: Vec<McpRule>,
}

impl McpConfig {
    pub(crate) fn from_raw(raw: RawMcpConfig, group_projects: &[String], source: Source) -> Self {
        McpConfig {
            rules: raw
                .rules
                .into_iter()
                .map(|r| {
                    let decision = match r.decision.as_str() {
                        "allow" => Decision::Allow,
                        "deny" => Decision::Deny,
                        "ask" => Decision::Ask,
                        other => panic!("Invalid decision '{}' for mcp tool '{}'", other, r.tool),
                    };
                    let projects = merge_and_expand_projects(group_projects, &r.projects);
                    let meta = RuleMeta {
                        source_file: source.clone(),
                        rule_kind: RuleKind::Explicit,
                        rule_command: Some(r.tool.clone()),
                        rule_args: Some(r.tool.clone()),
                    };
                    McpRule {
                        decision,
                        pattern: compile_pattern(&r.tool),
                        reason: r.reason.unwrap_or_else(|| "ok".into()),
                        projects,
                        meta,
                    }
                })
                .collect(),
        }
    }
}

pub(crate) struct McpRule {
    pub(crate) decision: Decision,
    pub(crate) pattern: Pattern,
    pub(crate) reason: String,
    pub(crate) projects: Vec<PathBuf>,
    pub(crate) meta: RuleMeta,
}

#[derive(Default, Deserialize)]
pub(crate) struct RawMcpConfig {
    #[serde(default)]
    pub(crate) rules: Vec<RawMcpRule>,
}

#[derive(Deserialize)]
pub(crate) struct RawMcpRule {
    pub(crate) tool: String,
    pub(crate) decision: String,
    pub(crate) reason: Option<String>,
    #[serde(default)]
    pub(crate) projects: Vec<String>,
}

#[derive(Default, Deserialize)]
pub(crate) struct RawConfig {
    #[serde(default)]
    pub(crate) bash: RawCommandConfig,
    #[serde(default)]
    pub(crate) powershell: RawCommandConfig,
    #[serde(default, rename = "web-fetch")]
    pub(crate) web_fetch: RawWebFetchConfig,
    #[serde(default)]
    pub(crate) mcp: RawMcpConfig,
    pub(crate) log: Option<LogConfig>,
    #[serde(default, rename = "worktree-protection")]
    pub(crate) worktree_protection: RawWorktreeProtectionConfig,
    #[serde(default)]
    pub(crate) approval: RawApprovalConfig,
    #[serde(default)]
    pub(crate) group: Vec<RawGroupConfig>,
}

#[derive(Default, Deserialize)]
pub(crate) struct RawGroupConfig {
    #[serde(default)]
    pub(crate) projects: Vec<String>,
    #[serde(default)]
    pub(crate) bash: RawCommandConfig,
    #[serde(default)]
    pub(crate) powershell: RawCommandConfig,
    #[serde(default, rename = "web-fetch")]
    pub(crate) web_fetch: RawWebFetchConfig,
    #[serde(default)]
    pub(crate) mcp: RawMcpConfig,
}

impl From<RawConfig> for Config {
    fn from(raw: RawConfig) -> Self {
        Config::from_raw(raw, None)
    }
}

impl Config {
    pub(crate) fn from_raw(raw: RawConfig, source: Source) -> Self {
        let mut bash = CommandRules::from_raw(raw.bash, &[], source.clone());
        let mut powershell = CommandRules::from_raw(raw.powershell, &[], source.clone());
        let mut web_fetch = WebFetchConfig::from_raw(raw.web_fetch, &[], source.clone());
        let mut mcp = McpConfig::from_raw(raw.mcp, &[], source.clone());

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

            let group_mcp = McpConfig::from_raw(group.mcp, &group.projects, source.clone());
            mcp.rules.extend(group_mcp.rules);
        }

        Config {
            bash,
            powershell,
            web_fetch,
            mcp,
            log: raw.log,
            worktree_protection: WorktreeProtectionConfig {
                enabled: raw.worktree_protection.enabled,
            },
            approval: ApprovalConfig {
                enabled: raw.approval.enabled,
                live_rules: raw.approval.live_rules,
                state_dir: raw.approval.state_dir,
                guardrail_commands: raw.approval.guardrail_commands,
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

pub(crate) enum Pattern {
    Glob(String),
    Regex(Regex),
}

impl Pattern {
    pub(crate) fn is_match(&self, text: &str) -> bool {
        match self {
            Pattern::Glob(g) => glob_match_ultra::glob_match(g, text),
            Pattern::Regex(r) => r.is_match(text),
        }
    }
}

pub(crate) fn compile_pattern(s: &str) -> Pattern {
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
pub(crate) struct LogConfig {
    #[serde(default)]
    pub(crate) enabled: bool,
    pub(crate) path: Option<String>,
}

pub(crate) struct WorktreeProtectionConfig {
    pub(crate) enabled: bool,
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
pub(crate) struct RawWorktreeProtectionConfig {
    #[serde(default = "default_true")]
    pub(crate) enabled: bool,
}

fn default_true() -> bool {
    true
}

impl Default for RawWorktreeProtectionConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

// Opt-in central approval. Disabled by default so installing this version never changes
// an existing user's gate behavior. When enabled and a live TUI is present, ask/pass-through
// calls are routed to the TUI queue instead of Claude Code's own prompt.
// Destructive, path-operating commands whose TUI allow/deny-always rules default to a
// tight, path-specific (full-args) scope instead of subcommand scope — so a one-off
// `rm -rf ./tmp` never persists as a blanket `rm -rf` allow. Always on; users extend it.
const DEFAULT_GUARDRAIL: &[&str] = &[
    "rm",
    "rmdir",
    "dd",
    "mkfs",
    "shred",
    "truncate",
    "del",
    "rd",
    "Remove-Item",
    "Clear-Content",
];

#[derive(Default)]
pub(crate) struct ApprovalConfig {
    pub(crate) enabled: bool,
    pub(crate) live_rules: Option<String>,
    pub(crate) state_dir: Option<String>,
    pub(crate) guardrail_commands: Vec<String>,
}

impl ApprovalConfig {
    // enabling anywhere enables; an explicit file/dir from a later config overrides;
    // guardrail lists accumulate (union) so protection can only be added, never removed.
    fn merge(mut self, other: Self) -> Self {
        self.guardrail_commands.extend(other.guardrail_commands);
        Self {
            enabled: self.enabled || other.enabled,
            live_rules: other.live_rules.or(self.live_rules),
            state_dir: other.state_dir.or(self.state_dir),
            guardrail_commands: self.guardrail_commands,
        }
    }

    pub(crate) fn live_rules_file(&self) -> &str {
        self.live_rules.as_deref().unwrap_or("99-live.toml")
    }

    // Built-in destructive set unioned with the user's additions.
    pub(crate) fn is_guardrail(&self, command: &str) -> bool {
        DEFAULT_GUARDRAIL.contains(&command) || self.guardrail_commands.iter().any(|c| c == command)
    }
}

#[derive(Default, Deserialize)]
pub(crate) struct RawApprovalConfig {
    #[serde(default)]
    pub(crate) enabled: bool,
    pub(crate) live_rules: Option<String>,
    pub(crate) state_dir: Option<String>,
    #[serde(default)]
    pub(crate) guardrail_commands: Vec<String>,
}

pub(crate) fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        dirs::home_dir()
            .expect("Could not determine home directory")
            .join(rest)
    } else {
        PathBuf::from(path)
    }
}

pub(crate) fn find_project_config(cwd: &str) -> Option<PathBuf> {
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

pub(crate) fn lord_kali_config_dir() -> PathBuf {
    dirs::config_dir()
        .expect("Could not determine config directory")
        .join("lord-kali")
}

pub(crate) fn load_config(cwd: Option<&str>) -> Config {
    let initial = cwd
        .and_then(find_project_config)
        .map(|p| parse_config_file(&p))
        .unwrap_or_default();

    let config_dir = lord_kali_config_dir();

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision::{handle_bash, handle_web_fetch};

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

    // --- group flattening ---

    #[test]
    fn group_projects_applied_to_rules() {
        let raw = RawConfig {
            bash: RawCommandConfig::default(),
            powershell: RawCommandConfig::default(),
            web_fetch: RawWebFetchConfig::default(),
            log: None,
            worktree_protection: RawWorktreeProtectionConfig::default(),
            approval: RawApprovalConfig::default(),
            mcp: RawMcpConfig::default(),
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
                mcp: RawMcpConfig::default(),
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
            approval: RawApprovalConfig::default(),
            mcp: RawMcpConfig::default(),
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
                mcp: RawMcpConfig::default(),
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
            approval: RawApprovalConfig::default(),
            mcp: RawMcpConfig::default(),
            group: vec![RawGroupConfig {
                projects: vec!["/home/user/projects/test".into()],
                bash: RawCommandConfig {
                    allowed_commands: vec!["rustup".into()],
                    rules: vec![],
                },
                powershell: RawCommandConfig::default(),
                web_fetch: RawWebFetchConfig::default(),
                mcp: RawMcpConfig::default(),
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
            approval: RawApprovalConfig::default(),
            mcp: RawMcpConfig::default(),
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
                mcp: RawMcpConfig::default(),
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
            approval: RawApprovalConfig::default(),
            mcp: RawMcpConfig::default(),
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
                mcp: RawMcpConfig::default(),
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

    // --- worktree protection config ---

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
}
