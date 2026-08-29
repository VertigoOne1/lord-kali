// `lord-kali prune-rules` — audit the live ruleset the approval TUI writes, and with
// `--apply` drop the rules that can never fire.
//
// Rule precedence is deliberately firewall-like (docs/A-persistable-approvals.md): an
// earlier `ask`/`deny` outranks a later `allow` no matter which file it sits in, and the
// live file loads last. So the TUI can persist a well-formed rule that is dead on arrival.
// `watch.rs::shadow_warning` (A5) asks that question of one rule at write time; this is the
// batch form of the same question, asked of every rule in the file, and the two must agree —
// both re-resolve through the real `dispatch` rather than reimplementing precedence.
//
// The question is asked by *witness*. The TUI builds an args pattern from a literal command
// (`scope::tight_args` / `flag_scoped_args`), so that pattern can be read backwards into a
// command the rule was written for. Resolve that witness against the fully merged config and
// see which rule the gate lands on: a rule that cannot decide its own witness decides
// nothing. A witness that cannot be derived — a `/regex/` pattern, a hand-written glob —
// makes the rule unanalysable, and unanalysable rules are always kept. That is the same
// principle as `log::prune_log_file` keeping lines it cannot date.

use crate::config::{expand_tilde, load_config_in, lord_kali_config_dir, Config, RawConfig};
use crate::decision::{deciding_index, dispatch};
use crate::log::{now_ms, DEFAULT_LOG_PATH};
use crate::queue::write_atomic;
use crate::{HookInput, ToolInput};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub(crate) const USAGE: &str = "\
lord-kali prune-rules [--apply] [--days N] [--cold] [--file <path>] [--config-dir <path>]

Reports which rules in the live ruleset can never fire, and with --apply removes them.
Only the live file is ever rewritten; the hand-written rule files are inputs.

  --apply             rewrite the live file (a timestamped .bak-<stamp> is written first)
  --days N            only count log entries from the last N days when deciding coldness
  --cold              also remove cold rules. NOT implied by --apply: a short log window is
                      not evidence that a rule is useless, only that nothing needed it
                      lately, so removing cold rules is always a separate, deliberate ask
  --file <path>       live ruleset to audit (name or path inside the config dir)
  --config-dir <path> config directory to resolve the merged ruleset from";

// What a `**` stands in for when a rule's pattern wildcards its operands. A witness has to
// be a concrete string, and this is the most neutral token available: no glob
// metacharacters, no path separators, nothing a real rule is likely to single out.
const WITNESS_OPERAND: &str = "_";
// Source label for the one-rule config the self-check resolves against, so a deciding node
// from it is unmistakably the rule under audit and not something inherited.
const SELF_SOURCE: &str = "<rule under audit>";

const DAY_MS: u64 = 86_400_000;

pub(crate) struct Options {
    pub(crate) apply: bool,
    pub(crate) cold: bool,
    pub(crate) days: Option<u64>,
    pub(crate) file: Option<String>,
    pub(crate) config_dir: Option<PathBuf>,
    pub(crate) now_ms: u64,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            apply: false,
            cold: false,
            days: None,
            file: None,
            config_dir: None,
            now_ms: now_ms(),
        }
    }
}

// ---- rule tables -----------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum Table {
    Bash,
    Powershell,
    WebFetch,
    WebSearch,
    Mcp,
    File,
}

impl Table {
    fn label(self) -> &'static str {
        match self {
            Table::Bash => "bash",
            Table::Powershell => "powershell",
            Table::WebFetch => "web-fetch",
            Table::WebSearch => "web-search",
            Table::Mcp => "mcp",
            Table::File => "file",
        }
    }
}

struct Rule {
    table: Table,
    // command basename for the shell tables; the url/query/tool/path pattern for the rest.
    target: String,
    args: Option<String>,
    projects: Vec<String>,
}

impl Rule {
    // How this rule appears in a `NodeTrace`'s meta. The pattern tables record their single
    // pattern as both `rule_command` and `rule_args` (see `config::PatternRules::from_raw`),
    // so identity has to be read the same way here.
    fn meta_pair(&self) -> (String, Option<String>) {
        match self.table {
            Table::Bash | Table::Powershell => (self.target.clone(), self.args.clone()),
            _ => (self.target.clone(), Some(self.target.clone())),
        }
    }

    fn identity(&self) -> (Table, String, Option<String>, Vec<String>) {
        (
            self.table,
            self.target.clone(),
            self.args.clone(),
            self.projects.clone(),
        )
    }
}

// A block holds exactly one rule; whichever table it landed in is the table it belongs to.
// Anything else — a `[[group]]`, a table this audit does not know, an unparseable block, a
// decision string the loader would reject — yields None and is kept untouched.
fn rule_from_block(text: &str) -> Option<Rule> {
    let raw: RawConfig = toml::from_str(text).ok()?;
    let found = [
        (raw.bash.rules.into_iter().next())
            .map(|r| (Table::Bash, r.command, r.args, r.decision, r.projects)),
        (raw.powershell.rules.into_iter().next())
            .map(|r| (Table::Powershell, r.command, r.args, r.decision, r.projects)),
        (raw.web_fetch.rules.into_iter().next())
            .map(|r| (Table::WebFetch, r.pattern, None, r.decision, r.projects)),
        (raw.web_search.rules.into_iter().next())
            .map(|r| (Table::WebSearch, r.pattern, None, r.decision, r.projects)),
        (raw.mcp.rules.into_iter().next())
            .map(|r| (Table::Mcp, r.tool, None, r.decision, r.projects)),
        (raw.file.rules.into_iter().next())
            .map(|r| (Table::File, r.path, None, r.decision, r.projects)),
    ];
    let (table, target, args, decision, projects) = found.into_iter().flatten().next()?;
    matches!(decision.as_str(), "allow" | "deny" | "ask").then_some(Rule {
        table,
        target,
        args,
        projects,
    })
}

// ---- witness derivation ------------------------------------------------------------------

struct Witness {
    table: Table,
    target: String,
    args: Option<String>,
    cwd: Option<String>,
}

impl Witness {
    fn hook_input(&self) -> HookInput {
        let mut input = ToolInput::default();
        let tool = match self.table {
            Table::Bash => {
                input.command = Some(self.command_line());
                "Bash"
            }
            Table::Powershell => {
                input.command = Some(self.command_line());
                "PowerShell"
            }
            Table::WebFetch => {
                input.url = Some(self.target.clone());
                "WebFetch"
            }
            Table::WebSearch => {
                input.query = Some(self.target.clone());
                "WebSearch"
            }
            // MCP gating keys on the tool name itself, which is what the rule pattern is.
            Table::Mcp => {
                return HookInput {
                    tool_name: self.target.clone(),
                    tool_input: input,
                    cwd: self.cwd.clone(),
                    hook_event_name: None,
                    session_id: None,
                    tool_use_id: None,
                    permission_mode: None,
                    agent_type: None,
                }
            }
            // Any mutating tool resolves the same path rules; Edit is the representative one.
            Table::File => {
                input.file_path = Some(self.target.clone());
                "Edit"
            }
        };
        HookInput {
            tool_name: tool.to_string(),
            tool_input: input,
            cwd: self.cwd.clone(),
            hook_event_name: None,
            session_id: None,
            tool_use_id: None,
            permission_mode: None,
            agent_type: None,
        }
    }

    fn command_line(&self) -> String {
        match &self.args {
            Some(a) if !a.is_empty() => format!("{} {a}", self.target),
            _ => self.target.clone(),
        }
    }

    fn display(&self) -> String {
        match self.table {
            Table::Bash | Table::Powershell => self.command_line(),
            _ => self.target.clone(),
        }
    }
}

// `compile_pattern` reads `/…/` as a regex; a regex cannot be read backwards into the text
// it was built from, so those rules have no witness.
fn is_regex(pattern: &str) -> bool {
    pattern
        .strip_prefix('/')
        .and_then(|s| s.strip_suffix('/'))
        .is_some()
}

// Reverse `scope::escape_glob`. None when the pattern still carries a live glob
// metacharacter, i.e. it is not literal text that was escaped on the way in.
fn unescape_glob(pattern: &str) -> Option<String> {
    let mut out = String::with_capacity(pattern.len());
    let mut chars = pattern.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => out.push(chars.next()?),
            '*' | '?' | '[' | ']' | '{' | '}' | '!' => return None,
            _ => out.push(c),
        }
    }
    Some(out)
}

// The arguments a command matching this rule would carry.
//
// `{, **}` is the "tolerate extra trailing args" suffix `scope::tight_args` and `scope_args`
// append; stripping it leaves the literal the rule was built from. A trailing ` **` is the
// flag-scoped rung, whose operands were deliberately wildcarded — those cannot be recovered,
// so the witness carries a placeholder operand instead.
fn witness_args(pattern: &str) -> Option<String> {
    if is_regex(pattern) {
        return None;
    }
    if let Some(head) = pattern.strip_suffix("{, **}") {
        return unescape_glob(head);
    }
    if let Some(head) = pattern.strip_suffix(" **") {
        return Some(format!("{} {WITNESS_OPERAND}", unescape_glob(head)?));
    }
    unescape_glob(pattern)
}

// The url/query/tool/path a call matching this rule would carry. `{,/**}` is the
// domain/subtree shape ("the thing itself, or anything under it"), whose empty alternative
// makes the prefix its own witness; a bare `/**` suffix needs a child to match.
fn witness_target(pattern: &str) -> Option<String> {
    if is_regex(pattern) {
        return None;
    }
    if let Some(head) = pattern.strip_suffix("{,/**}") {
        return unescape_glob(head);
    }
    if let Some(head) = pattern.strip_suffix("/**") {
        return Some(format!("{}/{WITNESS_OPERAND}", unescape_glob(head)?));
    }
    unescape_glob(pattern)
}

fn witness_for(rule: &Rule) -> Option<Witness> {
    let (target, args) = match rule.table {
        Table::Bash | Table::Powershell => {
            let args = match &rule.args {
                Some(p) => Some(witness_args(p)?),
                None => None,
            };
            (unescape_glob(&rule.target)?, args)
        }
        _ => (witness_target(&rule.target)?, None),
    };
    // A project-scoped rule is unreachable from anywhere outside its projects, so resolving
    // it from nowhere would make every such rule look dead. Resolve it from inside.
    let cwd = rule
        .projects
        .first()
        .map(|p| expand_tilde(p).display().to_string());
    Some(Witness {
        table: rule.table,
        target,
        args,
        cwd,
    })
}

// ---- resolution --------------------------------------------------------------------------

// The gate's answer for one witness: the verdict for the whole call, plus which rule set it.
// Both halves matter — the behaviour-preservation check compares them as a pair, because a
// removal can leave the deciding rule intact and still change the call's outcome.
#[derive(Clone, PartialEq)]
struct Outcome {
    final_decision: String,
    deciding: Option<serde_json::Value>,
}

impl Outcome {
    // Which rule decided, as a value comparable across two loads of the config. The source
    // is compared by file name, not full path: the pruned config is staged in a scratch
    // directory, and a rule that moved directory has not changed.
    fn deciding_id(&self) -> String {
        match &self.deciding {
            None => "(nothing)".to_string(),
            Some(v) => format!(
                "{}|{}|{}|{}",
                self.winner_file(),
                v["rule_kind"].as_str().unwrap_or(""),
                v["rule_command"].as_str().unwrap_or(""),
                v["rule_args"].as_str().unwrap_or(""),
            ),
        }
    }

    fn identifies(&self, source: &str, command: &str, args: Option<&str>) -> bool {
        match &self.deciding {
            None => false,
            Some(v) => {
                v["source_file"].as_str() == Some(source)
                    && v["rule_kind"].as_str() == Some("explicit")
                    && v["rule_command"].as_str() == Some(command)
                    && v["rule_args"].as_str() == args
            }
        }
    }

    fn winner_file(&self) -> String {
        self.deciding
            .as_ref()
            .and_then(|v| v["source_file"].as_str())
            .and_then(|p| p.rsplit(['/', '\\']).next())
            .unwrap_or("another rule")
            .to_string()
    }

    fn winner_rule(&self) -> String {
        let Some(v) = &self.deciding else {
            return "an earlier rule".to_string();
        };
        match (v["rule_command"].as_str(), v["rule_args"].as_str()) {
            (Some(c), Some(a)) => format!("{c} {a}"),
            (Some(c), None) => c.to_string(),
            _ => "an earlier rule".to_string(),
        }
    }

    fn winner_decision(&self) -> String {
        self.deciding
            .as_ref()
            .and_then(|v| v["decision"].as_str())
            .unwrap_or("?")
            .to_string()
    }
}

fn resolve(config: &Config, witness: &Witness) -> Outcome {
    let trace = dispatch(config, &witness.hook_input(), witness.cwd.as_deref());
    Outcome {
        final_decision: match &trace.final_decision {
            Some((d, _)) => d.as_str().to_string(),
            None => "passthrough".to_string(),
        },
        deciding: deciding_index(&trace.nodes).map(|i| trace.nodes[i].to_json()),
    }
}

// Does the rule match the command its own witness was read out of? Resolved against a config
// holding nothing but this rule, so the answer is about the derivation and not about
// precedence. A `no` means the reversal was wrong, and the rule is left alone.
fn self_matches(block_text: &str, rule: &Rule, witness: &Witness) -> bool {
    let Ok(raw) = toml::from_str::<RawConfig>(block_text) else {
        return false;
    };
    let mut solo = Config::from_raw(raw, Some(Arc::from(SELF_SOURCE)));
    // `[file] enabled` lives in the operator's settings, not in a rule block; the real
    // resolution below reports it as disabled if it is, but the self-check is only asking
    // whether the pattern matches.
    solo.file.enabled = true;
    let (command, args) = rule.meta_pair();
    resolve(&solo, witness).identifies(SELF_SOURCE, &command, args.as_deref())
}

// ---- block splitting ---------------------------------------------------------------------

// The live file carries a header comment, hand-edited content and multi-line TOML strings.
// Re-serialising parsed TOML would throw all of that away, so rules are removed as text
// blocks: a block runs from its `[[table.rules]]` header, plus any comment lines attached
// immediately above it, to just before the next header.
struct BlockRange {
    start: usize,
    end: usize,
}

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Code,
    Basic,
    Literal,
    MultiBasic,
    MultiLiteral,
}

// Where one line leaves the lexer. Only enough of TOML to know whether a `[[` at the start
// of a line is a table header or text inside a string — the live file really does contain
// `python -c """…"""` blocks whose content could start with anything.
fn scan_line(line: &str, start: Mode) -> Mode {
    let b = line.as_bytes();
    let mut mode = start;
    let mut i = 0;
    while i < b.len() {
        match mode {
            Mode::Code => {
                if b[i] == b'#' {
                    break;
                }
                if b[i..].starts_with(b"\"\"\"") {
                    mode = Mode::MultiBasic;
                    i += 3;
                    continue;
                }
                if b[i..].starts_with(b"'''") {
                    mode = Mode::MultiLiteral;
                    i += 3;
                    continue;
                }
                if b[i] == b'"' {
                    mode = Mode::Basic;
                } else if b[i] == b'\'' {
                    mode = Mode::Literal;
                }
                i += 1;
            }
            Mode::Basic => {
                if b[i] == b'\\' {
                    i += 2;
                    continue;
                }
                if b[i] == b'"' {
                    mode = Mode::Code;
                }
                i += 1;
            }
            Mode::Literal => {
                if b[i] == b'\'' {
                    mode = Mode::Code;
                }
                i += 1;
            }
            Mode::MultiBasic => {
                if b[i] == b'\\' {
                    i += 2;
                    continue;
                }
                if b[i..].starts_with(b"\"\"\"") {
                    mode = Mode::Code;
                    i += 3;
                    continue;
                }
                i += 1;
            }
            Mode::MultiLiteral => {
                if b[i..].starts_with(b"'''") {
                    mode = Mode::Code;
                    i += 3;
                    continue;
                }
                i += 1;
            }
        }
    }
    // A single-line TOML string cannot span a newline, so those always close at end of line.
    match mode {
        Mode::Basic | Mode::Literal => Mode::Code,
        other => other,
    }
}

fn split_blocks(lines: &[&str]) -> Vec<BlockRange> {
    let mut headers = Vec::new();
    let mut mode = Mode::Code;
    for (i, line) in lines.iter().enumerate() {
        if mode == Mode::Code && line.trim_start().starts_with("[[") {
            headers.push(i);
        }
        mode = scan_line(line, mode);
    }

    let mut blocks: Vec<BlockRange> = Vec::with_capacity(headers.len());
    for (n, &header) in headers.iter().enumerate() {
        let floor = if n == 0 { 0 } else { headers[n - 1] + 1 };
        let mut start = header;
        while start > floor && lines[start - 1].trim_start().starts_with('#') {
            start -= 1;
        }
        // A comment run reaching the top of the file is the file's own header, not a note on
        // the first rule; it stays in the preamble.
        if start == 0 {
            start = header;
        }
        let end = headers.get(n + 1).copied().unwrap_or(lines.len());
        blocks.push(BlockRange { start, end });
    }
    // Each block's end is the next block's start, comments included.
    for n in 0..blocks.len().saturating_sub(1) {
        blocks[n].end = blocks[n + 1].start;
    }
    blocks
}

fn header_of(block: &[&str]) -> String {
    block
        .iter()
        .find(|l| l.trim_start().starts_with("[["))
        .unwrap_or(&"")
        .trim()
        .to_string()
}

fn rebuild(lines: &[&str], blocks: &[BlockRange], drop: &HashSet<usize>, newline: &str) -> String {
    let preamble_end = blocks.first().map_or(lines.len(), |b| b.start);
    let mut out: Vec<&str> = lines[..preamble_end].to_vec();
    for (i, b) in blocks.iter().enumerate() {
        if !drop.contains(&i) {
            out.extend_from_slice(&lines[b.start..b.end]);
        }
    }
    let mut text = out.join(newline);
    if !text.is_empty() {
        text.push_str(newline);
    }
    text
}

// ---- coldness --------------------------------------------------------------------------

// Which rules actually decided something in the retained log, keyed the way a rule
// identifies itself in a decision record.
#[derive(Debug)]
enum ColdData {
    Scanned {
        seen: HashSet<(String, String, String)>,
        entries: usize,
        window: String,
    },
    // Deliberate degradation, and the reason it is safe: with no log there is no evidence
    // either way, so nothing is called cold and `--cold` refuses rather than treating an
    // empty scan as proof that every rule is dead.
    Unavailable(String),
}

impl ColdData {
    fn decided(&self, live_file: &str, command: &str, args: Option<&str>) -> bool {
        match self {
            ColdData::Unavailable(_) => true,
            ColdData::Scanned { seen, .. } => seen.contains(&(
                live_file.to_string(),
                command.to_string(),
                args.unwrap_or_default().to_string(),
            )),
        }
    }
}

fn basename(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default()
}

fn scan_log(config: &Config, opts: &Options) -> ColdData {
    let Some(log) = config.log.as_ref().filter(|l| l.enabled) else {
        return ColdData::Unavailable("logging is disabled in this config".to_string());
    };
    let path = expand_tilde(log.path.as_deref().unwrap_or(DEFAULT_LOG_PATH));
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) => {
            return ColdData::Unavailable(format!("{}: {e}", path.display()));
        }
    };
    let cutoff = opts
        .days
        .map(|d| opts.now_ms.saturating_sub(d.saturating_mul(DAY_MS)));

    let mut seen = HashSet::new();
    let mut entries = 0usize;
    for line in content.lines() {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if let Some(c) = cutoff {
            if v["ts_ms"].as_u64().is_some_and(|ts| ts < c) {
                continue;
            }
        }
        entries += 1;
        let deciding = &v["lk_decision"]["deciding"];
        let (Some(file), Some(command)) = (
            deciding["source_file"].as_str(),
            deciding["rule_command"].as_str(),
        ) else {
            continue;
        };
        seen.insert((
            basename(Path::new(file)),
            command.to_string(),
            deciding["rule_args"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
        ));
    }

    if entries == 0 {
        return ColdData::Unavailable(format!("{} holds no entries", path.display()));
    }
    ColdData::Scanned {
        seen,
        entries,
        window: match opts.days {
            Some(d) => format!("last {d}d of {}", path.display()),
            None => format!("whole retained log at {}", path.display()),
        },
    }
}

// ---- the audit ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
enum Verdict {
    Live,
    Cold,
    Shadowed {
        file: String,
        rule: String,
        decision: String,
    },
    Subsumed {
        rule: String,
        decision: String,
    },
    Unanalysable {
        why: String,
    },
}

impl Verdict {
    fn removable(&self) -> bool {
        matches!(self, Verdict::Shadowed { .. } | Verdict::Subsumed { .. })
    }
}

#[derive(Debug)]
struct Row {
    table: &'static str,
    target: String,
    args: Option<String>,
    verdict: Verdict,
}

impl Row {
    fn describe(&self) -> String {
        format!("{:<11} {}", self.table, self.subject())
    }

    // The command/target and its args pattern, as one string.
    fn subject(&self) -> String {
        match &self.args {
            Some(a) => format!("{}  {a}", self.target),
            None => self.target.clone(),
        }
    }
}

#[derive(Debug)]
pub(crate) struct Report {
    file: PathBuf,
    rows: Vec<Row>,
    rules_before: usize,
    lines_before: usize,
    rules_after: usize,
    lines_after: usize,
    cold: ColdData,
    // Set only when `--apply` actually rewrote the file.
    backup: Option<PathBuf>,
}

impl Report {
    fn count(&self, want: impl Fn(&Verdict) -> bool) -> usize {
        self.rows.iter().filter(|r| want(&r.verdict)).count()
    }

    fn removed(&self) -> usize {
        self.rules_before - self.rules_after
    }
}

// Resolve the live file to audit. Only a file the loader actually reads can be audited: the
// whole method is to ask what the *merged* config does with a witness, and a file outside the
// config directory is not part of any merge.
fn resolve_live_path(
    config_dir: &Path,
    config: &Config,
    file: Option<&str>,
) -> Result<PathBuf, String> {
    let Some(file) = file else {
        return Ok(config_dir.join(config.approval.live_rules_file()));
    };
    let given = Path::new(file);
    let resolved = match given.parent() {
        Some(p) if p.as_os_str().is_empty() => config_dir.join(given),
        _ => given.to_path_buf(),
    };
    if resolved.parent() != Some(config_dir) {
        return Err(format!(
            "{} is not in the config dir {} — rules are resolved through the merged config, \
             so the file has to be one the loader reads",
            resolved.display(),
            config_dir.display()
        ));
    }
    Ok(resolved)
}

pub(crate) fn run(opts: &Options) -> Result<Report, String> {
    let config_dir = opts.config_dir.clone().unwrap_or_else(lord_kali_config_dir);
    let base = load_config_in(&config_dir, None);
    let live_path = resolve_live_path(&config_dir, &base, opts.file.as_deref())?;
    let live_name = basename(&live_path);
    let live_source = live_path.display().to_string();

    let content =
        std::fs::read_to_string(&live_path).map_err(|e| format!("{}: {e}", live_path.display()))?;
    // Whatever the file already uses; a rewrite must not silently flip its line endings.
    let newline = if content.contains(
        "
",
    ) {
        "\r\n"
    } else {
        "\n"
    };
    let lines: Vec<&str> = content.lines().collect();
    let blocks = split_blocks(&lines);
    let cold = scan_log(&base, opts);
    if opts.cold {
        if let ColdData::Unavailable(why) = &cold {
            return Err(format!(
                "--cold needs the decision log to know what has fired, and it is unreadable ({why})"
            ));
        }
    }

    let mut configs: HashMap<Option<String>, Config> = HashMap::new();
    let mut rows: Vec<Row> = Vec::with_capacity(blocks.len());
    let mut drop: HashSet<usize> = HashSet::new();
    // Witness plus its pre-prune outcome, for the rules that survive.
    let mut kept: Vec<(String, Witness, Outcome)> = Vec::new();
    let mut seen_identities: HashSet<(Table, String, Option<String>, Vec<String>)> = HashSet::new();

    for (i, block) in blocks.iter().enumerate() {
        let text = lines[block.start..block.end].join("\n");
        let Some(rule) = rule_from_block(&text) else {
            rows.push(Row {
                table: "?",
                target: header_of(&lines[block.start..block.end]),
                args: None,
                verdict: Verdict::Unanalysable {
                    why: "not a rule table this audit understands".to_string(),
                },
            });
            continue;
        };
        let (command, args) = rule.meta_pair();
        let mut row = Row {
            table: rule.table.label(),
            target: rule.target.clone(),
            args: rule.args.clone(),
            verdict: Verdict::Live,
        };

        let Some(witness) = witness_for(&rule) else {
            row.verdict = Verdict::Unanalysable {
                why: "no witness: the pattern is a regex or a glob, not escaped literal text"
                    .to_string(),
            };
            rows.push(row);
            continue;
        };
        if !self_matches(&text, &rule, &witness) {
            row.verdict = Verdict::Unanalysable {
                why: format!(
                    "no witness: the rule does not match `{}`, the call it was read back as",
                    witness.display()
                ),
            };
            rows.push(row);
            continue;
        }
        if rule.table == Table::File && !base.file.enabled {
            row.verdict = Verdict::Unanalysable {
                why: "[file] gating is disabled, so no file rule resolves".to_string(),
            };
            rows.push(row);
            continue;
        }
        // An exact repeat is indistinguishable from its original in a decision record, so it
        // is settled here rather than by resolution, which would credit the first one.
        if !seen_identities.insert(rule.identity()) {
            row.verdict = Verdict::Subsumed {
                rule: "an identical earlier rule".to_string(),
                decision: "same".to_string(),
            };
            rows.push(row);
            drop.insert(i);
            continue;
        }

        let config = configs
            .entry(witness.cwd.clone())
            .or_insert_with(|| load_config_in(&config_dir, witness.cwd.as_deref()));
        let outcome = resolve(config, &witness);

        row.verdict = if outcome.deciding.is_none() {
            Verdict::Unanalysable {
                why: format!("nothing resolved `{}`", witness.display()),
            }
        } else if outcome.identifies(&live_source, &command, args.as_deref()) {
            if cold.decided(&live_name, &command, args.as_deref()) {
                Verdict::Live
            } else {
                Verdict::Cold
            }
        } else if outcome.winner_file() == live_name {
            Verdict::Subsumed {
                rule: outcome.winner_rule(),
                decision: outcome.winner_decision(),
            }
        } else {
            Verdict::Shadowed {
                file: outcome.winner_file(),
                rule: outcome.winner_rule(),
                decision: outcome.winner_decision(),
            }
        };

        if row.verdict.removable() || (opts.cold && row.verdict == Verdict::Cold) {
            drop.insert(i);
        } else {
            kept.push((row.subject(), witness, outcome));
        }
        rows.push(row);
    }

    let pruned = rebuild(&lines, &blocks, &drop, newline);
    let mut report = Report {
        file: live_path.clone(),
        rules_before: blocks.len(),
        lines_before: lines.len(),
        rules_after: blocks.len() - drop.len(),
        lines_after: if pruned.is_empty() {
            0
        } else {
            pruned.lines().count()
        },
        rows,
        cold,
        backup: None,
    };

    if !opts.apply || drop.is_empty() {
        return Ok(report);
    }

    verify_preserved(&config_dir, &live_name, &pruned, &kept)?;

    let backup = live_path.with_file_name(format!("{live_name}.bak-{}", utc_stamp(opts.now_ms)));
    std::fs::copy(&live_path, &backup)
        .map_err(|e| format!("could not write backup {}: {e}", backup.display()))?;
    write_atomic(&live_path, &pruned).map_err(|e| format!("{}: {e}", live_path.display()))?;
    report.backup = Some(backup);
    Ok(report)
}

// The property that makes `--apply` trustworthy: every rule that survives must still get the
// same answer it got before. Removals interact — a call can reach several rules at once, so
// dropping one rule can change the verdict of a call another rule was deciding — and this is
// what catches that. It is checked against a scratch copy of the config directory rather than
// a bespoke merge, so the verification runs the real loader over the real neighbouring files.
fn verify_preserved(
    config_dir: &Path,
    live_name: &str,
    pruned: &str,
    kept: &[(String, Witness, Outcome)],
) -> Result<(), String> {
    if kept.is_empty() {
        return Ok(());
    }
    let scratch = scratch_config_dir(config_dir, live_name, pruned)
        .map_err(|e| format!("could not stage the pruned config for verification: {e}"))?;
    let mut configs: HashMap<Option<String>, Config> = HashMap::new();
    let mut failure = None;
    for (subject, witness, before) in kept {
        let config = configs
            .entry(witness.cwd.clone())
            .or_insert_with(|| load_config_in(&scratch, witness.cwd.as_deref()));
        let after = resolve(config, witness);
        if after.final_decision != before.final_decision
            || after.deciding_id() != before.deciding_id()
        {
            failure = Some(format!(
                "aborted, nothing written: pruning would change `{}` from {} ({}) to {} ({}). \
                 That is the call the kept rule `{subject}` was read back from — resolve it \
                 by hand first.",
                witness.display(),
                before.final_decision,
                before.winner_rule(),
                after.final_decision,
                after.winner_rule(),
            ));
            break;
        }
    }
    let _ = std::fs::remove_dir_all(&scratch);
    match failure {
        Some(msg) => Err(msg),
        None => Ok(()),
    }
}

fn scratch_config_dir(
    config_dir: &Path,
    live_name: &str,
    live_content: &str,
) -> std::io::Result<PathBuf> {
    let dir = std::env::temp_dir().join(format!(
        "lord-kali-prune-{}-{}",
        std::process::id(),
        now_ms()
    ));
    std::fs::create_dir_all(&dir)?;
    for entry in std::fs::read_dir(config_dir)? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) == Some("toml") {
            std::fs::copy(&path, dir.join(basename(&path)))?;
        }
    }
    std::fs::write(dir.join(live_name), live_content)?;
    Ok(dir)
}

// Days-to-calendar (Howard Hinnant's civil_from_days), so a backup can be stamped with a
// real UTC timestamp without a date crate.
fn utc_stamp(ms: u64) -> String {
    let secs = ms / 1000;
    let tod = secs % 86_400;
    let z = (secs / 86_400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}{month:02}{day:02}-{:02}{:02}{:02}",
        tod / 3600,
        (tod % 3600) / 60,
        tod % 60
    )
}

// ---- report ------------------------------------------------------------------------------

pub(crate) fn render(report: &Report) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "lord-kali prune-rules: {} ({} rules, {} lines)\n",
        report.file.display(),
        report.rules_before,
        report.lines_before
    ));
    match &report.cold {
        ColdData::Scanned {
            entries, window, ..
        } => out.push_str(&format!("cold window: {entries} entries, {window}\n")),
        ColdData::Unavailable(why) => out.push_str(&format!(
            "cold window: unavailable ({why}) — nothing is reported cold\n"
        )),
    }

    let section = |out: &mut String, title: &str, note: &str, want: fn(&Verdict) -> bool| {
        let rows: Vec<&Row> = report.rows.iter().filter(|r| want(&r.verdict)).collect();
        if rows.is_empty() {
            return;
        }
        out.push_str(&format!("\n{title} ({}) — {note}\n", rows.len()));
        for row in rows {
            out.push_str(&format!("  {}\n", row.describe()));
            match &row.verdict {
                Verdict::Shadowed {
                    file,
                    rule,
                    decision,
                } => out.push_str(&format!(
                    "      {file} decides first: {rule} → {decision}\n"
                )),
                Verdict::Subsumed { rule, decision } => {
                    out.push_str(&format!("      covered here by: {rule} → {decision}\n"))
                }
                Verdict::Unanalysable { why } => out.push_str(&format!("      {why}\n")),
                _ => {}
            }
        }
    };

    section(
        &mut out,
        "shadowed",
        "another file's rule decides first; edit that file to change the outcome",
        |v| matches!(v, Verdict::Shadowed { .. }),
    );
    section(
        &mut out,
        "subsumed",
        "an earlier rule in this file decides first; safe to drop",
        |v| matches!(v, Verdict::Subsumed { .. }),
    );
    section(
        &mut out,
        "cold",
        "never the deciding rule in the log window; KEPT unless --cold",
        |v| matches!(v, Verdict::Cold),
    );
    section(
        &mut out,
        "unanalysable",
        "no witness could be derived; always kept",
        |v| matches!(v, Verdict::Unanalysable { .. }),
    );

    out.push_str(&format!(
        "\nlive {} · shadowed {} · subsumed {} · cold {} · unanalysable {}\n",
        report.count(|v| matches!(v, Verdict::Live)),
        report.count(|v| matches!(v, Verdict::Shadowed { .. })),
        report.count(|v| matches!(v, Verdict::Subsumed { .. })),
        report.count(|v| matches!(v, Verdict::Cold)),
        report.count(|v| matches!(v, Verdict::Unanalysable { .. })),
    ));

    if report.removed() == 0 {
        out.push_str("nothing to prune\n");
        return out;
    }
    out.push_str(&format!(
        "projected: {} → {} rules (-{}), {} → {} lines (-{})\n",
        report.rules_before,
        report.rules_after,
        report.removed(),
        report.lines_before,
        report.lines_after,
        report.lines_before - report.lines_after,
    ));
    match &report.backup {
        Some(backup) => out.push_str(&format!(
            "backup: {}\nwrote {}: {} rules, {} lines\n",
            backup.display(),
            report.file.display(),
            report.rules_after,
            report.lines_after
        )),
        None => out.push_str("report only — pass --apply to write it\n"),
    }
    out
}

// ---- cli -----------------------------------------------------------------------------------

fn parse_options(args: &[String]) -> Result<Option<Options>, String> {
    let mut opts = Options::default();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--help" | "-h" => return Ok(None),
            "--apply" => opts.apply = true,
            "--cold" => opts.cold = true,
            "--days" => {
                opts.days = Some(
                    it.next()
                        .and_then(|d| d.parse().ok())
                        .ok_or("--days requires a number")?,
                )
            }
            "--file" => opts.file = Some(it.next().ok_or("--file requires a path")?.clone()),
            "--config-dir" => {
                opts.config_dir = Some(PathBuf::from(
                    it.next().ok_or("--config-dir requires a path")?,
                ))
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    Ok(Some(opts))
}

pub(crate) fn prune_rules_cli(args: &[String]) {
    let opts = match parse_options(args) {
        Ok(Some(opts)) => opts,
        Ok(None) => {
            println!("{USAGE}");
            return;
        }
        Err(e) => {
            eprintln!("lord-kali prune-rules: {e}\n\n{USAGE}");
            std::process::exit(2);
        }
    };
    match run(&opts) {
        Ok(report) => print!("{}", render(&report)),
        Err(e) => {
            eprintln!("lord-kali prune-rules: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    const NOW: u64 = 1_800_000_000_000;

    // Every test owns its config dir. Nothing here reads the machine's real one, and nothing
    // sets an environment variable — tests in one binary share the environment.
    struct Fixture {
        dir: TempDir,
    }

    impl Fixture {
        fn new() -> Self {
            Fixture {
                dir: tempfile::tempdir().unwrap(),
            }
        }

        fn path(&self) -> &Path {
            self.dir.path()
        }

        fn write(&self, name: &str, content: &str) -> PathBuf {
            let p = self.dir.path().join(name);
            fs::write(&p, content).unwrap();
            p
        }

        // A log the audit can read, holding one decision record per (command, args) named.
        fn log(&self, decided: &[(&str, Option<&str>)]) {
            let log_path = self.dir.path().join("hook.jsonl");
            // The leading entry means an empty `decided` still reads as "the log works and
            // nothing fired", not as "there is no log".
            let mut content =
                serde_json::json!({"ts_ms": NOW, "lk_event": "session_start"}).to_string();
            for (command, args) in decided {
                content.push('\n');
                content.push_str(
                    &serde_json::json!({
                        "ts_ms": NOW,
                        "lk_event": "pre_tool_use",
                        "lk_decision": {"deciding": {
                            "source_file": "/somewhere/99-live.toml",
                            "rule_command": command,
                            "rule_args": args,
                        }},
                    })
                    .to_string(),
                );
            }
            content.push('\n');
            fs::write(&log_path, content).unwrap();
            self.log_config(&log_path);
        }

        fn log_config(&self, log_path: &Path) {
            self.write(
                "05-log.toml",
                &format!(
                    "[log]\nenabled = true\npath = {}\n",
                    toml::Value::String(log_path.display().to_string())
                ),
            );
        }

        fn opts(&self) -> Options {
            Options {
                config_dir: Some(self.dir.path().to_path_buf()),
                now_ms: NOW,
                ..Options::default()
            }
        }

        fn live(&self) -> String {
            fs::read_to_string(self.dir.path().join("99-live.toml")).unwrap()
        }
    }

    fn verdict_of<'a>(report: &'a Report, target: &str, args: Option<&str>) -> &'a Verdict {
        &report
            .rows
            .iter()
            .find(|r| r.target == target && r.args.as_deref() == args)
            .unwrap_or_else(|| panic!("no row for {target} {args:?}"))
            .verdict
    }

    // --- categorisation ---------------------------------------------------------------

    // The motivating case from docs/A-persistable-approvals.md: `00-base.toml` states an
    // unconditional `sed -i → ask`, so every `sed -i` rule the TUI ever persisted is dead.
    #[test]
    fn an_earlier_ask_in_another_file_shadows_a_live_rule() {
        let fx = Fixture::new();
        fx.write(
            "00-base.toml",
            "[[bash.rules]]\ncommand = \"sed\"\nargs = '/.*(^|\\s)(-i|--in-place).*/'\ndecision = \"ask\"\n",
        );
        fx.write(
            "99-live.toml",
            "[[bash.rules]]\ncommand = \"sed\"\nargs = \"-i s/a/b/ x.md{, **}\"\ndecision = \"allow\"\n",
        );

        let report = run(&fx.opts()).unwrap();
        match verdict_of(&report, "sed", Some("-i s/a/b/ x.md{, **}")) {
            Verdict::Shadowed { file, decision, .. } => {
                assert_eq!(file, "00-base.toml");
                assert_eq!(decision, "ask");
            }
            other => panic!("expected shadowed, got {}", describe(other)),
        }
    }

    #[test]
    fn a_broader_earlier_live_rule_subsumes_a_later_one() {
        let fx = Fixture::new();
        fx.write(
            "99-live.toml",
            "[[bash.rules]]\ncommand = \"git\"\nargs = \"push{, **}\"\ndecision = \"allow\"\n\n\
             [[bash.rules]]\ncommand = \"git\"\nargs = \"push origin main{, **}\"\ndecision = \"allow\"\n",
        );

        let report = run(&fx.opts()).unwrap();
        assert_eq!(
            verdict_of(&report, "git", Some("push{, **}")),
            &Verdict::Live
        );
        match verdict_of(&report, "git", Some("push origin main{, **}")) {
            Verdict::Subsumed { rule, .. } => assert!(rule.contains("push{, **}"), "{rule}"),
            other => panic!("expected subsumed, got {}", describe(other)),
        }
    }

    #[test]
    fn a_rule_nothing_outranks_is_live_and_survives_apply() {
        let fx = Fixture::new();
        fx.write(
            "99-live.toml",
            "[[bash.rules]]\ncommand = \"jq\"\nargs = \".{, **}\"\ndecision = \"allow\"\n\n\
             [[bash.rules]]\ncommand = \"jq\"\nargs = \". -r{, **}\"\ndecision = \"allow\"\n",
        );

        let report = run(&Options {
            apply: true,
            ..fx.opts()
        })
        .unwrap();
        assert_eq!(verdict_of(&report, "jq", Some(".{, **}")), &Verdict::Live);
        assert!(fx.live().contains("\".{, **}\""));
        assert!(!fx.live().contains("\". -r{, **}\""), "subsumed rule kept");
    }

    // Never remove what could not be analysed — the same principle as prune_log_file keeping
    // lines it cannot date. `--apply --cold` is the most aggressive run there is.
    #[test]
    fn a_regex_args_pattern_is_unanalysable_and_survives_apply_cold() {
        let fx = Fixture::new();
        fx.log(&[]);
        fx.write(
            "99-live.toml",
            "[[bash.rules]]\ncommand = \"sed\"\nargs = '/-i .*/'\ndecision = \"allow\"\n\n\
             [[bash.rules]]\ncommand = \"jq\"\nargs = \".{, **}\"\ndecision = \"allow\"\n",
        );

        let report = run(&Options {
            apply: true,
            cold: true,
            ..fx.opts()
        })
        .unwrap();
        assert!(matches!(
            verdict_of(&report, "sed", Some("/-i .*/")),
            Verdict::Unanalysable { .. }
        ));
        assert!(fx.live().contains("'/-i .*/'"), "{}", fx.live());
        assert!(!fx.live().contains("jq"), "cold rule should have gone");
    }

    // --- coldness ---------------------------------------------------------------------

    #[test]
    fn cold_is_reported_but_never_removed_without_the_flag() {
        let fx = Fixture::new();
        fx.log(&[("git", Some("push{, **}"))]);
        fx.write(
            "99-live.toml",
            "[[bash.rules]]\ncommand = \"git\"\nargs = \"push{, **}\"\ndecision = \"allow\"\n\n\
             [[bash.rules]]\ncommand = \"jq\"\nargs = \".{, **}\"\ndecision = \"allow\"\n",
        );

        let report = run(&Options {
            apply: true,
            ..fx.opts()
        })
        .unwrap();
        assert_eq!(
            verdict_of(&report, "git", Some("push{, **}")),
            &Verdict::Live
        );
        assert_eq!(verdict_of(&report, "jq", Some(".{, **}")), &Verdict::Cold);
        assert_eq!(report.removed(), 0);
        assert!(fx.live().contains("jq"), "cold rule removed without --cold");

        let report = run(&Options {
            apply: true,
            cold: true,
            ..fx.opts()
        })
        .unwrap();
        assert_eq!(report.removed(), 1);
        assert!(!fx.live().contains("jq"));
        assert!(fx.live().contains("git"));
    }

    // No log means no evidence, and no evidence is not evidence of death.
    #[test]
    fn cold_refuses_to_run_without_a_readable_log() {
        let fx = Fixture::new();
        fx.write(
            "99-live.toml",
            "[[bash.rules]]\ncommand = \"jq\"\nargs = \".{, **}\"\ndecision = \"allow\"\n",
        );

        let err = run(&Options {
            cold: true,
            ..fx.opts()
        })
        .unwrap_err();
        assert!(err.contains("--cold needs the decision log"), "{err}");

        let report = run(&fx.opts()).unwrap();
        assert_eq!(report.count(|v| matches!(v, Verdict::Cold)), 0);
    }

    #[test]
    fn days_narrows_the_window_a_rule_is_judged_against() {
        let fx = Fixture::new();
        let log_path = fx.path().join("hook.jsonl");
        fs::write(
            &log_path,
            format!(
                "{}\n",
                serde_json::json!({
                    "ts_ms": NOW - 5 * DAY_MS,
                    "lk_decision": {"deciding": {
                        "source_file": "/x/99-live.toml",
                        "rule_command": "jq",
                        "rule_args": ".{, **}",
                    }},
                })
            ),
        )
        .unwrap();
        fx.log_config(&log_path);
        fx.write(
            "99-live.toml",
            "[[bash.rules]]\ncommand = \"jq\"\nargs = \".{, **}\"\ndecision = \"allow\"\n",
        );

        let all = run(&fx.opts()).unwrap();
        assert_eq!(verdict_of(&all, "jq", Some(".{, **}")), &Verdict::Live);

        // Narrowing past every entry leaves nothing to scan, which is indistinguishable from
        // having no log at all — so it degrades to "cannot tell", not to "everything is dead".
        let recent = run(&Options {
            days: Some(2),
            ..fx.opts()
        })
        .unwrap();
        assert_eq!(
            recent.count(|v| matches!(v, Verdict::Cold)),
            0,
            "an empty window must not condemn a rule"
        );
    }

    // --- witness derivation -----------------------------------------------------------

    #[test]
    fn witness_derivation_round_trips_a_tui_written_rule() {
        use crate::config::compile_pattern;
        use crate::scope::ladder;

        // tight rung: the pattern reverses to exactly the command it was built from.
        let (rungs, _) = ladder("bash", "Bash", "git", "push origin main", None, true);
        let tight = rungs[0].args.clone().unwrap();
        assert_eq!(witness_args(&tight).as_deref(), Some("push origin main"));

        // Glob metacharacters survive the escape/unescape round trip.
        let args = r"-i '/^[[:space:]]*reminders:/d' gitops/envs/{staging,qa}/tags.yaml";
        let (rungs, _) = ladder("bash", "Bash", "sed", args, None, true);
        assert_eq!(
            witness_args(rungs[0].args.as_deref().unwrap()).as_deref(),
            Some(args)
        );

        // flag-scoped rung: the operands were deliberately wildcarded, so they cannot come
        // back — but the witness must still be a call the rule matches.
        let (rungs, def) = ladder("bash", "Bash", "sed", "-i 's/a/b/' x.md", None, false);
        let flagged = rungs[def].args.clone().unwrap();
        assert_eq!(flagged, "-i **");
        let witness = witness_args(&flagged).unwrap();
        assert_eq!(witness, format!("-i {WITNESS_OPERAND}"));
        assert!(compile_pattern(&flagged).is_match(&witness));

        // A hand-written glob is not a TUI shape and yields nothing.
        assert_eq!(witness_args("push *"), None);
        assert_eq!(witness_args("/.*-i.*/"), None);
    }

    #[test]
    fn a_project_scoped_rule_is_resolved_from_inside_its_project() {
        let fx = Fixture::new();
        let project = fx.path().join("proj");
        // `.git` stops `find_project_config` walking above the fixture on any machine.
        fs::create_dir_all(project.join(".git")).unwrap();
        fx.write(
            "99-live.toml",
            &format!(
                "[[bash.rules]]\ncommand = \"jq\"\nargs = \".{{, **}}\"\nprojects = [{}]\ndecision = \"allow\"\n",
                toml::Value::String(project.display().to_string())
            ),
        );

        let report = run(&fx.opts()).unwrap();
        assert_eq!(
            verdict_of(&report, "jq", Some(".{, **}")),
            &Verdict::Live,
            "a projects-scoped rule resolved from nowhere would look unreachable"
        );
    }

    // --- block rewriting --------------------------------------------------------------

    #[test]
    fn rewriting_keeps_the_header_and_the_comments_on_kept_blocks() {
        let fx = Fixture::new();
        fx.write(
            "00-base.toml",
            "[[bash.rules]]\ncommand = \"sed\"\nargs = '/.*-i.*/'\ndecision = \"ask\"\n",
        );
        fx.write(
            "99-live.toml",
            "# Live ruleset — appended to by the approval TUI.\n\
             # Safe to hand-edit.\n\
             \n\
             # keep me: this note belongs to the jq rule\n\
             [[bash.rules]]\n\
             command = \"jq\"\n\
             args = \".{, **}\"\n\
             decision = \"allow\"\n\
             \n\
             # drop me: this note belongs to the sed rule\n\
             [[bash.rules]]\n\
             command = \"sed\"\n\
             args = \"-i x.md{, **}\"\n\
             decision = \"allow\"\n",
        );

        run(&Options {
            apply: true,
            ..fx.opts()
        })
        .unwrap();

        let after = fx.live();
        assert!(after.starts_with("# Live ruleset"), "{after}");
        assert!(after.contains("# Safe to hand-edit."));
        assert!(after.contains("# keep me"));
        assert!(after.contains("command = \"jq\""));
        assert!(!after.contains("# drop me"), "{after}");
        assert!(!after.contains("command = \"sed\""), "{after}");
    }

    // A `[[` at the start of a line inside a multi-line string is not a table header. The
    // real live file contains `python -c """…"""` blocks, so this is not hypothetical.
    #[test]
    fn a_bracket_inside_a_multiline_string_is_not_a_block_header() {
        let content = "[[bash.rules]]\ncommand = \"python\"\nargs = \"\"\"\n-c \"\n[[not a table]]\n\"\"\"\ndecision = \"allow\"\n\n[[bash.rules]]\ncommand = \"jq\"\ndecision = \"allow\"\n";
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(split_blocks(&lines).len(), 2);
    }

    // --- safety -----------------------------------------------------------------------

    // Removals interact: a call can reach several rules at once, so dropping one can change
    // the verdict of a call another, kept, rule was deciding. `pwsh -Command "…"` is the real
    // shape of that — the bash node and the inner powershell node are gated separately, and
    // the call only allows when both do.
    #[test]
    fn apply_aborts_when_a_removal_would_change_a_kept_rules_outcome() {
        let fx = Fixture::new();
        fx.log(&[("pwsh", Some("-Command \"Get-Date\"{, **}"))]);
        let live = "[[bash.rules]]\ncommand = \"pwsh\"\nargs = '-Command \"Get-Date\"{, **}'\ndecision = \"allow\"\n\n\
                    [[powershell.rules]]\ncommand = \"Get-Date\"\ndecision = \"allow\"\n";
        fx.write("99-live.toml", live);

        let report = run(&fx.opts()).unwrap();
        assert_eq!(
            verdict_of(&report, "pwsh", Some("-Command \"Get-Date\"{, **}")),
            &Verdict::Live
        );
        assert_eq!(verdict_of(&report, "Get-Date", None), &Verdict::Cold);

        let err = run(&Options {
            apply: true,
            cold: true,
            ..fx.opts()
        })
        .unwrap_err();
        assert!(err.contains("aborted, nothing written"), "{err}");
        assert!(err.contains("pwsh"), "{err}");
        assert_eq!(fx.live(), live, "the file must be untouched");
        assert!(
            fs::read_dir(fx.path())
                .unwrap()
                .filter_map(|e| e.ok())
                .all(|e| !e.file_name().to_string_lossy().contains(".bak-")),
            "no backup should have been written"
        );
    }

    #[test]
    fn apply_backs_up_before_writing_and_touches_only_the_live_file() {
        let fx = Fixture::new();
        let base = "[[bash.rules]]\ncommand = \"sed\"\nargs = '/.*-i.*/'\ndecision = \"ask\"\n";
        fx.write("00-base.toml", base);
        fx.write(
            "99-live.toml",
            "[[bash.rules]]\ncommand = \"sed\"\nargs = \"-i x.md{, **}\"\ndecision = \"allow\"\n\n\
             [[bash.rules]]\ncommand = \"jq\"\nargs = \".{, **}\"\ndecision = \"allow\"\n",
        );

        let report = run(&Options {
            apply: true,
            ..fx.opts()
        })
        .unwrap();

        let backup = report.backup.clone().expect("a backup path");
        assert_eq!(
            basename(&backup),
            format!("99-live.toml.bak-{}", utc_stamp(NOW))
        );
        assert!(fs::read_to_string(&backup)
            .unwrap()
            .contains("command = \"sed\""));
        assert!(!fx.live().contains("command = \"sed\""));
        assert!(fx.live().contains("command = \"jq\""));
        assert_eq!(
            fs::read_to_string(fx.path().join("00-base.toml")).unwrap(),
            base,
            "only the live file is ever rewritten"
        );
        assert!(render(&report).contains("backup: "));
    }

    #[test]
    fn nothing_to_prune_is_a_noop_that_says_so() {
        let fx = Fixture::new();
        let live =
            "# header\n\n[[bash.rules]]\ncommand = \"jq\"\nargs = \".{, **}\"\ndecision = \"allow\"\n";
        fx.write("99-live.toml", live);

        let report = run(&Options {
            apply: true,
            ..fx.opts()
        })
        .unwrap();
        assert_eq!(report.removed(), 0);
        assert!(report.backup.is_none());
        assert!(render(&report).contains("nothing to prune"));
        assert_eq!(fx.live(), live);
    }

    #[test]
    fn a_live_file_outside_the_config_dir_is_refused() {
        let fx = Fixture::new();
        let other = tempfile::tempdir().unwrap();
        let stray = other.path().join("99-live.toml");
        fs::write(&stray, "").unwrap();

        let err = run(&Options {
            file: Some(stray.display().to_string()),
            ..fx.opts()
        })
        .unwrap_err();
        assert!(err.contains("is not in the config dir"), "{err}");
    }

    fn describe(v: &Verdict) -> String {
        match v {
            Verdict::Live => "live".into(),
            Verdict::Cold => "cold".into(),
            Verdict::Shadowed { file, rule, .. } => format!("shadowed by {file} {rule}"),
            Verdict::Subsumed { rule, .. } => format!("subsumed by {rule}"),
            Verdict::Unanalysable { why } => format!("unanalysable: {why}"),
        }
    }
}
