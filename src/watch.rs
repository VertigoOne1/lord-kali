// `lord-kali watch` tails the JSONL log and prints a colored line per gate decision,
// correlating each pre_tool_use with its post_tool_use so you can see in real time what
// ran, what is awaiting approval, and which command nodes matched no rule.

use crate::config::{expand_tilde, load_config};
use crate::log::{now_ms, DEFAULT_LOG_PATH};
use std::collections::HashMap;
use std::io::{IsTerminal, Read};
use std::path::PathBuf;

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

// A buffered tail of an append-only file: each read_new() returns the lines appended
// since the previous call. Shared by the plain `--tail` view and the TUI stream.
struct Tailer {
    path: PathBuf,
    offset: u64,
    carry: String,
}

impl Tailer {
    fn new(path: PathBuf) -> Self {
        let offset = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        Tailer {
            path,
            offset,
            carry: String::new(),
        }
    }

    fn read_new(&mut self) -> Vec<String> {
        use std::io::{Seek, SeekFrom};
        let mut lines = Vec::new();
        let len = std::fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0);
        if len < self.offset {
            self.offset = 0;
            self.carry.clear();
        }
        if len > self.offset {
            if let Ok(mut f) = std::fs::File::open(&self.path) {
                if f.seek(SeekFrom::Start(self.offset)).is_ok() {
                    let mut buf = String::new();
                    if let Ok(n) = f.read_to_string(&mut buf) {
                        self.offset += n as u64;
                        self.carry.push_str(&buf);
                        while let Some(idx) = self.carry.find('\n') {
                            let line: String = self.carry.drain(..=idx).collect();
                            let trimmed = line.trim_end();
                            if !trimmed.is_empty() {
                                lines.push(trimmed.to_string());
                            }
                        }
                    }
                }
            }
        }
        lines
    }
}

// `lord-kali watch` opens the interactive approval TUI. `lord-kali watch --tail` keeps
// the original line-by-line tail (logging only, no approval interaction).
pub(crate) fn watch(args: &[String]) {
    let tail_only = args.iter().any(|a| a == "--tail");
    let path = args
        .iter()
        .find(|a| !a.starts_with("--"))
        .map(|s| s.as_str());
    if tail_only {
        watch_tail(path);
    } else if let Err(e) = tui::run(path) {
        eprintln!("lord-kali watch: {e}");
    }
}

fn watch_tail(explicit_path: Option<&str>) {
    let path = resolve_log_path(explicit_path);
    let palette = Palette {
        color: std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none(),
    };

    eprintln!("lord-kali watch --tail — tailing {}", path.display());
    eprintln!(
        "PASS/ASK go to approval; an indented line shows whether they ran. Ctrl-C to stop.\n"
    );

    let mut tailer = Tailer::new(path);
    let mut pending: HashMap<String, PendingPre> = HashMap::new();

    loop {
        for line in tailer.read_new() {
            handle_line(&palette, &line, &mut pending);
        }
        sweep_pending(&palette, &mut pending);
        std::thread::sleep(std::time::Duration::from_millis(WATCH_POLL_MS));
    }
}

// The interactive approval TUI: a scrolling decision stream on top, and a pending-approval
// pane below where the operator rules on the actionable command nodes of each blocked call.
mod tui {
    use super::{event_target, resolve_log_path, unmatched_nodes, Tailer};
    use crate::config::{load_config, ApprovalConfig};
    use crate::live_rules::{append_rules, live_rules_path, LiveRule};
    use crate::log::now_ms;
    use crate::queue::{
        self, write_atomic, write_heartbeat_in, Action, QueueRequest, Verdict, VerdictNode,
    };
    use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
    use ratatui::layout::{Constraint, Layout, Rect};
    use ratatui::style::{Color, Modifier, Style};
    use ratatui::text::{Line, Span};
    use ratatui::widgets::{Block, Paragraph, Wrap};
    use ratatui::{DefaultTerminal, Frame};
    use std::collections::HashMap;
    use std::path::Path;
    use std::time::Duration;

    const POLL_MS: u64 = 200;
    const STREAM_CAP: usize = 1000;
    // A request from a crashed hook (no self-cleanup) is swept after this age.
    const REQ_MAX_AGE_MS: u64 = 120_000;

    // Which lane a node sits in. A commit resolves the whole call: allow the ALLOW lane,
    // deny the DENY lane, and hand ASK nodes back to Claude Code's own prompt (a passthrough,
    // which makes the call defer to the terminal). Default is Allow.
    #[derive(Clone, Copy, PartialEq, Debug)]
    enum Choice {
        Allow,
        Ask,
        Deny,
    }

    impl Choice {
        // space cycles allow -> ask -> deny -> allow.
        fn cycle(self) -> Choice {
            match self {
                Choice::Allow => Choice::Ask,
                Choice::Ask => Choice::Deny,
                Choice::Deny => Choice::Allow,
            }
        }

        // ←/→ step one lane toward allow / deny (clamped at the ends).
        fn left(self) -> Choice {
            match self {
                Choice::Deny => Choice::Ask,
                _ => Choice::Allow,
            }
        }

        fn right(self) -> Choice {
            match self {
                Choice::Allow => Choice::Ask,
                _ => Choice::Deny,
            }
        }
    }

    struct Pending {
        request: QueueRequest,
        choices: Vec<Choice>,
        // Per node: whether an *-always rule persists tight (full-args, path-specific)
        // rather than subcommand-scoped. Defaults true for guardrail commands.
        tight: Vec<bool>,
        cursor: usize,
    }

    impl Pending {
        fn new(request: QueueRequest, approval: &ApprovalConfig) -> Self {
            let choices = vec![Choice::Allow; request.nodes.len()];
            let tight = request
                .nodes
                .iter()
                .map(|n| approval.is_guardrail(&n.command))
                .collect();
            Pending {
                request,
                choices,
                tight,
                cursor: 0,
            }
        }
    }

    // A commit applies its mode (once = this call only; always = also persist a rule) to
    // every node, using each node's column for the allow/deny direction.
    #[derive(Clone, Copy)]
    enum CommitMode {
        Once,
        Always,
    }

    enum Key {
        Quit,
        Cycle,
        Left,
        Right,
        Up,
        Down,
        PrevReq,
        NextReq,
        ToggleScope,
        Commit(CommitMode),
        SkipCall,
        Ignore,
    }

    fn map_key(code: KeyCode) -> Key {
        match code {
            KeyCode::Char('q') | KeyCode::Esc => Key::Quit,
            KeyCode::Char(' ') => Key::Cycle,
            KeyCode::Left | KeyCode::Char('h') => Key::Left,
            KeyCode::Right | KeyCode::Char('l') => Key::Right,
            KeyCode::Up | KeyCode::Char('k') => Key::Up,
            KeyCode::Down | KeyCode::Char('j') => Key::Down,
            KeyCode::Tab => Key::NextReq,
            KeyCode::BackTab => Key::PrevReq,
            KeyCode::Char('t') => Key::ToggleScope,
            KeyCode::Char('a') => Key::Commit(CommitMode::Always),
            KeyCode::Char('o') => Key::Commit(CommitMode::Once),
            KeyCode::Char('s') => Key::SkipCall,
            _ => Key::Ignore,
        }
    }

    struct App {
        stream: Vec<Line<'static>>,
        pending: Vec<Pending>,
        focus: usize,
        should_quit: bool,
        // Armed by a first Ctrl-C; a second one quits (consistent with Claude Code). Any
        // other key disarms it.
        ctrl_c_armed: bool,
    }

    impl App {
        fn new() -> Self {
            App {
                stream: Vec::new(),
                pending: Vec::new(),
                focus: 0,
                should_quit: false,
                ctrl_c_armed: false,
            }
        }

        fn focused(&self) -> Option<&Pending> {
            self.pending.get(self.focus)
        }

        fn focused_mut(&mut self) -> Option<&mut Pending> {
            self.pending.get_mut(self.focus)
        }
    }

    // Scope a persisted rule to the node's subcommand: the first argument token plus any
    // trailing args (e.g. "push" -> "push{, **}"). None when the node had no args, which
    // persists command-wide. This is why allowing `git push` does not bless `git commit`.
    fn scope_args(args: &str) -> Option<String> {
        let first = args.split_whitespace().next()?;
        Some(format!("{first}{{, **}}"))
    }

    // Tight (path-specific) scope: pin the whole args string, tolerating extra trailing
    // args. So `rm -rf ./test-results` persists as `-rf ./test-results{, **}` — it can
    // never match `rm -rf /`. None (command-wide) only when there were no args at all.
    fn tight_args(args: &str) -> Option<String> {
        if args.is_empty() {
            None
        } else {
            Some(format!("{args}{{, **}}"))
        }
    }

    // The args pattern an *-always rule would persist for a node, honoring its tight flag.
    fn node_scope(tight: bool, shell: &str, args: &str) -> Option<String> {
        if shell == "web-fetch" {
            None
        } else if tight {
            tight_args(args)
        } else {
            scope_args(args)
        }
    }

    // Each node resolves by its lane: Allow -> allow, Deny -> deny, Ask -> passthrough
    // (deferred to Claude Code's prompt). The mode picks once vs always; *_always actions
    // persist a subcommand-scoped rule (web-fetch persists the exact URL). Ask never persists.
    fn build_verdict(p: &Pending, mode: CommitMode) -> (Verdict, Vec<LiveRule>) {
        let mut nodes = Vec::new();
        let mut live = Vec::new();
        for (i, node) in p.request.nodes.iter().enumerate() {
            let choice = p.choices[i];
            let action = match (choice, mode) {
                (Choice::Allow, CommitMode::Once) => Action::AllowOnce,
                (Choice::Allow, CommitMode::Always) => Action::AllowAlways,
                (Choice::Deny, CommitMode::Once) => Action::DenyOnce,
                (Choice::Deny, CommitMode::Always) => Action::DenyAlways,
                (Choice::Ask, _) => Action::Passthrough,
            };
            if matches!(mode, CommitMode::Always) && choice != Choice::Ask {
                live.push(LiveRule {
                    shell: node.shell.clone(),
                    target: node.command.clone(),
                    args: node_scope(p.tight[i], &node.shell, &node.args),
                    allow: choice == Choice::Allow,
                });
            }
            nodes.push(VerdictNode {
                command: node.command.clone(),
                args: node.args.clone(),
                action,
            });
        }
        (
            Verdict {
                id: p.request.id.clone(),
                nodes,
            },
            live,
        )
    }

    // Skip the whole call: every node passthrough, nothing persisted — defers the entire
    // call to Claude Code's own prompt, ignoring the lane settings.
    fn build_skip(p: &Pending) -> Verdict {
        Verdict {
            id: p.request.id.clone(),
            nodes: p
                .request
                .nodes
                .iter()
                .map(|n| VerdictNode {
                    command: n.command.clone(),
                    args: n.args.clone(),
                    action: Action::Passthrough,
                })
                .collect(),
        }
    }

    fn apply_key(app: &mut App, key: Key) -> Option<(Verdict, Vec<LiveRule>)> {
        match key {
            Key::Quit => {
                app.should_quit = true;
                None
            }
            Key::Up => {
                if let Some(p) = app.focused_mut() {
                    p.cursor = p.cursor.saturating_sub(1);
                }
                None
            }
            Key::Down => {
                if let Some(p) = app.focused_mut() {
                    if p.cursor + 1 < p.request.nodes.len() {
                        p.cursor += 1;
                    }
                }
                None
            }
            Key::Cycle => {
                if let Some(p) = app.focused_mut() {
                    if let Some(c) = p.choices.get_mut(p.cursor) {
                        *c = c.cycle();
                    }
                }
                None
            }
            Key::Left => {
                if let Some(p) = app.focused_mut() {
                    if let Some(c) = p.choices.get_mut(p.cursor) {
                        *c = c.left();
                    }
                }
                None
            }
            Key::Right => {
                if let Some(p) = app.focused_mut() {
                    if let Some(c) = p.choices.get_mut(p.cursor) {
                        *c = c.right();
                    }
                }
                None
            }
            Key::PrevReq => {
                app.focus = app.focus.saturating_sub(1);
                None
            }
            Key::NextReq => {
                if app.focus + 1 < app.pending.len() {
                    app.focus += 1;
                }
                None
            }
            Key::ToggleScope => {
                if let Some(p) = app.focused_mut() {
                    if let Some(t) = p.tight.get_mut(p.cursor) {
                        *t = !*t;
                    }
                }
                None
            }
            Key::Commit(mode) => app.focused().map(|p| build_verdict(p, mode)),
            Key::SkipCall => app.focused().map(|p| (build_skip(p), Vec::new())),
            Key::Ignore => None,
        }
    }

    // Surface "waiting for you" on the terminal tab itself (like Claude Code): the window
    // title carries the waiting count, and on Windows Terminal the tab/taskbar icon turns
    // amber (OSC 9;4 state 4) while approvals are pending. Terminals that don't understand
    // a given sequence ignore it.
    fn attention_title(count: usize) -> String {
        if count > 0 {
            format!("● lord-kali — {count} waiting")
        } else {
            "lord-kali — watching".to_string()
        }
    }

    fn set_attention(count: usize) {
        use std::io::Write;
        let mut out = std::io::stdout();
        let _ = write!(out, "\x1b]0;{}\x07", attention_title(count));
        let state = if count > 0 {
            "\x1b]9;4;4;0\x07"
        } else {
            "\x1b]9;4;0;0\x07"
        };
        let _ = write!(out, "{state}");
        let _ = out.flush();
    }

    fn ring_bell() {
        use std::io::Write;
        let mut out = std::io::stdout();
        let _ = write!(out, "\x07");
        let _ = out.flush();
    }

    fn clear_attention() {
        use std::io::Write;
        let mut out = std::io::stdout();
        let _ = write!(out, "\x1b]0;\x07\x1b]9;4;0;0\x07");
        let _ = out.flush();
    }

    pub(crate) fn run(explicit_path: Option<&str>) -> std::io::Result<()> {
        let cfg = load_config(None);
        let state_dir = queue::state_dir(&cfg.approval);
        let qdir = queue::queue_dir_in(&state_dir);
        let live_path = live_rules_path(&cfg.approval);
        let mut tailer = Tailer::new(resolve_log_path(explicit_path));

        let mut terminal = ratatui::init();
        let mut app = App::new();
        let result = run_loop(
            &mut terminal,
            &mut app,
            &mut tailer,
            &state_dir,
            &qdir,
            &live_path,
            &cfg.approval,
        );
        ratatui::restore();
        clear_attention();
        result
    }

    #[allow(clippy::too_many_arguments)]
    fn run_loop(
        terminal: &mut DefaultTerminal,
        app: &mut App,
        tailer: &mut Tailer,
        state_dir: &Path,
        qdir: &Path,
        live_path: &Path,
        approval: &ApprovalConfig,
    ) -> std::io::Result<()> {
        // usize::MAX forces the first iteration to set the title/taskbar without ringing
        // the bell for approvals that were already waiting when the TUI opened.
        let mut prev_pending = usize::MAX;
        loop {
            let _ = write_heartbeat_in(state_dir);

            for line in tailer.read_new() {
                if let Some(l) = stream_line(&line) {
                    app.stream.push(l);
                    if app.stream.len() > STREAM_CAP {
                        let drop = app.stream.len() - STREAM_CAP;
                        app.stream.drain(0..drop);
                    }
                }
            }

            sync_pending(app, qdir, approval);
            let count = app.pending.len();
            if count != prev_pending {
                set_attention(count);
                // Ring once when a new approval arrives (count rose), not on every change.
                if count > prev_pending {
                    ring_bell();
                }
                prev_pending = count;
            }
            terminal.draw(|f| ui(f, app))?;

            if event::poll(Duration::from_millis(POLL_MS))? {
                if let Event::Key(k) = event::read()? {
                    if k.kind != KeyEventKind::Press {
                        continue;
                    }
                    // Ctrl-C-C quits (consistent with Claude Code); first arms, second fires.
                    if k.code == KeyCode::Char('c') && k.modifiers.contains(KeyModifiers::CONTROL) {
                        if app.ctrl_c_armed {
                            return Ok(());
                        }
                        app.ctrl_c_armed = true;
                        continue;
                    }
                    app.ctrl_c_armed = false;
                    if let Some((verdict, live)) = apply_key(app, map_key(k.code)) {
                        let vpath = qdir.join(format!("{}.verdict.json", verdict.id));
                        if let Ok(j) = serde_json::to_string(&verdict) {
                            let _ = write_atomic(&vpath, &j);
                        }
                        let _ = append_rules(live_path, &live);
                        if app.focus < app.pending.len() {
                            app.pending.remove(app.focus);
                        }
                        if app.focus >= app.pending.len() {
                            app.focus = app.pending.len().saturating_sub(1);
                        }
                    }
                    if app.should_quit {
                        return Ok(());
                    }
                }
            }
        }
    }

    // Reconcile the in-memory pending list with the request files on disk, preserving each
    // item's selection/cursor by id and sweeping requests from hooks that died mid-wait.
    fn sync_pending(app: &mut App, qdir: &Path, approval: &ApprovalConfig) {
        let mut found: Vec<QueueRequest> = Vec::new();
        if let Ok(entries) = std::fs::read_dir(qdir) {
            for e in entries.flatten() {
                let path = e.path();
                let is_req = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.ends_with(".req.json"));
                if !is_req {
                    continue;
                }
                if let Ok(s) = std::fs::read_to_string(&path) {
                    if let Ok(req) = serde_json::from_str::<QueueRequest>(&s) {
                        if now_ms().saturating_sub(req.ts_ms) > REQ_MAX_AGE_MS {
                            let _ = std::fs::remove_file(&path);
                            continue;
                        }
                        found.push(req);
                    }
                }
            }
        }
        found.sort_by_key(|r| r.ts_ms);

        let mut prev: HashMap<String, (Vec<Choice>, Vec<bool>, usize)> = HashMap::new();
        for p in app.pending.drain(..) {
            prev.insert(p.request.id.clone(), (p.choices, p.tight, p.cursor));
        }
        app.pending = found
            .into_iter()
            .map(|req| match prev.remove(&req.id) {
                Some((choices, tight, cur)) if choices.len() == req.nodes.len() => Pending {
                    cursor: cur.min(req.nodes.len().saturating_sub(1)),
                    choices,
                    tight,
                    request: req,
                },
                _ => Pending::new(req, approval),
            })
            .collect();
        if app.focus >= app.pending.len() {
            app.focus = app.pending.len().saturating_sub(1);
        }
    }

    // Three stacked regions: the stream on top, the approval zone (>= half the screen
    // while there is work), and a help line locked to its own row at the very bottom so a
    // long node list can never push it off-screen.
    fn ui(f: &mut Frame, app: &App) {
        let body = if app.pending.is_empty() {
            Constraint::Length(3)
        } else {
            Constraint::Percentage(55)
        };
        let [top, mid, help] =
            Layout::vertical([Constraint::Min(3), body, Constraint::Length(1)]).areas(f.area());
        render_stream(f, top, app);
        render_body(f, mid, app);
        render_help(f, help, app);
    }

    fn render_stream(f: &mut Frame, area: Rect, app: &App) {
        let visible = area.height.saturating_sub(2) as usize;
        let start = app.stream.len().saturating_sub(visible);
        let lines: Vec<Line> = app.stream[start..].to_vec();
        let para = Paragraph::new(lines)
            .block(Block::bordered().title("lord-kali — stream"))
            .wrap(Wrap { trim: false });
        f.render_widget(para, area);
    }

    fn render_body(f: &mut Frame, area: Rect, app: &App) {
        let Some(p) = app.focused() else {
            let para = Paragraph::new(
                "No pending approvals. ask/pass-through calls appear here while this TUI runs.",
            )
            .block(Block::bordered().title("pending approvals (0)"));
            f.render_widget(para, area);
            return;
        };

        let [header, cols] =
            Layout::vertical([Constraint::Length(3), Constraint::Min(1)]).areas(area);

        let mut head = vec![Line::from(vec![
            Span::styled(
                format!("{}: ", p.request.tool),
                Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            ),
            Span::raw(p.request.target.clone()),
            Span::styled(
                format!("   [call {}/{}]", app.focus + 1, app.pending.len()),
                Style::new().fg(Color::DarkGray),
            ),
        ])];
        head.push(Line::from(Span::styled(
            p.request
                .cwd
                .as_deref()
                .map(|c| format!("cwd {c}"))
                .unwrap_or_default(),
            Style::new().fg(Color::DarkGray),
        )));
        // What an *-always commit would persist for the focused node, so the operator sees
        // the exact (path-specific or subcommand-scoped) rule before pressing a/d.
        if let Some(fnode) = p.request.nodes.get(p.cursor) {
            let tight = p.tight[p.cursor];
            let pat = node_scope(tight, &fnode.shell, &fnode.args)
                .map(|a| format!("args=\"{a}\""))
                .unwrap_or_else(|| "any args".into());
            let mode = if tight { "tight" } else { "scope" };
            head.push(Line::from(Span::styled(
                format!(
                    "→ rule: {} {}   ·  t: {} (toggle)",
                    fnode.command, pat, mode
                ),
                Style::new().fg(if tight { Color::Green } else { Color::Yellow }),
            )));
        }
        f.render_widget(Paragraph::new(head), header);

        let [allow_area, ask_area, deny_area] = Layout::horizontal([
            Constraint::Percentage(34),
            Constraint::Percentage(33),
            Constraint::Percentage(33),
        ])
        .areas(cols);

        let mut lanes: [Vec<Line>; 3] = [Vec::new(), Vec::new(), Vec::new()];
        for (i, node) in p.request.nodes.iter().enumerate() {
            let mut style = Style::new();
            if i == p.cursor {
                style = style.add_modifier(Modifier::REVERSED);
            }
            let line = Line::from(Span::styled(
                format!("{} {}", node.command, node.args),
                style,
            ));
            let lane = match p.choices[i] {
                Choice::Allow => 0,
                Choice::Ask => 1,
                Choice::Deny => 2,
            };
            lanes[lane].push(line);
        }
        let [allow_lines, ask_lines, deny_lines] = lanes;

        let lane = |lines: Vec<Line<'static>>, title: String, color: Color| {
            Paragraph::new(lines)
                .block(
                    Block::bordered()
                        .title(title)
                        .border_style(Style::new().fg(color)),
                )
                .wrap(Wrap { trim: false })
        };
        let (na, nk, nd) = (allow_lines.len(), ask_lines.len(), deny_lines.len());
        f.render_widget(
            lane(allow_lines, format!("ALLOW ({na})"), Color::Green),
            allow_area,
        );
        f.render_widget(
            lane(ask_lines, format!("ASK ({nk})"), Color::Yellow),
            ask_area,
        );
        f.render_widget(
            lane(deny_lines, format!("DENY ({nd})"), Color::Red),
            deny_area,
        );
    }

    fn render_help(f: &mut Frame, area: Rect, app: &App) {
        if app.ctrl_c_armed {
            f.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    "press Ctrl-C again to quit",
                    Style::new().fg(Color::Yellow),
                ))),
                area,
            );
            return;
        }
        let text = if app.pending.is_empty() {
            "q quit · waiting for approvals…"
        } else {
            "space cycle · ←→ lane · ↑↓ node · t scope · ⇥ call · a apply-always · o apply-once · s skip · q quit"
        };
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(
                text,
                Style::new().fg(Color::DarkGray),
            ))),
            area,
        );
    }

    fn stream_line(line: &str) -> Option<Line<'static>> {
        let v: serde_json::Value = serde_json::from_str(line).ok()?;
        if v["lk_event"].as_str()? != "pre_tool_use" {
            return None;
        }
        let tool = v["tool_name"].as_str().unwrap_or("?").to_string();
        let target = event_target(&v);
        let final_ = v["lk_decision"]["final"].as_str().unwrap_or("?");
        let (label, color) = match final_ {
            "allow" => ("ALLOW".to_string(), Color::Green),
            "deny" => ("DENY".to_string(), Color::Red),
            "ask" => ("ASK".to_string(), Color::Yellow),
            "passthrough" => ("PASS".to_string(), Color::Cyan),
            other => (other.to_string(), Color::Gray),
        };
        let mut spans = vec![
            Span::styled(format!("{label:<5}"), Style::new().fg(color)),
            Span::raw(format!("  {tool}: {target}")),
        ];
        if matches!(final_, "deny" | "ask") {
            if let Some(r) = v["lk_decision"]["reason"].as_str() {
                spans.push(Span::styled(
                    format!("  — {r}"),
                    Style::new().fg(Color::DarkGray),
                ));
            }
        }
        let gaps = unmatched_nodes(&v["lk_decision"]);
        if !gaps.is_empty() {
            spans.push(Span::styled(
                format!("  (no rule: {})", gaps.join(", ")),
                Style::new().fg(Color::Cyan),
            ));
        }
        Some(Line::from(spans))
    }

    #[cfg(test)]
    mod tui_tests {
        use super::*;
        use crate::decision::Decision;
        use crate::queue::{combine_verdict, QueueNode};

        fn req() -> QueueRequest {
            QueueRequest {
                id: "id1".into(),
                ts_ms: 0,
                cwd: None,
                tool: "Bash".into(),
                target: "gh pr list | jq .".into(),
                nodes: vec![
                    QueueNode {
                        shell: "bash".into(),
                        command: "gh".into(),
                        args: "pr list".into(),
                        decision: "passthrough".into(),
                    },
                    QueueNode {
                        shell: "bash".into(),
                        command: "jq".into(),
                        args: ".".into(),
                        decision: "passthrough".into(),
                    },
                ],
            }
        }

        fn pending_app() -> App {
            let mut app = App::new();
            app.pending
                .push(Pending::new(req(), &ApprovalConfig::default()));
            app
        }

        fn rm_request() -> QueueRequest {
            QueueRequest {
                id: "rm1".into(),
                ts_ms: 0,
                cwd: None,
                tool: "Bash".into(),
                target: "rm -rf ./test-results".into(),
                nodes: vec![QueueNode {
                    shell: "bash".into(),
                    command: "rm".into(),
                    args: "-rf ./test-results".into(),
                    decision: "passthrough".into(),
                }],
            }
        }

        // A guardrail command (rm) defaults to tight, path-specific persistence; `t` toggles
        // it to the broad subcommand scope only when the operator deliberately asks.
        #[test]
        fn guardrail_defaults_tight_and_t_toggles() {
            let mut app = App::new();
            app.pending
                .push(Pending::new(rm_request(), &ApprovalConfig::default()));
            assert!(app.focused().unwrap().tight[0], "rm should default tight");

            let (_, live) = apply_key(&mut app, Key::Commit(CommitMode::Always)).expect("commit");
            assert_eq!(live[0].args.as_deref(), Some("-rf ./test-results{, **}"));

            apply_key(&mut app, Key::ToggleScope);
            assert!(!app.focused().unwrap().tight[0]);
            let (_, live2) = apply_key(&mut app, Key::Commit(CommitMode::Always)).expect("commit");
            assert_eq!(live2[0].args, scope_args("-rf ./test-results"));
        }

        // A non-guardrail command defaults to subcommand scope (not tight).
        #[test]
        fn non_guardrail_defaults_to_subcommand_scope() {
            let app = pending_app();
            assert!(!app.focused().unwrap().tight[0], "gh should not be tight");
        }

        #[test]
        fn arrows_step_allow_ask_deny() {
            let mut app = pending_app();
            apply_key(&mut app, Key::Right);
            assert_eq!(app.focused().unwrap().choices[0], Choice::Ask);
            apply_key(&mut app, Key::Right);
            assert_eq!(app.focused().unwrap().choices[0], Choice::Deny);
            apply_key(&mut app, Key::Right); // clamped at Deny
            assert_eq!(app.focused().unwrap().choices[0], Choice::Deny);
            apply_key(&mut app, Key::Left);
            assert_eq!(app.focused().unwrap().choices[0], Choice::Ask);
        }

        // gh -> Deny (two steps), jq stays Allow, commit-always: call denies and both
        // lanes persist subcommand-scoped rules.
        #[test]
        fn deny_lane_commit_always_resolves_and_persists() {
            let mut app = pending_app();
            apply_key(&mut app, Key::Right);
            apply_key(&mut app, Key::Right);
            let (verdict, live) =
                apply_key(&mut app, Key::Commit(CommitMode::Always)).expect("commit");
            assert_eq!(verdict.nodes[0].action, Action::DenyAlways);
            assert_eq!(verdict.nodes[1].action, Action::AllowAlways);
            assert_eq!(
                combine_verdict(&verdict.nodes).map(|(d, _)| d),
                Some(Decision::Deny)
            );
            assert_eq!(live.len(), 2);
            let gh = live.iter().find(|r| r.target == "gh").unwrap();
            assert!(!gh.allow);
            assert_eq!(gh.args, scope_args("pr list"));
            assert!(live.iter().find(|r| r.target == "jq").unwrap().allow);
        }

        // An ASK node passes through (defers the whole call) and persists nothing for itself.
        #[test]
        fn ask_lane_defers_call() {
            let mut app = pending_app();
            apply_key(&mut app, Key::Right); // gh -> Ask
            let (verdict, live) =
                apply_key(&mut app, Key::Commit(CommitMode::Always)).expect("commit");
            assert_eq!(verdict.nodes[0].action, Action::Passthrough);
            assert_eq!(verdict.nodes[1].action, Action::AllowAlways);
            assert_eq!(combine_verdict(&verdict.nodes), None);
            assert_eq!(live.len(), 1);
            assert_eq!(live[0].target, "jq");
        }

        #[test]
        fn attention_title_reflects_waiting_count() {
            assert_eq!(attention_title(0), "lord-kali — watching");
            let t = attention_title(3);
            assert!(t.contains("3 waiting"), "got {t}");
            assert!(t.starts_with('●'), "got {t}");
        }

        #[test]
        fn all_allow_once_allows_call_without_persisting() {
            let mut app = pending_app();
            let (verdict, live) =
                apply_key(&mut app, Key::Commit(CommitMode::Once)).expect("commit");
            assert!(live.is_empty());
            assert_eq!(
                combine_verdict(&verdict.nodes).map(|(d, _)| d),
                Some(Decision::Allow)
            );
        }

        // Global skip overrides the lanes: every node passthrough, nothing persisted.
        #[test]
        fn skip_call_passes_everything_through() {
            let mut app = pending_app();
            apply_key(&mut app, Key::Right);
            apply_key(&mut app, Key::Right); // gh -> Deny, would otherwise deny
            let (verdict, live) = apply_key(&mut app, Key::SkipCall).expect("skip");
            assert!(verdict
                .nodes
                .iter()
                .all(|n| n.action == Action::Passthrough));
            assert!(live.is_empty());
            assert_eq!(combine_verdict(&verdict.nodes), None);
        }

        #[test]
        fn renders_without_panic() {
            use ratatui::backend::TestBackend;
            use ratatui::Terminal;
            let mut app = pending_app();
            apply_key(&mut app, Key::Right); // exercise the ASK lane + cursor highlight
            app.stream.push(Line::raw("ALLOW  Bash: ls"));
            let mut terminal = Terminal::new(TestBackend::new(120, 40)).unwrap();
            terminal.draw(|f| ui(f, &app)).unwrap();
            // also exercise the idle (no-pending) layout
            let idle = App::new();
            terminal.draw(|f| ui(f, &idle)).unwrap();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
