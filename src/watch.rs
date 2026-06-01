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
    use crate::config::load_config;
    use crate::live_rules::{append_rules, live_rules_path, LiveRule};
    use crate::log::now_ms;
    use crate::queue::{
        self, write_atomic, write_heartbeat_in, Action, QueueRequest, Verdict, VerdictNode,
    };
    use crossterm::event::{self, Event, KeyCode, KeyEventKind};
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

    struct Pending {
        request: QueueRequest,
        selected: Vec<bool>,
        cursor: usize,
    }

    impl Pending {
        fn new(request: QueueRequest) -> Self {
            let selected = vec![true; request.nodes.len()];
            Pending {
                request,
                selected,
                cursor: 0,
            }
        }
    }

    #[derive(Clone, Copy)]
    enum Commit {
        AllowOnce,
        AllowAlways,
        DenyOnce,
        DenyAlways,
    }

    enum Key {
        Quit,
        Toggle,
        Up,
        Down,
        Prev,
        Next,
        Commit(Commit),
        Ignore,
    }

    fn map_key(code: KeyCode) -> Key {
        match code {
            KeyCode::Char('q') | KeyCode::Esc => Key::Quit,
            KeyCode::Char(' ') => Key::Toggle,
            KeyCode::Up | KeyCode::Char('k') => Key::Up,
            KeyCode::Down | KeyCode::Char('j') => Key::Down,
            KeyCode::Left => Key::Prev,
            KeyCode::Right => Key::Next,
            KeyCode::Char('a') => Key::Commit(Commit::AllowAlways),
            KeyCode::Char('o') => Key::Commit(Commit::AllowOnce),
            KeyCode::Char('d') => Key::Commit(Commit::DenyAlways),
            KeyCode::Char('x') => Key::Commit(Commit::DenyOnce),
            _ => Key::Ignore,
        }
    }

    struct App {
        stream: Vec<Line<'static>>,
        pending: Vec<Pending>,
        focus: usize,
        should_quit: bool,
    }

    impl App {
        fn new() -> Self {
            App {
                stream: Vec::new(),
                pending: Vec::new(),
                focus: 0,
                should_quit: false,
            }
        }

        fn focused(&self) -> Option<&Pending> {
            self.pending.get(self.focus)
        }

        fn focused_mut(&mut self) -> Option<&mut Pending> {
            self.pending.get_mut(self.focus)
        }
    }

    // Selected nodes take the chosen action; unselected nodes are left as passthrough so
    // the hook combine defers them to Claude Code. Only *_always actions persist a rule.
    fn build_verdict(p: &Pending, kind: Commit) -> (Verdict, Vec<LiveRule>) {
        let mut nodes = Vec::new();
        let mut live = Vec::new();
        for (i, node) in p.request.nodes.iter().enumerate() {
            let action = if p.selected[i] {
                match kind {
                    Commit::AllowOnce => Action::AllowOnce,
                    Commit::AllowAlways => Action::AllowAlways,
                    Commit::DenyOnce => Action::DenyOnce,
                    Commit::DenyAlways => Action::DenyAlways,
                }
            } else {
                Action::Passthrough
            };
            match action {
                Action::AllowAlways => live.push(LiveRule {
                    shell: node.shell.clone(),
                    target: node.command.clone(),
                    allow: true,
                }),
                Action::DenyAlways => live.push(LiveRule {
                    shell: node.shell.clone(),
                    target: node.command.clone(),
                    allow: false,
                }),
                _ => {}
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
            Key::Toggle => {
                if let Some(p) = app.focused_mut() {
                    if let Some(s) = p.selected.get_mut(p.cursor) {
                        *s = !*s;
                    }
                }
                None
            }
            Key::Prev => {
                app.focus = app.focus.saturating_sub(1);
                None
            }
            Key::Next => {
                if app.focus + 1 < app.pending.len() {
                    app.focus += 1;
                }
                None
            }
            Key::Commit(kind) => app.focused().map(|p| build_verdict(p, kind)),
            Key::Ignore => None,
        }
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
        );
        ratatui::restore();
        result
    }

    fn run_loop(
        terminal: &mut DefaultTerminal,
        app: &mut App,
        tailer: &mut Tailer,
        state_dir: &Path,
        qdir: &Path,
        live_path: &Path,
    ) -> std::io::Result<()> {
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

            sync_pending(app, qdir);
            terminal.draw(|f| ui(f, app))?;

            if event::poll(Duration::from_millis(POLL_MS))? {
                if let Event::Key(k) = event::read()? {
                    if k.kind != KeyEventKind::Press {
                        continue;
                    }
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
    fn sync_pending(app: &mut App, qdir: &Path) {
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

        let mut prev: HashMap<String, (Vec<bool>, usize)> = HashMap::new();
        for p in app.pending.drain(..) {
            prev.insert(p.request.id.clone(), (p.selected, p.cursor));
        }
        app.pending = found
            .into_iter()
            .map(|req| match prev.remove(&req.id) {
                Some((sel, cur)) if sel.len() == req.nodes.len() => Pending {
                    cursor: cur.min(req.nodes.len().saturating_sub(1)),
                    selected: sel,
                    request: req,
                },
                _ => Pending::new(req),
            })
            .collect();
        if app.focus >= app.pending.len() {
            app.focus = app.pending.len().saturating_sub(1);
        }
    }

    fn ui(f: &mut Frame, app: &App) {
        let [top, bottom] =
            Layout::vertical([Constraint::Min(3), Constraint::Length(14)]).areas(f.area());
        render_stream(f, top, app);
        render_pending(f, bottom, app);
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

    fn render_pending(f: &mut Frame, area: Rect, app: &App) {
        let block = Block::bordered().title(format!("pending approvals ({})", app.pending.len()));
        let Some(p) = app.focused() else {
            let para = Paragraph::new(
                "No pending approvals. The TUI is live; ask/pass-through calls will appear here.\n\nq quit",
            )
            .block(block);
            f.render_widget(para, area);
            return;
        };

        let mut lines: Vec<Line> = Vec::new();
        lines.push(Line::from(vec![
            Span::styled(
                format!("{}: ", p.request.tool),
                Style::new().fg(Color::Cyan),
            ),
            Span::raw(p.request.target.clone()),
        ]));
        if let Some(cwd) = &p.request.cwd {
            lines.push(Line::from(Span::styled(
                format!("  cwd {cwd}"),
                Style::new().fg(Color::DarkGray),
            )));
        }
        lines.push(Line::raw(""));
        for (i, node) in p.request.nodes.iter().enumerate() {
            let mark = if p.selected[i] { "[x]" } else { "[ ]" };
            let text = format!("{mark} {} {}  ({})", node.command, node.args, node.decision);
            let mut style = Style::new();
            if i == p.cursor {
                style = style.add_modifier(Modifier::REVERSED);
            }
            if !p.selected[i] {
                style = style.fg(Color::DarkGray);
            }
            lines.push(Line::from(Span::styled(text, style)));
        }
        lines.push(Line::raw(""));
        lines.push(Line::from(Span::styled(
            "space toggle · ↑↓ node · ←→ request · a allow-always · o allow-once · d deny-always · x deny-once · q quit",
            Style::new().fg(Color::DarkGray),
        )));
        f.render_widget(
            Paragraph::new(lines)
                .block(block)
                .wrap(Wrap { trim: false }),
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

        #[test]
        fn deselect_then_allow_always_maps_per_node() {
            let mut app = App::new();
            app.pending.push(Pending::new(req()));
            // cursor starts at node 0 (gh); toggle it off, move to node 1 (jq), allow-always.
            assert!(apply_key(&mut app, Key::Toggle).is_none());
            assert!(apply_key(&mut app, Key::Down).is_none());
            let (verdict, live) =
                apply_key(&mut app, Key::Commit(Commit::AllowAlways)).expect("commit");
            assert_eq!(verdict.nodes[0].action, Action::Passthrough);
            assert_eq!(verdict.nodes[1].action, Action::AllowAlways);
            assert_eq!(live.len(), 1);
            assert_eq!(live[0].target, "jq");
            assert!(live[0].allow);
            // a node left as passthrough means the whole call defers to the terminal.
            assert_eq!(combine_verdict(&verdict.nodes), None);
        }

        #[test]
        fn all_selected_allow_once_allows_call_without_persisting() {
            let mut app = App::new();
            app.pending.push(Pending::new(req()));
            let (verdict, live) =
                apply_key(&mut app, Key::Commit(Commit::AllowOnce)).expect("commit");
            assert!(live.is_empty());
            assert_eq!(
                combine_verdict(&verdict.nodes).map(|(d, _)| d),
                Some(Decision::Allow)
            );
        }

        #[test]
        fn deny_once_selected_denies_call() {
            let mut app = App::new();
            app.pending.push(Pending::new(req()));
            let (verdict, _) = apply_key(&mut app, Key::Commit(Commit::DenyOnce)).expect("commit");
            assert_eq!(
                combine_verdict(&verdict.nodes).map(|(d, _)| d),
                Some(Decision::Deny)
            );
        }

        #[test]
        fn renders_without_panic() {
            use ratatui::backend::TestBackend;
            use ratatui::Terminal;
            let mut app = App::new();
            app.pending.push(Pending::new(req()));
            app.stream.push(Line::raw("ALLOW  Bash: ls"));
            let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
            terminal.draw(|f| ui(f, &app)).unwrap();
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
