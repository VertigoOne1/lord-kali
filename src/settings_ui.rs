// The settings editor from docs/C-config-in-tui.md — `m` in `lord-kali watch`.
//
// A full-screen modal that owns input while it is open. It deliberately owns *input only*:
// the watch loop keeps writing the heartbeat, syncing the queue and ticking the auto-approver
// behind it, so the gate never degrades to pass-through because the operator is editing
// config. `handle_key` is a pure state transition and never blocks, which is what makes that
// true by construction.

use crate::config::{lord_kali_config_dir, ApprovalConfig, MutationScope};
use crate::live_rules::live_rules_path;
use crate::queue;
use crate::settings::{self, Conflict, FieldKind, FieldSpec, Settings};
use crossterm::event::KeyCode;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph, Wrap};
use ratatui::Frame;
use std::path::{Path, PathBuf};

const LABEL_W: usize = 24;
const VALUE_W: usize = 30;
const SOURCE_W: usize = 14;

// The five keys of the budget invariant (docs/B-ai-first-gating.md, docs/C §C3). A consult
// that can outlast the gate's own timeout is a consult the operator never gets to see.
const K_QUEUE_WAIT: &str = "approval.llm.queue_wait_ms";
const K_TIMEOUT: &str = "approval.llm.timeout_ms";
const K_ATTEMPTS: &str = "approval.llm.max_attempts";
const K_PROPOSAL_WAIT: &str = "approval.llm.proposal_wait_ms";
const K_SELF_TIMEOUT: &str = "approval.self_timeout_ms";

// The one field whose *value* must never reach the screen: it names an env var holding an
// API key, so the editor renders the name and a presence bit and nothing else (§C6).
const K_API_KEY_ENV: &str = "approval.llm.api_key_env";

// The one field whose fallback is a typed value in the gate rather than a literal in the
// field table. Read it from there so the two cannot drift: a default column naming a
// behaviour the gate does not actually take is worse than no default column at all.
const K_MUTATION_SCOPE: &str = "file.mutation_scope";

fn default_of(spec: &FieldSpec) -> &'static str {
    if spec.key == K_MUTATION_SCOPE {
        settings::mutation_scope_str(MutationScope::default())
    } else {
        spec.default
    }
}

// Everything the read-only footer answers "where is my config?" with. Resolved once by the
// caller that already owns these paths rather than re-derived here.
#[derive(Clone, Default)]
pub(crate) struct Paths {
    pub(crate) config_dir: PathBuf,
    pub(crate) settings_file: PathBuf,
    pub(crate) live_rules: PathBuf,
    pub(crate) state_dir: PathBuf,
    pub(crate) log: PathBuf,
}

impl Paths {
    pub(crate) fn resolve(approval: &ApprovalConfig, log_path: &Path) -> Paths {
        Paths {
            config_dir: lord_kali_config_dir(),
            settings_file: settings::settings_path(),
            live_rules: live_rules_path(approval),
            state_dir: queue::state_dir(approval),
            log: log_path.to_path_buf(),
        }
    }
}

// Sizes and listings sampled when the modal opens. None means the file is not there yet,
// which is rendered as such rather than as a zero.
struct Footer {
    live_rules_lines: Option<usize>,
    log_bytes: Option<u64>,
    loaded: Vec<String>,
}

impl Footer {
    fn sample(paths: &Paths) -> Footer {
        Footer {
            live_rules_lines: std::fs::read_to_string(&paths.live_rules)
                .ok()
                .map(|s| s.lines().count()),
            log_bytes: std::fs::metadata(&paths.log).ok().map(|m| m.len()),
            loaded: loaded_files(&paths.config_dir),
        }
    }
}

// The load order `load_config` actually uses: every `.toml` in the config dir, sorted. That
// includes `settings.toml`, and saying so is the point of the footer.
fn loaded_files(config_dir: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(config_dir) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("toml"))
        .filter_map(|p| p.file_stem().and_then(|s| s.to_str()).map(str::to_string))
        .collect();
    names.sort();
    names
}

struct Edit {
    key: &'static str,
    buf: String,
    error: Option<String>,
}

pub(crate) enum Outcome {
    Stay,
    Close,
    // A save landed; the payload is the line the watch stream should carry.
    Saved(String),
}

pub(crate) struct SettingsModal {
    paths: Paths,
    settings: Settings,
    // The document as it sits on disk, so "unsaved edits" is a comparison rather than a flag
    // that can drift out of step with the edits themselves.
    saved: Settings,
    conflicts: Vec<Conflict>,
    // Where each settings section resolves from. Needed because a key nobody set here may
    // still be supplied by a rule file, and calling that "default" would be a lie.
    origins: Vec<settings::SectionOrigin>,
    footer: Footer,
    // A settings.toml that will not parse. Editing from a blank document would silently
    // discard whatever is in the file, so saving is refused until it is fixed by hand.
    load_error: Option<String>,
    cursor: usize,
    edit: Option<Edit>,
    status: Option<(String, bool)>,
    confirm_discard: bool,
    revision: u64,
}

impl SettingsModal {
    pub(crate) fn open(paths: Paths) -> SettingsModal {
        let (settings, load_error) = match Settings::load_from(&paths.settings_file) {
            Ok(s) => (s, None),
            Err(e) => (Settings::default(), Some(e)),
        };
        let origins = settings::section_origins(&paths.config_dir, &settings);
        let conflicts = settings::conflicts_from(&origins);
        let footer = Footer::sample(&paths);
        SettingsModal {
            saved: settings.clone(),
            settings,
            conflicts,
            origins,
            footer,
            load_error,
            paths,
            cursor: 0,
            edit: None,
            status: None,
            confirm_discard: false,
            revision: 0,
        }
    }

    pub(crate) fn revision(&self) -> u64 {
        self.revision
    }

    pub(crate) fn handle_key(&mut self, code: KeyCode) -> Outcome {
        self.revision += 1;
        if self.edit.is_some() {
            return self.edit_key(code);
        }
        // Armed by a first Esc while dirty; anything else stands the arming down.
        let armed = self.confirm_discard;
        if code != KeyCode::Esc {
            self.confirm_discard = false;
        }
        match code {
            KeyCode::Esc => {
                if armed || !self.dirty() {
                    Outcome::Close
                } else {
                    self.confirm_discard = true;
                    Outcome::Stay
                }
            }
            KeyCode::Up => {
                self.cursor = self.cursor.saturating_sub(1);
                self.status = None;
                Outcome::Stay
            }
            KeyCode::Down => {
                if self.cursor + 1 < field_count() {
                    self.cursor += 1;
                }
                self.status = None;
                Outcome::Stay
            }
            KeyCode::Tab | KeyCode::Char(']') => {
                self.cursor = step_group(self.cursor, 1);
                self.status = None;
                Outcome::Stay
            }
            KeyCode::BackTab | KeyCode::Char('[') => {
                self.cursor = step_group(self.cursor, -1);
                self.status = None;
                Outcome::Stay
            }
            KeyCode::Enter | KeyCode::Char(' ') => {
                self.activate(code);
                Outcome::Stay
            }
            KeyCode::Char('d') => {
                if let Some(spec) = spec_at(self.cursor) {
                    self.settings.unset(spec.key);
                    self.status = Some((format!("{} reset to default", spec.key), false));
                }
                Outcome::Stay
            }
            KeyCode::Char('s') => self.save(),
            _ => Outcome::Stay,
        }
    }

    // Enter opens a text input; on a bool or a choice it cycles instead, which is quicker and
    // cannot produce a value the field would reject. Space cycles but never opens an input,
    // so it is inert on the free-text fields.
    fn activate(&mut self, code: KeyCode) {
        let Some(spec) = spec_at(self.cursor) else {
            return;
        };
        self.status = None;
        match spec.kind {
            FieldKind::Bool => {
                let on = self.effective(spec) == "true";
                self.settings.set(spec.key, toml::Value::Boolean(!on));
            }
            FieldKind::Choice(options) => {
                let current = self.effective(spec);
                let next = options
                    .iter()
                    .position(|o| *o == current)
                    .map(|i| (i + 1) % options.len())
                    .unwrap_or(0);
                self.settings
                    .set(spec.key, toml::Value::String(options[next].to_string()));
            }
            _ if code == KeyCode::Enter => {
                self.edit = Some(Edit {
                    key: spec.key,
                    // Only what the document actually holds: an unset field opens empty, and
                    // committing it empty leaves it unset. Several defaults ("(none)",
                    // "(built-in set only)") describe a behaviour rather than name a value,
                    // so they are not something to pre-fill an input with.
                    buf: self.settings.display(spec.key).unwrap_or_default(),
                    error: None,
                });
            }
            _ => {}
        }
    }

    fn edit_key(&mut self, code: KeyCode) -> Outcome {
        match code {
            KeyCode::Esc => {
                self.edit = None;
            }
            KeyCode::Char(c) => {
                if let Some(e) = self.edit.as_mut() {
                    e.buf.push(c);
                    e.error = None;
                }
            }
            KeyCode::Backspace => {
                if let Some(e) = self.edit.as_mut() {
                    e.buf.pop();
                    e.error = None;
                }
            }
            KeyCode::Enter => self.commit_edit(),
            _ => {}
        }
        Outcome::Stay
    }

    // A rejected value keeps the editor open holding what was typed. Neither accepting it nor
    // dropping it silently is acceptable — the operator has to see why and decide.
    fn commit_edit(&mut self) {
        let Some(edit) = self.edit.as_mut() else {
            return;
        };
        let Some(spec) = spec_by_key(edit.key) else {
            self.edit = None;
            return;
        };
        match Settings::parse_input(spec, &edit.buf) {
            Ok(Some(value)) => {
                self.settings.set(spec.key, value);
                self.edit = None;
            }
            Ok(None) => {
                self.settings.unset(spec.key);
                self.edit = None;
            }
            Err(msg) => edit.error = Some(msg),
        }
    }

    fn save(&mut self) -> Outcome {
        if let Some(err) = &self.load_error {
            self.status = Some((format!("cannot save over an unreadable file — {err}"), true));
            return Outcome::Stay;
        }
        match self.settings.save_to(&self.paths.settings_file) {
            Ok(()) => {
                self.saved = self.settings.clone();
                self.origins = settings::section_origins(&self.paths.config_dir, &self.settings);
                self.conflicts = settings::conflicts_from(&self.origins);
                self.status = Some(("saved".to_string(), false));
                Outcome::Saved(format!(
                    "settings saved → {} · the hook reads it on its next call; \
                     this watch reloads what it can now and reports anything that needs a restart",
                    self.paths.settings_file.display()
                ))
            }
            Err(e) => {
                self.status = Some((e, true));
                Outcome::Stay
            }
        }
    }

    fn dirty(&self) -> bool {
        self.settings.as_table() != self.saved.as_table()
    }

    // What the field is worth right now: the document's value, or the default it inherits by
    // being absent.
    // The rule file still supplying this key's section, if `settings.toml` does not declare
    // it. `None` means nothing declares it and the built-in default really does apply.
    fn fallback_for(&self, key: &str) -> Option<&str> {
        let section = settings::section_of(key);
        self.origins
            .iter()
            .find(|o| o.section == section && !o.in_settings)
            .and_then(|o| o.fallback())
    }

    fn effective(&self, spec: &FieldSpec) -> String {
        self.settings
            .display(spec.key)
            .unwrap_or_else(|| default_of(spec).to_string())
    }

    fn num(&self, key: &str) -> u64 {
        self.settings
            .get(key)
            .and_then(|v| v.as_integer())
            .and_then(|i| u64::try_from(i).ok())
            .or_else(|| spec_by_key(key).and_then(|s| s.default.parse().ok()))
            .unwrap_or(0)
    }

    fn budget(&self) -> Budget {
        let queue_wait = self.num(K_QUEUE_WAIT);
        let timeout = self.num(K_TIMEOUT);
        let attempts = self.num(K_ATTEMPTS);
        let proposal_wait = self.num(K_PROPOSAL_WAIT);
        let total = queue_wait
            .saturating_add(timeout.saturating_mul(attempts))
            .saturating_add(proposal_wait);
        Budget {
            queue_wait,
            timeout,
            attempts,
            proposal_wait,
            total,
            limit: self.num(K_SELF_TIMEOUT),
        }
    }
}

struct Budget {
    queue_wait: u64,
    timeout: u64,
    attempts: u64,
    proposal_wait: u64,
    total: u64,
    limit: u64,
}

impl Budget {
    fn ok(&self) -> bool {
        self.total < self.limit
    }

    fn line(&self) -> String {
        format!(
            "{} + ({} × {}) + {} = {}  <  {} {}",
            self.queue_wait,
            self.timeout,
            self.attempts,
            self.proposal_wait,
            self.total,
            self.limit,
            if self.ok() { "✓" } else { "✗" }
        )
    }
}

fn field_count() -> usize {
    settings::groups().iter().map(|g| g.fields.len()).sum()
}

fn spec_at(index: usize) -> Option<&'static FieldSpec> {
    settings::groups()
        .iter()
        .flat_map(|g| g.fields.iter())
        .nth(index)
}

fn spec_by_key(key: &str) -> Option<&'static FieldSpec> {
    settings::groups()
        .iter()
        .flat_map(|g| g.fields.iter())
        .find(|s| s.key == key)
}

// The flat index of the first field of each group, which is what Tab/Shift-Tab jump between.
fn group_starts() -> Vec<usize> {
    let mut starts = Vec::new();
    let mut n = 0;
    for g in settings::groups() {
        starts.push(n);
        n += g.fields.len();
    }
    starts
}

fn step_group(cursor: usize, delta: isize) -> usize {
    let starts = group_starts();
    let here = starts.iter().rposition(|s| *s <= cursor).unwrap_or(0);
    let next = (here as isize + delta).clamp(0, starts.len() as isize - 1) as usize;
    starts[next]
}

// Pad or visibly truncate to an exact column width. A clipped value has to look clipped,
// otherwise a shortened path reads as a different path.
fn fit(s: &str, width: usize) -> String {
    let n = s.chars().count();
    if n <= width {
        let mut out = s.to_string();
        out.push_str(&" ".repeat(width - n));
        out
    } else {
        let mut out: String = s.chars().take(width.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u + 1 < UNITS.len() {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

pub(crate) fn render(f: &mut Frame, area: Rect, m: &SettingsModal) {
    let attention = attention_lines(m);
    // Sized to the wrapped height so nothing in it is silently clipped, but never more than
    // half the screen — a pathological parse error must not push the editor off the frame.
    let inner_w = area.width.saturating_sub(2).max(1) as usize;
    let wrapped: usize = attention
        .iter()
        .map(|l| l.width().max(1).div_ceil(inner_w))
        .sum();
    let attention_h = if attention.is_empty() {
        0
    } else {
        (wrapped as u16 + 2).min(area.height / 2)
    };
    let [warn, list, detail, footer, help] = Layout::vertical([
        Constraint::Length(attention_h),
        Constraint::Min(4),
        Constraint::Length(4),
        Constraint::Length(8),
        Constraint::Length(1),
    ])
    .areas(area);

    if attention_h > 0 {
        f.render_widget(
            Paragraph::new(attention)
                .block(
                    Block::bordered()
                        .title("attention")
                        .border_style(Style::new().fg(Color::Red)),
                )
                .wrap(Wrap { trim: false }),
            warn,
        );
    }
    render_list(f, list, m);
    render_detail(f, detail, m);
    render_footer(f, footer, m);
    render_help(f, help, m);
}

fn attention_lines(m: &SettingsModal) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    if let Some(e) = &m.load_error {
        lines.push(Line::from(Span::styled(
            format!(
                "⚠ {} will not parse, so saving is refused until it is fixed by hand — {}",
                settings::SETTINGS_FILE,
                e.split_whitespace().collect::<Vec<_>>().join(" ")
            ),
            Style::new().fg(Color::Red).add_modifier(Modifier::BOLD),
        )));
    }
    for c in &m.conflicts {
        lines.push(Line::from(Span::styled(
            format!(
                "⚠ [{}] is also declared in {} — {} wins; remove it there.",
                c.section,
                c.file,
                settings::SETTINGS_FILE
            ),
            Style::new().fg(Color::Yellow),
        )));
    }
    lines
}

fn render_list(f: &mut Frame, area: Rect, m: &SettingsModal) {
    let mut lines: Vec<Line<'static>> = Vec::new();
    let mut focus_line = 0usize;
    let mut index = 0usize;
    for group in settings::groups() {
        lines.push(Line::from(Span::styled(
            format!("── {} ", group.title),
            Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        )));
        for spec in group.fields {
            if index == m.cursor {
                focus_line = lines.len();
            }
            lines.push(field_row(m, spec, index == m.cursor));
            index += 1;
        }
    }

    let visible = area.height.saturating_sub(2) as usize;
    let start = focus_line.saturating_sub(visible.saturating_sub(1));
    let end = lines.len().min(start + visible);
    let title = format!(
        "settings — {}{}",
        m.paths.settings_file.display(),
        if m.dirty() { "  (unsaved)" } else { "" }
    );
    f.render_widget(
        Paragraph::new(lines[start.min(end)..end].to_vec()).block(Block::bordered().title(title)),
        area,
    );
}

fn field_row(m: &SettingsModal, spec: &FieldSpec, focused: bool) -> Line<'static> {
    let set = m.settings.display(spec.key);
    let mut spans = vec![
        Span::styled(
            if focused { "▸ " } else { "  " },
            Style::new().fg(Color::Yellow),
        ),
        Span::styled(
            fit(spec.label, LABEL_W),
            if focused {
                Style::new().add_modifier(Modifier::BOLD)
            } else {
                Style::new()
            },
        ),
    ];

    match m.edit.as_ref().filter(|e| e.key == spec.key) {
        Some(edit) => spans.push(Span::styled(
            fit(&format!("{}▏", edit.buf), VALUE_W),
            Style::new().fg(Color::Black).bg(Color::Yellow),
        )),
        None => spans.push(match &set {
            Some(v) => Span::styled(fit(v, VALUE_W), Style::new().fg(Color::White)),
            None => Span::styled(
                fit(default_of(spec), VALUE_W),
                Style::new().fg(Color::DarkGray),
            ),
        }),
    }

    // An unset key is not automatically "default": if a rule file still declares its
    // section, that is where the gate is taking the value from, and saying otherwise would
    // point the operator at the wrong file.
    spans.push(match (set, m.fallback_for(spec.key)) {
        (Some(_), _) => Span::styled(
            fit(settings::SETTINGS_FILE, SOURCE_W),
            Style::new().fg(Color::Green),
        ),
        (None, Some(file)) => Span::styled(fit(file, SOURCE_W), Style::new().fg(Color::Yellow)),
        (None, None) => Span::styled(fit("default", SOURCE_W), Style::new().fg(Color::DarkGray)),
    });
    spans.push(Span::styled(
        default_of(spec).to_string(),
        Style::new().fg(Color::DarkGray),
    ));

    // The key's value is never read — only whether the process has it — so it cannot reach
    // the screen, the log, or the config file from here.
    if spec.key == K_API_KEY_ENV {
        let present = std::env::var_os(m.effective(spec)).is_some();
        spans.push(Span::styled(
            format!("   key present: {}", if present { "yes" } else { "no" }),
            Style::new().fg(if present { Color::Green } else { Color::Red }),
        ));
    }

    if let Some(msg) = m
        .edit
        .as_ref()
        .filter(|e| e.key == spec.key)
        .and_then(|e| e.error.as_ref())
    {
        spans.push(Span::styled(
            format!("   ✗ {msg}"),
            Style::new().fg(Color::Red).add_modifier(Modifier::BOLD),
        ));
    }
    Line::from(spans)
}

fn render_detail(f: &mut Frame, area: Rect, m: &SettingsModal) {
    let spec = spec_at(m.cursor);
    let budget = m.budget();
    let lines = vec![
        Line::from(vec![
            Span::styled(
                spec.map(|s| s.key).unwrap_or("").to_string(),
                Style::new().fg(Color::Cyan),
            ),
            Span::raw("  "),
            Span::styled(
                spec.map(|s| s.help).unwrap_or("").to_string(),
                Style::new().fg(Color::Gray),
            ),
        ]),
        Line::from(vec![
            Span::styled("budget  ", Style::new().fg(Color::DarkGray)),
            Span::styled(
                budget.line(),
                if budget.ok() {
                    Style::new().fg(Color::Green)
                } else {
                    Style::new().fg(Color::Red).add_modifier(Modifier::BOLD)
                },
            ),
            Span::styled(
                "   queue_wait + (timeout × attempts) + proposal_wait  <  self_timeout",
                Style::new().fg(Color::DarkGray),
            ),
        ]),
    ];
    f.render_widget(
        Paragraph::new(lines).block(Block::bordered().title("detail")),
        area,
    );
}

fn render_footer(f: &mut Frame, area: Rect, m: &SettingsModal) {
    let row = |label: &str, value: String, note: Option<String>| {
        let mut spans = vec![
            Span::styled(fit(label, 12), Style::new().fg(Color::DarkGray)),
            Span::raw(value),
        ];
        if let Some(n) = note {
            spans.push(Span::styled(
                format!("   {n}"),
                Style::new().fg(Color::DarkGray),
            ));
        }
        Line::from(spans)
    };
    let lines = vec![
        row("config dir", m.paths.config_dir.display().to_string(), None),
        row(
            "settings",
            m.paths.settings_file.display().to_string(),
            None,
        ),
        row(
            "live rules",
            m.paths.live_rules.display().to_string(),
            Some(match m.footer.live_rules_lines {
                Some(n) => format!("({n} lines)"),
                None => "(not created)".to_string(),
            }),
        ),
        row("state dir", m.paths.state_dir.display().to_string(), None),
        row(
            "log",
            m.paths.log.display().to_string(),
            Some(match m.footer.log_bytes {
                Some(n) => format!("({})", human_bytes(n)),
                None => "(not created)".to_string(),
            }),
        ),
        row(
            "loaded",
            if m.footer.loaded.is_empty() {
                "(no .toml files in the config dir)".to_string()
            } else {
                format!(
                    "{}   ({} files, in this order)",
                    m.footer.loaded.join(", "),
                    m.footer.loaded.len()
                )
            },
            None,
        ),
    ];
    f.render_widget(
        Paragraph::new(lines).block(Block::bordered().title("where things are")),
        area,
    );
}

fn render_help(f: &mut Frame, area: Rect, m: &SettingsModal) {
    let text = if m.edit.is_some() {
        "⏎ commit · Esc cancel · ⌫ delete"
    } else if m.confirm_discard {
        "unsaved edits — Esc again to discard · s to save"
    } else {
        "↑↓ field · ⇥ / [ ] group · ⏎ edit or cycle · space cycle · d default · s save · Esc close"
    };
    let mut spans = vec![Span::styled(
        text,
        if m.confirm_discard {
            Style::new().fg(Color::Yellow)
        } else {
            Style::new().fg(Color::DarkGray)
        },
    )];
    if let Some((msg, is_error)) = &m.status {
        spans.push(Span::styled(
            format!("   ·   {msg}"),
            if *is_error {
                Style::new().fg(Color::Red).add_modifier(Modifier::BOLD)
            } else {
                Style::new().fg(Color::Green)
            },
        ));
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;
    use std::path::PathBuf;

    fn paths_in(dir: &Path) -> Paths {
        Paths {
            config_dir: dir.to_path_buf(),
            settings_file: dir.join(settings::SETTINGS_FILE),
            live_rules: dir.join("99-live.toml"),
            state_dir: dir.join("state"),
            log: dir.join("hook.jsonl"),
        }
    }

    fn modal_in(dir: &Path) -> SettingsModal {
        SettingsModal::open(paths_in(dir))
    }

    fn focus(m: &mut SettingsModal, key: &str) {
        let index = settings::groups()
            .iter()
            .flat_map(|g| g.fields.iter())
            .position(|s| s.key == key)
            .expect("known key");
        m.cursor = index;
    }

    fn type_in(m: &mut SettingsModal, text: &str) {
        for c in text.chars() {
            m.handle_key(KeyCode::Char(c));
        }
    }

    fn draw(m: &SettingsModal, w: u16, h: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
        terminal.draw(|f| render(f, f.area(), m)).unwrap();
        let buf = terminal.backend().buffer().clone();
        let mut out = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                out.push_str(buf.cell((x, y)).map(|c| c.symbol()).unwrap_or(" "));
            }
            out.push('\n');
        }
        out
    }

    // The row for `key` as one whitespace-collapsed line, so a column-width change does not
    // break every assertion.
    fn row_text(m: &SettingsModal, key: &str) -> String {
        let spec = spec_by_key(key).expect("known key");
        let rendered = draw(m, 200, 60);
        rendered
            .lines()
            .find(|l| l.contains(spec.label) && (l.contains('▸') || l.starts_with("│ ")))
            .map(|l| l.split_whitespace().collect::<Vec<_>>().join(" "))
            .unwrap_or_default()
    }

    #[test]
    fn esc_closes_a_clean_modal_and_q_is_swallowed() {
        let tmp = tempfile::tempdir().unwrap();
        let mut m = modal_in(tmp.path());
        assert!(matches!(m.handle_key(KeyCode::Char('q')), Outcome::Stay));
        assert!(matches!(m.handle_key(KeyCode::Esc), Outcome::Close));
    }

    #[test]
    fn esc_on_unsaved_edits_asks_first() {
        let tmp = tempfile::tempdir().unwrap();
        let mut m = modal_in(tmp.path());
        focus(&mut m, "log.enabled");
        m.handle_key(KeyCode::Enter);
        assert!(m.dirty());

        assert!(matches!(m.handle_key(KeyCode::Esc), Outcome::Stay));
        assert!(m.confirm_discard);
        assert!(matches!(m.handle_key(KeyCode::Esc), Outcome::Close));
    }

    #[test]
    fn any_other_key_stands_the_discard_prompt_down() {
        let tmp = tempfile::tempdir().unwrap();
        let mut m = modal_in(tmp.path());
        focus(&mut m, "log.enabled");
        m.handle_key(KeyCode::Enter);
        m.handle_key(KeyCode::Esc);
        m.handle_key(KeyCode::Down);
        assert!(!m.confirm_discard);
        assert!(matches!(m.handle_key(KeyCode::Esc), Outcome::Stay));
    }

    #[test]
    fn arrows_walk_fields_and_tab_walks_groups() {
        let tmp = tempfile::tempdir().unwrap();
        let mut m = modal_in(tmp.path());
        assert_eq!(m.cursor, 0);
        m.handle_key(KeyCode::Up);
        assert_eq!(m.cursor, 0, "clamped at the top");
        m.handle_key(KeyCode::Down);
        assert_eq!(spec_at(m.cursor).unwrap().key, "log.path");

        m.handle_key(KeyCode::Tab);
        assert_eq!(
            spec_at(m.cursor).unwrap().key,
            "worktree-protection.enabled"
        );
        m.handle_key(KeyCode::Char(']'));
        assert_eq!(spec_at(m.cursor).unwrap().key, "approval.enabled");
        m.handle_key(KeyCode::BackTab);
        assert_eq!(
            spec_at(m.cursor).unwrap().key,
            "worktree-protection.enabled"
        );

        for _ in 0..20 {
            m.handle_key(KeyCode::Char(']'));
        }
        assert_eq!(spec_at(m.cursor).unwrap().key, "otel.enabled");
        for _ in 0..20 {
            m.handle_key(KeyCode::Char('['));
        }
        assert_eq!(spec_at(m.cursor).unwrap().key, "log.enabled");

        m.cursor = field_count() - 1;
        m.handle_key(KeyCode::Down);
        assert_eq!(m.cursor, field_count() - 1, "clamped at the bottom");
    }

    #[test]
    fn editing_a_text_field_commits_on_enter() {
        let tmp = tempfile::tempdir().unwrap();
        let mut m = modal_in(tmp.path());
        focus(&mut m, "approval.llm.model");
        m.handle_key(KeyCode::Enter);
        type_in(&mut m, "anthropic/claude");
        m.handle_key(KeyCode::Backspace);
        m.handle_key(KeyCode::Enter);
        assert!(m.edit.is_none());
        assert_eq!(
            m.settings.display("approval.llm.model").as_deref(),
            Some("anthropic/claud")
        );
    }

    #[test]
    fn escaping_an_edit_leaves_the_value_alone() {
        let tmp = tempfile::tempdir().unwrap();
        let mut m = modal_in(tmp.path());
        focus(&mut m, "approval.llm.model");
        m.handle_key(KeyCode::Enter);
        type_in(&mut m, "throwaway");
        m.handle_key(KeyCode::Esc);
        assert!(m.edit.is_none());
        assert_eq!(m.settings.display("approval.llm.model"), None);
        assert!(!m.dirty());
    }

    #[test]
    fn committing_an_empty_input_unsets_the_field() {
        let tmp = tempfile::tempdir().unwrap();
        let mut m = modal_in(tmp.path());
        focus(&mut m, "approval.llm.model");
        m.settings
            .set("approval.llm.model", toml::Value::String("x".into()));
        m.handle_key(KeyCode::Enter);
        m.handle_key(KeyCode::Backspace);
        m.handle_key(KeyCode::Enter);
        assert_eq!(m.settings.display("approval.llm.model"), None);
    }

    #[test]
    fn an_invalid_number_is_rejected_and_the_value_is_unchanged() {
        let tmp = tempfile::tempdir().unwrap();
        let mut m = modal_in(tmp.path());
        focus(&mut m, "approval.self_timeout_ms");
        m.settings
            .set("approval.self_timeout_ms", toml::Value::Integer(50_000));
        m.handle_key(KeyCode::Enter);
        for _ in 0..6 {
            m.handle_key(KeyCode::Backspace);
        }
        type_in(&mut m, "9999999");
        m.handle_key(KeyCode::Enter);

        assert!(m.edit.is_some(), "the editor stays open on a rejection");
        assert_eq!(
            m.edit.as_ref().unwrap().error.as_deref(),
            Some("must be between 0 and 600000")
        );
        assert_eq!(
            m.settings.display("approval.self_timeout_ms").as_deref(),
            Some("50000"),
            "the stored value must not move"
        );
        assert!(row_text(&m, "approval.self_timeout_ms").contains("must be between 0 and 600000"));

        // Editing again clears the message; a value inside the bounds then commits.
        m.handle_key(KeyCode::Backspace);
        assert!(m.edit.as_ref().unwrap().error.is_none());
        m.handle_key(KeyCode::Backspace);
        m.handle_key(KeyCode::Enter);
        assert!(m.edit.is_none());
        assert_eq!(
            m.settings.display("approval.self_timeout_ms").as_deref(),
            Some("99999")
        );
    }

    #[test]
    fn non_numeric_text_in_a_number_field_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let mut m = modal_in(tmp.path());
        focus(&mut m, "approval.poll_ms");
        m.handle_key(KeyCode::Enter);
        type_in(&mut m, "soon");
        m.handle_key(KeyCode::Enter);
        assert_eq!(
            m.edit.as_ref().unwrap().error.as_deref(),
            Some("expected a whole number")
        );
        assert_eq!(m.settings.display("approval.poll_ms"), None);
    }

    #[test]
    fn bool_cycles_from_its_default_and_space_works_too() {
        let tmp = tempfile::tempdir().unwrap();
        let mut m = modal_in(tmp.path());
        focus(&mut m, "worktree-protection.enabled");
        assert_eq!(m.effective(spec_at(m.cursor).unwrap()), "true");

        m.handle_key(KeyCode::Enter);
        assert_eq!(
            m.settings.display("worktree-protection.enabled").as_deref(),
            Some("false")
        );
        m.handle_key(KeyCode::Char(' '));
        assert_eq!(
            m.settings.display("worktree-protection.enabled").as_deref(),
            Some("true")
        );
        assert!(m.edit.is_none(), "a bool never opens a text input");
    }

    #[test]
    fn choice_cycles_through_its_options_and_wraps() {
        let tmp = tempfile::tempdir().unwrap();
        let mut m = modal_in(tmp.path());
        focus(&mut m, "file.mutation_scope");
        m.handle_key(KeyCode::Enter);
        assert_eq!(
            m.settings.display("file.mutation_scope").as_deref(),
            Some("outside_cwd")
        );
        m.handle_key(KeyCode::Enter);
        assert_eq!(
            m.settings.display("file.mutation_scope").as_deref(),
            Some("all")
        );
        assert!(m.edit.is_none());
    }

    #[test]
    fn space_is_inert_on_a_free_text_field() {
        let tmp = tempfile::tempdir().unwrap();
        let mut m = modal_in(tmp.path());
        focus(&mut m, "approval.llm.model");
        m.handle_key(KeyCode::Char(' '));
        assert!(m.edit.is_none());
        assert!(!m.dirty());
    }

    #[test]
    fn d_resets_to_default_and_the_row_says_so() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join(settings::SETTINGS_FILE),
            "[approval.llm]\nmodel = \"custom/model\"\n",
        )
        .unwrap();
        let mut m = modal_in(tmp.path());
        focus(&mut m, "approval.llm.model");
        let before = row_text(&m, "approval.llm.model");
        assert!(before.contains("custom/model"));
        assert!(before.contains(settings::SETTINGS_FILE));

        m.handle_key(KeyCode::Char('d'));
        assert_eq!(m.settings.display("approval.llm.model"), None);
        let after = row_text(&m, "approval.llm.model");
        assert!(!after.contains("custom/model"));
        assert!(after.contains("default"));
        assert!(after.contains("mistralai/mistral-small-3.2-24b-instruct"));
    }

    #[test]
    fn saving_writes_the_file_and_reports_the_restart_caveat() {
        let tmp = tempfile::tempdir().unwrap();
        let mut m = modal_in(tmp.path());
        focus(&mut m, "approval.enabled");
        m.handle_key(KeyCode::Enter);
        assert!(m.dirty());

        let Outcome::Saved(note) = m.handle_key(KeyCode::Char('s')) else {
            panic!("expected a save");
        };
        assert!(
            note.contains("restart"),
            "the note must not imply a hot reload: {note}"
        );
        assert!(!m.dirty(), "a save clears the unsaved state");

        let written = std::fs::read_to_string(tmp.path().join(settings::SETTINGS_FILE)).unwrap();
        assert!(written.contains("[approval]"));
        assert!(written.contains("enabled = true"));

        let reopened = modal_in(tmp.path());
        assert_eq!(
            reopened.settings.display("approval.enabled").as_deref(),
            Some("true")
        );
    }

    #[test]
    fn an_unreadable_settings_file_blocks_saving_over_it() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join(settings::SETTINGS_FILE),
            "this is not = = toml",
        )
        .unwrap();
        let mut m = modal_in(tmp.path());
        assert!(m.load_error.is_some());

        assert!(matches!(m.handle_key(KeyCode::Char('s')), Outcome::Stay));
        let (msg, is_error) = m.status.clone().expect("a status");
        assert!(is_error);
        assert!(msg.contains("cannot save"));
        assert_eq!(
            std::fs::read_to_string(tmp.path().join(settings::SETTINGS_FILE)).unwrap(),
            "this is not = = toml",
            "the operator's file must be left exactly as it was"
        );
        assert!(draw(&m, 160, 40).contains("saving is refused until it is fixed by hand"));
    }

    #[test]
    fn the_budget_line_uses_defaults_when_the_fields_are_unset() {
        let tmp = tempfile::tempdir().unwrap();
        let m = modal_in(tmp.path());
        let b = m.budget();
        assert_eq!(
            (b.queue_wait, b.timeout, b.attempts, b.proposal_wait),
            (0, 8_000, 2, 5_000)
        );
        assert_eq!(b.total, 21_000);
        assert_eq!(b.limit, 50_000);
        assert!(b.ok());
        assert_eq!(b.line(), "0 + (8000 × 2) + 5000 = 21000  <  50000 ✓");
        assert!(draw(&m, 160, 40).contains("0 + (8000 × 2) + 5000 = 21000  <  50000 ✓"));
    }

    #[test]
    fn the_budget_line_follows_in_editor_values_and_flags_a_violation() {
        let tmp = tempfile::tempdir().unwrap();
        let mut m = modal_in(tmp.path());
        focus(&mut m, "approval.llm.timeout_ms");
        m.handle_key(KeyCode::Enter);
        type_in(&mut m, "30000");
        m.handle_key(KeyCode::Enter);

        let b = m.budget();
        assert_eq!(b.total, 65_000);
        assert!(!b.ok(), "60000+5000 exceeds the 50000 self timeout");
        assert_eq!(b.line(), "0 + (30000 × 2) + 5000 = 65000  <  50000 ✗");
        assert!(draw(&m, 160, 40).contains("= 65000  <  50000 ✗"));
    }

    #[test]
    fn raising_the_self_timeout_restores_the_budget() {
        let tmp = tempfile::tempdir().unwrap();
        let mut m = modal_in(tmp.path());
        m.settings.set(K_TIMEOUT, toml::Value::Integer(30_000));
        assert!(!m.budget().ok());
        m.settings.set(K_SELF_TIMEOUT, toml::Value::Integer(90_000));
        assert!(m.budget().ok());
    }

    // A key nobody set in settings.toml is only "default" when nothing else declares its
    // section. If a rule file still does, the gate is taking the value from there, and the
    // row must name that file — otherwise it points the operator at the wrong place to edit.
    #[test]
    fn an_unset_key_names_the_rule_file_still_supplying_its_section() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("00-base.toml"),
            "[log]\nenabled = true\npath = \"/x.jsonl\"\n",
        )
        .unwrap();
        let m = modal_in(tmp.path());

        assert_eq!(m.fallback_for("log.path"), Some("00-base.toml"));
        assert_eq!(m.fallback_for("log.enabled"), Some("00-base.toml"));
        assert!(draw(&m, 160, 40).contains("00-base.toml"));
    }

    // Once settings.toml declares the section, it is authoritative and the rule file is a
    // conflict rather than a source — the row must stop pointing at it.
    #[test]
    fn declaring_the_section_moves_the_source_off_the_rule_file() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("00-base.toml"), "[log]\nenabled = true\n").unwrap();
        std::fs::write(
            tmp.path().join(settings::SETTINGS_FILE),
            "[log]\nenabled = false\n",
        )
        .unwrap();
        let m = modal_in(tmp.path());

        assert_eq!(
            m.fallback_for("log.path"),
            None,
            "settings.toml owns the section now, so an unset key really is the default"
        );
        assert_eq!(m.conflicts.len(), 1);
    }

    #[test]
    fn nothing_declaring_a_section_leaves_its_keys_on_the_default() {
        let tmp = tempfile::tempdir().unwrap();
        let m = modal_in(tmp.path());
        assert_eq!(m.fallback_for("otel.endpoint"), None);
    }

    #[test]
    fn conflicts_render_when_a_rule_file_declares_the_same_section() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join(settings::SETTINGS_FILE),
            "[approval]\nenabled = true\n",
        )
        .unwrap();
        std::fs::write(
            tmp.path().join("95-approval.toml"),
            "[approval]\nenabled = false\n",
        )
        .unwrap();
        let m = modal_in(tmp.path());
        assert_eq!(m.conflicts.len(), 1);
        let text = draw(&m, 160, 40);
        assert!(text.contains("[approval] is also declared in 95-approval.toml"));
        assert!(text.contains("settings.toml wins; remove it there."));
    }

    #[test]
    fn no_conflict_block_when_nothing_overlaps() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join(settings::SETTINGS_FILE),
            "[approval]\nenabled = true\n",
        )
        .unwrap();
        std::fs::write(
            tmp.path().join("20-bash.toml"),
            "[[bash.rules]]\ncommand = \"ls\"\ndecision = \"allow\"\n",
        )
        .unwrap();
        let m = modal_in(tmp.path());
        assert!(m.conflicts.is_empty());
        let text = draw(&m, 160, 40);
        assert!(!text.contains("also declared in"));
        assert!(!text.contains("attention"));
    }

    // §C6: the editor knows the env var's NAME. Its value must never reach the screen.
    //
    // The search path stands in for the secret: it is set in every process and its value is
    // long and distinctive, so "did any of it get rendered?" is a real question. Declaring a
    // variable of our own would be the obvious alternative, but `set_var` races every other
    // test in this binary that reads the environment, so it is not one worth having.
    #[test]
    fn the_api_key_row_shows_presence_and_never_the_value() {
        let name = if cfg!(windows) { "Path" } else { "PATH" };
        let value = std::env::var(name).expect("the search path is set in every process");
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join(settings::SETTINGS_FILE),
            format!("[approval.llm]\napi_key_env = \"{name}\"\n"),
        )
        .unwrap();
        let m = modal_in(tmp.path());

        let rendered = draw(&m, 200, 60);
        assert!(
            !rendered.contains(&value),
            "the variable's value must never reach the screen"
        );
        for entry in std::env::split_paths(&value) {
            let entry = entry.display().to_string();
            if entry.len() > 12 {
                assert!(
                    !rendered.contains(&entry),
                    "not even one part of it: {entry}"
                );
            }
        }
        let row = row_text(&m, K_API_KEY_ENV);
        assert!(row.contains(name));
        assert!(row.contains("key present: yes"));
    }

    #[test]
    fn a_missing_env_var_reads_as_absent() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join(settings::SETTINGS_FILE),
            "[approval.llm]\napi_key_env = \"LORD_KALI_TEST_KEY_DEFINITELY_UNSET\"\n",
        )
        .unwrap();
        let m = modal_in(tmp.path());
        assert!(row_text(&m, K_API_KEY_ENV).contains("key present: no"));
    }

    #[test]
    fn the_footer_answers_where_is_my_config() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("99-live.toml"), "a\nb\nc\n").unwrap();
        std::fs::write(tmp.path().join("00-base.toml"), "[log]\n").unwrap();
        std::fs::write(tmp.path().join("hook.jsonl"), vec![b'x'; 2048]).unwrap();
        let m = modal_in(tmp.path());
        let text = draw(&m, 200, 60);
        assert!(text.contains("config dir"));
        assert!(text.contains("state dir"));
        assert!(text.contains("(3 lines)"));
        assert!(text.contains("(2.0 KB)"));
        assert!(text.contains("00-base, 99-live"));
    }

    #[test]
    fn the_footer_says_so_when_a_file_is_not_there_yet() {
        let tmp = tempfile::tempdir().unwrap();
        let m = modal_in(tmp.path());
        let text = draw(&m, 200, 60);
        assert!(text.contains("(not created)"));
        assert!(text.contains("no .toml files in the config dir"));
    }

    #[test]
    fn every_key_bumps_the_revision_so_the_loop_redraws() {
        let tmp = tempfile::tempdir().unwrap();
        let mut m = modal_in(tmp.path());
        let before = m.revision();
        m.handle_key(KeyCode::Down);
        assert!(m.revision() > before);
    }

    #[test]
    fn every_field_renders_when_the_list_is_scrolled_to_it() {
        let tmp = tempfile::tempdir().unwrap();
        let mut m = modal_in(tmp.path());
        for index in 0..field_count() {
            m.cursor = index;
            let spec = spec_at(index).unwrap();
            let rendered = draw(&m, 200, 24);
            assert!(
                rendered.contains(&fit(spec.label, LABEL_W)),
                "{} is unreachable at 24 rows",
                spec.key
            );
        }
    }

    #[test]
    fn a_long_value_is_visibly_truncated_rather_than_silently_cut() {
        assert_eq!(fit("abc", 5), "abc  ");
        assert_eq!(fit("abcdefgh", 5), "abcd…");
    }

    #[test]
    fn human_bytes_scales() {
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(2048), "2.0 KB");
        assert_eq!(human_bytes(19_000_000), "18.1 MB");
    }

    // The row's "default" column is what the operator is told happens when they press `d`.
    // If it drifts from the fallback the gate actually uses, the editor is lying about a
    // behaviour rather than merely being out of date.
    #[test]
    fn the_mutation_scope_default_is_the_one_the_gate_falls_back_to() {
        let spec = spec_by_key(K_MUTATION_SCOPE).unwrap();
        assert_eq!(default_of(spec), "all");
        assert_eq!(
            default_of(spec),
            spec.default,
            "the field table has drifted"
        );
    }

    #[test]
    fn every_choice_default_is_one_of_its_own_options() {
        for spec in settings::groups().iter().flat_map(|g| g.fields.iter()) {
            if let FieldKind::Choice(options) = spec.kind {
                assert!(
                    options.contains(&default_of(spec)),
                    "{} defaults to {:?}, which it does not offer",
                    spec.key,
                    spec.default
                );
            }
        }
    }

    #[test]
    fn resolve_uses_the_configured_state_and_live_rules_paths() {
        let approval = ApprovalConfig::default();
        let paths = Paths::resolve(&approval, &PathBuf::from("/tmp/hook.jsonl"));
        assert_eq!(paths.config_dir, lord_kali_config_dir());
        assert_eq!(
            paths.settings_file,
            lord_kali_config_dir().join(settings::SETTINGS_FILE)
        );
        assert!(paths.live_rules.starts_with(&paths.config_dir));
        assert_eq!(paths.log, PathBuf::from("/tmp/hook.jsonl"));
    }
}
