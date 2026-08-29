// The *behaviour* half of lord-kali's configuration — paths, timers, model, endpoints,
// feature switches — as opposed to *rules*, which stay in the numbered files and keep their
// merge-and-order semantics.
//
// Settings resolve from ONE file, `settings.toml` in the config dir, and a section present
// there REPLACES the same section from the rule files rather than merging with it. Merging
// was the confusing part: `[log]` was last-wins, `[approval] enabled` ORed across files, and
// `guardrail_commands` unioned — three different rules, so some values could not be turned
// off from any one place, which is exactly what a settings editor has to be able to do.
//
// A section still declared in a rule file is reported as a conflict rather than silently
// combined, so the migration is visible while it is in progress.

use crate::config::{lord_kali_config_dir, MutationScope};
use crate::queue::write_atomic;
use std::path::{Path, PathBuf};

pub(crate) const SETTINGS_FILE: &str = "settings.toml";

const HEADER: &str = "\
# lord-kali settings — managed by `lord-kali watch` (press `m`).
#
# This file holds BEHAVIOUR only: paths, timers, model, endpoints, feature switches.
# Rules ([[bash.rules]], allowed_commands, [[group]], ...) live in the numbered files
# alongside it and are not read from here.
#
# A section here REPLACES the same section in the numbered files. Editing by hand is fine;
# comments outside this header are not preserved when the TUI saves.
";

// The settings sections. `file` is split: its `enabled`/`mutation_scope` are settings, while
// `[[file.rules]]` are rules and stay in the rule files.
pub(crate) const SECTIONS: &[&str] = &["log", "worktree-protection", "approval", "file", "otel"];

#[derive(Clone, Copy, PartialEq, Debug)]
pub(crate) enum FieldKind {
    Bool,
    // Inclusive bounds. A timer with no sensible ceiling still gets one, so a typo cannot
    // silently park the gate for a day.
    Num { min: u64, max: u64 },
    Text,
    // A filesystem path; `~` is expanded on use, not on entry.
    PathText,
    Choice(&'static [&'static str]),
    // Comma-separated on entry, stored as a TOML array.
    List,
}

pub(crate) struct FieldSpec {
    // Dotted path into the document, e.g. "approval.llm.model".
    pub(crate) key: &'static str,
    pub(crate) label: &'static str,
    pub(crate) kind: FieldKind,
    // Rendered when the key is absent — the behaviour you get by leaving it unset.
    pub(crate) default: &'static str,
    pub(crate) help: &'static str,
}

macro_rules! f {
    ($key:literal, $label:literal, $kind:expr, $default:literal, $help:literal) => {
        FieldSpec {
            key: $key,
            label: $label,
            kind: $kind,
            default: $default,
            help: $help,
        }
    };
}

const MS: FieldKind = FieldKind::Num {
    min: 0,
    max: 600_000,
};

pub(crate) struct Group {
    pub(crate) title: &'static str,
    pub(crate) fields: &'static [FieldSpec],
}

pub(crate) fn groups() -> &'static [Group] {
    const LOG: &[FieldSpec] = &[
        f!(
            "log.enabled",
            "enabled",
            FieldKind::Bool,
            "false",
            "Write the JSONL record for every hook invocation."
        ),
        f!(
            "log.path",
            "path",
            FieldKind::PathText,
            "~/.local/state/lord-kali/hook.jsonl",
            "Where that record is appended."
        ),
        f!(
            "log.retain_days",
            "retain days",
            FieldKind::Num { min: 1, max: 365 },
            "3",
            "How far back `prune-logs` and the watch housekeeper keep entries."
        ),
    ];
    const WORKTREE: &[FieldSpec] = &[f!(
        "worktree-protection.enabled",
        "enabled",
        FieldKind::Bool,
        "true",
        "Deny file ops targeting the parent project from inside a worktree."
    )];
    const APPROVAL: &[FieldSpec] = &[
        f!(
            "approval.enabled",
            "enabled",
            FieldKind::Bool,
            "false",
            "Route ask/passthrough calls to the central TUI instead of Claude Code's prompt."
        ),
        f!(
            "approval.live_rules",
            "live rules file",
            FieldKind::Text,
            "99-live.toml",
            "File the TUI appends allow/deny-always rules to."
        ),
        f!(
            "approval.state_dir",
            "state dir",
            FieldKind::PathText,
            "~/.local/state/lord-kali",
            "Queue and heartbeat live here."
        ),
        f!(
            "approval.guardrail_commands",
            "extra guardrails",
            FieldKind::List,
            "(built-in set only)",
            "Commands that default to tight scope, on top of rm/dd/Remove-Item/..."
        ),
        f!(
            "approval.self_timeout_ms",
            "self timeout",
            MS,
            "50000",
            "Max wait on the TUI before handing the call back to Claude Code."
        ),
        f!(
            "approval.poll_ms",
            "gate poll",
            MS,
            "200",
            "How often a blocked gate checks for its verdict."
        ),
        f!(
            "approval.heartbeat_fresh_ms",
            "heartbeat freshness",
            MS,
            "3000",
            "Heartbeat age past which the gate treats the TUI as dead."
        ),
        f!(
            "approval.pending_timeout_ms",
            "pending timeout",
            MS,
            "60000",
            "How long `watch --tail` tracks an un-executed call before flagging it."
        ),
        f!(
            "approval.watch_poll_ms",
            "watch poll",
            MS,
            "200",
            "The watch/TUI loop interval."
        ),
    ];
    const LLM: &[FieldSpec] = &[
        f!(
            "approval.llm.enabled",
            "enabled",
            FieldKind::Bool,
            "false",
            "Consult a safety model on passthrough calls. It can only ever auto-approve."
        ),
        f!(
            "approval.llm.model",
            "model",
            FieldKind::Text,
            "mistralai/mistral-small-3.2-24b-instruct",
            "Model id at the configured endpoint."
        ),
        f!(
            "approval.llm.base_url",
            "base url",
            FieldKind::Text,
            "https://openrouter.ai/api/v1/chat/completions",
            "Any OpenAI-compatible chat-completions endpoint."
        ),
        f!(
            "approval.llm.api_key_env",
            "api key env var",
            FieldKind::Text,
            "OPENROUTER_API_KEY",
            "NAME of the env var holding the key. The key itself never lives in config."
        ),
        f!(
            "approval.llm.queue_wait_ms",
            "operator grace (before)",
            MS,
            "0",
            "0 means the model answers first and you review its opinion."
        ),
        f!(
            "approval.llm.proposal_wait_ms",
            "your window (after)",
            MS,
            "5000",
            "How long you have to override a proposal before it auto-applies."
        ),
        f!(
            "approval.llm.timeout_ms",
            "request timeout",
            MS,
            "8000",
            "Per-attempt."
        ),
        f!(
            "approval.llm.max_attempts",
            "max attempts",
            FieldKind::Num { min: 1, max: 5 },
            "2",
            "Only transient errors retry. 1 escalates to you instead."
        ),
        f!(
            "approval.llm.cache_ttl_ms",
            "verdict cache TTL",
            FieldKind::Num {
                min: 0,
                max: 86_400_000
            },
            "3600000",
            "Reuse a verdict for an identical (tool, command, cwd). 0 disables."
        ),
        f!(
            "approval.llm.max_concurrent",
            "max concurrent",
            FieldKind::Num { min: 1, max: 32 },
            "4",
            "In-flight consults; the excess queues rather than hitting rate limits."
        ),
        f!(
            "approval.llm.tools",
            "tools judged",
            FieldKind::List,
            "Bash, PowerShell",
            "The model is a shell-command gate; other tools ride the operator path."
        ),
    ];
    const FILE: &[FieldSpec] = &[
        f!(
            "file.enabled",
            "enabled",
            FieldKind::Bool,
            "false",
            "Gate file mutations by target path."
        ),
        f!(
            "file.mutation_scope",
            "mutation scope",
            FieldKind::Choice(&["all", "outside_cwd"]),
            "all",
            "`all` gates every mutation; `outside_cwd` only those escaping cwd."
        ),
    ];
    const OTEL: &[FieldSpec] = &[
        f!("otel.enabled", "enabled", FieldKind::Bool, "false", "Export metrics and logs to an OTLP receiver."),
        f!("otel.endpoint", "endpoint", FieldKind::Text, "http://localhost:4318", "OTLP/HTTP base; /v1/metrics and /v1/logs are appended."),
        f!("otel.protocol", "protocol", FieldKind::Choice(&["http/json"]), "http/json", "Only OTLP/HTTP+JSON is implemented; anything else is a hard error, never a silent downgrade."),
        f!("otel.headers_env", "headers env var", FieldKind::Text, "LORD_KALI_OTEL_HEADERS", "NAME of the env var holding `k=v,k=v` auth headers. Values are never logged."),
        f!("otel.export_interval_ms", "export interval", FieldKind::Num { min: 1_000, max: 600_000 }, "10000", "How often the watch flushes a batch."),
        f!("otel.metrics", "export metrics", FieldKind::Bool, "true", ""),
        f!("otel.logs", "export logs", FieldKind::Bool, "true", ""),
        f!("otel.include_command", "include full command", FieldKind::Bool, "true", "Ships complete command lines to the collector. Check `redact` before pointing this at a remote one."),
        f!("otel.redact", "redact patterns", FieldKind::List, "(none)", "/regex/ patterns replaced in command text before export."),
        f!("otel.service_name", "service name", FieldKind::Text, "lord-kali", ""),
        f!("otel.checkpoint", "checkpoint", FieldKind::PathText, "~/.local/state/lord-kali/otel.checkpoint", "Last exported ts_ms, so a restart resumes."),
    ];
    &[
        Group {
            title: "log",
            fields: LOG,
        },
        Group {
            title: "worktree protection",
            fields: WORKTREE,
        },
        Group {
            title: "approval",
            fields: APPROVAL,
        },
        Group {
            title: "approval.llm",
            fields: LLM,
        },
        Group {
            title: "file",
            fields: FILE,
        },
        Group {
            title: "otel",
            fields: OTEL,
        },
    ]
}

pub(crate) fn settings_path() -> PathBuf {
    lord_kali_config_dir().join(SETTINGS_FILE)
}

// The editable document. Backed by a TOML table rather than a typed struct so one field
// table drives rendering, validation and persistence — and so an unset key stays unset
// (inheriting its default) instead of being written back as an explicit value.
#[derive(Clone, Default)]
pub(crate) struct Settings {
    table: toml::value::Table,
}

impl Settings {
    pub(crate) fn load_from(path: &Path) -> Result<Self, String> {
        match std::fs::read_to_string(path) {
            Ok(s) => toml::from_str::<toml::value::Table>(&s)
                .map(|table| Settings { table })
                .map_err(|e| format!("{}: {e}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Settings::default()),
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    }

    pub(crate) fn save_to(&self, path: &Path) -> Result<(), String> {
        let body = toml::to_string_pretty(&toml::Value::Table(self.table.clone()))
            .map_err(|e| format!("serializing settings: {e}"))?;
        write_atomic(path, &format!("{HEADER}\n{body}"))
            .map_err(|e| format!("{}: {e}", path.display()))
    }

    pub(crate) fn get(&self, key: &str) -> Option<&toml::Value> {
        let mut parts = key.split('.').peekable();
        let mut table = &self.table;
        while let Some(part) = parts.next() {
            let v = table.get(part)?;
            if parts.peek().is_none() {
                return Some(v);
            }
            table = v.as_table()?;
        }
        None
    }

    // Render a value the way the editor shows it, or None when the key is unset.
    pub(crate) fn display(&self, key: &str) -> Option<String> {
        Some(match self.get(key)? {
            toml::Value::String(s) => s.clone(),
            toml::Value::Boolean(b) => b.to_string(),
            toml::Value::Integer(i) => i.to_string(),
            toml::Value::Array(a) => a
                .iter()
                .map(|v| match v {
                    toml::Value::String(s) => s.clone(),
                    other => other.to_string(),
                })
                .collect::<Vec<_>>()
                .join(", "),
            other => other.to_string(),
        })
    }

    pub(crate) fn set(&mut self, key: &str, value: toml::Value) {
        let parts: Vec<&str> = key.split('.').collect();
        let Some((last, path)) = parts.split_last() else {
            return;
        };
        let mut table = &mut self.table;
        for part in path {
            // A non-table sitting where a section belongs is replaced; the field table is the
            // authority on shape, so a malformed hand edit is corrected rather than honoured.
            let entry = table
                .entry(part.to_string())
                .or_insert_with(|| toml::Value::Table(toml::value::Table::new()));
            if !entry.is_table() {
                *entry = toml::Value::Table(toml::value::Table::new());
            }
            table = entry.as_table_mut().expect("just ensured a table");
        }
        table.insert(last.to_string(), value);
    }

    // Remove a key so it falls back to its default. Empty parent sections are dropped too,
    // otherwise the file accumulates `[approval.llm]` headers with nothing under them.
    pub(crate) fn unset(&mut self, key: &str) {
        let parts: Vec<&str> = key.split('.').collect();
        unset_in(&mut self.table, &parts);
    }

    // Parse editor input for a field, or explain why it is not acceptable. An empty string
    // unsets the field (Ok(None)) rather than storing an empty value.
    pub(crate) fn parse_input(
        spec: &FieldSpec,
        input: &str,
    ) -> Result<Option<toml::Value>, String> {
        let t = input.trim();
        if t.is_empty() {
            return Ok(None);
        }
        Ok(Some(match spec.kind {
            FieldKind::Bool => match t.to_ascii_lowercase().as_str() {
                "true" | "yes" | "on" | "1" => toml::Value::Boolean(true),
                "false" | "no" | "off" | "0" => toml::Value::Boolean(false),
                _ => return Err("expected true or false".into()),
            },
            FieldKind::Num { min, max } => {
                let n: u64 = t
                    .parse()
                    .map_err(|_| "expected a whole number".to_string())?;
                if n < min || n > max {
                    return Err(format!("must be between {min} and {max}"));
                }
                toml::Value::Integer(n as i64)
            }
            FieldKind::Choice(options) => {
                if !options.contains(&t) {
                    return Err(format!("expected one of: {}", options.join(", ")));
                }
                toml::Value::String(t.to_string())
            }
            FieldKind::List => toml::Value::Array(
                t.split(',')
                    .map(|p| p.trim())
                    .filter(|p| !p.is_empty())
                    .map(|p| toml::Value::String(p.to_string()))
                    .collect(),
            ),
            FieldKind::Text | FieldKind::PathText => toml::Value::String(t.to_string()),
        }))
    }

    // Which settings sections this document actually declares. Only these replace the rule
    // files, so a partially-migrated setup keeps working.
    pub(crate) fn declared_sections(&self) -> Vec<&'static str> {
        SECTIONS
            .iter()
            .copied()
            .filter(|s| self.section_is_meaningful(s))
            .collect()
    }

    // `[file]` carries rules as well as settings, so a `[file]` table holding only `rules`
    // does not count as a declared settings section.
    fn section_is_meaningful(&self, section: &str) -> bool {
        declares(&self.table, section)
    }

    pub(crate) fn as_table(&self) -> &toml::value::Table {
        &self.table
    }
}

fn unset_in(table: &mut toml::value::Table, parts: &[&str]) {
    let Some((first, rest)) = parts.split_first() else {
        return;
    };
    if rest.is_empty() {
        table.remove(*first);
        return;
    }
    if let Some(toml::Value::Table(inner)) = table.get_mut(*first) {
        unset_in(inner, rest);
        if inner.is_empty() {
            table.remove(*first);
        }
    }
}

// A settings section declared in a rule file while `settings.toml` also declares it. Reported
// rather than merged: which one wins is exactly the thing that used to be unguessable.
pub(crate) struct Conflict {
    pub(crate) section: &'static str,
    pub(crate) file: String,
}

// Where one settings section currently resolves from. A section absent from `settings.toml`
// still applies from whatever rule file declares it, so this is what stops the editor
// claiming "default" for a value the gate is actually taking from somewhere else.
pub(crate) struct SectionOrigin {
    pub(crate) section: &'static str,
    pub(crate) in_settings: bool,
    // Rule files declaring it, in load order.
    pub(crate) rule_files: Vec<String>,
}

impl SectionOrigin {
    // What to show as the source of a value nobody has set in `settings.toml`.
    pub(crate) fn fallback(&self) -> Option<&str> {
        self.rule_files.first().map(String::as_str)
    }
}

// Does this table declare `section` as a *settings* section? `[[file.rules]]` is a rule, so a
// `[file]` table holding only rules declares nothing.
fn declares(table: &toml::value::Table, section: &str) -> bool {
    match table.get(section) {
        Some(toml::Value::Table(t)) if section == "file" => t.keys().any(|k| k != "rules"),
        Some(_) => true,
        None => false,
    }
}

// Scan the rule files for settings sections. `settings.toml` itself is excluded. Files that
// cannot be read or parsed are skipped — this reports where things come from, it does not
// validate configs.
pub(crate) fn section_origins(config_dir: &Path, settings: &Settings) -> Vec<SectionOrigin> {
    let declared = settings.declared_sections();
    let mut origins: Vec<SectionOrigin> = SECTIONS
        .iter()
        .map(|s| SectionOrigin {
            section: s,
            in_settings: declared.contains(s),
            rule_files: Vec::new(),
        })
        .collect();

    let Ok(entries) = std::fs::read_dir(config_dir) else {
        return origins;
    };
    let mut paths: Vec<PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.extension().and_then(|e| e.to_str()) == Some("toml")
                && p.file_name().and_then(|n| n.to_str()) != Some(SETTINGS_FILE)
        })
        .collect();
    paths.sort();

    for path in paths {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Ok(table) = toml::from_str::<toml::value::Table>(&text) else {
            continue;
        };
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        for origin in origins.iter_mut() {
            if declares(&table, origin.section) {
                origin.rule_files.push(name.to_string());
            }
        }
    }
    origins
}

// A section declared in both places. Derived from the same scan as the source column, so the
// two can never disagree about where a value comes from.
pub(crate) fn conflicts_from(origins: &[SectionOrigin]) -> Vec<Conflict> {
    origins
        .iter()
        .filter(|o| o.in_settings)
        .flat_map(|o| {
            o.rule_files.iter().map(move |file| Conflict {
                section: o.section,
                file: file.clone(),
            })
        })
        .collect()
}

// The settings section a dotted field key belongs to.
pub(crate) fn section_of(key: &str) -> &str {
    key.split('.').next().unwrap_or(key)
}

pub(crate) fn mutation_scope_str(scope: MutationScope) -> &'static str {
    match scope {
        MutationScope::All => "all",
        MutationScope::OutsideCwd => "outside_cwd",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(pairs: &[(&str, toml::Value)]) -> Settings {
        let mut st = Settings::default();
        for (k, v) in pairs {
            st.set(k, v.clone());
        }
        st
    }

    #[test]
    fn nested_keys_round_trip() {
        let st = s(&[
            ("approval.llm.model", toml::Value::String("m".into())),
            ("log.enabled", toml::Value::Boolean(true)),
        ]);
        assert_eq!(st.display("approval.llm.model").as_deref(), Some("m"));
        assert_eq!(st.display("log.enabled").as_deref(), Some("true"));
        assert_eq!(st.display("log.path"), None);
    }

    #[test]
    fn unset_removes_the_key_and_any_section_it_emptied() {
        let mut st = s(&[("approval.llm.model", toml::Value::String("m".into()))]);
        st.unset("approval.llm.model");
        assert_eq!(st.display("approval.llm.model"), None);
        assert!(
            st.as_table().is_empty(),
            "an emptied section must not linger: {:?}",
            st.as_table()
        );
    }

    #[test]
    fn unset_keeps_siblings() {
        let mut st = s(&[
            ("approval.llm.model", toml::Value::String("m".into())),
            ("approval.enabled", toml::Value::Boolean(true)),
        ]);
        st.unset("approval.llm.model");
        assert_eq!(st.display("approval.enabled").as_deref(), Some("true"));
    }

    #[test]
    fn a_hand_written_scalar_where_a_section_belongs_is_corrected() {
        let mut st = Settings::default();
        st.table.insert("approval".into(), toml::Value::Integer(1));
        st.set("approval.enabled", toml::Value::Boolean(true));
        assert_eq!(st.display("approval.enabled").as_deref(), Some("true"));
    }

    fn spec(kind: FieldKind) -> FieldSpec {
        FieldSpec {
            key: "k",
            label: "k",
            kind,
            default: "",
            help: "",
        }
    }

    #[test]
    fn blank_input_unsets_rather_than_storing_an_empty_value() {
        assert_eq!(
            Settings::parse_input(&spec(FieldKind::Text), "   ").unwrap(),
            None
        );
    }

    #[test]
    fn bool_accepts_the_usual_spellings_and_rejects_the_rest() {
        for yes in ["true", "YES", "on", "1"] {
            assert_eq!(
                Settings::parse_input(&spec(FieldKind::Bool), yes).unwrap(),
                Some(toml::Value::Boolean(true))
            );
        }
        for no in ["false", "No", "off", "0"] {
            assert_eq!(
                Settings::parse_input(&spec(FieldKind::Bool), no).unwrap(),
                Some(toml::Value::Boolean(false))
            );
        }
        assert!(Settings::parse_input(&spec(FieldKind::Bool), "maybe").is_err());
    }

    #[test]
    fn numbers_are_bounded_and_the_message_says_the_bounds() {
        let k = FieldKind::Num { min: 1, max: 5 };
        assert_eq!(
            Settings::parse_input(&spec(k), "3").unwrap(),
            Some(toml::Value::Integer(3))
        );
        let e = Settings::parse_input(&spec(k), "9").unwrap_err();
        assert!(e.contains('1') && e.contains('5'), "{e}");
        assert!(Settings::parse_input(&spec(k), "x").is_err());
    }

    #[test]
    fn choice_rejects_anything_off_the_list() {
        let k = FieldKind::Choice(&["all", "outside_cwd"]);
        assert!(Settings::parse_input(&spec(k), "all").is_ok());
        let e = Settings::parse_input(&spec(k), "some").unwrap_err();
        assert!(e.contains("outside_cwd"), "{e}");
    }

    #[test]
    fn lists_split_on_commas_and_drop_empties() {
        let v = Settings::parse_input(&spec(FieldKind::List), " a , b ,, c ")
            .unwrap()
            .unwrap();
        assert_eq!(
            v,
            toml::Value::Array(vec![
                toml::Value::String("a".into()),
                toml::Value::String("b".into()),
                toml::Value::String("c".into()),
            ])
        );
    }

    #[test]
    fn file_and_save_round_trip_through_disk() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(SETTINGS_FILE);
        let st = s(&[
            ("approval.enabled", toml::Value::Boolean(true)),
            ("approval.llm.max_concurrent", toml::Value::Integer(8)),
        ]);
        st.save_to(&path).unwrap();

        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.starts_with("# lord-kali settings"), "header missing");

        let back = Settings::load_from(&path).unwrap();
        assert_eq!(back.display("approval.enabled").as_deref(), Some("true"));
        assert_eq!(
            back.display("approval.llm.max_concurrent").as_deref(),
            Some("8")
        );
    }

    #[test]
    fn a_missing_file_loads_as_empty_not_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        let st = Settings::load_from(&tmp.path().join("nope.toml")).unwrap();
        assert!(st.declared_sections().is_empty());
    }

    // A broken file must say so. Silently treating it as empty would reset every setting.
    #[test]
    fn a_malformed_file_is_an_error_not_an_empty_document() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join(SETTINGS_FILE);
        std::fs::write(&path, "this is not = = toml").unwrap();
        assert!(Settings::load_from(&path).is_err());
    }

    #[test]
    fn only_declared_sections_are_reported() {
        let st = s(&[("log.enabled", toml::Value::Boolean(true))]);
        assert_eq!(st.declared_sections(), vec!["log"]);
    }

    // `[[file.rules]]` is a rule, not a setting, so a file section holding only rules must
    // not claim the section and must not be flagged as a conflict.
    #[test]
    fn file_rules_alone_are_not_a_settings_section() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("97-file.toml"),
            "[[file.rules]]\npath = \"**/*.md\"\ndecision = \"allow\"\n",
        )
        .unwrap();

        let mut only_rules = Settings::default();
        only_rules.set("file.rules", toml::Value::Array(vec![]));
        assert!(only_rules.declared_sections().is_empty());

        let with_setting = s(&[("file.enabled", toml::Value::Boolean(true))]);
        assert_eq!(with_setting.declared_sections(), vec!["file"]);
        assert!(
            conflicts_from(&section_origins(tmp.path(), &with_setting)).is_empty(),
            "a rules-only [file] section is not a settings conflict"
        );
    }

    #[test]
    fn conflicts_name_the_section_and_the_file() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("00-base.toml"),
            "[log]\nenabled = true\n[[bash.rules]]\ncommand = \"ls\"\ndecision = \"allow\"\n",
        )
        .unwrap();
        std::fs::write(
            tmp.path().join("95-approval.toml"),
            "[approval]\nenabled = true\n",
        )
        .unwrap();
        // Must be ignored as a source of conflicts with itself.
        std::fs::write(tmp.path().join(SETTINGS_FILE), "[log]\nenabled = true\n").unwrap();

        let st = s(&[
            ("log.enabled", toml::Value::Boolean(true)),
            ("approval.enabled", toml::Value::Boolean(true)),
        ]);
        let found = conflicts_from(&section_origins(tmp.path(), &st));
        let pairs: Vec<(&str, &str)> = found.iter().map(|c| (c.section, c.file.as_str())).collect();
        assert_eq!(
            pairs,
            vec![("log", "00-base.toml"), ("approval", "95-approval.toml")]
        );
    }

    #[test]
    fn nothing_declared_means_nothing_to_conflict_with() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("00-base.toml"), "[log]\nenabled = true\n").unwrap();
        assert!(conflicts_from(&section_origins(tmp.path(), &Settings::default())).is_empty());
    }

    // An unparseable rule file must not take the conflict scan down with it.
    #[test]
    fn a_broken_rule_file_is_skipped_not_fatal() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("00-broken.toml"), "= =").unwrap();
        std::fs::write(tmp.path().join("10-log.toml"), "[log]\nenabled = true\n").unwrap();
        let st = s(&[("log.enabled", toml::Value::Boolean(true))]);
        let found = conflicts_from(&section_origins(tmp.path(), &st));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].file, "10-log.toml");
    }

    #[test]
    fn every_field_key_is_unique_and_sits_under_a_known_section() {
        let mut seen = std::collections::HashSet::new();
        for g in groups() {
            for f in g.fields {
                assert!(seen.insert(f.key), "duplicate field key {}", f.key);
                let section = f.key.split('.').next().unwrap();
                assert!(
                    SECTIONS.contains(&section),
                    "{} is not under a known settings section",
                    f.key
                );
            }
        }
        assert!(seen.len() > 25, "field table looks truncated");
    }

    // Every default shown to the operator must be a value that field would actually accept,
    // or the editor is documenting something it would reject.
    #[test]
    fn documented_defaults_are_themselves_valid_input() {
        for g in groups() {
            for f in g.fields {
                if f.default.starts_with('(') {
                    continue; // "(none)" / "(built-in set only)" describe absence
                }
                assert!(
                    Settings::parse_input(f, f.default).is_ok(),
                    "{} documents a default its own validator rejects: {}",
                    f.key,
                    f.default
                );
            }
        }
    }
}
