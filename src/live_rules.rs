// Persists "always" decisions made in the approval TUI to a live ruleset file under
// ~/.config/lord-kali/ (default 99-live.toml, sorted last so it never shadows explicit
// user rules). Each entry is an ordinary [[bash/powershell/web-fetch.rules]] table with no
// args, so it reuses the existing config format and matches the command for any arguments.

use crate::config::{lord_kali_config_dir, ApprovalConfig};
use crate::queue::write_atomic;
use std::path::{Path, PathBuf};

pub(crate) struct LiveRule {
    // "bash", "powershell", or "web-fetch" — picks the rules table.
    pub(crate) shell: String,
    // command basename for bash/powershell, or the full URL for web-fetch.
    pub(crate) target: String,
    pub(crate) allow: bool,
}

pub(crate) fn live_rules_path(approval: &ApprovalConfig) -> PathBuf {
    lord_kali_config_dir().join(approval.live_rules_file())
}

fn render_rule(r: &LiveRule) -> String {
    let decision = if r.allow { "allow" } else { "deny" };
    let value = toml::Value::String(r.target.clone()).to_string();
    let (table, key) = match r.shell.as_str() {
        "web-fetch" => ("web-fetch.rules", "url"),
        "powershell" => ("powershell.rules", "command"),
        _ => ("bash.rules", "command"),
    };
    format!(
        "\n[[{table}]]\n{key} = {value}\ndecision = \"{decision}\"\nreason = \"approval-tui\"\n"
    )
}

// Append entries to the live file (read-modify-write atomically). Existing rules are
// preserved; we never rewrite or dedup, keeping the writer trivial and the file an
// append-only audit of what was whitelisted.
pub(crate) fn append_rules(path: &Path, rules: &[LiveRule]) -> std::io::Result<()> {
    if rules.is_empty() {
        return Ok(());
    }
    let mut content = std::fs::read_to_string(path).unwrap_or_default();
    if !content.is_empty() && !content.ends_with('\n') {
        content.push('\n');
    }
    for r in rules {
        content.push_str(&render_rule(r));
    }
    write_atomic(path, &content)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, RawConfig};
    use crate::decision::{handle_bash, handle_web_fetch, Decision};

    fn load(path: &Path) -> Config {
        let content = std::fs::read_to_string(path).unwrap();
        let raw: RawConfig = toml::from_str(&content).unwrap();
        Config::from(raw)
    }

    #[test]
    fn allow_and_deny_round_trip_through_loader() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("99-live.toml");
        append_rules(
            &path,
            &[
                LiveRule {
                    shell: "bash".into(),
                    target: "gh".into(),
                    allow: true,
                },
                LiveRule {
                    shell: "bash".into(),
                    target: "curl".into(),
                    allow: false,
                },
            ],
        )
        .unwrap();

        let config = load(&path);
        assert_eq!(
            handle_bash(&config.bash, None, "gh pr list").map(|(d, _)| d),
            Some(Decision::Allow)
        );
        assert_eq!(
            handle_bash(&config.bash, None, "curl https://x").map(|(d, _)| d),
            Some(Decision::Deny)
        );
    }

    #[test]
    fn appends_preserve_prior_rules() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("99-live.toml");
        append_rules(
            &path,
            &[LiveRule {
                shell: "bash".into(),
                target: "gh".into(),
                allow: true,
            }],
        )
        .unwrap();
        append_rules(
            &path,
            &[LiveRule {
                shell: "bash".into(),
                target: "jq".into(),
                allow: true,
            }],
        )
        .unwrap();

        let config = load(&path);
        assert_eq!(
            handle_bash(&config.bash, None, "gh pr list").map(|(d, _)| d),
            Some(Decision::Allow)
        );
        assert_eq!(
            handle_bash(&config.bash, None, "jq .").map(|(d, _)| d),
            Some(Decision::Allow)
        );
    }

    #[test]
    fn web_fetch_persists_url() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("99-live.toml");
        append_rules(
            &path,
            &[LiveRule {
                shell: "web-fetch".into(),
                target: "https://docs.rs/tokio".into(),
                allow: true,
            }],
        )
        .unwrap();

        let config = load(&path);
        assert_eq!(
            handle_web_fetch(&config.web_fetch, None, "https://docs.rs/tokio").map(|(d, _)| d),
            Some(Decision::Allow)
        );
    }
}
