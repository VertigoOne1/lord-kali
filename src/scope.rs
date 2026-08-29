// The persisted-scope ladder behind the approval TUI's `t` toggle. Each actionable node
// exposes an ordered list of `ScopeRung`s (tightest → broadest); `t` cycles which rung an
// apply-always rule is written at.
//
// Commands: tight (full args) → flag-scoped (flags kept, operands wildcarded) → subcommand
// (first token) → command-wide. The flag-scoped rung exists because the subcommand heuristic
// is meaningless for a flag-first command — `sed -i '<script>' <file>` has no subcommand, and
// tight pins the whole script so it can never match twice. It is omitted when there is
// nothing to generalise. Files: full path → dir subtree → cwd subtree → extension glob.
//
// Argument text is escaped before it becomes a pattern: it is literal text going into a glob,
// and real commands contain `*`, `[`, `{`.
//
// A rung carries the full (target, args) the LiveRule will use: command rungs vary `args`
// and pin `target` to the basename; file/web/mcp rungs vary `target` and carry no `args`.

// Mutating file tools — these get the full multi-rung ladder and route to the gate.
pub(crate) const MUTATION_TOOLS: &[&str] = &["Write", "Edit", "MultiEdit", "NotebookEdit"];
// Read-class file tools — gated only when the path escapes cwd, persisted at a single
// (full-path) rung, so they never cycle.
pub(crate) const READ_TOOLS: &[&str] = &["Read", "Glob", "Grep"];

pub(crate) fn is_mutation_tool(tool: &str) -> bool {
    MUTATION_TOOLS.contains(&tool)
}

pub(crate) fn is_read_tool(tool: &str) -> bool {
    READ_TOOLS.contains(&tool)
}

#[derive(Clone, PartialEq, Debug)]
pub(crate) struct ScopeRung {
    pub(crate) target: String,
    pub(crate) args: Option<String>,
}

// Build the ladder for one node plus the default selected index.
// - `shell`: "bash"/"powershell"/"web-fetch"/"mcp"/"file"
// - `tool`: the originating tool name (distinguishes file mutation vs read)
// - `command`: command basename for shells, full URL/tool name for web/mcp, the resolved
//   (forward-slash, absolute) path for file nodes
// - `args`: the command's arguments (ignored for non-shell kinds)
// - `cwd`: the hook cwd, used for the file "cwd subtree" rung
// - `guardrail`: whether a command basename is destructive (defaults its rung to tight)
pub(crate) fn ladder(
    shell: &str,
    tool: &str,
    command: &str,
    args: &str,
    cwd: Option<&str>,
    guardrail: bool,
) -> (Vec<ScopeRung>, usize) {
    match shell {
        "bash" | "powershell" => {
            let rung = |args| ScopeRung {
                target: command.to_string(),
                args,
            };
            let tight = rung(tight_args(args));
            // Omitted entirely when there is nothing to generalise — a rung with no args
            // pattern is the command-wide rung, which already sits at the end of the ladder.
            let flagged = flag_scoped_args(args).map(|a| rung(Some(a)));
            let sub = rung(scope_args(args));
            let wide = rung(None);

            // Guardrail commands pin their full arguments. Otherwise the first token decides:
            // for a flag-first command like `sed -i '<script>' <file>` the "subcommand" is the
            // flag `-i`, which says nothing useful, so the flag-scoped rung is the sane
            // default there. See docs/A-persistable-approvals.md §A2.
            let preferred = match (&flagged, guardrail) {
                (_, true) => tight.clone(),
                // A flag-first command's "subcommand" is the flag itself, which says nothing
                // useful; the flag-scoped rung is the sane default there instead.
                (Some(f), false) if is_flag(args.split_whitespace().next().unwrap_or("")) => {
                    f.clone()
                }
                _ => sub.clone(),
            };
            let mut rungs = vec![tight];
            rungs.extend(flagged);
            rungs.push(sub);
            rungs.push(wide);
            dedup(&mut rungs);
            let default = rungs.iter().position(|r| *r == preferred).unwrap_or(0);
            (rungs, default)
        }
        "file" if is_read_tool(tool) => (vec![full_rung(command)], 0),
        "file" => {
            let path = normalize(command);
            let mut rungs = vec![full_rung(&path)];
            if let Some(dir) = parent_dir(&path) {
                rungs.push(subtree_rung(dir));
            }
            if let Some(c) = cwd.map(normalize) {
                let c = c.trim_end_matches('/');
                if !c.is_empty() && under(&path, c) {
                    rungs.push(subtree_rung(c));
                }
            }
            if let Some(ext) = extension(&path) {
                rungs.push(ScopeRung {
                    target: format!("**/*.{ext}"),
                    args: None,
                });
            }
            dedup(&mut rungs);
            (rungs, 0)
        }
        // web-fetch, mcp, and anything else: one fixed rung, no args — `t` is a no-op.
        _ => (
            vec![ScopeRung {
                target: command.to_string(),
                args: None,
            }],
            0,
        ),
    }
}

fn full_rung(path: &str) -> ScopeRung {
    ScopeRung {
        target: normalize(path),
        args: None,
    }
}

fn subtree_rung(dir: &str) -> ScopeRung {
    ScopeRung {
        target: format!("{dir}/**"),
        args: None,
    }
}

// Scope a command rule to its subcommand: first arg token + trailing wildcard (e.g.
// "push" -> "push{, **}"). None when the node had no args (command-wide).
fn scope_args(args: &str) -> Option<String> {
    let first = args.split_whitespace().next()?;
    Some(format!("{first}{{, **}}"))
}

// Tight (full-args) scope, tolerating extra trailing args. None only when there were none.
// The arguments are escaped first: they are literal text going into a *glob*, and a real
// command routinely contains `*`, `[`, `{` — a sed script like `/^[[:space:]]*x/d` would
// otherwise become a character class and brace alternation, matching far more than the
// command it came from.
fn tight_args(args: &str) -> Option<String> {
    if args.is_empty() {
        None
    } else {
        Some(format!("{}{{, **}}", escape_glob(args)))
    }
}

// Escape every glob metacharacter so the text matches itself and nothing else.
pub(crate) fn escape_glob(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(c, '\\' | '*' | '?' | '[' | ']' | '{' | '}' | '!') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

fn is_flag(token: &str) -> bool {
    token.starts_with('-') && token.len() > 1
}

// Flags kept verbatim, everything from the first non-flag token on collapsed to `**`.
// `**` and not `*`, because arguments routinely contain `/` — paths, and sed scripts like
// 's/a/b/' — and `*` stops at a segment boundary, so `-i *` would not match `-i 's/a/b/' x`.
//
// None when there is nothing to generalise (no arguments, or nothing but flags), so this rung
// collapses into the tight one rather than duplicating it.
fn flag_scoped_args(args: &str) -> Option<String> {
    let mut flags: Vec<&str> = Vec::new();
    let mut saw_operand = false;
    for tok in args.split_whitespace() {
        if saw_operand || !is_flag(tok) {
            saw_operand = true;
        } else {
            flags.push(tok);
        }
    }
    // Nothing to generalise: no operands to wildcard, or no flags to keep — the latter would
    // produce a bare `**`, which is command-wide and already the broadest rung.
    if !saw_operand || flags.is_empty() {
        return None;
    }
    Some(format!("{} **", escape_glob(&flags.join(" "))))
}

fn normalize(path: &str) -> String {
    path.replace('\\', "/")
}

fn parent_dir(path: &str) -> Option<&str> {
    let idx = path.rfind('/')?;
    if idx == 0 {
        None
    } else {
        Some(&path[..idx])
    }
}

fn under(path: &str, dir: &str) -> bool {
    path == dir || path.starts_with(&format!("{dir}/"))
}

// The extension of the final path segment, or None for extensionless / dotfile names.
fn extension(path: &str) -> Option<&str> {
    let seg = path.rsplit('/').next()?;
    let dot = seg.rfind('.')?;
    if dot == 0 || dot + 1 >= seg.len() {
        None
    } else {
        Some(&seg[dot + 1..])
    }
}

// Drop later rungs equal to an earlier one, preserving order. Argless commands and files
// directly in cwd collapse to a single rung this way, making `t` a true no-op there.
fn dedup(rungs: &mut Vec<ScopeRung>) {
    let mut seen: Vec<ScopeRung> = Vec::new();
    rungs.retain(|r| {
        if seen.contains(r) {
            false
        } else {
            seen.push(r.clone());
            true
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rung(target: &str, args: Option<&str>) -> ScopeRung {
        ScopeRung {
            target: target.to_string(),
            args: args.map(String::from),
        }
    }

    // ---- A2: the flag-scoped rung (docs/A-persistable-approvals.md) ---------------------

    // `sed -i '<script>' <file>` is the motivating case: tight pins the whole script so it
    // can never match twice, and the "subcommand" is the flag `-i`, which says nothing.
    #[test]
    fn a_flag_first_command_defaults_to_the_flag_scoped_rung() {
        let (rungs, def) = ladder("bash", "Bash", "sed", "-i 's/a/b/' x.md", None, false);
        assert_eq!(rungs[def], rung("sed", Some("-i **")));
        assert_eq!(def, 1, "tighter than subcommand, broader than tight");
        assert_eq!(rungs[0].args.as_deref(), Some(r"-i 's/a/b/' x.md{, **}"));
        assert_eq!(rungs[2], rung("sed", Some("-i{, **}")));
        assert_eq!(
            rungs[3],
            rung("sed", None),
            "command-wide is the broadest rung"
        );
    }

    #[test]
    fn multiple_flags_are_all_kept() {
        let (rungs, def) = ladder("bash", "Bash", "sed", "-i -e 's/a/b/' x.md", None, false);
        assert_eq!(rungs[def].args.as_deref(), Some("-i -e **"));
    }

    // A flag appearing after an operand is not hoisted — the kept prefix is only the leading
    // run of flags, so the rule stays predictable from reading the command left to right.
    #[test]
    fn only_the_leading_run_of_flags_is_kept() {
        let (rungs, _) = ladder("bash", "Bash", "sed", "-i x.md -e 's/a/b/'", None, false);
        assert_eq!(rungs[1].args.as_deref(), Some("-i **"));
    }

    // No flags means nothing to generalise beyond command-wide, so the rung is omitted
    // rather than emitted as a bare `**` duplicate of it.
    #[test]
    fn a_subcommand_style_command_gets_no_flag_rung() {
        let (rungs, def) = ladder("bash", "Bash", "git", "push origin", None, false);
        assert_eq!(rungs[def], rung("git", Some("push{, **}")));
        assert!(
            rungs.iter().all(|r| r.args.as_deref() != Some("**")),
            "a bare ** rung duplicates command-wide: {rungs:?}"
        );
    }

    #[test]
    fn a_command_with_only_flags_has_no_separate_flag_rung() {
        let (rungs, _) = ladder("bash", "Bash", "sed", "--version", None, false);
        assert_eq!(rungs[0].args.as_deref(), Some("--version{, **}"));
        assert!(rungs
            .iter()
            .all(|r| r.args.as_deref() != Some("--version **")));
    }

    // A lone "-" is an operand (stdin), not a flag.
    #[test]
    fn a_bare_dash_is_an_operand() {
        assert!(!is_flag("-"));
        assert!(is_flag("-i"));
        assert!(is_flag("--in-place"));
    }

    // ---- A4: arguments are literal text going into a glob -------------------------------

    // The bug this fixes, end to end: a real sed script contains glob metacharacters, and
    // interpolating it raw produced a pattern that matched far more than the command it came
    // from. Verified through the actual matcher, not just the escaping function.
    #[test]
    fn a_persisted_tight_rule_matches_its_own_command_and_not_a_broader_one() {
        use crate::config::compile_pattern;
        let args = r"-i '/^[[:space:]]*reminders:/d' gitops/envs/{staging,qa}/image-tags.yaml";
        let (rungs, _) = ladder("bash", "Bash", "sed", args, None, true);
        let pattern = compile_pattern(rungs[0].args.as_deref().unwrap());

        assert!(
            pattern.is_match(args),
            "must match the command it came from"
        );
        assert!(
            !pattern.is_match("-i '/^ reminders:/d' gitops/envs/staging/image-tags.yaml"),
            "brace alternation and the character class must not have stayed live"
        );
    }

    #[test]
    fn every_glob_metacharacter_survives_a_round_trip() {
        use crate::config::compile_pattern;
        for literal in [
            "a*b",
            "a?b",
            "a[0-9]b",
            "a{x,y}b",
            "!a",
            r"C:\Users\me",
            "**",
            "a]b",
            "a}b",
        ] {
            let pattern = compile_pattern(&format!("{}{{, **}}", escape_glob(literal)));
            assert!(pattern.is_match(literal), "{literal} must match itself");
        }
    }

    #[test]
    fn escaping_does_not_widen_a_pattern() {
        use crate::config::compile_pattern;
        let pattern = compile_pattern(&format!("{}{{, **}}", escape_glob("rm -rf ./out*")));
        assert!(pattern.is_match("rm -rf ./out*"));
        assert!(
            !pattern.is_match("rm -rf ./output-everything"),
            "the literal * must not have stayed a wildcard"
        );
    }

    #[test]
    fn command_non_guardrail_defaults_to_subcommand() {
        let (rungs, def) = ladder("bash", "Bash", "git", "push origin", None, false);
        assert_eq!(rungs[0], rung("git", Some("push origin{, **}"))); // tight
        assert_eq!(rungs[1], rung("git", Some("push{, **}"))); // subcommand
        assert_eq!(def, 1, "non-guardrail prefers subcommand");
    }

    #[test]
    fn command_guardrail_defaults_to_tight() {
        let (rungs, def) = ladder("bash", "Bash", "rm", "-rf ./out", None, true);
        assert_eq!(def, 0);
        assert_eq!(rungs[def], rung("rm", Some("-rf ./out{, **}")));
    }

    #[test]
    fn argless_command_collapses_to_single_rung() {
        let (rungs, def) = ladder("bash", "Bash", "gh", "", None, false);
        assert_eq!(rungs.len(), 1);
        assert_eq!(rungs[0], rung("gh", None));
        assert_eq!(def, 0);
    }

    // Regression: command rung args must equal the legacy scope_args/tight_args output.
    #[test]
    fn command_rungs_match_legacy_scope() {
        assert_eq!(scope_args("pr list"), Some("pr{, **}".to_string()));
        assert_eq!(scope_args(""), None);
        assert_eq!(tight_args("-rf ./x"), Some("-rf ./x{, **}".to_string()));
        assert_eq!(tight_args(""), None);
    }

    #[test]
    fn web_and_mcp_single_fixed_rung() {
        let (w, dw) = ladder(
            "web-fetch",
            "WebFetch",
            "https://docs.rs/tokio?x=1",
            "",
            None,
            false,
        );
        assert_eq!(w, vec![rung("https://docs.rs/tokio?x=1", None)]);
        assert_eq!(dw, 0);
        let (m, _) = ladder("mcp", "mcp__x__y", "mcp__x__y", "", None, false);
        assert_eq!(m, vec![rung("mcp__x__y", None)]);
    }

    #[test]
    fn file_mutation_full_dir_cwd_ext_ladder() {
        let (rungs, def) = ladder(
            "file",
            "Edit",
            "/home/u/proj/src/app/main.rs",
            "",
            Some("/home/u/proj"),
            false,
        );
        assert_eq!(def, 0);
        assert_eq!(
            rungs,
            vec![
                rung("/home/u/proj/src/app/main.rs", None),
                rung("/home/u/proj/src/app/**", None),
                rung("/home/u/proj/**", None),
                rung("**/*.rs", None),
            ]
        );
    }

    #[test]
    fn file_mutation_windows_path_normalized() {
        let (rungs, _) = ladder(
            "file",
            "Write",
            r"C:\Users\me\proj\Startup.cs",
            "",
            Some(r"C:\Users\me\proj"),
            false,
        );
        // file directly in cwd: dir-subtree and cwd-subtree coincide and dedup to one.
        assert_eq!(
            rungs,
            vec![
                rung("C:/Users/me/proj/Startup.cs", None),
                rung("C:/Users/me/proj/**", None),
                rung("**/*.cs", None),
            ]
        );
    }

    #[test]
    fn file_outside_cwd_has_no_cwd_rung() {
        let (rungs, _) = ladder(
            "file",
            "Edit",
            "/other/repo/x/y.cs",
            "",
            Some("/home/u/proj"),
            false,
        );
        assert_eq!(
            rungs,
            vec![
                rung("/other/repo/x/y.cs", None),
                rung("/other/repo/x/**", None),
                rung("**/*.cs", None),
            ]
        );
    }

    #[test]
    fn file_read_is_single_full_rung() {
        let (rungs, def) = ladder(
            "file",
            "Read",
            "/other/lib/util.rs",
            "",
            Some("/home/u/proj"),
            false,
        );
        assert_eq!(rungs, vec![rung("/other/lib/util.rs", None)]);
        assert_eq!(def, 0);
    }

    #[test]
    fn extensionless_and_dotfiles_have_no_ext_rung() {
        let (rungs, _) = ladder("file", "Edit", "/p/Makefile", "", None, false);
        assert!(rungs.iter().all(|r| !r.target.starts_with("**/*.")));
        let (rungs2, _) = ladder("file", "Edit", "/p/.gitignore", "", None, false);
        assert!(rungs2.iter().all(|r| !r.target.starts_with("**/*.")));
    }
}
