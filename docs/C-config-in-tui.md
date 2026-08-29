# C — Config management in the TUI

**Status:** approved
**Goal:** press `m` in `lord-kali watch` to open a settings editor for the config that
controls lord-kali's *behaviour* — paths, timers, model, endpoints, feature switches. Rule
lists stay out of scope; those are the `a`/`o`/`t` flow and [A](A-persistable-approvals.md).

**C is also the larger half of A's remedy.** Since rule precedence stays as it is
([A](A-persistable-approvals.md), decisions), the only way to change a shadowed outcome is to
edit the rule that outranks it — so A is scheduled after C, and A's shadow report (§A5) lands
in this screen.

## 1. Why it is confusing today

### Configuration is spread across 21 files in a directory nobody remembers

`lord_kali_config_dir()` (`src/config.rs:792`) is `dirs::config_dir()/lord-kali`. On this
machine that resolves to `C:\Users\MarnusvanWyk\AppData\Roaming\lord-kali\` — **not**
`~/.config/lord-kali/` as the README says everywhere. The README is wrong on Windows, which is
a documentation bug worth fixing alongside this work.

State lives in a *different* tree: `~/.local/state/lord-kali/` (`hook.jsonl`, `queue/`,
`tui.heartbeat`).

Behaviour settings are scattered across the rule files by convention only:

| section | currently lives in |
|---|---|
| `[log]` | `00-base.toml` |
| `[worktree-protection]` | nowhere — implicit default |
| `[approval]` | `95-approval.toml` (2 lines) |
| `[approval.llm]` | `96-llm.toml` (4 lines) |
| `[file]` | `97-file.toml`, mixed in with `[[file.rules]]` |

### Merge semantics differ per section, invisibly

- `[log]` — last file with the section wins
- `[approval]` — `enabled` ORs across files; other keys last-wins; `guardrail_commands` unions
- `[[*.rules]]` — concatenated, first-match-wins

Three different rules in one config system. This is the real source of "I can never remember
where config is or which copy wins", and no amount of TUI polish fixes it without addressing
it directly.

## 2. Proposed work

### C1 — Separate settings from rules in the model

Introduce an explicit split in `src/config.rs`:

- **settings** — scalar behaviour: `[log]`, `[worktree-protection]`, `[approval]`,
  `[approval.llm]`, `[file] enabled`/`mutation_scope`, and `[otel]` from [E](E-otel.md)
- **rules** — `[[*.rules]]`, `allowed_commands`, `[[group]]`

Only rules need the merge-and-order machinery. Settings do not.

### C2 — One canonical settings file, loaded independently of rule order

The TUI writes to a single file — proposed `settings.toml` in the config dir.

Ordering is the trap: `[log]` is last-wins, so a `10-settings.toml` would *lose* to
`00-base.toml`'s `[log]`. Two ways out:

- **(a) Settings resolve from the designated settings file only**, independent of the
  lexicographic rule-file order. If a settings section also appears in a rule file, it is
  reported as a conflict rather than silently merged. **Recommended** — it removes the
  ordering puzzle instead of encoding it in a filename.
- (b) Name it `98-settings.toml` so it wins the last-wins sections. Cheaper, but keeps the
  puzzle and still breaks for union-merged keys like `guardrail_commands`.

**Migration.** On first open, if settings sections are found in rule files, offer to hoist
them into `settings.toml`, leaving a pointer comment behind. One-time, explicit, reversible —
never silent.

### C3 — What the editor shows

A scrollable form, grouped by section. Each row: **key · current value · effective source
(which file set it) · default**. Types: bool toggle, bounded integer, string, path, enum,
string list.

Sections and keys:

| section | keys |
|---|---|
| `[log]` | `enabled`, `path`, retention days *(new — the 3-day prune window is hardcoded)* |
| `[worktree-protection]` | `enabled` |
| `[approval]` | `enabled`, `live_rules`, `state_dir`, `guardrail_commands`, `self_timeout_ms`, `poll_ms`, `heartbeat_fresh_ms`, `pending_timeout_ms`, `watch_poll_ms` |
| `[approval.llm]` | `enabled`, `model`, `base_url`, `api_key_env`, `queue_wait_ms`, `proposal_wait_ms`, `timeout_ms`, `max_attempts`, `tools`, `system`, `user` |
| `[file]` | `enabled`, `mutation_scope` |
| `[otel]` | see [E](E-otel.md) |

**Live validation.** The budget invariant from [B](B-ai-first-gating.md) renders as a computed
line, red when violated:

```
queue_wait_ms + (timeout_ms × max_attempts) + proposal_wait_ms  <  self_timeout_ms
```

**A read-only footer that answers "where is my config?" permanently:**

```
config dir   C:\Users\…\AppData\Roaming\lord-kali\
settings     …\settings.toml
live rules   …\99-live.toml            (7798 lines, 95 shadowed — see prune-rules)
state dir    C:\Users\…\.local\state\lord-kali\
log          …\hook.jsonl              (18.1 MB)
loaded       00-base, 15-noop-captures, 20-bash, … , 99-live
```

This footer is arguably more of the fix than the editing is.

### C4 — Reload semantics

The hook loads config fresh per process, so a saved change takes effect on the very next tool
call with no restart. Good.

`watch` is the problem: it reads config once at startup, and the running `AutoApprover`,
timers, and log tail are built from it. A save must rebuild them in place:

- `[approval]` timers — re-read into the loop
- `[approval.llm]` — rebuild the `AutoApprover` (including re-reading the API key env var, and
  reporting cleanly when the newly-named var is unset)
- `[log] path` — reopen the tail
- `[otel]` — rebuild the exporter

Anything that cannot be hot-applied must say so explicitly rather than appearing to save.

### C5 — Write safety

Reuse `queue::write_atomic`. Note that serialising a settings struct back to TOML **destroys
comments**. That is acceptable for a dedicated, generated file with a "managed by
`lord-kali watch`" header; it is not acceptable for hand-written commented files like
`00-base.toml`. This is a second, independent argument for C2(a).

### C6 — Secrets

`api_key_env` is a variable *name*. The editor edits the name and displays presence only:

```
api_key_env   OPENROUTER_API_KEY        key present in this process: yes
```

The value is never rendered, never logged, never written to config. Same for any `[otel]`
auth header — configure via `headers_env`, not literal values.

### C7 — Keybinding

`m` for menu. The current TUI binds `←/→`, `space`, `↑/↓`, `t`, `Tab`, `a`, `o`, `s`, `q` —
`m` is free. It should be a **modal overlay** that fully owns input while open (approvals keep
queueing behind it and the heartbeat keeps beating, so the gate never degrades because the
operator is editing settings). `Esc` cancels, `Enter`/`s` saves.

## 3. Open questions

1. **Settings-file resolution** — (a) independent designated file, or (b) `98-` prefix
   ordering? (a) recommended.
2. **Migration prompt** — hoist existing sections automatically on first open (with
   confirmation), or emit a report and let the operator move them?
3. **Project-local config.** `.claude/lord-kali.toml` is discovered per-project and has the
   highest priority. Should the TUI edit it too? Recommend **global only** — a shared TUI
   editing a repo-committed file is a footgun — but the footer should *show* when a
   project-local file is overriding a setting.
4. **Multiline prompt fields** (`[approval.llm] system` / `user`). Inline editor, or shell out
   to `$EDITOR`? Shelling out from inside a ratatui alternate screen needs care.
5. **Should `m` also expose actions**, not just values — "open config dir", "reload now",
   "run prune-rules", "run prune-logs"? These are the other things one leaves the TUI for.
6. **Does the `[approval] enabled` toggle need a guard?** Turning it off from inside the TUI
   makes the TUI itself inert. Probably fine, but it should say so before saving.
