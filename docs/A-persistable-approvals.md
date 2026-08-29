# A — Persistable approvals (the `sed -i` class)

**Status:** scoped down — scheduled last
**Symptom reported:** "`sed -i` is impossible to approve permanently — it always prompts."

## Decisions taken

| question | decision |
|---|---|
| Change rule precedence so live rules can override an earlier `ask`/`deny`? | **No.** An `ask` or `deny` outranks a later `allow` regardless of which file it sits in — like a firewall rule. The engine is correct as designed |
| So what is the `sed -i` case? | **A misconfiguration**, not a code defect. `00-base.toml` states an unconditional `sed -i → ask`; the TUI has been trying to override it from the wrong end |
| Middle scope rung for flag-first commands (A2) | **Approved** |
| Ordering | **Last**, after [C](C-config-in-tui.md). Cleaning up the config is the larger part of the remedy |

## 1. What is actually happening

### The precedence chain

Config files merge in lexicographic order and the merged rule list is **first-match-wins**
(`src/config.rs:798`). Within a file, explicit `[[bash.rules]]` come first and
`allowed_commands` are appended after them (`src/config.rs:83`).

For `sed`:

| # | source | pattern | decision |
|---|---|---|---|
| 1 | `00-base.toml:51` explicit | `-i` / `--in-place` regex | **ask** ← always wins |
| 2 | `00-base.toml` explicit | `w`/`W`/`e` regex | ask |
| 3 | `00-base.toml` `allowed_commands` | any args | allow |
| 4 | `99-live.toml` × 95 | specific `sed -i …` | allow — never reached |

That is the firewall behaving correctly. Rule 1 says "always confirm in-place edits", and no
lower-priority allow may quietly repeal it. The 95 dead rules in `99-live.toml` are the
consequence of asking the TUI to do something the model forbids.

### The real remedy, available today with no code change

Rules within a file are evaluated in definition order, so a scoped exception placed **above**
the catch-all in `00-base.toml` resolves it:

```toml
# sed -i is routine in these repos; confirm it everywhere else.
[[bash.rules]]
command = "sed"
args = "-i **"
decision = "allow"
projects = ["~/coflo", "~/lord-kali"]

[[bash.rules]]
command = "sed"
args = '/.*(^|\s)(-i|--in-place).*/'
decision = "ask"
reason = "sed -i/--in-place rewrites files in place — confirm."
```

Broad in arguments, narrow in blast radius — the exception is a deliberate, reviewable line in
the config, which is exactly what the firewall model wants.

> **`**`, not `*`.** Under glob-match-ultra, `*` stops at `/`. Command arguments routinely
> contain `/` — paths, and sed scripts like `'s/a/b/'` — so `-i *` would **not** match
> `sed -i 's/a/b/' file.md`. Every wildcarded-operand pattern must use `**`. This applies to
> the generated rung in A2 as well.

## 2. What is still worth building

### A2 — A middle rung for flag-first commands *(approved)*

`src/scope.rs::ladder()` offers shell commands two rungs, and for a flag-first command both
are useless:

- **tight** — the full argument string. For `sed -i '<script>' <file>` it pins the entire
  script, so it can never match a second time. The 95 live rules are 95 one-shot rules.
- **subcommand** — the first whitespace token, which for a flag-first command is the flag
  itself: `-i{, **}`. A blanket "any `sed -i`, anywhere".

Nothing in between expresses *"`sed -i` with any script, but only here"*.

| rung | shape | `sed -i 's/a/b/' x.md` |
|---|---|---|
| 0 tight | full args | `-i 's/a/b/' x.md{, **}` |
| 1 **flags + wildcard operands** *(new)* | flag tokens verbatim, positionals → `**` | `-i **` |
| 2 subcommand | first token | `-i{, **}` |
| 3 command-wide *(new)* | no args | *(any)* |

Rung 1 needs a small classifier: tokens starting with `-`/`--` are flags and are preserved;
everything else is a positional operand and collapses to `**`. For `sed` the first positional
is the script rather than a path, so "wildcard all positionals" is the correct generalisation —
path anchoring is A3's job, not the pattern's.

When the first token is a flag, rung 1 should be the **default** selection; the subcommand
rung is meaningless there.

### A3 — Persist `projects` scope from the TUI

`projects` exists on every rule type and the TUI never writes it. Add a second axis to the
scope control (a `p` key alongside `t`) toggling the persisted rule between global and
`projects = ["<repo root of cwd>"]`.

A2 without A3 is a downgrade: it makes it *easy* to persist `-i **` globally. The two ship
together, and rung 1 should default to project-scoped.

### A4 — Escape metacharacters when building patterns *(correctness bug)*

`tight_args()` (`src/scope.rs:121`) builds `format!("{args}{{, **}}")` from literal command
arguments, and the result is matched as a glob. From `99-live.toml`:

```toml
args = "-i '/^[[:space:]]*reminders:[[:space:]]/d' gitops/envs/{staging,qa,sandbox,…}/image-tags.yaml{, **}"
```

`[[:space:]]` is a glob character class and `{staging,qa,…}` is brace-alternation. The rule
does not mean what it appears to mean, and the error direction is **broadening**. Independent
of precedence; worth fixing regardless of the rest of A.

Fix: escape glob metacharacters, or emit a `/regex/` pattern built from an escaped literal.
Round-trip test — persist a rule from a command containing `[`, `{`, `*`; assert it matches
that command and does not match a broader one.

### A5 — Shadow detection *(not override)*

Under the firewall model this matters **more**, not less. The TUI can persist a rule that
provably cannot match, and today it reports success. That is silent failure.

After writing a live rule, re-resolve it against the freshly merged config and check the new
rule is the deciding one. If it is not, say so, and name the rule that outranks it:

```
persisted, but SHADOWED by 00-base.toml:51  sed  /.*(^|\s)(-i|--in-place).*/  → ask
edit that rule to change this outcome
```

The remedy is now a config edit — which is precisely what [C](C-config-in-tui.md) puts in
reach from the same screen. That dependency is why A goes after C.

### A6 — Rule garbage collection

`99-live.toml` is 7,798 lines. `lord-kali prune-rules` reports (and with `--apply`, removes):

- **shadowed** — another rule always decides first (flags the 95 sed rules immediately)
- **subsumed** — wholly covered by a broader live rule
- **cold** — never the deciding rule in the retained log window

### A7 — Provenance on persisted rules

`live_rules.rs::render_rule` hardcodes `reason = "approval-tui"` for operator and LLM rules
alike. Split into `"approval-tui: operator"` / `"approval-tui: llm <model>"` so A6 can prune by
source and [B](B-ai-first-gating.md) §B6 can attribute them.

## 3. Interaction with the other workstreams

- [B](B-ai-first-gating.md) — AI-first makes the auto-approver persist more rules, sooner, and
  it always persists at rung 0. Live-rule growth will accelerate before A lands; the
  `lordkali.rules.persisted` counter in [E](E-otel.md) is the early warning.
- [C](C-config-in-tui.md) — A5's shadow report is a panel in the settings screen, and C is what
  makes acting on it practical.

## 4. Open questions

1. **Does the `00-base.toml` `sed -i` rule get the scoped exception from §1**, or is it
   dropped entirely in favour of `[file]` gating plus the LLM? The exception is recommended —
   it keeps the confirm-by-default posture outside known repos.
2. **Rung 1 default scope** — project-scoped always, or global when the operator has already
   pressed `p`? Recommend project-scoped by default for flag-first commands.
3. **`prune-rules` automation** — report-only, or auto-apply inside `watch` like `prune-logs`?
   Auto-deleting rules the operator explicitly approved deserves a deliberate answer.
4. **Migration** — fold the current `99-live.toml` by hand again, or ship `prune-rules` first
   and let it drive the fold? The latter, if A6 lands with A.
