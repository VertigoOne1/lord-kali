# CLAUDE.md

Guidance for LLM agents working in this repository.

## Phase: active construction

lord-kali is being extended from a stateless pass/deny hook into a system that also
**takes over approvals centrally** via a long-lived TUI (see
`docs/plans/tui-approval-gate.md`). This is a deliberate, fair departure from the
binary's original minimalist scope. While this work is in flight, prefer momentum and
clarity over rule-literalism.

The strict production ruleset that previously governed this repo is preserved at
`docs/archive/CLAUDE.md`. Its principles remain *valuable* — treat them as the bar to
return to at stabilization, not as gates that block construction now.

## Principles (guidance, not gates)

These still matter. Honor their intent; don't be pedantic when construction needs the
latitude.

1. **DRY** — factor shared logic (line rendering, log IO, config parse) into one place.
   Some duplication while a design is still settling is acceptable; consolidate before
   the feature lands.

2. **Keep it simple by default** — reach for the simplest thing that works first. But
   the central-approval feature legitimately adds complexity (file-based IPC, a
   heartbeat, a ratatui TUI). New dependencies and new directories (`docs/plans/`,
   `docs/archive/`) are fine when they serve the plan. Don't reject a needed tool on
   minimalism grounds alone.

3. **Transparent errors — but graceful degradation is not error-hiding.** The old rule
   forbade fallbacks; this feature is *built* on intentional fallbacks (degrade to
   passthrough when no TUI is alive, self-timeout before Claude Code's hook timeout).
   The distinction: a **fallback that masks a failure** is forbidden; a **documented,
   deliberate degradation path** that keeps agents unblocked is the design. Make
   degradation paths explicit and commented as such. Genuine errors still surface
   loudly.

4. **Comments earn their place** — skip comments a competent engineer would infer.
   *Do* comment the non-obvious: why a degradation path exists, why a value must stay
   below Claude Code's timeout, what an IPC invariant guarantees.

5. **Tidy as you go** — don't leave dead files or half-wired code in a landed commit.
   Planning and archive artifacts under `docs/` are intentional and exempt.

## Safety rails (these stay firm)

- **Do not replace the installed binary** at `~/.local/bin/lord-kali` until the full
  test suite passes and disabled-mode parity is verified. Verify against the
  repo-built binary or stdin-fed hook JSON, never the installed path.
- **Opt-in by default** — new gating behavior must default off so existing users are
  unaffected until they enable it.
- **`cargo test` stays green** — the existing suite is the regression contract for the
  unchanged hook path. Baseline before this work: 151 passing.

## Code style

- Format with `cargo fmt`.
