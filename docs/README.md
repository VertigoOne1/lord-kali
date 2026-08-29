# lord-kali — planned work

Five workstreams, scoped separately so they can be taken one at a time. Each doc states the
problem with evidence from this machine, the decisions already taken, a proposed design, and
the open questions that remain.

| doc | area | status | one-line problem |
|---|---|---|---|
| [B](B-ai-first-gating.md) | AI-first gating | approved | The operator is forced to move before the model has an opinion — swap the two turns |
| [D](D-hook-coverage.md) | Hook coverage | approved | Claude Code exposes 31 hook events; lord-kali uses 2, and auto-mode denials are invisible to it |
| [C](C-config-in-tui.md) | Config in the TUI | approved | Behaviour settings are scattered across 21 files in a directory that is not where the README says it is |
| [E](E-otel.md) | OpenTelemetry | approved | No metrics or standard-format logs; lord-kali adopts OTel as its own producer |
| [A](A-persistable-approvals.md) | Persistable approvals | scoped down, last | `sed -i` is a config error, not a code error — but flag-first commands still have no usable scope rung |

## Order

1. **B** — smallest change, largest daily effect. `queue_wait_ms = 0` plus the TUI
   `consulting` state, a verdict cache and a concurrency cap for five concurrent sessions.
2. **D** — hook coverage and the TUI event labelling. Do the hook-input field parsing
   (`tool_use_id`, `permission_mode`, `agent_id`, `agent_type`) first; C, E and A all want it.
3. **C** — settings editor. Independent of everything, and its read-only footer alone removes
   the "where is my config" problem.
4. **E** — metrics and logs. Wants D's fields; reports on B's and A's behaviour.
5. **A** — after C, because the remedy for a shadowed rule is now a config edit.

## Decisions taken

Recorded here so they are not relitigated; each doc carries the same table in context.

- **Rule precedence is correct and does not change.** An `ask` or `deny` outranks a later
  `allow` regardless of which file it sits in, like a firewall rule. The `sed -i` case is a
  misconfiguration in `00-base.toml`, fixable today with a project-scoped exception placed
  above the catch-all. What remains in A is the flag-first scope rung (A2), the glob-escaping
  correctness bug (A4), and shadow *detection* — never override.
- **The model goes first, the operator reviews.** `queue_wait_ms → 0`, `proposal_wait_ms`
  stays at 5 s. The model never auto-denies; the operator always wins.
- **No daemon.** `watch` is kept open permanently, fronting ~5 concurrent Claude sessions.
  Both the AI-first path and the OTel exporter ride it.
- **lord-kali's OTel is its own.** Own `service.name`, own namespace, own config. No trace
  parenting or correlation with Claude Code's telemetry, which is handled separately.
- **The TUI must name the hook event** behind every stream line and pending call, now that
  more than one event feeds it.

## Cross-cutting

- **`tool_use_id`** ([D](D-hook-coverage.md) §D4) is the correlation key for the pre/post fix
  (D1), the TUI dedupe (D6) and the OTel record identity (E). Parse it early.
- **`operator_commit` logging** ([B](B-ai-first-gating.md) §B6) is the missing signal behind
  both the prompt-tuning loop and E's `lordkali.llm.agreement` metric. 151 model verdicts are
  logged today; not one operator decision is.
- **Timeout budget.** The hook timeout is 600 s, not the 60 s `self_timeout_ms = 50000` was
  sized for. B's swap shortens the exchange to ~13 s, so no change is needed now — but the
  constraint is gone if the operator window is ever widened.
