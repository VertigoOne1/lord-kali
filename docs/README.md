# lord-kali — planned work

Five workstreams, scoped separately so they can be taken one at a time. Each doc states the
problem with evidence from this machine, the decisions already taken, a proposed design, and
the open questions that remain.

| doc | area | status | what landed |
|---|---|---|---|
| [B](B-ai-first-gating.md) | AI-first gating | **done** | model first (`queue_wait_ms = 0`), verdict cache, concurrency cap, live model status in the approval zone, `operator_commit` records, `eval --from-log` |
| [D](D-hook-coverage.md) | Hook coverage | **done** | ten events dispatched, `PermissionRequest` gating with `tool_use_id` dedupe, `PostToolUseFailure` + `PermissionDenied` captured, event tags in the TUI |
| [C](C-config-in-tui.md) | Config in the TUI | **done** | `settings.toml` authoritative (replace, not merge), conflict reporting, `m` settings editor, resolved-paths footer |
| [E](E-otel.md) | OpenTelemetry | **done** | OTLP/HTTP+JSON exporter riding the watch, checkpoint replay, metrics and logs for every event |
| [A](A-persistable-approvals.md) | Persistable approvals | **partly** | A2 (flag-scoped rung) and A4 (glob escaping) done. A3, A5, A6, A7 open — see below |

## Still open

- **A3 — persist `projects` scope from the TUI.** A2 made the broad rungs reachable; A3 is what makes choosing one comfortable (broad in arguments, narrow in blast radius).
- **A5 — shadow detection.** Under firewall precedence the TUI can still persist a rule that provably cannot match, and reports success. This matters *more* now, not less, because the only remedy is a config edit.
- **A6 — `prune-rules`.** `99-live.toml` is ~7,800 lines with 95 dead `sed` rules in it.
- **A7 — provenance on persisted rules** (`operator` vs `llm <model>`), which A6 needs to prune by source.
- **C4 — hot reload.** Deliberately not built. The save note says the running watch keeps its current timers and model until restarted, rather than implying otherwise.
- **The `sed -i` policy decision itself.** Precedence is unchanged by design, so `00-base.toml`'s unconditional `sed -i → ask` still wins over anything the TUI persists. The remedy is a scoped exception placed above it — a deliberate, reviewable line in the config. That is a policy call, not a code change.

## Original order (for reference)

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
