# B — AI-first gating

**Status:** approved, design settled — open questions narrowed
**Goal:** swap the order of the two turns. The model opines **immediately**; the operator
decides afterwards, within a short window. Today it is the other way round, so the operator is
forced to interrupt a decision the model has not yet made.

## Decisions taken

| question | decision |
|---|---|
| Front operator grace (`queue_wait_ms`) | **Collapse to 0** — the model answers first |
| Operator window (`proposal_wait_ms`) | **Keep 5 s.** Not raised — 5 s after seeing the model's opinion is enough |
| Headless daemon | **Not now.** `watch` is kept open permanently, fronting ~5 concurrent Claude sessions |
| Auto-deny | **Never.** Unchanged — the model only ever auto-approves |
| Data mining | **In scope** — mine operator/model disagreement to tune the prompt (§B6) |

## 1. The swap

**Today** — the operator moves first, blind:

```
request ──▶ operator grace 10 s ──▶ model 8 s×2 ──▶ proposal ──▶ operator grace 5 s ──▶ apply
            ▲
            └── to act here, the operator must pre-empt an opinion that doesn't exist yet
```

**Wanted** — the model moves first, the operator reviews:

```
request ──▶ model (immediate) ──▶ proposal ──▶ operator window 5 s ──▶ apply
                                              ▲
                                              └── operator now decides *against a stated opinion*
```

Mechanically this is `queue_wait_ms = 0`. Conceptually it is the important change: the
operator stops interrupting and starts reviewing, and every operator action becomes a signal
about the model rather than a substitute for it (§B6).

Invariants that must survive:

- **The model never auto-denies.** `unsafe`, malformed JSON, transport errors and timeouts all
  fall through to existing behaviour.
- **The operator always wins.** Acting on a pending call at any point cancels the model path,
  before or after the proposal lands.

## 2. Implementation notes

### B1 — `queue_wait_ms = 0` must be genuinely immediate and must not double-spawn

The consult decision is made in the watch poll loop (`watch_poll_ms`, default 200 ms), so a
zero window means the consult fires on the first poll after the request lands. Two details:

- Confirm `sync_pending` inserts `LlmPhase::Requested` before the spawn decision is
  re-evaluated, so a request is never consulted twice.
- **Render the pending row in a `consulting` state from the outset.** With a zero window the
  row and the "consulting model on: …" note appear within one poll of each other; a row that
  looks actionable and then changes under the cursor is worse than one that says it is waiting
  on the model. This is the visible half of the swap.

### B2 — Concurrency, with 5 Claude sessions in front of one watch

Every passthrough now costs a model call, and five sessions running parallel tool calls will
burst. Needed:

- **Verdict cache**, keyed on `(tool, normalised command, project root)`. Five sessions in the
  same repo run the same commands constantly; this is the single highest-value mitigation and
  it caps spend as well as latency.
- **A concurrency cap** on in-flight consults, with the excess queued. Unbounded spawning
  against a rate-limited endpoint turns bursts into 429s, and a 429 is a passthrough — i.e.
  the gate silently gets worse exactly when it is busiest.
- **`max_attempts = 1`** on the hot path. A transient failure now escalates to the operator,
  which is the intended fallback anyway; keep the retry budget out of the critical path.

### B3 — Budget

Freed time at the front is not spent. The exchange shortens:

```
0 + (8 000 × 1) + 5 000 = 13 000 ms      (was 31 000 ms)
```

`self_timeout_ms` can stay at 50 000 with substantial headroom. The 600 s hook timeout
discovered in [D](D-hook-coverage.md) §2 means there is no external pressure here either — no
change needed unless the operator window is later widened.

### B4 — Unsafe verdicts should not be invisible

An `unsafe` verdict is currently indistinguishable from a timeout at the gate: both pass
through silently. With the model on every passthrough, its opinion is worth carrying:

- surface the reason in the TUI stream against the pending row, and
- pass it into the gate's passthrough so it reaches Claude Code's own prompt text
  (`additionalContext` on `PreToolUse`, [D](D-hook-coverage.md) §D4).

Behaviour is unchanged — still a passthrough, still never an auto-deny. Only the reasoning
becomes visible.

### B5 — Scope of what the model persists

AI-first means the auto-approver persists more rules, sooner, and it always persists at the
**tightest** rung (`src/watch.rs:936`) — the one that can never match a second time for
flag-first commands. That is [A](A-persistable-approvals.md) §A2's problem, and A is scheduled
last, so expect live-rule growth to accelerate in the interim. Worth watching the
`lordkali.rules.persisted` counter from [E](E-otel.md) as an early warning.

## 3. B6 — Mining the disagreement to tune the prompt

The point of putting the model first is that **every operator action afterwards is labelled
data**: the model stated an opinion, and the operator either let it stand or overrode it.

### What is already logged

| event | count in current log | content |
|---|---|---|
| `llm_consult` | 151 | model, tool, target, cwd |
| `llm_result` | 151 | verdict (safe/unsafe/malformed/error), reason, latency |
| `llm_auto_approve` | 67 | the ones that auto-applied |

So all 151 model verdicts are captured. **The other 84 are unaccounted for** — declined by the
model, or pre-empted by the operator, with no record of which, and no record of what the
operator chose instead.

### The gap

Operator commits are not logged as events at all. There is no `log_event` call on the
`a`/`o`/`s` paths — the only trace is the resulting `pre_tool_use` record reading
`"Approved at approval TUI"`, which loses the lane assignment, the scope rung, and any
relationship to the model's verdict.

### Proposed

Emit an event on every operator commit, carrying the model's standing opinion when there is
one:

```json
{ "lk_event": "operator_commit",
  "id": "…", "tool": "Bash", "target": "sed -i …", "cwd": "…",
  "mode": "always|once|skip",
  "lanes": [{"node": "sed", "lane": "allow", "scope_rung": 1}],
  "lk_llm": { "model": "…", "verdict": "safe", "reason": "…", "phase": "proposed" } }
```

Four cells fall out of it, and they are the training signal:

| model said | operator did | meaning |
|---|---|---|
| safe | allowed (or let it auto-apply) | agreement — the prompt is working |
| **safe** | **denied / asked** | **false-safe — the expensive error class** |
| unsafe | allowed | over-caution — the source of unnecessary prompts |
| unsafe | denied / skipped | agreement |

### Reusing the eval harness

`lord-kali eval` already scores (model × prompt) matrices over labelled JSONL cases in
`eval/cases/`, with prompts in `eval/prompts.toml`. Add `lord-kali eval --from-log` to emit a
case file from `operator_commit` records, with `expected` derived from the operator's action.
Real traffic, labelled by the person whose judgement the gate is meant to reproduce, in the
format the existing harness already consumes — no second mechanism.

Then the loop is: run a week, export cases, sweep prompt variants against them, adopt the
winner into `[approval.llm] system`. The prompt already lives in config precisely so it can be
tuned without rebuilding.

The metric `lordkali.llm.agreement{verdict, operator_outcome}` in [E](E-otel.md) makes the
same four cells visible continuously, so drift shows up without waiting for an export.

## 4. Configuration

```toml
[approval.llm]
enabled = true
queue_wait_ms = 0               # B1 — was 10000; the model goes first
proposal_wait_ms = 5000         # unchanged — the operator's review window
max_attempts = 1                # B2
cache_ttl_ms = 3600000          # B2, new
max_concurrent = 4              # B2, new
```

All editable from the settings screen in [C](C-config-in-tui.md), which shows the budget
invariant as a live computed line.

## 5. Open questions

1. **Cache lifetime and scope.** Per `watch` run, or persisted across restarts? A persisted
   cache is effectively a second rule store with different semantics and no audit trail —
   in-memory per run is the safer default. Confirm.
2. **Concurrency cap value.** 4 is a guess; the right number depends on the endpoint's rate
   limit and how bursty five sessions actually get. Measure with
   `lordkali.llm.consults` before fixing it.
3. **Cost ceiling.** Every passthrough now costs a call. Wanted: a per-hour or per-day cap? If
   so, what happens on exhaustion — escalate to operator (safe, noisier) or pass through
   (quiet, less gated)?
4. **Should a cached verdict still show in the TUI?** A cache hit resolving silently is fast
   but invisible; showing it keeps the stream honest about what was decided and how.
5. **`--from-log` labelling.** Does `skip` count as a label at all? It means "not deciding
   here", which is neither agreement nor override — probably excluded from the case set rather
   than guessed at.
