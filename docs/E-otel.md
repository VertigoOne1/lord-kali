# E — OpenTelemetry export

**Status:** approved
**Goal:** lord-kali adopts OTel as its own telemetry standard — metrics (AI calls, approvals,
passes, user accepts, temp accepts) and logs (with full command logging) emitted to an OTLP
receiver. The JSONL log stays.

## Decisions taken

| question | decision |
|---|---|
| Relationship to Claude Code's telemetry | **Independent.** lord-kali is its own OTel producer, its own service, its own namespace. Claude Code's telemetry is separately handled |
| Trace parenting / correlation with Claude Code spans | **Not wanted.** No span linking, no shared trace ids |
| Scope | Metrics + logs. Traces only if lord-kali later wants its own, standalone |

## 1. Two constraints that determine the design

### lord-kali needs its own OTel configuration

From the hooks reference, on inherited environment:

> One set of variables is not inherited: Claude Code removes `OTEL_*` exporter variables from
> every subprocess it spawns, including hooks.

This is not an obstacle — it is the reason the design is clean. Claude Code's own telemetry
(`CLAUDE_CODE_ENABLE_TELEMETRY=1`, `OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318` in
`~/.claude/settings.json`) is handled separately and stays separate. lord-kali carries its own
`[otel]` block, points at whatever receiver it is told to, and emits under its own
`service.name`. If env-var configuration is ever wanted it takes a distinct prefix
(`LORD_KALI_OTEL_*`) so the two can never be confused.

### The gate is a short-lived process

`PreToolUse` spawns one lord-kali process per tool call. No batching, no background flush, no
retry queue, no connection reuse. A synchronous OTLP POST on the gate path would add latency
to every tool call and introduce a new way for a dead collector to stall an agent.

## 2. Design — two tiers

**Tier 1 — the gate never exports.** It writes the JSONL record, exactly as today. That record
is already the source of truth and its write is already best-effort and non-blocking. Zero
added latency, no new failure mode on the hot path. This is consistent with CLAUDE.md
principle 4: deliberate degradation, documented, never masking a real error.

**Tier 2 — a long-lived exporter tails the log and emits OTLP.** `lord-kali watch` already
tails `hook.jsonl`; a new `lord-kali otel-export` provides the same without a TUI. Being
long-lived, it can batch, retry, hold the connection, and checkpoint. It also already holds
the LLM outcomes (`llm_consult`, `llm_auto_approve`) that the gate record never carries.

Consequences worth stating plainly:

- **Nothing is lost when the collector is down.** The exporter checkpoints the last exported
  offset / `ts_ms` and resumes. `lord-kali otel-export --since <ts>` replays.
- **Nothing exports live when no exporter runs.** The log still has everything, and a later
  run backfills. This is a deliberate gap, not silent loss.
- The checkpoint must survive `prune-logs` rewriting the file (it rewrites atomically, so a
  byte offset is not stable — checkpoint on `ts_ms`).

## 3. Transport

OTLP/HTTP to `:4318`, paths `/v1/metrics` and `/v1/logs`.

- **`http/json`** — buildable with the existing `serde_json` + `ureq`, **no new dependencies**.
- **`http/protobuf`** — needs `prost` and generated types, or the `opentelemetry-otlp` stack,
  which pulls in a runtime and a large dependency tree.

Recommend **JSON first** (KISS), with `protocol` as a config key so protobuf can be added
later without a config break. Most collectors accept JSON on the same port; the local one at
`:4318` needs a five-minute confirmation.

## 4. Resource attributes

```
service.name        = "lord-kali"
service.version     = CARGO_PKG_VERSION
host.name           = <hostname>
```

Per-record attributes drawn from the hook input (requires [D](D-hook-coverage.md) §D4 to parse
them): `session.id`, `claude.prompt_id`, `claude.agent_id`, `claude.agent_type`,
`claude.permission_mode`, `claude.tool_use_id`, `claude.hook_event`.

These name *what lord-kali observed about the caller*; they are lord-kali's own attributes and
carry no expectation of joining Claude Code's series. Naming follows OTel semantic conventions
where one exists, and the `lordkali.` / `claude.` prefixes otherwise.

## 5. Metrics

| instrument | type | attributes |
|---|---|---|
| `lordkali.gate.decisions` | counter | `decision` (allow/deny/ask/passthrough), `kind`, `tool`, `matched`, `rule_kind`, `source_file` |
| `lordkali.gate.duration` | histogram | `decision`, `blocked` (did it reach the queue) |
| `lordkali.approval.requests` | counter | `tool`, `kind` |
| `lordkali.approval.resolutions` | counter | `outcome`, `lane` |
| `lordkali.approval.wait` | histogram | `outcome` — queue submit → verdict |
| `lordkali.llm.consults` | counter | `model`, `verdict` (safe/unsafe/malformed/error) |
| `lordkali.llm.latency` | histogram | `model`, `verdict` |
| `lordkali.llm.tokens` | counter | `model` — `total_tokens` is already parsed in `src/llm.rs:319` |
| `lordkali.llm.agreement` | counter | `verdict` (safe/unsafe), `operator_outcome` (allowed/denied/asked/unattended) — the four-cell table from [B](B-ai-first-gating.md) §B6 |
| `lordkali.rules.persisted` | counter | `source` (operator/llm), `shell`, `scope_rung` |
| `lordkali.rules.active` | gauge | `state` (live / shadowed) — see [A](A-persistable-approvals.md) §A5 |

`approval.resolutions.outcome` values, mapped directly to the metrics asked for:

| asked for | series |
|---|---|
| AI calls | `lordkali.llm.consults` |
| passes | `gate.decisions{decision="allow"}` + `{decision="passthrough"}` |
| approvals | `approval.resolutions{outcome=~"operator_.*"}` |
| user accepts | `approval.resolutions{outcome="operator_always"}` |
| temp accepts | `approval.resolutions{outcome="operator_once"}` |

Remaining outcomes: `operator_skip`, `operator_deny`, `llm_auto`, `timeout_passthrough`.

## 6. Logs

One OTel LogRecord per JSONL record.

- **Body** — the decision reason.
- **Severity** — `deny` → ERROR, `ask` → WARN, `allow`/`passthrough` → INFO.
- **Attributes** — `lordkali.tool`, `lordkali.decision`, `lordkali.kind`, `lordkali.cwd`,
  `lordkali.rule.source_file`, `lordkali.rule.command`, `lordkali.rule.args`, plus the
  resource/session attributes above.
- **Full command logging** — `lordkali.command` carries the complete `tool_input.command`, and
  per-node command/args are emitted as a structured attribute.

**This ships full command lines to the collector.** Command lines routinely contain absolute
paths, hostnames, internal URLs and occasionally credentials in argv. Two controls are
required, not optional:

```toml
include_command = true
redact = ['/[A-Za-z0-9_]*(TOKEN|SECRET|PASSWORD|KEY|PAT)=\S+/']
```

`redact` is a list of regexes replaced before export. Default to on for a localhost collector,
and document the exposure loudly for any remote one.

## 7. Traces

**Out of scope.** No correlation with Claude Code's spans, no shared trace ids, no parenting —
that is deliberately not wanted, and dropping it removes the only part of this design that
depended on Claude Code's telemetry internals.

If lord-kali ever wants traces of its own, the natural shape is a standalone span per gate
decision — `queue wait → model consult → operator window → verdict` — which is useful for
diagnosing where the 13 s budget in [B](B-ai-first-gating.md) §B3 actually goes. That is a
separate decision, made on its own merits, after metrics and logs land.

## 8. Configuration

```toml
[otel]
enabled = false                    # opt-in, like every other feature
endpoint = "http://localhost:4318"
protocol = "http/json"             # or "http/protobuf" later
headers_env = "LORD_KALI_OTEL_HEADERS"   # auth via env var name, never a literal value
export_interval_ms = 10000
metrics = true
logs = true
include_command = true
redact = []
service_name = "lord-kali"
checkpoint = "~/.local/state/lord-kali/otel.checkpoint"
```

Editable from the settings screen in [C](C-config-in-tui.md).

## 9. Open questions

1. **JSON or protobuf?** Depends on what the local collector at `:4318` accepts. JSON is
   dependency-free; confirm before committing.
2. **Where does the exporter run?** Riding `watch` is sufficient today — the TUI is kept open
   permanently. `lord-kali otel-export --since` remains the backfill path for any window where
   it was not. A daemon is explicitly not needed now; if one is ever built, the exporter should
   live in it rather than becoming a third process.
3. **Should the events from [D](D-hook-coverage.md) be exported too** once registered —
   `PermissionDenied` in particular is a metric worth having
   (`lordkali.claude.denied{denied_by,classifier_verdict}`)?
4. **Redaction defaults** — ship with a conservative default pattern set, or default to empty
   and make the operator opt in?
5. **Retention interaction.** `prune-logs` drops records older than 3 days. If the exporter is
   ever behind by more than that, data is lost before export. Should `prune-logs` refuse to
   prune past the exporter checkpoint?
6. **Cardinality.** `source_file` and `rule_args` as metric attributes could explode series
   count. They likely belong on logs only, not metrics — worth deciding before building.
