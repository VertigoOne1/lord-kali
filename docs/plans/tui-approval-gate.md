# Implementation plan: central TUI approval gate

Status: proposed
Branch: `feat/tui-approval-gate` (off `main`)

## Motivation

Today a `PreToolUse` decision of `ask` or pass-through (no rule matched) defers to
Claude Code's own permission prompt, which appears in whichever terminal that
particular Claude instance happens to own. With several Claude instances running, the
operator has no single place to triage approvals.

This feature adds an **opt-in central approver**: a long-lived TUI (`lord-kali watch`
evolved) that receives every `ask`/pass-through call from every Claude instance,
shows the live decision stream on top and a pending-approval queue at the bottom, and
lets the operator whitelist command nodes once or always — building up a live ruleset
during an intensive "new territory" session (e.g. bringing up a new Rust/cargo
workflow). When the TUI is closed, behavior degrades exactly to today's.

## Non-negotiable constraints

1. **Graceful degradation.** If no TUI is alive, the hook behaves byte-identically to
   today: existing rules are still fully evaluated; `ask` emits `ask`; pass-through
   emits nothing (Claude Code's native prompt). The queue path engages only when the
   `[approval]` flag is on **and** a fresh TUI heartbeat is present.
2. **Never brick an agent.** A slow or absent operator must never stall a Claude
   instance past Claude Code's hook timeout. The hook self-times-out below that and
   falls back to today's behavior.
3. **Opt-in.** `[approval].enabled` defaults to `false`. Installing this version does
   not change any existing user's gate behavior.
4. **Do not replace the installed binary** at `~/.local/bin/lord-kali` until the full
   existing test suite passes and manual verification confirms the hook path is
   unchanged when approval is disabled. See [Rollout](#rollout).

## Architecture

### File-based IPC (`~/.local/state/lord-kali/`)

Reuses the codebase's existing poll-the-filesystem idiom (the 200 ms tail loop in
`watch`). No sockets or named pipes; cross-platform by construction.

```
queue/<id>.req.json       hook writes the request, then polls for the verdict
queue/<id>.verdict.json   TUI writes the operator's decision (write temp + rename)
tui.heartbeat             TUI rewrites this file's mtime every loop iteration
```

- `<id>` = `{session_id}-{ts_ms}-{pid}` — unique per blocked hook invocation.
- All writes are atomic (write to `*.tmp`, then rename) so a reader never sees a
  half-written file.

#### Request payload (`*.req.json`)

```json
{
  "id": "…",
  "ts_ms": 0,
  "cwd": "…",
  "tool": "Bash",
  "target": "pwd && gh pr list | jq .",
  "nodes": [
    { "shell": "bash", "command": "gh",  "args": "pr list", "decision": "passthrough" },
    { "shell": "bash", "command": "jq",  "args": ".",       "decision": "passthrough" }
  ]
}
```

`nodes` is the set of **actionable** nodes only — those that drove the call to
`ask`/pass-through (`ask`-decision nodes and unmatched nodes). Already-`allow`ed nodes
and `deny` nodes are excluded (a `deny` resolves instantly and never reaches the
queue).

#### Verdict payload (`*.verdict.json`)

```json
{
  "id": "…",
  "nodes": [
    { "command": "gh", "args": "pr list", "action": "allow_always" },
    { "command": "jq", "args": ".",       "action": "passthrough" }
  ]
}
```

`action` ∈ `allow_once | allow_always | deny_once | deny_always | passthrough`.

### Hook decision flow

```
worktree protection ─► (unchanged)
resolve rules ─► Allow  ─► emit allow            (unchanged, instant)
                Deny   ─► emit deny             (unchanged, instant)
                Ask | None (pass-through):
                    approval.enabled? ── no ──► today's behavior
                          │ yes
                    heartbeat fresh? ── no ──► today's behavior
                          │ yes
                    write req → poll verdict (200 ms) up to SELF_TIMEOUT
                          │
                    timeout ──► today's behavior
                          │ verdict arrived
                    combine node actions → emit allow / deny / (pass-through)
```

#### Verdict → call outcome (node-level combine)

- any node `deny_once`/`deny_always` → **deny** (reason names the offending nodes)
- else every actionable node is `allow_once`/`allow_always` → **allow**
- else (≥1 node left `passthrough`) → **pass-through** → Claude Code's native terminal
  prompt handles the whole call this time, "to approve specifically"

`allow_always` / `deny_always` are persisted to the live ruleset **regardless** of the
final call outcome, so gaps close over time even when only a subset is whitelisted this
round.

### Live ruleset (`~/.config/lord-kali/99-live.toml`)

- Loaded by the existing `load_config` glob (`*.toml`, lexicographic order). `99-`
  sorts last → **lowest priority** → never shadows explicit user rules.
- `allow_always` for a node appends `command` to `[bash]`/`[powershell]`
  `allowed_commands` (any args), matching existing `allowed_commands` ergonomics.
- `deny_always` appends a `[[bash.rules]]` / `[[powershell.rules]]` entry with
  `decision = "deny"`.
- Reuses the existing TOML format and parse/merge path — **no new config schema** for
  rules. Hooks already reload config on every invocation, so a freshly written rule
  takes effect on the next call.
- The TUI is the only writer; writes are atomic (temp + rename).

### Config additions

```toml
[approval]
enabled = true                 # default false; opt in to the queue path
live_rules = "99-live.toml"    # file the TUI appends always-rules to
```

`state_dir` defaults to `~/.local/state/lord-kali/` (same root as the log).

### TUI (`lord-kali watch`, ratatui + crossterm)

New dependencies: `ratatui`, `crossterm`. Justified by the two-pane interactive layout;
this is the largest divergence from the codebase's current minimalism and is gated
behind the approval feature being used.

- **Top pane** — live decision stream. Reuses today's `handle_line` rendering logic
  (allow/deny/ask/pass + `(no rule: …)` annotations + run-correlation), scrolling.
- **Bottom pane** — pending-approval queue. Each pending call expands to its actionable
  **node checklist**:
  - `↑/↓` move cursor, `space` toggle a node (default: all selected)
  - `a` allow-**always** selected → append to `99-live.toml`
  - `o` allow-**once** selected (no persistence)
  - `d` deny-**always** selected → append deny rule; `x` deny-**once**
  - `enter` commit → write `*.verdict.json`; any unselected node ⇒ call drops to
    pass-through
  - `q`/`Ctrl-C` quit (stops the heartbeat → instances revert to default)
- Writes `tui.heartbeat` each loop iteration; watches `queue/` alongside the log tail.
- Sweeps stale `*.req.json` (writer died mid-wait) by mtime, mirroring today's
  `sweep_pending`.

The pure-tail mode (no queue interaction) is preserved as `lord-kali watch --tail` so
logging-only users keep their current tool.

## Code-level changes (`src/main.rs`)

- New structs: `ApprovalConfig`, `QueueRequest`, `QueueNode`, `Verdict`, `VerdictNode`.
  Wire `[approval]` into `RawConfig`/`Config`/`merge`.
- New module-ish section `queue`: paths, atomic write helper, heartbeat read/write,
  request enqueue + verdict poll, stale sweep. Pure functions where possible for
  testability.
- `run_hook`: between rule resolution and `print_decision`, insert the
  `enabled && heartbeat-fresh` branch that enqueues and blocks. The
  actionable-node set is derived from the already-built `InvocationTrace.nodes`
  (nodes with `decision ∈ {ask, passthrough}`), so no second extraction.
- `combine_verdict(nodes: &[VerdictNode]) -> Option<(Decision, String)>` — the
  node-level combine above. Unit-tested.
- Live-rules writer: append `allowed_commands` / deny rule, atomic.
- `watch`: split into `watch_tail` (today's loop, behind `--tail`) and `watch_tui`
  (ratatui app). Shared line-rendering helpers stay deduplicated (DRY).

## Test requirements

Driving a full ratatui session in CI is impractical; the strategy is to make the
**logic** pure and unit-tested, and verify the **interactive shell** manually plus a
headless event-injection test.

### Unit tests (must pass in `cargo test`, no TTY)

1. `combine_verdict`:
   - all `allow_once`/`allow_always` → `Allow`
   - any `deny_*` → `Deny`, reason names the node(s)
   - any `passthrough` left → `None` (pass-through)
   - mixed allow + passthrough → `None`
2. Actionable-node extraction: from a trace with allow/deny/ask/unmatched nodes, only
   `ask` + unmatched are emitted into the request; allow/deny excluded.
3. Request/verdict JSON round-trips (serde) by `id`.
4. Atomic write helper: temp file is renamed; no partial file observable; parent dir
   created.
5. Heartbeat freshness: `is_tui_live` true within window, false when stale/absent.
6. Live-rules append: writing `allow_always` for `gh` yields a `99-live.toml` that,
   when parsed by the existing loader, resolves `gh` → `Allow`; `deny_always` →
   `Deny`. (Round-trip through the real parser — guards the format.)
7. **Regression / safety:** with `approval.enabled = false`, the existing decision
   functions (`handle_bash_tool`, `handle_powershell`, `handle_web_fetch`,
   worktree protection) return byte-identical results to `main`. The existing suite
   covers most of this; add an explicit "approval disabled = passthrough emits
   nothing" assertion.

### Headless TUI test (no real terminal)

8. ratatui supports a `TestBackend`. Render the app against a `TestBackend`, feed a
   scripted sequence of `crossterm` key events (`space`, `a`, `enter`) into the
   update function, and assert the resulting `*.verdict.json`. This exercises the
   keybinding→verdict mapping without a TTY.

### Manual verification (run in a controlled shell)

9. Two terminals: one runs `lord-kali watch`; the other pipes a crafted hook-input
   JSON into `lord-kali` (stdin) emulating Claude Code, with `approval.enabled` and a
   fresh heartbeat. Confirm: request appears in the TUI; selecting + `a` writes the
   verdict and `99-live.toml`; the blocked hook prints `allow`; a re-run of the same
   command now resolves instantly via the live rule without queueing.
10. Kill the TUI; confirm the same hook input falls straight through to today's
    behavior (no hang, ≤ the poll interval).
11. Timeout path: with a stale/absent heartbeat but `enabled`, confirm fallback is
    immediate; with a fresh heartbeat but no operator action, confirm self-timeout
    fallback before Claude Code's hook timeout.

## Rollout

- Build with `cargo build --release` into the repo target; **do not** copy over
  `~/.local/bin/lord-kali` until tests (7) and manual checks (9–11) pass.
- For verification, point a scratch Claude Code settings hook at the repo-built binary,
  or feed hook JSON on stdin directly — never the installed path.
- Only after confirming disabled-mode parity: `make install`.

## Open questions / deferred

- Per-node `args`-specific persistence (vs command-wide `allowed_commands`) — start
  command-wide; revisit if too loose.
- Multi-select across *different* pending calls (batch approve) - not necessary
- The self-tuning agent noted in memory (`log-watcher-and-tuner`) could later consume the verdict log to suggest rules; out of scope here.
  - the watcher and tuner would slot into this later as possibly some agent driven haiku agent to help drive
