# D — Hook coverage

**Status:** approved
**Goal:** intercept everything Claude Code can be intercepted at, and know precisely what
cannot be.

## Decisions taken

| question | decision |
|---|---|
| Expand hook coverage | **Yes** — build the gate + observe tiers in §4 |
| Surface the hook event in the TUI | **Yes, required** — every stream line and pending call names the event it came from (§D8) |

**Reference:** [Hooks reference](https://code.claude.com/docs/en/hooks) and
[hooks guide](https://code.claude.com/docs/en/hooks-guide), read 2026-08-29 against
Claude Code **2.1.240**. Note the docs moved from `docs.anthropic.com/en/docs/claude-code/*`
to `code.claude.com/docs/en/*`; the README's links 301-redirect.

## 1. Where we stand

Claude Code exposes **31 hook events**. lord-kali registers **2** (`PreToolUse`,
`PostToolUse`), both with `matcher: "*"` and exec form (`"args": []`), which is correct — exec
form avoids the Git-Bash profile-echo trap the docs call out, where a profile `echo` prepends
text to stdout and Claude Code silently discards the JSON.

Full event list, with a proposed disposition:

| event | disposition |
|---|---|
| `PreToolUse` | **gate** — registered |
| `PostToolUse` | **observe** — registered |
| `PostToolUseFailure` | **observe** — D1, missing |
| `PermissionRequest` | **gate** — D2, missing |
| `PermissionDenied` | **observe** — D3, missing |
| `PostToolBatch` | observe (optional) |
| `SessionStart` / `SessionEnd` | observe — session scope for [E](E-otel.md) |
| `SubagentStart` / `SubagentStop` | observe — agent attribution |
| `Stop` / `StopFailure` | observe — turn boundary, D6 |
| `UserPromptSubmit` / `UserPromptExpansion` | out of scope |
| `Notification` / `MessageDisplay` | out of scope |
| `ConfigChange` | observe — C4 reload trigger |
| `CwdChanged` / `DirectoryAdded` / `FileChanged` | out of scope |
| `InstructionsLoaded` | out of scope |
| `WorktreeCreate` / `WorktreeRemove` | consider — worktree protection |
| `PreCompact` / `PostCompact` | out of scope |
| `Elicitation` / `ElicitationResult` | consider — MCP servers requesting user input |
| `TaskCreated` / `TaskCompleted` / `TeammateIdle` | out of scope |
| `Setup` | out of scope |

## 2. Facts that change existing assumptions

**Hook timeout is 600 s, not 60 s.** `command`, `http` and `mcp_tool` hooks default to 600 s
and accept a per-hook `timeout` field in seconds. (`UserPromptSubmit` lowers it to 30 s,
`MessageDisplay` to 10 s; `prompt` hooks 30 s, `agent` hooks 60 s.) `self_timeout_ms = 50 000`
was sized against a 60 s budget that no longer applies — see [B](B-ai-first-gating.md) §B5.

**`PreToolUse` fires before any permission-mode check, in every mode** including `dontAsk` and
`bypassPermissions`. A hook `deny` cannot be bypassed by changing permission mode. The reverse
does *not* hold: a hook `allow` does not override settings deny rules, nor MCP tools marked
`requiresUserInteraction`, nor connector tools an organisation set to `ask`. Hooks tighten,
never loosen. This is a real ceiling on "everything managed by lord-kali".

**`permissionDecision` accepts `allow`, `deny`, `ask` — plus `defer`** (headless `-p` only,
preserving the tool call so an Agent SDK wrapper can resume). Current `ask` output remains
valid.

**Multiple hooks combine most-restrictive-first**, in the order `deny`, `defer`, `ask`,
`allow`; `additionalContext` from every hook is concatenated.

**The only documented tool exemption is `EndConversation`**, which skips both `PreToolUse` and
`PostToolUse`. There is no other blanket "these tools skip hooks" carve-out.

**Background subagents in non-interactive mode cannot show a prompt.** Hooks still run, and
**if no hook returns a decision, the call is denied.** lord-kali's passthrough is "no output" —
in that context it becomes a deny. Worth knowing before assuming passthrough is always the
safe default.

**`OTEL_*` exporter variables are removed from every subprocess Claude Code spawns, hooks
included.** Drives the whole of [E](E-otel.md).

**Matcher semantics** (this version): `"*"`/empty matches everything; a matcher of only
letters, digits, `_`, `-`, spaces, `,`, `|` is an exact string or `|`/`,`-separated list;
anything else is an **unanchored JavaScript regex**. Exact matching of `-` and `,` requires
v2.1.195+. Matchers are case-sensitive. MCP servers match as `mcp__<server>__.*` — the `.*` is
required.

**Per-hook `if` filtering** using permission-rule syntax (`Bash(git *)`, `Edit(src/**)`), with
Bash `if` patterns checked per subcommand, through leading assignments and inside `$( )`.

**`async: true`** command hooks run in the background, do not block, and are **not subject to
`timeout`**. `asyncRewake: true` additionally wakes Claude on exit 2. This is the correct shape
for pure-observation hooks.

## 3. Gaps

### D1 — `PostToolUseFailure` is not registered

A tool call that **fails** fires `PostToolUseFailure`, not `PostToolUse`. Consequences:

1. Failures are absent from `hook.jsonl` entirely.
2. `watch --tail`'s correlation is wrong. Its one negative signal —
   *"a passthrough/ask with no execution within 60 s → rejected or abandoned?"* — currently
   counts every **failed** call as a possible rejection, because no `PostToolUse` ever arrives.

That heuristic is the foundation the deferred self-tuning agent was to be built on. Fixing it
is cheap: register the event, log it as `post_tool_use_failure`, and treat it as *executed*
in the correlation.

### D2 — `PermissionRequest` is not registered

This event fires exactly when Claude Code is **about to prompt the user** — the moment the
central approval TUI wants to own. Registering it gives a second interception point covering
everything that reaches Claude Code's prompt *despite* lord-kali passing through: settings
`permissions.ask` entries, MCP `requiresUserInteraction`, auto-mode escalation.

Its output shape differs — the field is `decision: "allow" | "deny"` with `reason`, **not**
`permissionDecision` — so `print_decision` needs a second branch keyed on `hook_event_name`.
Note the guide's warning: a broad matcher here auto-approves every permission prompt, so this
must be gated by real rules, never a blanket allow.

Limitation: in plain `-p` runs and with `--permission-prompt-tool`, no prompt exists, so
`PermissionRequest` never fires; `PreToolUse` remains the gate there.

### D3 — `PermissionDenied` is not registered — likely the reported "missing interception"

This machine runs `"defaultMode": "auto"` (`~/.claude/settings.json`). Auto mode has its own
classifier that can deny a tool call. `PermissionDenied` carries:

- `denied_by`: `classifier | rule | hook | unknown`
- `classifier_verdict`: the reason

**Today, a call denied by Claude Code's auto-mode classifier leaves no trace anywhere in
lord-kali.** The gate sees `PreToolUse`, returns passthrough, and never learns the call was
killed downstream. From the operator's seat that looks exactly like "lord-kali missed it".

The hook can also return `retry: true`, which tells the model it may retry — so lord-kali can
un-deny a call it holds a positive rule for.

This is the highest-value single addition in this document.

### D4 — `HookInput` drops fields we already receive

`hook.jsonl` records already contain `permission_mode`, `tool_use_id`, `agent_id`,
`agent_type`, `prompt_id`, `transcript_path`, `effort` — the raw input is logged verbatim —
but `HookInput` (`src/main.rs:21`) parses only `tool_name`, `tool_input`, `cwd`,
`hook_event_name`, `session_id`, so no decision or TUI logic can use them.

| field | use |
|---|---|
| `tool_use_id` | exact `Pre`↔`Post` correlation, replacing the timing heuristic; the natural span/trace key for [E](E-otel.md) |
| `permission_mode` | policy input — e.g. do not route to the TUI in `plan` mode; be stricter under `bypassPermissions` |
| `agent_id` / `agent_type` | show *which* subagent is asking in the TUI; break metrics down by agent type |
| `prompt_id` | group all gate decisions belonging to one user turn |

`queue::request_id` currently derives from `session_id` alone; `tool_use_id` is a
better-defined key.

### D5 — Tool coverage inside `PreToolUse`

`dispatch` (`src/decision.rs:133`) handles `Bash`, `PowerShell`, `WebFetch`, `WebSearch`,
`mcp__*`, and the seven file tools. Everything else falls to `empty_trace("unknown")` →
passthrough, and because `actionable_nodes()` is then empty, it **never reaches the TUI even
when approval is enabled**.

Observed in `hook.jsonl` but unhandled:

| tool | count | note |
|---|---|---|
| `Agent` | 24 | spawns a subagent that will run its own commands |
| `AskUserQuestion` | 28 | harmless |
| `ToolSearch` | 17 | harmless |
| `SendMessage` | 10 | outbound to other sessions/agents |
| `TaskStop` | 4 | |
| `Skill` | 4 | executes packaged instructions |

Proposal: a generic `[[tool.rules]]` section keying on tool name (glob or `/regex/`) with an
optional matcher over `tool_input`, defaulting to passthrough. That is the honest answer to
"I want everything intercepted" — it makes any tool Claude Code adds tomorrow gateable
without a code change, and it collapses `[[mcp.rules]]` into a special case of one mechanism
rather than a parallel one.

**To verify:** the reference lists `Shell` and `Fetch` among standard tool names alongside
`Bash`/`PowerShell`. lord-kali dispatches on `WebFetch`. There are **zero** `WebFetch` /
`WebSearch` / `Fetch` / `Shell` records in the retained log — but the log is pruned to 3 days,
so that proves nothing on its own. A deliberate `WebFetch` and `WebSearch` call, then a grep of
`hook.jsonl`, settles whether `web-fetch`/`web-search` rules are live or dead. Cheap; do it
first.

### D6 — Shell-written files bypass file gating

The guide is explicit: Claude can create or modify files by running shell commands, so a hook
that must see every file change needs a `Stop` hook scanning the working tree once per turn,
or a per-call `Bash|PowerShell` hook running `git status --porcelain`.

`[file]` gates the file *tools*. It does not gate `cat > x`, `Set-Content`, or a script that
writes. Worth stating plainly in the README so the guarantee is not overstated; a `Stop`-hook
tree scan is the available closure if desired.

### D7 — Events supporting the other workstreams

- `SessionStart` / `SessionEnd` — session-scoped resource attributes and a flush point for
  [E](E-otel.md). `SessionEnd` hooks share a **1.5 s budget** (raisable to 60 s via `timeout`),
  so a flush there must be fast.
- `ConfigChange` (`config_source`: `user_settings | project_settings | local_settings |
  policy_settings | skills`) — a natural signal for [C](C-config-in-tui.md)'s reload, though
  it tracks *Claude Code's* settings, not lord-kali's own TOML.
- `WorktreeCreate` / `WorktreeRemove` — worktree protection currently infers worktrees from
  the POSIX substring `/.claude/worktrees/` in `cwd`, which `00-base.toml` already flags as
  possibly not firing on Windows backslash paths. These events give the worktree path
  authoritatively.

### D8 — Show which hook a call came from, in the TUI *(required)*

With one event, the source is implicit. With six or more, "why is this in front of me?" becomes
a real question, and the answer changes what the operator should do:

- a `PreToolUse` pending call is **blocking an agent** — decide now
- a `PermissionRequest` pending call means Claude Code was about to prompt anyway — lord-kali
  intercepted a prompt that would otherwise have appeared in one of five terminals
- a `PermissionDenied` line is **already dead** — informational, nothing to decide
- a `PostToolUseFailure` line means it ran and failed — nothing to decide

Requirements:

- **Every stream line carries an event tag**, short and colour-coded (`PRE`, `PERM`, `DENIED`,
  `POST`, `FAIL`), distinct from the existing allow/deny/ask colouring so decision and origin
  are separately legible.
- **Every pending call in the approval zone names its event in the header**, next to the tool
  and cwd, so the operator knows whether a keystroke unblocks an agent or merely annotates a
  record.
- **Non-actionable events never enter the approval zone.** `PermissionDenied`,
  `PostToolUseFailure` and `PostToolUse` are stream-only. Only events that can return a
  decision produce pending calls.
- **`queue::QueueRequest` gains a `hook_event` field**, since the TUI cannot infer it from the
  request today.

This pairs with §D4: with `agent_id` / `agent_type` parsed, a pending row can read
`PRE · Bash · crafter · co-flo-wpm`, which is what "fronting five Claudes" actually needs.

## 4. Proposed registration

One binary, dispatching on `hook_event_name`. Blocking only where a decision is returned;
everything else `async: true` so it cannot add latency or time out.

| event | matcher | mode | blocking |
|---|---|---|---|
| `PreToolUse` | `*` | gate | yes, `timeout` set explicitly |
| `PermissionRequest` | `*` | gate | yes |
| `PostToolUse` | `*` | log | `async: true` |
| `PostToolUseFailure` | `*` | log | `async: true` |
| `PermissionDenied` | `*` | log (+ optional `retry`) | yes if retry is used, else async |
| `SessionStart` / `SessionEnd` | `*` | log / flush | `async: true` |
| `SubagentStart` / `SubagentStop` | `*` | log | `async: true` |
| `Stop` | — | log | `async: true` |

`main.rs` already branches on `hook_event_name` for `PostToolUse`; this generalises that into a
proper event dispatch table.

## 5. Open questions

1. **Verify `Fetch` / `Shell` tool naming** before anything else — a 10-minute test that
   determines whether the `web-fetch` rules are live.
2. **Which tier to build.** Recommend: gate = `PreToolUse` + `PermissionRequest`; observe =
   `PostToolUse`, `PostToolUseFailure`, `PermissionDenied`, `SessionStart/End`,
   `SubagentStart/Stop`. Defer the rest.
3. **Should lord-kali gate `Agent` and `Skill`?** Both cause downstream tool calls that *are*
   individually gated. Gating the spawn as well may be redundant noise, or may be exactly the
   control wanted.
4. **Generic `[[tool.rules]]`** — worth the design, or keep adding typed handlers per tool?
   Generic is DRY-er and future-proof; typed gives better TUI affordances per kind.
5. **`PermissionDenied` + `retry: true`** — should lord-kali actively override Claude Code's
   auto-mode classifier when it holds an explicit allow rule? Powerful, and a deliberate
   loosening of someone else's safety decision.
6. **Does `PermissionRequest` double-prompt?** If lord-kali gates at `PreToolUse` and again at
   `PermissionRequest`, the same call could reach the TUI twice. Needs the dedupe key —
   `tool_use_id` (D4) — designed in from the start.
7. **`self_timeout_ms` / hook `timeout`** — settle the new numbers together with
   [B](B-ai-first-gating.md) §B5.
