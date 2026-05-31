# lord-kali

A Claude Code [PreToolUse hook](https://docs.anthropic.com/en/docs/claude-code/hooks) that filters Bash and WebFetch tool calls with a more powerful matching system than Claude Code supports natively, and protects worktrees from accidental parent-directory file operations.

Bash commands are parsed with [tree-sitter-bash](https://github.com/tree-sitter/tree-sitter-bash), correctly handling pipelines, `&&`, `||`, `;` chains, subshells, command substitutions (`$(...)`), and `xargs`-wrapped commands. WebFetch URLs are matched against configurable glob/regex patterns. Worktree protection automatically denies file reads/writes targeting the parent project when Claude is operating inside a `.claude/worktrees/<name>` directory.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/insidewhy/lord-kali/main/scripts/install.sh | bash
```

Or clone and build manually:

```sh
make install   # builds and copies to ~/.local/bin/
```

Then point your Claude Code hook at the binary in `~/.claude/settings.json` or `~/.config/claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "$HOME/.local/bin/lord-kali"
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "$HOME/.local/bin/lord-kali"
          }
        ]
      }
    ]
  }
}
```

The `PreToolUse` entry is what does the gating. The `PostToolUse` entry is optional and only used for logging — it lets the log capture what actually ran after a call was allowed or approved (see [Logging](#logging)). Omit it if you only want the gate.

## Configuration

### Project-local configuration

You can commit a `.claude/lord-kali.toml` file inside your project repository. This file is discovered by walking up from `cwd` until a `.git` directory is found. `cwd` is the working directory that Claude Code passes in the hook's JSON input, reflecting the project directory Claude Code is operating in (not the process working directory of lord-kali itself). Project-local rules have the highest priority and are evaluated before any global rules.

### Global configuration

All `*.toml` files in `~/.config/lord-kali/` are loaded in lexicographic order and merged. This lets you split config into files like `00-base.toml`, `10-bash.toml`, `20-groups.toml`. If no `.toml` files are found, a default config is used (everything passes through).

Config loading order (highest priority first):

1. `.claude/lord-kali.toml` (project-local, found by walking up from `cwd`)
2. `~/.config/lord-kali/*.toml` (global, in lexicographic order)

Within each file, rules are ordered: top-level rules first, then group rules in definition order. When files are merged, each file's rules are appended after the previous file's. The combined result is evaluated first-match-wins, so rules from earlier files have higher priority. For bash rules sharing the same command key, both files' rules are concatenated (earlier file first). For `[log]`, the last file with a `[log]` section wins.

```toml
# Optional - omit or set enabled=false to disable
[log]
enabled = true
path = "~/.local/state/lord-kali/hook.jsonl"

# Worktree protection is enabled by default.
# Uncomment to disable:
# [worktree-protection]
# enabled = false

### Bash tool filtering

[bash]
# A simple way to configure commands that are allowed with any arguments,
# use `rules` entries with `decision = "allow"` for more complicated
# argument matching
allowed_commands = ["tail", "grep", "ls", "find", "cat", "head", "wc"]

[[bash.rules]]
command = "cargo"
# Arguments can be matched with regexes (wrapped in //) or glob
# patterns. The matcher tests all arguments joined by spaces.
args = "/(fmt|build|test)( .*)?/"
decision = "allow"

[[bash.rules]]
command = "pnpm"
# Empty brace alternative allows matching with or without arguments
args = "{ls,why,info,view}{, **}"
decision = "allow"

[[bash.rules]]
command = "rm"
args = "-rf **"
decision = "deny"
reason = "No recursive force deletes"

[[bash.rules]]
command = "rm"
decision = "ask"
reason = "rm can be dangerous, please ask."

[[bash.rules]]
command = "npm"
decision = "deny"
reason = "Use pnpm instead of npm."

[[bash.rules]]
command = "npx"
decision = "deny"
reason = "Use pnpm dlx instead of npx."

### Web fetch filtering

[[web-fetch.rules]]
url = "https://evil.com/**"
decision = "deny"
reason = "Blocked domain"

# Regex pattern (wrapped in //)
[[web-fetch.rules]]
url = '/.*\.internal\..*/'
decision = "ask"
reason = "Internal URL, please confirm"

# Allow any URL without query parameters that didn't match prior rules
[[web-fetch.rules]]
url = "/[^?]*/"
decision = "allow"
```

See [`config.toml`](config.toml) for a more thorough example with many common rules.

### Bash rules

Rules are defined as `[[bash.rules]]` entries. Each rule has:

- **`command`** (required): the command name to match (basename only, e.g. `rm` not `/usr/bin/rm`)
- **`decision`** (required): `allow`, `deny`, or `ask`
- **`args`** (optional): glob or regex pattern matched against the command's arguments (joined by spaces). Omitting matches any arguments. Use `{, **}` to match with or without trailing arguments, e.g. `logs{, **}` matches both `logs` and `logs --tail 100`.
- **`reason`** (optional): message shown to the user. Defaults to `"ok"` for allow rules.

Rules for the same command are evaluated in config file order - the first rule whose `args` pattern matches wins. `allowed_commands` entries are appended after all explicit rules as `allow` matching any arguments.

### WebFetch rules

Rules are defined as `[[web-fetch.rules]]` entries. Each rule has:

- **`url`** (required): glob or regex pattern matched against the full URL
- **`decision`** (required): `allow`, `deny`, or `ask`
- **`reason`** (optional): message shown to the user. Defaults to `"ok"`.

Rules are evaluated in config file order - the first matching rule wins.

### Per-rule project scoping

Any rule (bash or web-fetch) can have an optional `projects` array to restrict it to specific directories. A rule with `projects` only applies when the hook's `cwd` is inside one of the listed directories. Rules without `projects` are global (match all cwds). `~` is expanded in project paths.

```toml
[[bash.rules]]
command = "cargo"
args = "publish{, **}"
decision = "deny"
projects = ["~/projects/my-rust-project"]
```

### Groups

Groups set shared `projects` for all rules within them. If a rule inside a group also has `projects`, they merge (union).

```toml
[[group]]
projects = ["~/projects/my-rust-project", "~/projects/other"]

[group.bash]
allowed_commands = ["rustup"]

[[group.bash.rules]]
command = "cargo"
args = "publish{, **}"
decision = "deny"
reason = "Do not publish from these projects"

[[group.bash.rules]]
command = "make"
decision = "allow"
projects = ["~/projects/third"]
# effective projects = group's + ["~/projects/third"]

[[group.web-fetch.rules]]
url = "https://internal.example.com/**"
decision = "allow"
```

Multiple `[[group]]` sections can be defined. Group rules are appended after top-level rules (first-match-wins, definition order). Group `bash` and `web-fetch` sections use the same format as the top-level sections.

### Worktree protection

When Claude Code uses [worktrees](https://docs.anthropic.com/en/docs/claude-code/worktrees), the working directory is inside `.claude/worktrees/<name>` within the parent project. Claude sometimes attempts to read or write files in the parent project instead of the worktree, which can cause unintended changes to the wrong checkout.

Worktree protection detects when `cwd` matches `<parent>/.claude/worktrees/<name>` and denies file-related tool calls (`Read`, `Write`, `Edit`, `Glob`, `Grep`, `NotebookEdit`, `MultiEdit`) that target the parent project at `<parent>/...` instead of the worktree. The deny reason includes the full corrected worktree path so Claude can retry with the right location.

This is enabled by default. To disable it:

```toml
[worktree-protection]
enabled = false
```

If any config file (project-local or global) sets `enabled = false`, worktree protection is disabled.

### Patterns

- **[Glob via glob-match-ultra](https://github.com/insidewhy/glob-match#syntax)** (default): `*` matches within a segment (stops at `/`), `**` matches across `/` boundaries, `?` matches a single character. Also supports `[a-z]` character classes, `{a,b}` brace expansion with empty alternatives (e.g. `{, **}` to match with or without arguments), and `!` negation.
- **Regex**: wrap the pattern in `//` delimiters, e.g. `/(fmt|build|test)( .*)?/`. `^` and `$` anchors are added automatically - do not include them in the pattern.

## Logging

When `[log]` is enabled, every hook invocation appends one JSON object (one line, JSONL) to the log file. Each record is the raw hook input Claude Code sent, plus lord-kali fields:

- **`ts_ms`**: epoch milliseconds when the record was written
- **`lk_event`**: `pre_tool_use` for gate invocations, `post_tool_use` for after-execution records

To capture `post_tool_use` records you must also register the binary as a `PostToolUse` hook (see [Install](#install)). PostToolUse fires only after a tool actually ran (auto-allowed or user-approved), so it never gates — it only logs, and the tool's `tool_response` is stripped to keep records compact.

Logging is best-effort: if the log file cannot be created or written, the failure is swallowed so it can never block or alter a gate decision.

### `lk_decision` (pre_tool_use only)

`pre_tool_use` records carry an `lk_decision` object describing how the gate ruled. It is built alongside the decision and never affects it:

- **`final`**: `allow`, `deny`, `ask`, or `passthrough`
- **`kind`**: `command_chain`, `web_fetch`, `worktree_protection`, or `unknown`
- **`reason`**: the message shown to Claude (absent when `final` is `passthrough`)
- **`deciding`**: the node that set the final verdict — the first deny, else the first ask, else the first matched allow — or `null` if nothing matched
- **`nodes`**: every command (or URL) extracted from the call. Each node records its `shell`, `command`, `args`, resolved `decision`, and whether it `matched` a rule. When a rule matched, the node also carries that rule's `reason`, `rule_kind` (`explicit` or `allowed_commands`), `rule_command`, `rule_args`, and `source_file` so you can trace which rule in which config file made the call.

## Decision priority

### Bash

Given the set of commands extracted from a bash string, each command is resolved against its rules (first args match wins). Then across all commands:

1. **deny** - if ANY command resolves to deny
2. **ask** - if ANY command resolves to ask
3. **allow** - if ALL commands resolve to allow
4. **pass-through** - otherwise (no output, defers to Claude Code defaults)

### WebFetch

Given a URL, rules are evaluated in config file order:

1. **First matching rule** - its decision (allow/deny/ask) is returned
2. **pass-through** - if no rule matches (no output, defers to Claude Code defaults)

## Parsing

Commands are extracted by walking the full tree-sitter-bash AST. This covers:

- Pipelines: `ls | grep foo` extracts `ls`, `grep`
- Chains: `ls && rm foo` extracts `ls`, `rm`
- Subshells: `(rm foo)` extracts `rm`
- Command substitutions: `echo $(rm foo)` extracts `echo`, `rm`
- `xargs` sub-commands: `find . | xargs -I {} rm {}` extracts `find`, `xargs`, `rm`
- Path normalization: `/usr/bin/rm` matches a rule for `rm`

## Tests

```sh
cargo test
```
