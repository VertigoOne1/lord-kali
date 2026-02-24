# lord-kali

A Claude Code [PreToolUse hook](https://docs.anthropic.com/en/docs/claude-code/hooks) that filters Bash and WebFetch tool calls.

Bash commands are parsed with [tree-sitter-bash](https://github.com/tree-sitter/tree-sitter-bash), correctly handling pipelines, `&&`/`||`/`;` chains, subshells, command substitutions (`$(...)`), and `xargs`-wrapped commands. WebFetch URLs are matched against configurable glob/regex patterns.

## Install

```sh
make install   # builds and copies to ~/.local/bin/
```

Then point your Claude Code hook at the binary in `~/.config/claude/settings.json`:

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
    ]
  }
}
```

## Configuration

Config lives at `~/.config/lord-kali/config.toml`. See [`config.toml`](config.toml) for an example.

```toml
# Optional — omit or set enabled=false to disable
[log]
enabled = true
path = "~/.local/state/lord-kali/hook.jsonl"

[bash]
allowed_commands = ["tail", "grep", "ls", "find", "cat", "head", "wc"]

# Rules are evaluated in config order per command. First matching rule wins.
# Each rule requires "command" and "decision" (allow/deny/ask).
# "args" and "reason" are optional.

[[bash.rules]]
command = "cargo"
args = "/(fmt|build|test)( .*)?/"
decision = "allow"

[[bash.rules]]
command = "rm"
args = "-rf *"
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
command = "git"
args = "status"
decision = "allow"

[[bash.rules]]
command = "git"
args = "log *"
decision = "allow"

# --- WebFetch URL filtering ---

[[web-fetch.rules]]
url = "https://evil.com/*"
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

### Bash rules

Rules are defined as `[[bash.rules]]` entries. Each rule has:

- **`command`** (required): the command name to match (basename only, e.g. `rm` not `/usr/bin/rm`)
- **`decision`** (required): `allow`, `deny`, or `ask`
- **`args`** (optional): glob or regex pattern matched against the command's arguments (joined by spaces). Omitting matches any arguments.
- **`reason`** (optional): message shown to the user. Defaults to `"ok"` for allow rules.

Rules for the same command are evaluated in config file order — the first rule whose `args` pattern matches wins. `allowed_commands` entries are appended after all explicit rules as `allow` matching any arguments.

### WebFetch rules

Rules are defined as `[[web-fetch.rules]]` entries. Each rule has:

- **`url`** (required): glob or regex pattern matched against the full URL
- **`decision`** (required): `allow`, `deny`, or `ask`
- **`reason`** (optional): message shown to the user. Defaults to `"ok"`.

Rules are evaluated in config file order — the first matching rule wins.

### Patterns

- **Glob** (default): `*` matches any characters, `?` matches a single character. All regex metacharacters are escaped.
- **Regex**: wrap the pattern in `//` delimiters, e.g. `/(fmt|build|test)( .*)?/`. `^` and `$` anchors are added automatically — do not include them in the pattern.

## Decision priority

### Bash

Given the set of commands extracted from a bash string, each command is resolved against its rules (first args match wins). Then across all commands:

1. **deny** — if ANY command resolves to deny
2. **ask** — if ANY command resolves to ask
3. **allow** — if ALL commands resolve to allow
4. **pass-through** — otherwise (no output, defers to Claude Code defaults)

### WebFetch

Given a URL, rules are evaluated in config file order:

1. **First matching rule** — its decision (allow/deny/ask) is returned
2. **pass-through** — if no rule matches (no output, defers to Claude Code defaults)

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
