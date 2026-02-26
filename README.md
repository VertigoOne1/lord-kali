# lord-kali

A Claude Code [PreToolUse hook](https://docs.anthropic.com/en/docs/claude-code/hooks) that filters Bash and WebFetch tool calls with a more powerful matching system than Claude Code supports natively.

Bash commands are parsed with [tree-sitter-bash](https://github.com/tree-sitter/tree-sitter-bash), correctly handling pipelines, `&&`, `||`, `;` chains, subshells, command substitutions (`$(...)`), and `xargs`-wrapped commands. WebFetch URLs are matched against configurable glob/regex patterns.

## Install

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
    ]
  }
}
```

## Configuration

All `*.toml` files in `~/.config/lord-kali/` are loaded in lexicographic order and merged. This lets you split config into files like `00-base.toml`, `10-bash.toml`, `20-groups.toml`. If no `.toml` files are found, a default config is used (everything passes through).

Within each file, rules are ordered: top-level rules first, then group rules in definition order. When files are merged, each file's rules are appended after the previous file's. The combined result is evaluated first-match-wins, so rules from earlier files have higher priority. For bash rules sharing the same command key, both files' rules are concatenated (earlier file first). For `[log]`, the last file with a `[log]` section wins.

```toml
# Optional - omit or set enabled=false to disable
[log]
enabled = true
path = "~/.local/state/lord-kali/hook.jsonl"

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

### Patterns

- **[Glob via glob-match-ultra](https://github.com/insidewhy/glob-match#syntax)** (default): `*` matches within a segment (stops at `/`), `**` matches across `/` boundaries, `?` matches a single character. Also supports `[a-z]` character classes, `{a,b}` brace expansion with empty alternatives (e.g. `{, **}` to match with or without arguments), and `!` negation.
- **Regex**: wrap the pattern in `//` delimiters, e.g. `/(fmt|build|test)( .*)?/`. `^` and `$` anchors are added automatically - do not include them in the pattern.

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
