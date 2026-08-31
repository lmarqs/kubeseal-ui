---
name: cli-design
description: This skill should be used when designing CLI commands, flag conventions, output formats, I/O channel allocation, exit code semantics, pipe ergonomics, or non-interactive modes. Activates on mentions of CLI design, command interface, stdout/stderr contract, flag handling, output format, pipe-safe output, exit codes, spinner behavior, --ci mode, non-interactive fallback, or kubeseal flag compatibility.
---

# CLI Design System

Design patterns for building CLI tools that compose well in Unix pipelines, respect terminal conventions, and provide excellent developer experience. Focused on tools that offer a familiar surface over an existing tool's job, as `ksui` does for `kubeseal`.

**Core philosophy:** A CLI earns trust by being predictable. Data flows through stdout, progress through stderr, flags work like the tools users already know, and scripts never break when upgrading.

## CLI Design Process

```
1. What operation? → Map to existing conventions (kubeseal, kubectl, git)
2. What output?   → Choose channel + format per mode (human/json/ci)
3. What flags?    → Inherit from the reference tool, add novel ones without collision
4. What errors?   → Actionable messages with hints, correct exit codes
5. Validate       → Test in pipes, CI, interactive terminal, non-TTY
```

---

## 1. The Familiar-Surface Principle

A tool that does the same job as an established CLI should be answerable with the
habits and scripts users already have, whether or not it runs that CLI. `ksui`
seals in-process rather than shelling out, so the compatibility it offers is a
matter of deliberate flag naming, not inheritance.

| Layer | Strategy | Example |
|-------|----------|---------|
| **Preserve** | Same name, same meaning as the reference tool | `--cert`, `--scope`, `-w`, `--fetch-cert` |
| **Diverge** | Better default, documented as a difference | `--format` defaults to `yaml`, not `json` |
| **Add** | Novel flags using unclaimed names | `--ci`, `--from-literal` |

**Rules:**
- A shared name must never carry a different meaning without being documented as
  such. `ksui --namespace` names the namespace the secret is sealed for, where
  kubeseal binds it as a kubeconfig override — so the contract says so outright.
- Divergent defaults are chosen for the common case and recorded, never silent.
- Novel additions use names the reference tool hasn't claimed.
- The whole comparison lives in one place: `docs/reference/cli-io-contract.md`.

---

## 2. Output Channel Contract

The fundamental rule: **stdout is for data, stderr is for humans.**

| Channel | Content | Consumer |
|---------|---------|----------|
| **stdout** | Data: the manifest, a fetched certificate, build information | Pipes, scripts, `jq`, `kubectl apply -f -` |
| **stderr** | Progress: the wizard, spinners, warnings, validation results | Human eyes only |

Writing the interactive flow to stderr is what makes `ksui > sealed.yaml` work
while the wizard is still on screen.

### Mode matrix

| Mode | stdout | stderr |
|------|--------|--------|
| Interactive (stderr and stdin are TTYs) | The manifest, once sealed | The wizard, spinners, warnings |
| Flags only | The manifest | Warnings and validation results |
| `-w <path>` or `merge` | Nothing — the file receives it | Warnings and validation results |
| `--ci`, or `CI` set, or either stream not a TTY | The manifest | Warnings only; missing input is a usage error, never a prompt |

### Critical invariants

- Piping stdout must never produce ANSI escapes or spinner artifacts
- Redirecting stdout to a file yields the data alone; `2>/dev/null` discards every
  diagnostic and leaves the data intact
- The interactive flow requires both stderr and stdin to be terminals
- `--ci` suppresses it explicitly, for runners where a stream might still be a TTY

---

## 3. Flag Design

### Compatibility flags (named after the reference tool)

- Keep the spelling and the short form: `-o`/`--format`, `-w`/`--sealed-secret-file`
- Keep the meaning too, or document the difference where one is unavoidable
- Borrow shorthands from the ecosystem, not just the one tool: `-n` is
  `--namespace` because that is how kubectl spells it

### Novel flags (your tool's additions)

- Always double-dash only: `--ci`, `--from-literal`, `--remove`
- Use names the reference tool hasn't claimed
- Repeatable flags are declared as arrays, so `--from-file` twice means two keys

### Flag categories

| Category | Examples | Rule |
|----------|----------|------|
| **Value flags** | `--name X`, `--cert X` | One value, last occurrence wins |
| **Repeatable** | `--from-literal`, `--from-file`, `--remove` | Accumulate; order is preserved |
| **Bool flags** | `--validate`, `--fetch-cert`, `--ci` | Never consume the next argument |

### Per-command flag sets

A subcommand takes only the flags it can honour. `ksui merge` reads the name,
namespace, type and sealing scope out of the file it was given, so it does not
offer `--name`, `--namespace` or `--scope` at all — changing any of them would
make the values already sealed in that file unreadable. Rejecting a flag by not
defining it beats accepting it and then explaining why it was ignored.

---

## 4. Exit Codes

Every code is part of the published contract, so each one names a distinct
outcome a script can branch on:

| Code | Meaning | When |
|------|---------|------|
| `0` | Success | The secret was sealed, or the wizard was left through one of its own actions |
| `1` | Error | A runtime failure: unreachable controller, RBAC denial, unwritable path |
| `2` | Usage | The command line needs changing: unknown flag, missing `--name`, no entries |
| `3` | Validation failed | The controller could not decrypt the result (`--validate`) |
| `130` | Interrupted | A signal, or Ctrl+C in the wizard, ended the run (128 + SIGINT) |

Rules:
- Separate "you must fix the command line" from "the world did not cooperate".
  Only the first is worth a `hint:`; only the second is worth retrying.
- Give the code and its hint a home in the error value, not in the text. A
  `codedError{code, hint, err}` lets the top-level handler report both without
  parsing message strings.
- Parser errors are usage errors. A framework that exits 1 on an unknown flag is
  contradicting the table, so route its errors through the same type.
- Exit 0 does not imply every check ran. When `--validate` is skipped because no
  controller was reachable, the warning on stderr is what distinguishes the two.

---

## 5. Spinner & Progress

### When to show

```
showSpinner = !ci && os.Getenv("CI") == "" && isTerminal(stderr) && isTerminal(stdin)
```

Every condition must hold. This ensures:
- CI gets clean logs, whether it announces itself by flag or by environment
- Redirected stdout stays pure
- Piped stderr stays artifact-free

### How to render

- Write to stderr only
- Use `\r\033[K` (carriage return + clear line) for updates
- Show elapsed time for long operations: `Fetching certificate... (12s)`
- Clear completely on finish (no trailing artifacts)
- Start after 200ms delay (avoid flash on fast operations)

---

## 6. Error Messages

- Write to stderr via the framework's error handling
- Start with lowercase (Go convention: `fmt.Errorf("sealing: %w", err)`)
- Wrap with context: what failed + why
- Add hints for actionable recovery: `hint: pass --controller-namespace if the
  controller is not in kube-system`
- Never use "Press X to Y" patterns (that's TUI territory)
- Include the failing path/resource when available

---

## 7. Pipe Ergonomics

Every CLI command must work in these compositions:

```bash
# Filter pattern: stdin → transform → stdout
pass show db/password | ksui --name db-creds -n payments --from-file password=-

# Redirection pattern: data to a file, diagnostics to the terminal
ksui --name db-creds -n payments --from-literal a=b > db-creds.yaml

# Composition pattern: hand the manifest straight to another tool
ksui --name db-creds -n payments --from-literal a=b -o json | jq '.spec.encryptedData'
ksui --name db-creds -n payments --from-literal a=b | kubectl apply -f -
```

### Stdin conventions

- `-` means stdin (universal Unix convention), and so does `/dev/stdin`
- Detect stdin availability: `!isatty(stdin)`
- If no stdin and no file argument → error with suggestions
- Never block waiting for stdin without indicating what's expected
- Only one value may be read from stdin. A second would silently receive nothing,
  so asking twice is a usage error rather than a surprise at runtime.

---

## 8. Non-Interactive Fallback

When stdin is not a TTY:
- Skip interactive modes (TUI, prompts, confirmations)
- Render output and exit immediately
- If interaction is required → name the missing input and how to supply it:
  `hint: pass --name to say what the secret is called`

When stdout is not a TTY:
- Suppress ANSI color/formatting in stdout
- Keep data format identical (just strip decoration)

---

## 9. Output Format Design

### When the format is someone else's schema

A SealedSecret is a Kubernetes resource, so `-o yaml` and `-o json` are two
encodings of one object, not two schemas. The tool picks neither the field names
nor the shape — it renders what the API type says. `kubectl apply -f -` accepting
the result is the test.

Choose the default for where the output usually ends up. `ksui` defaults to
`yaml` because manifests get committed to repositories, and records the departure
from kubeseal's `json` in the contract.

### When editing in place, keep the shape you were handed

`ksui merge` defaults `--format` to neither. A file that arrived as YAML leaves as
YAML, so rotating one key never reformats the whole manifest in a diff.

### If you do design a schema

- Top-level object with a `version` field for future evolution
- Consistent field naming, matching the ecosystem the output will be read in
- Errors as structured objects, not strings
- NDJSON for streaming operations (one JSON object per line)

---

## 10. Config Resolution

When your tool has its own config file:

```
CLI flags  >  env vars  >  project config  >  user config  >  defaults
```

Rules:
- Config file absence is non-fatal (standalone mode)
- Parse errors are fatal with actionable hint
- Config never contradicts CLI flags (flags always win)
- Log which config was loaded at debug level

---

## Anti-Patterns

| # | Anti-Pattern | Fix |
|---|-------------|-----|
| 1 | **Data on stderr** | Data always goes to stdout, even errors about data |
| 2 | **ANSI in piped output** | Detect TTY, strip when piped |
| 3 | **Novel flag collides with the reference tool** | Check its flag namespace before naming |
| 4 | **Spinner on stdout** | Spinner goes to stderr, gated by TTY check |
| 5 | **Blocking stdin without signal** | Show "reading from stdin..." or error if no pipe |
| 6 | **Exit 0 on error** | Always exit non-zero on failure |
| 7 | **Reshaping a schema you do not own** | Render the API type as-is; the format flag picks the encoding, not the fields |
| 8 | **Interactive prompts in piped mode** | Detect non-TTY stdin, use flags instead |
| 9 | **Inconsistent flag naming** | Pick one style (double-dash for novel) and stick to it |
| 10 | **A shared flag name that quietly means something else** | Keep the meaning, or document the difference where it is unavoidable |
| 11 | **Silently skipping a check the caller asked for** | Warn on stderr, so exit 0 is never mistaken for "verified" |

---

## Compatibility Checklist

Before shipping a CLI command:

- [ ] `cmd -o json | jq '.'` works (stdout is clean JSON)
- [ ] `cmd > /dev/null` produces no ANSI artifacts
- [ ] `cmd 2>/dev/null` suppresses all progress (only data on stdout)
- [ ] `cmd > out.yaml` leaves the file holding the manifest alone
- [ ] Works in `set -e` scripts (correct exit codes)
- [ ] `--ci` and `CI=1` both refuse to prompt, and say what is missing
- [ ] Non-TTY stdin handled gracefully (error or read, no hang)
- [ ] Every flag shared with the reference tool has the same meaning, or the
      difference is written down
- [ ] Output another tool consumes is accepted by that tool (`kubectl apply -f -`)
- [ ] Error messages include enough context to debug without re-running
- [ ] `--help` output goes to stdout (convention for piping to pager)

---

## Benchmarks & References

Tools with excellent CLI UX to study:

| Tool | Notable for |
|------|-------------|
| **ripgrep** | Perfect output channel separation, smart TTY detection |
| **jq** | Pure filter pattern, composable, predictable |
| **gh (GitHub CLI)** | Wraps API elegantly, `--json` with field selection |
| **kubectl** | Multiple output formats (`-o json/yaml/wide/name`), `-f -` for stdin |
| **kubeseal** | The flag surface this tool matches, and where it deliberately does not |
| **exa/eza** | Graceful color degradation, `--no-color` respect |
| **fd** | Smart defaults that differ from `find`, great pipe behavior |

## What This Skill is NOT

- Not a replacement for testing in real shells and CI environments.
- Not framework-specific (applies to cobra, urfave/cli, clap, click).
- Not about TUI/interactive mode — that's the tui-design skill.
- Not an excuse to reinvent existing conventions.
