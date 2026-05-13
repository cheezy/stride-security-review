# stride-security-review

**AI-powered security review of code changes as a Claude Code plugin.**

Run a single slash command — `/stride-security-review:security-review` — to get a structured, severity-graded list of security findings on whatever you've changed. Powered by a dedicated `security-reviewer` agent that uses semantic analysis, not pattern matching, and filters out low-impact noise so the findings you see are the ones worth acting on.

## Installation

```bash
/plugin marketplace add cheezy/stride-marketplace
/plugin install stride-security-review@stride-marketplace
```

The plugin auto-discovers the slash command, the agent, and the skill on install. No further configuration needed.

## Invocation form

Claude Code ships with a built-in `/security-review` command (a diff-only review that does NOT understand this plugin's flags — `--full`, `--json`, `--maestro`, `--rci`, `--baseline`, `--patches` are silently ignored). To invoke **this** plugin, use the namespaced form `/stride-security-review:security-review`. All examples below use that form.

> **Renamed in v2.0.0.** This plugin was previously named `security-review`, which created a namespace collision with the Claude Code built-in. The rename to `stride-security-review` resolves the collision: the bare `/security-review` cleanly belongs to the built-in, and this plugin lives at `/stride-security-review:security-review`. If you have scripted invocations of the old namespaced form, update them to the new one.

## Quick start

In any git repository, run:

```text
# Diff mode (default) — review what's changed against HEAD
/stride-security-review:security-review                  # all working-tree changes (staged + unstaged) vs HEAD
/stride-security-review:security-review lib/auth.ex      # scope to one file
/stride-security-review:security-review lib/ test/       # scope to directories
/stride-security-review:security-review --json           # raw JSON output for piping into tools
/stride-security-review:security-review --json lib/foo   # path-scoped, raw JSON

# Full mode (--full) — review the codebase end-to-end (new in v1.1.0)
/stride-security-review:security-review --full           # every tracked file in the repo
/stride-security-review:security-review --full lib/      # full scan scoped to a path
/stride-security-review:security-review --full --json    # full scan, raw JSON output

# MAESTRO 7-layer classification (--maestro) — group findings by agentic-AI threat layer
/stride-security-review:security-review --maestro                # classify each finding by MAESTRO layer
/stride-security-review:security-review --maestro --full         # full scan + layer classification
/stride-security-review:security-review --maestro --json lib/    # raw JSON with maestro_layer fields

# Recursive Criticism & Improvement (--rci [N]) — run N additional critique passes
/stride-security-review:security-review --rci                    # one extra critique pass after the first dispatch
/stride-security-review:security-review --rci 2                  # two extra critique passes (clamped to 3)
/stride-security-review:security-review --rci --full             # critique pass over a full scan (expensive)

# Baseline suppression (--baseline) — suppress already-acknowledged findings
/stride-security-review:security-review --baseline               # auto-detect .security-review-baseline.json in repo root
/stride-security-review:security-review --baseline ci.json       # explicit baseline path
/stride-security-review:security-review --update-baseline        # rewrite the baseline from current findings

# Auto-remediation patches (--patches) — emit surgical-fix diffs alongside findings
/stride-security-review:security-review --patches                # diff mode + per-finding patch suggestions
/stride-security-review:security-review --patches --json         # raw JSON includes the patch field
```

Diff mode answers *"is this change safe to merge?"* — invoke it before pushing a PR. Full mode answers *"what latent issues are in this codebase right now?"* — invoke it when onboarding the plugin onto an existing repo, or on a periodic posture-check cadence. MAESTRO mode answers *"which architectural layer needs the most attention?"* — invoke it on codebases that wire LLMs / agents / Model Context Protocol clients into the request flow, so findings can be grouped by the seven-layer model from Cloud Security Alliance's MAESTRO framework. The flags compose: `--maestro --full --json lib/` is valid. The output JSON schema is identical in diff and full modes; `--maestro` is the one flag that adds an optional field (`maestro_layer`) to each finding when set.

Sample output for a small diff with one finding:

```text
Security review — 1 finding across 2 files
Critical: 0   High: 1   Medium: 0   Low: 0   Info: 0

## High

**[injection]** lib/users.ex:42 — confidence: high — CWE-89, A03:2021
User-supplied `username` parameter is concatenated directly into a SQL string at the call to
Repo.query/2 below. The trust boundary is the HTTP request handler at line 38, and the sink is
the raw query string passed to Postgres — classic SQL injection. Worst-case outcome is
full-table read for any user with credentials to reach this endpoint.

Fix: Use Ecto's parameterized query API. Replace the string-concatenated query with
Repo.query("SELECT * FROM users WHERE username = $1", [username]) so user input is bound as a
parameter rather than interpolated into the SQL text.
```

## What it catches

The `security-reviewer` agent (see [`agents/security-reviewer.md`](agents/security-reviewer.md)) reviews diffs across these vulnerability classes:

| Class | Examples |
|---|---|
| Injection | SQL, command, LDAP, NoSQL, XXE, template, header |
| Authentication | Missing auth check, timing-vulnerable comparison, weak password requirements |
| Authorization | IDOR, privilege escalation through parameter tampering, trusting client roles |
| Data exposure | Hardcoded secrets, secrets in logs, PII in error responses, sensitive data over plaintext |
| Cryptography | MD5/SHA1 for passwords, ECB mode, static IVs, predictable RNG for tokens |
| Input validation | Path traversal, SSRF, open redirect, zip-bomb decompression, trusting client validation |
| Race conditions | Filesystem TOCTOU, unlocked read-modify-write on security-sensitive state, symlink races |
| XSS / code execution | DOM/reflected/stored XSS, SSTI, deserialization of untrusted data |
| Insecure configuration | CORS `*` with credentials, disabled CSRF, debug mode in prod, missing security headers, disabled cert verification |
| Supply chain | Floating-tag container base images, `curl \| sh` installers, CI/CD references by branch/tag instead of immutable SHA, manifest/lockfile drift, typosquat or hallucinated package names — multi-platform (Docker, GitHub Actions, GitLab CI, CircleCI, Bitbucket Pipelines, Jenkins) and multi-ecosystem (npm/PyPI/RubyGems/Hex/crates.io/Maven/NuGet/Packagist/Go modules) |

In addition to the universal classes above, three framework-specific rule packs ship by default — they activate based on file extension AND import detection (never extension alone):

| Pack | Activates on | Idiomatic rules |
|---|---|---|
| Django / Python | `.py` with `django.*` / `rest_framework` / `django.db` imports | `mark_safe` on user input, `extra` / `raw()` query interpolation, CSRF disabled, `DEBUG=True` in prod settings, mass-assignment via `cleaned_data` |
| Phoenix / Elixir | `.ex` / `.exs` / `.heex` / `.eex` with `Phoenix.LiveView` / `Phoenix.Controller` / `Plug.Conn` / `Ecto.Query` / `Phoenix.HTML` references | `Phoenix.HTML.raw/1` on user-controlled data, missing `force_ssl`, `Plug.CSRFProtection` disabled, `Ecto.Query.fragment` with string interpolation, LiveView event handler trusting `phx-value-id` without re-scoping |
| Rails / Ruby | `.rb` / `.erb` with `ActionController` / `ActiveRecord` / `ApplicationController` references | `html_safe` / `raw()` on user input, `find_by_sql` with interpolation, `protect_from_forgery` disabled, `params.permit!` mass-assignment, `eval` / `send` / `instance_eval` with user input |

Each pack's rules map to one of the universal vulnerability classes — there are NO per-framework enum values. Adding a fourth pack (Spring, Express, Gin, Laravel, FastAPI, etc.) follows the documented template in the agent prompt.

A dedicated **CI/CD pipeline rule pack** activates on recognized pipeline files across eight platforms (alphabetical): Azure Pipelines, Bitbucket Pipelines, CircleCI, Drone, GitHub Actions, GitLab CI, Jenkins, Tekton. The same five rules apply to every platform: (1) external action / orb / template not pinned to an immutable SHA, (2) overly-broad permissions or scopes, (3) untrusted-ref or fork-PR build patterns, (4) secrets exposed alongside attacker-controlled input, (5) expression / interpolation injection in shell-step bodies. Activation is by file path (`.github/workflows/*.yml`, `.gitlab-ci.yml`, `.circleci/config.yml`, `bitbucket-pipelines.yml`, `Jenkinsfile`, `azure-pipelines.yml`, `.drone.yml`, `.tekton/*.yaml`) — generic YAML never triggers these rules. Adding a ninth platform means listing its file path and walking the five existing rules; the rule count stays fixed.

For codebases that integrate LLMs, AI agents, or Model Context Protocol clients, five additional MAESTRO-derived classes activate (the file must import a recognized LLM/agent/MCP SDK in any language — Python, JavaScript/TypeScript, Go, Ruby, Elixir, Java/Kotlin all supported):

| Class | Examples |
|---|---|
| Prompt injection | Untrusted text concatenated into an LLM prompt without separation; `messages=[{"role":"user","content": user_input}]` patterns; un-delimited RAG context |
| Tool abuse | Agent function-call / MCP tool layer exposing file/shell/DB/HTTP/credential operations without per-tool authorization or input validation |
| Agent trust boundary | Agent-to-agent (A2A) message passing where one agent's output flows into another's prompt without the receiver treating it as untrusted |
| Model output execution | LLM response text flowing into `eval`, `exec`, `subprocess` with `shell=True`, `Function()`, `os/exec.Command`, or any code-execution sink |
| Vector store poisoning | User-controllable content embedded into a vector DB (Pinecone, Weaviate, Chroma, pgvector, etc.) without sanitization or source attribution |

The agent uses **semantic analysis**: a `grep` hit on `eval(` is not a finding; `eval(user_input)` at a trust boundary is. The analysis methodology, severity rubric, and JSON output schema live in the agent prompt.

## What it deliberately ignores

To keep signal-to-noise high, the agent suppresses findings whose only impact is:

- **Denial-of-service** that is not also a data-integrity or confidentiality issue.
- **Rate limiting** as a general concern — unless its absence is on a credential or token-generation endpoint (which falls under Authentication).
- **Memory exhaustion** unless it enables another vulnerability class.
- **Hypothetical risks** not realizable through the changed code.
- **Code style** disguised as security concerns.

If your organization needs those classes flagged, see [Customization](#customization) — extend the agent prompt rather than working around the filter.

## Output schema

The agent always returns a single fenced ```json document conforming to:

```json
{
  "findings": [
    {
      "severity": "critical | high | medium | low | info",
      "file": "path/relative/to/repo/root.ext",
      "line": 42,
      "vulnerability_class": "injection | authentication | authorization | data_exposure | crypto | input_validation | race_condition | xss_or_code_exec | insecure_config | supply_chain | prompt_injection | tool_abuse | agent_trust_boundary | model_output_execution | vector_store_poisoning",
      "cwe": ["CWE-89"],
      "owasp": ["A03:2021"],
      "description": "What and why",
      "remediation": "Specific fix",
      "confidence": "high | medium | low",
      "maestro_layer": "data-operations",
      "patch": "--- a/lib/users.ex\n+++ b/lib/users.ex\n@@ ..."
    }
  ],
  "summary": {
    "files_reviewed": 7,
    "findings_by_severity": {"critical": 0, "high": 1, "medium": 2, "low": 0, "info": 0},
    "files_skipped": [{"path": "priv/static/app.js", "reason": "oversize"}],
    "suppressed_count": 0,
    "rci_passes": 0
  }
}
```

**Required per-finding fields** (always present): `severity`, `file`, `line`, `vulnerability_class`, `cwe`, `owasp`, `description`, `remediation`, `confidence`. Every finding carries `cwe` (array of CWE-IDs like `["CWE-89"]`) and `owasp` (array of OWASP Top 10 2021 category strings like `["A03:2021"]`) so triage tools can group findings by canonical class without parsing prose. Both arrays default to `[]` only when a finding doesn't map to any standard category (rare).

**Optional per-finding fields** (emitted only when the corresponding flag is set):

| Field | Emitted when | Notes |
|---|---|---|
| `maestro_layer` | `--maestro` is set | One of seven canonical layer IDs from CSA MAESTRO: `foundation-models`, `data-operations`, `agent-frameworks`, `deployment-infrastructure`, `evaluation-observability`, `security-compliance`, `agent-ecosystem`. Omitted entirely when `--maestro` is not set. |
| `patch` | `--patches` is set AND the agent can produce a surgical fix | A unified-diff string the user can pipe to `git apply`. The agent emits a patch only when the fix is surgical (1–20 lines, single file, no new deps, no API breaks), unambiguous, and verifiable from the supplied input alone. Most findings won't have one even with `--patches` set. |

**Optional summary fields**:

| Field | Emitted when | Notes |
|---|---|---|
| `files_skipped` | `--full` is set | Array of `{path, reason}` records for files the binary/size filters dropped. `reason` is one of `binary`, `oversize`, `unreadable`. Always emitted in full mode (even as `[]` to prove the filter ran); omitted in diff mode. |
| `suppressed_count` | `--baseline` is set | Integer count of findings filtered out by the baseline. Omitted entirely when no baseline is in play. |
| `rci_passes` | `--rci [N]` is set | Integer recording how many Recursive Criticism & Improvement passes ran on top of the initial dispatch. Omitted when `--rci` is not set. |

**Cross-batch dedup (full mode).** Full-mode batches are merged with an order-stable dedup pass keyed by `(file, line, vulnerability_class)` — duplicates that surface across batches or RCI passes collapse to the first occurrence. Diff mode is a single dispatch and dedup is a no-op there; the merged document is byte-identical to the agent's output.

**Flag composition.** All flags compose. `--maestro --rci 2 --patches --baseline --full --json lib/` is a valid invocation. The `--json` flag prints the document verbatim so other tools (CI gates, Stride hooks, dashboards) can consume it.

## Full-codebase scan mode

The default `/stride-security-review:security-review` invocation reviews the working-tree diff against `HEAD`. That answers *"is this PR safe to merge?"* — but not *"what latent issues are in this codebase right now?"* The `--full` flag (added in v1.1.0) answers the second question by reviewing whole files rather than hunks.

Typical reasons to reach for `--full`: onboarding the plugin onto an existing repo (establish a baseline before you start gating PRs); a periodic posture check (quarterly, or on a cron); vendoring or forking an upstream codebase (review the imported code end-to-end before integrating); or a class-wide audit where the changed code is not the unit of interest. For PR-time gating, stay in diff mode — it is faster and the right shape for that question.

```text
/stride-security-review:security-review --full                     # review every tracked file
/stride-security-review:security-review --full lib/ apps/web/      # scope to listed paths
/stride-security-review:security-review --full --json              # raw JSON for piping
```

`--full` is **additive** — it composes with path arguments and with `--json`. Diff mode remains the default and its behavior is unchanged. The output JSON schema is identical in both modes, so any tool already consuming the diff-mode JSON continues to work against a `--full` run.

### Contract

This is the surface contract every downstream piece of the plugin (slash command, agent prompt, skill, fixtures) follows. Implementation details for each bullet live in the file that owns that piece.

| Concern | Decision |
|---|---|
| **Flag** | `--full`. Parsed in the slash command's argument step and stripped from the path list before it reaches enumeration. |
| **Enumeration source** | `git ls-files` (optionally narrowed to user-supplied paths). This honors `.gitignore`, untracked-exclusions, and sparse-checkout — none of which `find` or a filesystem walk would honor for free. Untracked files are intentionally out of scope; if you want them reviewed, `git add -N` them first. |
| **Binary filter** | A single-shot `grep -Il . <file1> <file2> ...` call lists every non-empty text file in the enumeration. Any candidate path NOT in `grep`'s stdout is treated as binary and skipped. This preserves the original null-byte-in-prefix heuristic (`grep -I`) and avoids dispatching the agent on PNGs, compiled artifacts, or minified bundles whose null bytes break tokenization. The call is batched into chunks of ~50 paths to stay under `ARG_MAX`; each chunk is a single Bash invocation matching the slash command's `Bash(grep:*)` permission entry, so the filter runs unattended in CI (no per-file pipe to gate). |
| **Size cap** | Skip any file larger than **262,144 bytes (256 KiB)**. Above this threshold the file is almost always generated, vendored, or minified, and the agent's signal-to-noise on it collapses. A single-shot `wc -c <file1> <file2> ...` call (batched into chunks of ~50) yields one `<bytes> <path>` line per file; any path over the threshold lands in `files_skipped` with `reason: "oversize"`. Each `wc` chunk is a single Bash invocation matching `Bash(wc:*)`. |
| **Batch size** | Dispatch the `security-reviewer` agent on **10 files per batch**. Below this we burn dispatch overhead; above it we crowd the context window and lose per-file fidelity. Batches MAY be dispatched in parallel via multiple Agent tool calls in a single response. |
| **Findings merge rule** | The output of each batch is a JSON document conforming to the schema in the previous section. Merge in batch order, then run an order-stable dedup pass keyed by `(file, line, vulnerability_class)` — first occurrence wins. Dedup catches the rare case where shared setup code drives different batches to converge on the same finding, and where RCI passes replay the same batch. `summary.findings_by_severity` is recomputed from the post-dedup findings list, not summed from per-batch counters (those drift after dedup). `summary.files_reviewed` is summed across batches. The dedup pass is a no-op in diff mode (one dispatch, no RCI) so diff-mode JSON output is byte-identical to the agent's response. |
| **Skipped-files reporting** | The Step 2b enumeration loop records every filtered file as `{path, reason}` where `reason ∈ {binary, oversize, unreadable}`. The merged document carries these as `summary.files_skipped` (always emitted in full mode, even as `[]`) so users can audit coverage. The human-readable report renders a `## Skipped` block capped at 50 entries with an `... and N more` overflow line. |
| **Empty-input short-circuit** | If enumeration yields zero files after filtering (e.g., empty repo, all files binary or over-cap), print the same short-circuit message diff mode uses for an empty diff and stop without dispatching the agent. |
| **Output schema** | The JSON document downstream tools consume is identical in diff and full modes for the required fields; full mode additionally emits `summary.files_skipped`. Optional fields gated by flags (`maestro_layer`, `patch`, `summary.rci_passes`, `summary.suppressed_count`) compose the same way in both modes. |

### What `--full` deliberately does NOT do

- **It does not change vulnerability classes, severity rubric, or the false-positive filter.** Those live in the agent prompt and apply to both modes.
- **It does not become the default.** Diff mode is the PR-gating workflow most users invoke; full mode is an explicit posture-check action.
- **It does not enumerate untracked files.** `git ls-files` is the source of truth; if a file isn't tracked, it isn't reviewed.
- **It does not deduplicate findings against an earlier run.** Each invocation is independent; trend tracking is the consumer's job.

## Customization

Two customization knobs:

1. **Scope by path.** Pass paths as arguments to limit the review to a subset of changed files (diff mode) or tracked files (full mode). Useful in monorepos. Composable with both modes.
2. **Extend the agent prompt.** Fork or patch [`agents/security-reviewer.md`](agents/security-reviewer.md) to add organization-specific vulnerability classes or to tighten/loosen the false-positive filter. **Keep the output schema stable** so downstream tooling continues to parse correctly.

The skill at [`skills/security-review-essentials/SKILL.md`](skills/security-review-essentials/SKILL.md) documents the *surface*; the agent prompt documents the *behavior*. Customize the agent prompt for behavior changes; customize the skill description for trigger-phrase tuning.

## Composing with other plugins

The `--json` flag makes `/stride-security-review:security-review` pipeable. Examples:

- A Stride completion hook can run `/stride-security-review:security-review --json` and refuse to mark a task `done` if a critical finding is present.
- A CI gate can run `/stride-security-review:security-review --full --json` on a schedule to track the codebase-wide finding count over time without coupling to any one PR.
- A CI gate can call the agent directly (without the slash command) by importing the agent prompt and feeding it a diff from `git diff origin/main`.
- A dashboard can ingest the JSON across many runs and chart the per-class trend.

The agent does not call any external service, so composition is safe in repos with sensitive content.

## Running the eval locally

The `scripts/run_eval.sh` runner dispatches the `security-reviewer` agent against every fixture in `test/fixtures/` and asserts the findings documented in `test/fixtures/EXPECTED.md`. It is the same suite CI runs (`.github/workflows/eval.yml`).

### Prerequisites

- `jq` on `$PATH`
- The Claude Code CLI (`claude`) on `$PATH` — set `CLAUDE_CLI` if your binary lives elsewhere
- `ANTHROPIC_API_KEY` exported (unless using `--dry-run`)

### Run

```bash
bash scripts/run_eval.sh                                  # all 23 expectations
bash scripts/run_eval.sh --fixture test/fixtures/sql_injection.py
bash scripts/run_eval.sh --dry-run                        # parser/comparator only; no API calls
bash scripts/run_eval.sh --verbose                        # echo prompts and raw agent JSON to stderr
```

Output is [TAP 13](https://testanything.org/tap-version-13-specification.html): one `ok N` / `not ok N` line per fixture, followed by a trailing pass/fail summary. Exit code `0` means every expected `vulnerability_class` + `severity` was produced at least once on the expected file (the Bitbucket multi-finding fixture requires both expected findings).

Per fixture, two files land in `logs/` (gitignored):

- `logs/<sanitized-path>.json` — the parsed JSON document the agent emitted, with any wrapping prose stripped.
- `logs/<sanitized-path>.raw.txt` — the full unmodified stdout from `claude -p`, useful when the parser can't fence-extract or when you want to see what surrounded the JSON.

### Tolerance

The runner asserts `(file, vulnerability_class, severity, count)`. CWE and OWASP mismatches surface as `# warn:` TAP comments but do not fail the run — they are advisory metadata, not the contract. EXPECTED.md is the spec; do not modify it to match the agent.

## Contributing

Issues and PRs welcome at <https://github.com/cheezy/stride-security-review>. For prompt or filter changes, please include a smoke-test diff and the expected finding in your PR description so reviewers can verify the change does what you say.

## License

MIT — see [LICENSE](LICENSE).
