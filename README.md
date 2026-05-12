# security-review

**AI-powered security review of code changes as a Claude Code plugin.**

Run a single slash command — `/security-review` — to get a structured, severity-graded list of security findings on whatever you've changed. Powered by a dedicated `security-reviewer` agent that uses semantic analysis, not pattern matching, and filters out low-impact noise so the findings you see are the ones worth acting on.

## Installation

```bash
/plugin marketplace add cheezy/stride-marketplace
/plugin install security-review@stride-marketplace
```

The plugin auto-discovers the slash command, the agent, and the skill on install. No further configuration needed.

## Quick start

In any git repository, run:

```text
# Diff mode (default) — review what's changed against HEAD
/security-review                  # all working-tree changes (staged + unstaged) vs HEAD
/security-review lib/auth.ex      # scope to one file
/security-review lib/ test/       # scope to directories
/security-review --json           # raw JSON output for piping into tools
/security-review --json lib/foo   # path-scoped, raw JSON

# Full mode (--full) — review the codebase end-to-end (new in v1.1.0)
/security-review --full           # every tracked file in the repo
/security-review --full lib/      # full scan scoped to a path
/security-review --full --json    # full scan, raw JSON output

# MAESTRO 7-layer classification (--maestro) — group findings by agentic-AI threat layer
/security-review --maestro                # classify each finding by MAESTRO layer
/security-review --maestro --full         # full scan + layer classification
/security-review --maestro --json lib/    # raw JSON with maestro_layer fields
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
      "vulnerability_class": "injection | authentication | authorization | data_exposure | crypto | input_validation | race_condition | xss_or_code_exec | insecure_config",
      "cwe": ["CWE-89"],
      "owasp": ["A03:2021"],
      "description": "What and why",
      "remediation": "Specific fix",
      "confidence": "high | medium | low"
    }
  ],
  "summary": {
    "files_reviewed": 7,
    "findings_by_severity": {"critical": 0, "high": 1, "medium": 2, "low": 0, "info": 0}
  }
}
```

Every finding carries `cwe` (array of CWE-IDs like `["CWE-89"]`) and `owasp` (array of OWASP Top 10 2021 category strings like `["A03:2021"]`) so triage tools can group findings by canonical class without parsing prose. Both default to `[]` only when a finding doesn't map to any standard category (rare).

When the slash command is invoked with `--maestro`, each finding gains an optional `maestro_layer` field carrying one of seven canonical layer IDs (`foundation-models`, `data-operations`, `agent-frameworks`, `deployment-infrastructure`, `evaluation-observability`, `security-compliance`, `agent-ecosystem`) from the Cloud Security Alliance MAESTRO framework. When `--maestro` is not set, the field is OMITTED from the JSON entirely — callers that don't opt in see byte-identical legacy output.

The `--json` flag prints this document verbatim so other tools (CI gates, Stride hooks, dashboards) can consume it.

## Full-codebase scan mode

The default `/security-review` invocation reviews the working-tree diff against `HEAD`. That answers *"is this PR safe to merge?"* — but not *"what latent issues are in this codebase right now?"* The `--full` flag (added in v1.1.0) answers the second question by reviewing whole files rather than hunks.

Typical reasons to reach for `--full`: onboarding the plugin onto an existing repo (establish a baseline before you start gating PRs); a periodic posture check (quarterly, or on a cron); vendoring or forking an upstream codebase (review the imported code end-to-end before integrating); or a class-wide audit where the changed code is not the unit of interest. For PR-time gating, stay in diff mode — it is faster and the right shape for that question.

```text
/security-review --full                     # review every tracked file
/security-review --full lib/ apps/web/      # scope to listed paths
/security-review --full --json              # raw JSON for piping
```

`--full` is **additive** — it composes with path arguments and with `--json`. Diff mode remains the default and its behavior is unchanged. The output JSON schema is identical in both modes, so any tool already consuming the diff-mode JSON continues to work against a `--full` run.

### Contract

This is the surface contract every downstream piece of the plugin (slash command, agent prompt, skill, fixtures) follows. Implementation details for each bullet live in the file that owns that piece.

| Concern | Decision |
|---|---|
| **Flag** | `--full`. Parsed in the slash command's argument step and stripped from the path list before it reaches enumeration. |
| **Enumeration source** | `git ls-files` (optionally narrowed to user-supplied paths). This honors `.gitignore`, untracked-exclusions, and sparse-checkout — none of which `find` or a filesystem walk would honor for free. Untracked files are intentionally out of scope; if you want them reviewed, `git add -N` them first. |
| **Binary filter** | A file is treated as binary (and skipped) when `grep -Iq . <file>` exits non-zero. This is the same heuristic `grep -I` uses internally — null-byte-in-prefix detection — and avoids dispatching the agent on PNGs, compiled artifacts, or minified bundles whose null bytes break tokenization. |
| **Size cap** | Skip any file larger than **262,144 bytes (256 KiB)**. Above this threshold the file is almost always generated, vendored, or minified, and the agent's signal-to-noise on it collapses. Skipped files are counted in the summary but never reach the agent. |
| **Batch size** | Dispatch the `security-reviewer` agent on **10 files per batch**. Below this we burn dispatch overhead; above it we crowd the context window and lose per-file fidelity. Batches MAY be dispatched in parallel via multiple Agent tool calls in a single response. |
| **Findings merge rule** | The output of each batch is a JSON document conforming to the schema in the previous section. To merge N batch results: concatenate every batch's `findings` array; sum `summary.files_reviewed` across batches; sum each entry of `summary.findings_by_severity` (`critical`, `high`, `medium`, `low`, `info`) across batches. Do NOT deduplicate — different batches review different files and cannot collide on `(file, line)`. |
| **Empty-input short-circuit** | If enumeration yields zero files after filtering (e.g., empty repo, all files binary or over-cap), print the same short-circuit message diff mode uses for an empty diff and stop without dispatching the agent. |
| **Output schema** | Unchanged. The JSON document downstream tools consume is identical in diff and full modes; only the input shape and the human-readable header differ. |

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

The `--json` flag makes `/security-review` pipeable. Examples:

- A Stride completion hook can run `/security-review --json` and refuse to mark a task `done` if a critical finding is present.
- A CI gate can run `/security-review --full --json` on a schedule to track the codebase-wide finding count over time without coupling to any one PR.
- A CI gate can call the agent directly (without the slash command) by importing the agent prompt and feeding it a diff from `git diff origin/main`.
- A dashboard can ingest the JSON across many runs and chart the per-class trend.

The agent does not call any external service, so composition is safe in repos with sensitive content.

## Contributing

Issues and PRs welcome at <https://github.com/cheezy/security-review>. For prompt or filter changes, please include a smoke-test diff and the expected finding in your PR description so reviewers can verify the change does what you say.

## License

MIT — see [LICENSE](LICENSE).
