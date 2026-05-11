---
name: security-review-essentials
description: Use when about to merge code changes that touch security-sensitive surfaces — authentication, authorization, cryptography, user input handling, secrets management, database queries, shell-outs, file uploads, redirects, or response rendering. Also use before pushing a PR that modifies any of the above, or when a human reviewer asks for a security check. Surfaces the /security-review slash command and the security-reviewer agent. Findings are structured JSON grouped by severity (critical / high / medium / low / info) with semantic — not pattern-match — analysis. Low-impact noise (denial-of-service, rate-limiting, memory-exhaustion) is intentionally filtered out unless it intersects another vulnerability class.
skills_version: 1.0
---

# security-review-essentials

This skill documents how to invoke the AI-powered security review delivered by the `security-review` plugin. It tells you *when* to invoke and *what the output means*. The analysis methodology itself lives in the `security-reviewer` agent prompt — do not duplicate it here.

## When to invoke

Invoke the security review **before** any of the following:

- Pushing a PR that touches authentication, authorization, session handling, or password/token handling.
- Pushing a PR that touches cryptography (hashing, signing, encryption, random number generation for security purposes).
- Pushing a PR that touches user input handling, query building, shell-outs, file uploads, redirects, or response rendering.
- Merging code into `main` or any deployment branch when the diff is large enough that a manual security read is impractical.
- A human reviewer asks "did you run a security check on this?"

Invoke as:

```text
/security-review                 # all working-tree changes (staged + unstaged) vs HEAD
/security-review path/to/file    # scope to specific paths
/security-review --json          # raw JSON output (for piping into tools)
```

## When NOT to invoke

- On a clean working tree (no changes against HEAD). The command short-circuits with a single line.
- On docs-only or test-only changes that touch no production paths. The agent will return an empty findings list, but the dispatch cost is not zero.
- As a substitute for routine secure-coding hygiene. The agent is a backstop, not the front line.

## What the agent does

The `security-reviewer` agent (`agents/security-reviewer.md` in this plugin) receives the diff and returns a JSON document with one finding per vulnerability. Vulnerability classes covered: injection, authentication, authorization, data exposure, cryptography, input validation, race conditions, XSS/code execution, insecure configuration.

The agent operates on **semantic analysis, not pattern matching**. A `grep` hit on `eval(` is not a finding; `eval(user_input)` at a trust boundary is. This is the agent's distinguishing property versus a static analyzer.

## Output shape

Each finding has:

| Field | Meaning |
|---|---|
| `severity` | `critical`, `high`, `medium`, `low`, or `info` — see the agent prompt for assignment rubric |
| `file` / `line` | Source location of the issue |
| `vulnerability_class` | One of the nine classes listed above |
| `description` | What the vulnerability is, what trust boundary is crossed, what the worst realistic outcome is |
| `remediation` | The specific change that fixes it |
| `confidence` | `high`, `medium`, or `low` — how certain the agent is given only the diff context |

A `summary` object reports `files_reviewed` and a per-severity finding count.

## False-positive filter

The agent intentionally suppresses findings whose only impact is generic denial-of-service, generic rate-limiting absence, or generic memory exhaustion — unless those intersect another class (e.g., rate-limiting absence on an authentication endpoint stays in scope under Authentication flaws). This filter exists because experience showed those classes generate noise that drowns out the actionable findings.

If your organization has a stricter policy that wants those classes flagged, extend the agent prompt — do not work around it by ignoring the filter list, because that loses the auditability trail.

## Customization

Two customization knobs at v1.0:

1. **Scope by path.** Pass paths as arguments to scope the review to a subset of changed files. Useful for monorepos where one team's diff doesn't need review by another team's security baseline.
2. **Extend the agent prompt.** Fork or patch `agents/security-reviewer.md` to add organization-specific vulnerability classes or to tighten/loosen the false-positive filter. The output schema is the contract — keep that stable so downstream tooling continues to parse correctly.

## Composing with other workflows

The `--json` flag makes the command pipeable. Other plugins (e.g., a Stride completion hook that wants to gate task completion on a clean review) can dispatch `/security-review --json`, parse the result, and decide whether to block. The agent does not call out to any external service, so this composition is safe for sensitive repos.

## What this skill does NOT cover

- The actual analysis methodology (in `agents/security-reviewer.md`).
- The command pipeline (in `commands/security-review.md`).
- Output rendering details (in the same command file).

This skill is the *surface* description. Implementation lives in the files referenced above.
