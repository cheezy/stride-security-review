---
description: AI-powered security review of the current git diff (or specified paths). Dispatches the security-reviewer agent and prints findings grouped by severity.
allowed-tools: Bash(git diff:*), Bash(git status:*), Bash(git ls-files:*), Bash(git rev-parse:*), Read, Glob, Grep, Agent
argument-hint: "[--json] [path ...]"
---

Run an AI-powered security review of code changes in this repository. Detects vulnerabilities across injection, authentication/authorization, data exposure, cryptography, input validation, race conditions, XSS/code execution, and insecure configuration. Filters out low-impact noise (denial-of-service, rate-limiting, memory-exhaustion).

## What to do

Follow these steps in order. Do NOT skip steps. The command is a pipeline: gather diff → dispatch agent → render output.

### Step 1: Parse arguments

The user invoked you with the arguments `$ARGUMENTS`. Treat them as a space-separated list:

- If `--json` appears anywhere in the list, set `JSON_MODE=true` and remove that token from the list. Otherwise `JSON_MODE=false`.
- Whatever remains is a list of file or directory paths to scope the review to. If the list is empty, scope is "all changed files in the working tree".

### Step 2: Gather the diff

You must produce a single unified diff text that the agent will analyze. The rules:

- **No path arguments → all working-tree changes:**

  ```bash
  git diff --no-color HEAD
  ```

  This captures both staged and unstaged changes against the last commit. Do NOT use `git diff` alone (misses staged) or `git diff --cached` alone (misses unstaged). Do NOT compare against `origin/main` or any upstream — branch-aware comparison is intentionally out of scope for v1 because it requires knowing the upstream name, which varies across repos.

- **Path arguments present:**

  ```bash
  git diff --no-color HEAD -- <path1> <path2> ...
  ```

  Pass the user's paths verbatim after the `--` separator. Do NOT shell-glob them yourself; git handles the matching.

- **Capture the list of changed files** with `git diff --name-only HEAD` (or with the path filter). You will pass this list to the agent alongside the diff.

### Step 3: Handle the empty-diff edge case

If the diff text is empty (no changed lines at all), do not dispatch the agent. Print exactly:

> No security-relevant changes detected. The working tree matches HEAD for the requested scope.

Then stop. This avoids burning an agent dispatch on a clean tree and avoids the agent fabricating findings on empty input.

### Step 4: Dispatch the security-reviewer agent

Use the Agent tool with `subagent_type: "security-reviewer"`. Pass a prompt that contains:

1. A one-line statement that this is a `/security-review` invocation.
2. The list of changed files (from Step 2).
3. The full diff text, fenced in a ```diff block.
4. A reminder that the output must be a single fenced ```json document conforming to the agent's documented schema.

Wait for the agent's response. It will be a fenced JSON block matching this shape:

```json
{
  "findings": [
    {"severity": "...", "file": "...", "line": 1, "vulnerability_class": "...",
     "description": "...", "remediation": "...", "confidence": "..."}
  ],
  "summary": {"files_reviewed": 0, "findings_by_severity": {...}}
}
```

Parse the JSON. If parsing fails, print a one-line error explaining the agent returned malformed output and include the first 500 characters of the response for the user to inspect — then stop.

### Step 5: Render the output

**If `JSON_MODE=true`:** Print the raw JSON document to stdout. No header, no formatting, no trailing prose. Other tools may pipe the output, so emit only the JSON. Stop.

**If `JSON_MODE=false`:** Print a human-readable report:

1. A one-line header: `Security review — N findings across M files`.
2. The `summary.findings_by_severity` counts as a single line: `Critical: a   High: b   Medium: c   Low: d   Info: e`.
3. For each severity tier in descending order (critical → high → medium → low → info), if the tier has any findings, print a section:
   - A heading: `## Critical` (or `## High`, etc.).
   - For each finding in that tier, print:
     - One bold line: `**[vulnerability_class]** file:line — confidence: high|medium|low`
     - The `description` as a paragraph below.
     - A `Fix:` line followed by the `remediation` text.
     - A blank line between findings.
4. If there are zero findings, print the single line: `No findings. Reviewed M files.` and stop.

Do not invent any additional commentary, suggestions, or follow-up questions. The report is the deliverable.

## Operational rules

- **Diff-aware is the whole point.** Never analyze the entire repository by default. The diff scopes the work and keeps invocations fast.
- **Handle both staged and unstaged.** The user should not have to `git add` first. Always use `git diff HEAD`.
- **Don't embed the agent prompt here.** The `security-reviewer` agent owns its own prompt — your job is to gather the input and format the output, not to re-specify the analysis methodology.
- **Don't second-guess the agent's findings.** If the agent returns a finding you don't agree with, print it anyway. The user is the one who decides whether to act.
- **Binary files** are skipped automatically by `git diff` for diff content; the changed-files list will include them but the agent will see only the header lines. That is the correct behavior — security review on binary blobs is out of scope.

## Examples

| Invocation | Effect |
|---|---|
| `/security-review` | Reviews all working-tree changes (staged + unstaged) against HEAD. |
| `/security-review lib/auth.ex` | Reviews changes to `lib/auth.ex` only. |
| `/security-review lib/ test/` | Reviews changes under `lib/` and `test/`. |
| `/security-review --json` | Same as the first, but prints raw JSON. |
| `/security-review --json lib/auth.ex` | Path-scoped review, raw JSON output. |
