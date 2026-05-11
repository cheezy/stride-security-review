---
description: AI-powered security review of the current git diff (or specified paths). Dispatches the security-reviewer agent and prints findings grouped by severity.
allowed-tools: Bash(git diff:*), Bash(git status:*), Bash(git ls-files:*), Bash(git rev-parse:*), Read, Glob, Grep, Agent
argument-hint: "[--full] [--json] [path ...]"
---

Run an AI-powered security review of code changes in this repository. Detects vulnerabilities across injection, authentication/authorization, data exposure, cryptography, input validation, race conditions, XSS/code execution, and insecure configuration. Filters out low-impact noise (denial-of-service, rate-limiting, memory-exhaustion).

## What to do

Follow these steps in order. Do NOT skip steps. The command is a pipeline: parse args → gather input → dispatch agent → render output.

### Step 1: Parse arguments

The user invoked you with the arguments `$ARGUMENTS`. Treat them as a space-separated list and walk the tokens in any order:

- If `--full` appears anywhere in the list, set `FULL_MODE=true` and remove that token from the list. Otherwise `FULL_MODE=false`. This selects between the two scan modes documented in the plugin README: `diff` (default) reviews working-tree changes against `HEAD`; `full` reviews tracked files end-to-end.
- If `--json` appears anywhere in the list, set `JSON_MODE=true` and remove that token from the list. Otherwise `JSON_MODE=false`.
- Whatever remains is a list of file or directory paths to scope the review to. The flags compose freely with each other and with path arguments — `--full --json lib/` is valid and selects full scan + JSON output + scoped to `lib/`.

When `FULL_MODE=false`, an empty path list means "all changed files in the working tree." When `FULL_MODE=true`, an empty path list means "every tracked file in the repo."

### Step 2: Gather the input

The shape of the input depends on `FULL_MODE`. Each branch produces a payload you will hand to the agent in Step 4, plus a count of files for use in Step 3's empty-input check.

#### Step 2a: Diff mode (`FULL_MODE=false`, default)

You must produce a single unified diff text that the agent will analyze:

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

- **Capture the list of changed files** with `git diff --name-only HEAD` (or with the path filter). You will pass this list to the agent alongside the diff. The diff-mode file count for Step 3 is the length of this list.

#### Step 2b: Full mode (`FULL_MODE=true`)

You must produce a filtered list of `(file_path, file_contents)` records that the agent will analyze. The filtering rules are fixed by the contract in the plugin README ("Full-codebase scan mode (v1.1.0)") — do not relax them.

- **Enumerate tracked files with `git ls-files`:**

  ```bash
  # No path arguments → every tracked file:
  git ls-files

  # Path arguments → scope the enumeration:
  git ls-files -- <path1> <path2> ...
  ```

  Pass the user's paths verbatim after the `--` separator. `git ls-files` honors `.gitignore`, sparse-checkout, and untracked-exclusions automatically — that is why we use it instead of `find` or a filesystem walk. Untracked files are intentionally out of scope; if a user wants them reviewed they can run `git add -N` first.

- **Filter out binary files.** For each enumerated path, drop it from the list if it is binary. The standard test is:

  ```bash
  grep -Iq . "$file"
  ```

  `grep -I` treats a file as binary when it contains a null byte in the inspected prefix; the exit code is non-zero for binary files and zero for text files. Skip binaries silently — do NOT count them in `files_reviewed` and do NOT dispatch the agent on them.

- **Filter out oversized files.** Drop any file whose size exceeds **262,144 bytes (256 KiB)**. The byte size comes from `wc -c < "$file"` (or `stat`); above this threshold the file is almost always generated, vendored, or minified and the agent's signal-to-noise on it collapses. Skip oversized files the same way you skip binaries.

- **Putting the enumeration and filters together**, the surviving file list can be produced with this concrete loop (run once, capture stdout):

  ```bash
  git ls-files -- <path1> <path2> ... | while IFS= read -r f; do
    grep -Iq . "$f" || continue                # drop binaries
    [ "$(wc -c < "$f")" -le 262144 ] || continue   # drop > 256 KiB
    printf '%s\n' "$f"
  done
  ```

  When no path arguments were given, omit the `-- <path1> ...` suffix. The output is the canonical surviving list for the rest of the pipeline.

- **Capture file contents** for each surviving path. Read each file with the Read tool; you will hand the agent a list of `(file_path, contents)` records in Step 4. The full-mode file count for Step 3 is the length of this surviving list (post-filter).

### Step 3: Handle the empty-input edge case

After Step 2, you have a file count (changed files in diff mode; surviving files in full mode). If the count is zero, do not dispatch the agent. Print one of:

- **Diff mode (`FULL_MODE=false`):**

  > No security-relevant changes detected. The working tree matches HEAD for the requested scope.

- **Full mode (`FULL_MODE=true`):**

  > No tracked files in scope for review. Enumeration produced no files after binary and size filters were applied.

Then stop. This avoids burning an agent dispatch on a clean tree (or an empty/binary-only enumeration) and avoids the agent fabricating findings on empty input.

### Step 4: Dispatch the security-reviewer agent

Dispatch behavior depends on `FULL_MODE` from Step 1. In both modes every dispatch passes an input-mode tag at the top of the agent's prompt so the agent knows which methodology branch to apply (see `agents/security-reviewer.md` "Input modes"). The agent's output JSON schema is identical in both modes:

```json
{
  "findings": [
    {"severity": "...", "file": "...", "line": 1, "vulnerability_class": "...",
     "description": "...", "remediation": "...", "confidence": "..."}
  ],
  "summary": {"files_reviewed": 0, "findings_by_severity": {...}}
}
```

#### Step 4a: Diff mode (`FULL_MODE=false`, default)

Dispatch the Agent tool **once** with `subagent_type: "security-reviewer"`. The prompt must contain, in order:

1. A one-line statement: `/security-review invocation, mode: diff`.
2. The list of changed files (from Step 2a).
3. The full diff text, fenced in a ```diff block.
4. A reminder that the output must be a single fenced ```json document conforming to the agent's documented schema.

Wait for the agent's response. Parse the fenced JSON. If parsing fails, print a one-line error naming `batch 0 (diff mode)` and include the first 500 characters of the response for the user to inspect — then stop. The parsed JSON IS the final document; no merge step is needed in diff mode.

#### Step 4b: Full mode (`FULL_MODE=true`)

Split the surviving file list from Step 2b into **batches of 10 files each**, in the order produced by `git ls-files` (so reruns are deterministic). The last batch may be smaller. Number the batches starting from `0`; let `TOTAL` be the number of batches.

For each batch, dispatch the Agent tool with `subagent_type: "security-reviewer"`. The prompt must contain, in order:

1. A one-line statement: `/security-review invocation, mode: full_file, batch <index> of <TOTAL>`.
2. The list of file paths in this batch.
3. For each file in the batch, in order: a `path: <relative-path>` line followed by a fenced code block containing the file's full contents. The fence language should match the file's extension where obvious (e.g., ` ```python`, ` ```javascript`, ` ```elixir`); fall back to a bare ` ``` ` fence when the extension is unknown.
4. A reminder that the output must be a single fenced ```json document conforming to the agent's documented schema.

**Parallel dispatch.** Batches MAY be dispatched in parallel by making multiple Agent tool calls in a single response. Each batch reviews a disjoint set of files and produces its own JSON document — they cannot interfere. Sequential dispatch also works; choose based on context-window pressure and observed latency. Either way, every batch must complete before Step 5.

**Per-batch error handling.** If any batch returns malformed JSON, print a one-line error naming the batch (`batch <index> of <TOTAL>`) and include the first 500 characters of that batch's response for the user to inspect — then stop. Do not silently drop a failed batch; do not fall back to a partial merge.

**Merge rule.** After all batches succeed, merge their JSON documents into a single document of the same shape and hand it to Step 5 as if a single dispatch had produced it. Build the merged document as follows:

- `findings`: concatenate every batch's `findings` array in batch order (batch 0's findings first, then batch 1, etc.). Do NOT deduplicate — different batches review disjoint files and cannot collide on `(file, line)`.
- `summary.files_reviewed`: sum each batch's `summary.files_reviewed`.
- `summary.findings_by_severity`: for each of the five keys (`critical`, `high`, `medium`, `low`, `info`), sum the value across all batches. Always emit all five keys even when the count is zero.

Step 5's rendering does not need to know about batching — it sees one document either way.

### Step 5: Render the output

**If `JSON_MODE=true`:** Print the raw JSON document to stdout. No header, no formatting, no trailing prose. Other tools may pipe the output, so emit only the JSON. This output is byte-for-byte identical in diff and full modes — the schema is the contract and is mode-independent. Stop.

**If `JSON_MODE=false`:** Print a human-readable report. Only the one-line header and the zero-findings short-circuit differ between modes; every other element is shared.

1. A one-line header that reflects the scan mode:
   - In **diff mode** (`FULL_MODE=false`): `Security review — N findings across M files`. `M` is the changed-file count from Step 2a.
   - In **full mode** (`FULL_MODE=true`): `Security review (full scan) — N findings across M files`. `M` is the post-filter file count from Step 2b — i.e., the count actually handed to the agent, which already excludes binaries and oversized files.
2. The `summary.findings_by_severity` counts as a single line: `Critical: a   High: b   Medium: c   Low: d   Info: e`. Identical in both modes.
3. For each severity tier in descending order (critical → high → medium → low → info), if the tier has any findings, print a section:
   - A heading: `## Critical` (or `## High`, etc.).
   - For each finding in that tier, print:
     - One bold line: `**[vulnerability_class]** file:line — confidence: high|medium|low`
     - The `description` as a paragraph below.
     - A `Fix:` line followed by the `remediation` text.
     - A blank line between findings.

   Section rendering is identical in both modes.
4. If there are zero findings, print the single mode-appropriate line and stop:
   - Diff mode: `No findings. Reviewed M files.`
   - Full mode: `No findings. Reviewed M files in full-scan mode.`

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
