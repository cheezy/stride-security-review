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
- If `--maestro` appears anywhere in the list, set `MAESTRO_MODE=true` and remove that token from the list. Otherwise `MAESTRO_MODE=false`. This activates MAESTRO 7-layer classification — each finding's JSON gains a `maestro_layer` field, and the human-readable output adds a "By MAESTRO layer" subsection grouping findings by architectural layer. When `MAESTRO_MODE=false`, the `maestro_layer` field MUST NOT appear in the JSON document (preserves byte-identical output for callers that don't opt in). See [Cloud Security Alliance's MAESTRO framework](https://cloudsecurityalliance.org/blog/2025/02/06/agentic-ai-threat-modeling-framework-maestro) for the seven-layer model.
- If `--rci` appears, set `RCI_PASSES` to the value of the NEXT token if that token parses as an integer in `1..3` — otherwise default `RCI_PASSES=1`. If `--rci` is absent, `RCI_PASSES=0` (no recursive criticism, single dispatch as today). RCI = Recursive Criticism & Improvement: after the standard dispatch produces a findings document, run `RCI_PASSES` additional critique-and-refine dispatches that receive both the prior pass's JSON AND the original input, and asks the agent to drop false positives and surface anything that was missed. OpenSSF documents this technique as reducing security weaknesses by up to an order of magnitude. The cap of 3 bounds cost; `RCI_PASSES > 3` is silently clamped. Combining `--rci` with `--full` is supported but expensive — N=2 over a 41-batch full scan is 41+82 = 123 agent dispatches. See Step 4.5 below for the iteration loop.
- Whatever remains is a list of file or directory paths to scope the review to. The flags compose freely with each other and with path arguments — `--full --json --maestro --rci 2 lib/` is valid.

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
     "cwe": ["CWE-89"], "owasp": ["A03:2021"],
     "description": "...", "remediation": "...", "confidence": "..."}
  ],
  "summary": {"files_reviewed": 0, "findings_by_severity": {...}}
}
```

#### Step 4a: Diff mode (`FULL_MODE=false`, default)

Dispatch the Agent tool **once** with `subagent_type: "security-reviewer"`. The prompt must contain, in order:

1. A one-line statement: `/security-review invocation, mode: diff`.
2. When `MAESTRO_MODE=true`: a one-line statement `MAESTRO classification: required` followed by the seven-layer reference table (see "MAESTRO layer reference" subsection below). Otherwise omit this line so the agent does not emit `maestro_layer` fields on findings.
3. The list of changed files (from Step 2a).
4. The full diff text, fenced in a ```diff block.
5. A reminder that the output must be a single fenced ```json document conforming to the agent's documented schema.

Wait for the agent's response. Parse the fenced JSON. If parsing fails, print a one-line error naming `batch 0 (diff mode)` and include the first 500 characters of the response for the user to inspect — then stop. The parsed JSON IS the final document; no merge step is needed in diff mode.

#### Step 4b: Full mode (`FULL_MODE=true`)

Split the surviving file list from Step 2b into **batches of 10 files each**, in the order produced by `git ls-files` (so reruns are deterministic). The last batch may be smaller. Number the batches starting from `0`; let `TOTAL` be the number of batches.

For each batch, dispatch the Agent tool with `subagent_type: "security-reviewer"`. The prompt must contain, in order:

1. A one-line statement: `/security-review invocation, mode: full_file, batch <index> of <TOTAL>`.
2. When `MAESTRO_MODE=true`: a one-line statement `MAESTRO classification: required` followed by the seven-layer reference table (see "MAESTRO layer reference" subsection below). Otherwise omit so the agent does not emit `maestro_layer` fields.
3. The list of file paths in this batch.
4. For each file in the batch, in order: a `path: <relative-path>` line followed by a fenced code block containing the file's full contents. The fence language should match the file's extension where obvious (e.g., ` ```python`, ` ```javascript`, ` ```elixir`); fall back to a bare ` ``` ` fence when the extension is unknown.
5. A reminder that the output must be a single fenced ```json document conforming to the agent's documented schema.

#### MAESTRO layer reference

Include this seven-row block in every agent dispatch when `MAESTRO_MODE=true`. The layer IDs match the canonical CSA MAESTRO data file (CloudSecurityAlliance/MAESTRO/src/data/maestro.ts) verbatim — the agent's `maestro_layer` field MUST contain one of these exact strings.

| Layer ID | Name | Scope |
|---|---|---|
| `foundation-models` | Foundation Models | Core AI models (LLMs, custom-trained models). Threats: model poisoning, data leakage, member inference attacks. |
| `data-operations` | Data Operations | Data handling for agents — storage, processing, vector embeddings. Threats: prompt injection via data, vector-store poisoning, embedding leaks. |
| `agent-frameworks` | Agent Frameworks | Software frameworks and APIs used to create, orchestrate, and manage agents (LangChain, AutoGen, LangGraph, Genkit, MCP SDKs). Threats: tool-use abuse, planner injection, framework CVEs. |
| `deployment-infrastructure` | Deployment & Infrastructure | Servers, networks, containers, and underlying resources hosting agents and APIs. Threats: container escape, exposed API endpoints, model-serving runtime CVEs. |
| `evaluation-observability` | Evaluation & Observability | Systems to monitor, evaluate, and debug agent behavior. Threats: log tampering, eval gaming, observability blind spots. |
| `security-compliance` | Security & Compliance | Security controls and compliance measures spanning the agent system. Threats: missing access controls, regulatory gaps, audit-trail integrity. |
| `agent-ecosystem` | Agent Ecosystem | The broader environment where multiple agents interact, collaborate, and potentially compete. Threats: multi-agent collusion, A2A trust failures, untrusted-MCP-server pivots. |

When `MAESTRO_MODE=true`, each finding's JSON gains an optional `maestro_layer` field. The agent SHOULD populate it with the best-fit layer ID for the finding's architectural location. If the finding genuinely doesn't fit any layer (e.g., a classic web vulnerability like SQL injection in a non-AI codebase), the field may be omitted. Step 5's renderer treats a missing or null `maestro_layer` the same way.

**Parallel dispatch.** Batches MAY be dispatched in parallel by making multiple Agent tool calls in a single response. Each batch reviews a disjoint set of files and produces its own JSON document — they cannot interfere. Sequential dispatch also works; choose based on context-window pressure and observed latency. Either way, every batch must complete before Step 5.

**Per-batch error handling.** If any batch returns malformed JSON, print a one-line error naming the batch (`batch <index> of <TOTAL>`) and include the first 500 characters of that batch's response for the user to inspect — then stop. Do not silently drop a failed batch; do not fall back to a partial merge.

**Merge rule.** After all batches succeed, merge their JSON documents into a single document of the same shape and hand it to Step 5 as if a single dispatch had produced it. Build the merged document as follows:

- `findings`: concatenate every batch's `findings` array in batch order (batch 0's findings first, then batch 1, etc.). Do NOT deduplicate — different batches review disjoint files and cannot collide on `(file, line)`.
- `summary.files_reviewed`: sum each batch's `summary.files_reviewed`.
- `summary.findings_by_severity`: for each of the five keys (`critical`, `high`, `medium`, `low`, `info`), sum the value across all batches. Always emit all five keys even when the count is zero.

Step 5's rendering does not need to know about batching — it sees one document either way.

### Step 4.5: Recursive criticism & improvement (when `RCI_PASSES > 0`)

After Step 4 has produced a findings document (either via the single diff-mode dispatch or via the full-mode merge), if `RCI_PASSES > 0`, run a critique loop:

For `i` in `1..RCI_PASSES`:

1. Dispatch the Agent tool with `subagent_type: "security-reviewer"`. The prompt must contain, in order:
   - A one-line statement: `/security-review invocation, mode: rci_pass <i> of <RCI_PASSES>`.
   - A directive paragraph: `You produced (or inherited) the JSON findings document below. Critically re-review it against the original input. (a) Remove any finding that is a false positive or whose risk is bounded enough to fail the realism filter. (b) Add any finding that the prior pass missed but that is clearly exploitable in the supplied input. Return a single fenced ` + "```json" + ` document conforming to the documented schema. Preserve the schema exactly — same per-finding fields, same summary shape. Do NOT inflate findings to look thorough.`
   - The prior-pass findings, fenced in a ```json block.
   - The ORIGINAL input that was passed in Step 4 (the diff text in diff mode, OR the per-file content list from the batch that originally produced the finding in full mode — for full mode, dispatch one rci pass per ORIGINAL batch so each critique pass only sees its own batch's files plus its own batch's findings; merge per the same Step 4b merge rule after every pass).
   - A reminder that the output must be a single fenced ```json document, same schema as the prior pass.

2. Parse the returned JSON. If parsing fails, print a one-line error naming the pass (`rci pass <i>`) plus the first 500 characters of the response, and stop — do NOT silently fall back to the prior pass's findings.

3. Replace the working findings document with the new one. Add the pass index to `summary.rci_passes` (an integer counter — schema addition active only when `RCI_PASSES > 0`).

After the loop, the final document goes to Step 5. If a pass produces a smaller-or-equal-size findings list than the prior pass AND only removes findings (no new ones added), that's the expected convergence — log nothing special. If a pass repeatedly adds new findings on every iteration, the rubric is unstable; the human reviewer should investigate.

**Cost note:** every `--rci` pass roughly doubles the agent-call cost. `--rci 1` over a single diff is 2 dispatches; `--rci 3 --full` over a 41-batch scan is 41 + 41*3 = 164 dispatches. The slash command does not warn about this — it's the user's choice; the help text and README document the trade-off.

### Step 5: Render the output

**If `JSON_MODE=true`:** Print the raw JSON document to stdout. No header, no formatting, no trailing prose. Other tools may pipe the output, so emit only the JSON. This output is byte-for-byte identical in diff and full modes — the schema is the contract and is mode-independent. Stop.

**If `JSON_MODE=false`:** Print a human-readable report. Only the one-line header and the zero-findings short-circuit differ between modes; every other element is shared.

1. A one-line header that reflects the scan mode:
   - In **diff mode** (`FULL_MODE=false`): `Security review — N findings across M files`. `M` is the changed-file count from Step 2a.
   - In **full mode** (`FULL_MODE=true`): `Security review (full scan) — N findings across M files`. `M` is the post-filter file count from Step 2b — i.e., the count actually handed to the agent, which already excludes binaries and oversized files.
   - When `MAESTRO_MODE=true`, append the suffix ` — MAESTRO classification active` to the header so the reader knows the per-finding `maestro_layer` field is populated.
2. The `summary.findings_by_severity` counts as a single line: `Critical: a   High: b   Medium: c   Low: d   Info: e`. Identical in both modes.
3. For each severity tier in descending order (critical → high → medium → low → info), if the tier has any findings, print a section:
   - A heading: `## Critical` (or `## High`, etc.).
   - For each finding in that tier, print:
     - One bold line: `**[vulnerability_class]** file:line — confidence: high|medium|low` — optionally followed by ` — <CWE-IDs and OWASP categories>` when either `cwe` or `owasp` is non-empty. The reference string is the joined `cwe` array followed by the joined `owasp` array, comma-separated (e.g. `CWE-89, CWE-209, A03:2021`). When both arrays are empty, OMIT the trailing ` — ...` segment entirely so the line ends after the confidence.
     - When `MAESTRO_MODE=true` AND the finding's `maestro_layer` field is populated, append a third dash-segment ` — layer: <layer-id>` to the bold line (e.g. `... confidence: high — CWE-89, A03:2021 — layer: data-operations`). Omit when the field is missing.
     - The `description` as a paragraph below.
     - A `Fix:` line followed by the `remediation` text.
     - A blank line between findings.

   Section rendering is identical in both modes.
4. When `MAESTRO_MODE=true` AND at least one finding has a populated `maestro_layer`, after the severity-grouped sections print an additional summary section:
   - A heading: `## By MAESTRO layer`.
   - For each of the seven layers (in canonical order: foundation-models, data-operations, agent-frameworks, deployment-infrastructure, evaluation-observability, security-compliance, agent-ecosystem), if any finding maps to that layer, print one line: `**<layer-id>** (<count>): <comma-separated file:line references>`.
   - This subsection summarizes the scan by architectural layer so a reader can spot which MAESTRO tier needs the most attention without re-reading severity-grouped findings.
5. If there are zero findings, print the single mode-appropriate line and stop:
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
