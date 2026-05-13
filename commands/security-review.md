---
description: AI-powered security review of the current git diff (or specified paths). Dispatches the security-reviewer agent and prints findings grouped by severity.
allowed-tools: Bash(git diff:*), Bash(git status:*), Bash(git ls-files:*), Bash(git rev-parse:*), Bash(grep:*), Bash(wc:*), Bash(exit:*), Read, Glob, Grep, Agent
argument-hint: "[--full] [--json | --sarif] [--fail-on <severity>] [--base <ref>] [path ...]"
---

Run an AI-powered security review of code changes in this repository. Detects vulnerabilities across injection, authentication/authorization, data exposure, cryptography, input validation, race conditions, XSS/code execution, and insecure configuration. Filters out low-impact noise (denial-of-service, rate-limiting, memory-exhaustion).

## What to do

Follow these steps in order. Do NOT skip steps. The command is a pipeline: parse args → gather input → dispatch agent → render output.

### Step 1: Parse arguments

The user invoked you with the arguments `$ARGUMENTS`. Treat them as a space-separated list and walk the tokens in any order:

- If `--full` appears anywhere in the list, set `FULL_MODE=true` and remove that token from the list. Otherwise `FULL_MODE=false`. This selects between the two scan modes documented in the plugin README: `diff` (default) reviews working-tree changes against `HEAD`; `full` reviews tracked files end-to-end.
- If `--json` appears anywhere in the list, set `JSON_MODE=true` and remove that token from the list. Otherwise `JSON_MODE=false`.
- If `--sarif` appears anywhere in the list, set `SARIF_MODE=true` and remove that token from the list. Otherwise `SARIF_MODE=false`. This activates SARIF v2.1.0 output (see Step 5). `--sarif` and `--json` are MUTUALLY EXCLUSIVE: their top-level JSON shapes are incompatible (one is the agent's native schema, the other is the SARIF document). If both flags are present, run a final `exit 2` via Bash with one stderr line `--sarif and --json are mutually exclusive` — do NOT proceed and do NOT pick one silently. When both flags are absent, output is the human-readable report.
- If `--maestro` appears anywhere in the list, set `MAESTRO_MODE=true` and remove that token from the list. Otherwise `MAESTRO_MODE=false`. This activates MAESTRO 7-layer classification — each finding's JSON gains a `maestro_layer` field, and the human-readable output adds a "By MAESTRO layer" subsection grouping findings by architectural layer. When `MAESTRO_MODE=false`, the `maestro_layer` field MUST NOT appear in the JSON document (preserves byte-identical output for callers that don't opt in). See [Cloud Security Alliance's MAESTRO framework](https://cloudsecurityalliance.org/blog/2025/02/06/agentic-ai-threat-modeling-framework-maestro) for the seven-layer model.
- If `--rci` appears, set `RCI_PASSES` to the value of the NEXT token if that token parses as an integer in `1..3` — otherwise default `RCI_PASSES=1`. If `--rci` is absent, `RCI_PASSES=0` (no recursive criticism, single dispatch as today). RCI = Recursive Criticism & Improvement: after the standard dispatch produces a findings document, run `RCI_PASSES` additional critique-and-refine dispatches that receive both the prior pass's JSON AND the original input, and asks the agent to drop false positives and surface anything that was missed. OpenSSF documents this technique as reducing security weaknesses by up to an order of magnitude. The cap of 3 bounds cost; `RCI_PASSES > 3` is silently clamped. Combining `--rci` with `--full` is supported but expensive — N=2 over a 41-batch full scan is 41+82 = 123 agent dispatches. See Step 4.5 below for the iteration loop.
- If `--baseline` appears, treat the NEXT token as the path to a baseline-suppression file and set `BASELINE_PATH` to that token. Otherwise auto-detect by looking for `.security-review-baseline.json` in the repo root — if present, set `BASELINE_PATH` to that path; if absent, set `BASELINE_PATH=""` (no suppression). A malformed baseline file produces a one-line warning (`Baseline file malformed — proceeding without suppression`) and `BASELINE_PATH=""`. Baseline file schema is `{"schema_version": 1, "generated_at": "<ISO8601>", "acknowledged": [{"fingerprint": "<hex>", "vulnerability_class": "...", "file": "...", "line": 42, "note": "human note"}]}`. Each entry's `fingerprint` is `SHA256(vulnerability_class + "|" + file + "|" + line + "|" + first_80_chars_of_description)`. See Step 4.6 below for the suppression merge.
- If `--update-baseline` appears, set `UPDATE_BASELINE=true`. After Step 4.6 produces the final findings document, write a baseline file at `BASELINE_PATH` (or `.security-review-baseline.json` if unset) containing every finding from the current run, then print one line: `Baseline updated: <path> (N entries)`. If a baseline already exists at that path, prompt the user with one line: `Overwrite existing baseline at <path>? [y/N]` — abort without writing on anything other than `y`/`Y`.
- If `--patches` appears, set `PATCHES_MODE=true` and inject a `Patches mode: enabled` directive into the agent's prompt in Step 4 (both modes). This instructs the agent to emit an optional `patch` field (unified-diff text the user could `git apply`) on each finding where a minimal, surgical fix exists. When `--patches` is absent (`PATCHES_MODE=false`), the agent MUST NOT emit a `patch` field — the JSON document stays byte-identical for callers that don't opt in. Patches are opt-in because they cost agent tokens. Surgical-fix only: when the correct fix requires understanding code outside the reviewed unit (refactor, architecture change, new dependency), the agent OMITS the `patch` field on that finding even with --patches set. The slash command does NOT auto-apply patches — they're review-and-apply suggestions, not auto-merge changes.
- If `--base` appears, treat the NEXT token as a git ref name and set `BASE_REF` to it. Otherwise leave `BASE_REF` unset. When set, Step 2a uses the three-dot range `<ref>...HEAD` instead of `git diff HEAD`, scoping the review to changes the current branch introduced over the named base. Before use, validate the ref with one Bash invocation: `git rev-parse --verify <ref>^{commit}`. On non-zero exit, run a final `exit 2` via Bash with one stderr line `--base ref not found: <ref>` — do NOT proceed and do NOT silently fall back to `HEAD`. `--base` is ignored in `--full` mode (full mode uses `git ls-files`, which is ref-independent); print one stderr line `--base is a diff-mode flag and was ignored under --full` and continue. This flag is designed for PR-against-base CI gating: a GitHub Actions workflow passes `--base ${{ github.base_ref }}`, GitLab passes the merge-request target, etc.
- If `--fail-on` appears, treat the NEXT token as a severity threshold and set `FAIL_ON_SEVERITY` to it. Valid values: `critical`, `high`, `medium`, `low`. If the next token is missing, is not one of those four values, or `--fail-on` appears at the end of the argument list, run a final `exit 2` via Bash with one stderr line `--fail-on requires one of: critical, high, medium, low` — do NOT proceed. If `--fail-on` is absent, leave `FAIL_ON_SEVERITY` unset; the command's exit code stays `0` regardless of findings, preserving byte-identical exit behavior for callers that do not opt in. See Step 6 below for the threshold evaluation. This flag is designed for CI gating: a PR workflow that wants to block merges on critical issues only sets `--fail-on critical`; a stricter posture uses `--fail-on high`.
- Whatever remains is a list of file or directory paths to scope the review to. The flags compose freely with each other and with path arguments — `--full --json --maestro --rci 2 --baseline ci-baseline.json --patches --fail-on critical lib/` is valid.

When `FULL_MODE=false`, an empty path list means "all changed files in the working tree." When `FULL_MODE=true`, an empty path list means "every tracked file in the repo."

### Step 2: Gather the input

The shape of the input depends on `FULL_MODE`. Each branch produces a payload you will hand to the agent in Step 4, plus a count of files for use in Step 3's empty-input check.

#### Step 2a: Diff mode (`FULL_MODE=false`, default)

You must produce a single unified diff text that the agent will analyze:

When `BASE_REF` is set (from `--base <ref>` in Step 1), replace every `HEAD` below with the three-dot range `<BASE_REF>...HEAD`. Two-dot would include base-side commits since divergence and produce a noisier diff; three-dot scopes strictly to changes introduced on the current branch.

- **No path arguments → all working-tree changes:**

  ```bash
  git diff --no-color HEAD                       # default
  git diff --no-color <BASE_REF>...HEAD           # when --base <ref> was set
  ```

  Default form captures both staged and unstaged changes against the last commit. Do NOT use `git diff` alone (misses staged) or `git diff --cached` alone (misses unstaged). The `--base` form widens the scope to every change on the current branch relative to the named base — the canonical CI shape (GitHub `${{ github.base_ref }}`, GitLab merge-request target, etc.). Prior versions explicitly avoided branch-aware comparison because it required knowing the upstream name; `--base` makes that name an explicit argument the caller supplies.

- **Path arguments present:**

  ```bash
  git diff --no-color HEAD -- <path1> <path2> ...                       # default
  git diff --no-color <BASE_REF>...HEAD -- <path1> <path2> ...           # when --base <ref> was set
  ```

  Pass the user's paths verbatim after the `--` separator. Do NOT shell-glob them yourself; git handles the matching.

- **Capture the list of changed files** with `git diff --name-only HEAD` (or with the path filter; or `git diff --name-only <BASE_REF>...HEAD` when `BASE_REF` is set). You will pass this list to the agent alongside the diff. The diff-mode file count for Step 3 is the length of this list.

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

- **Filter out binary files** with a single-shot `grep` invocation that takes every enumerated path as a separate argument:

  ```bash
  grep -Il . <file1> <file2> <file3> ...
  ```

  `grep -I` excludes binary files (those with a null byte in the inspected prefix). `grep -l` lists matching files only. With pattern `.` (any non-empty line), the output is the set of non-empty text files. Any candidate that is NOT in grep's stdout is either binary or empty — record it in `files_skipped` with `reason: "binary"`. (Empty files have nothing to review, so treating them as binary-skipped is fine.)

  For repos with very many tracked files, batch the argument list into chunks of ~50 paths per `grep` call to stay under the OS `ARG_MAX` limit. Each chunk is a single Bash invocation with no pipe; the `allowed-tools` declaration covers it via `Bash(grep:*)`.

- **Filter out oversized files** with a single-shot `wc` invocation over the post-binary-filter list:

  ```bash
  wc -c <file1> <file2> <file3> ...
  ```

  `wc -c` outputs one `<bytes> <path>` line per file. Parse the output; any file whose byte count exceeds **262,144 bytes (256 KiB)** is oversize — record it in `files_skipped` with `reason: "oversize"` and skip. Above this threshold the file is almost always generated, vendored, or minified and the agent's signal-to-noise on it collapses.

  As with `grep`, batch into chunks of ~50 paths per `wc` call to stay under `ARG_MAX`. Each chunk is a single Bash invocation covered by `Bash(wc:*)`.

- **Why two single-shot calls instead of a per-file loop:** Claude Code's permission system matches the FULL Bash command string against the `allowed-tools` prefix list. A piped while-loop like `git ls-files | while ...; do grep ...; wc ...; done` does not match any single prefix — it gets prompted (or blocked) every invocation. Two batched, pipe-free calls each match a single `allowed-tools` entry cleanly, so the command runs unattended in CI.

- **Track `files_skipped`.** Maintain an in-memory array of `{path: <string>, reason: <"binary" | "oversize" | "unreadable">}` objects as you classify each enumerated path. Carry this array into the merged document Step 4b produces (see `summary.files_skipped` below). The reason vocabulary is fixed — do not invent additional values. If a file survives both filters but cannot be read in the next step (permission denied, IO error), append a `{path, reason: "unreadable"}` entry then.

- **Capture file contents** for each surviving path with the Read tool; you will hand the agent a list of `(file_path, contents)` records in Step 4. The full-mode file count for Step 3 is the length of this surviving list (post-filter).

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
2. When `MAESTRO_MODE=true`: a one-line statement `MAESTRO classification: required` followed by the seven-layer reference table (see "MAESTRO layer reference" subsection below). Otherwise omit this line so the agent does not emit `maestro_layer` fields on findings. When `PATCHES_MODE=true`: add a one-line statement `Patches mode: enabled` so the agent emits surgical-fix patches on findings where one exists. Otherwise omit so the `patch` field stays out of the JSON document.
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

When `MAESTRO_MODE=true`, each finding's JSON gains an optional `maestro_layer` field. The agent SHOULD populate it with the best-fit layer ID for the finding's architectural location. For non-AI findings (classic web vulnerabilities from the Django/Phoenix/Rails packs), the agent prompt's "MAESTRO 7-layer classification" subsection specifies the canonical mapping: data-flow issues (injection, XSS, mass-assignment, SSRF, deserialization) → `data-operations`; access-control or audit issues (missing auth, CSRF disabled, DEBUG=True, missing security headers) → `security-compliance`. If a finding fits none of those, the field may be omitted. Step 5's renderer treats a missing or null `maestro_layer` the same way.

**Parallel dispatch.** Batches MAY be dispatched in parallel by making multiple Agent tool calls in a single response. Each batch reviews a disjoint set of files and produces its own JSON document — they cannot interfere. Sequential dispatch also works; choose based on context-window pressure and observed latency. Either way, every batch must complete before Step 5.

**Per-batch error handling.** If any batch returns malformed JSON, print a one-line error naming the batch (`batch <index> of <TOTAL>`) and include the first 500 characters of that batch's response for the user to inspect — then stop. Do not silently drop a failed batch; do not fall back to a partial merge.

**Merge rule.** After all batches succeed, merge their JSON documents into a single document of the same shape and hand it to Step 5 as if a single dispatch had produced it. Build the merged document as follows:

- `findings`: concatenate every batch's `findings` array in batch order (batch 0's findings first, then batch 1, etc.), then run an order-stable dedup pass keyed by `(file, line, vulnerability_class)`. The first occurrence wins; later duplicates are dropped. Batches review disjoint files, so collisions are rare — but a single file can produce duplicate findings when an RCI pass (Step 4.5) replays the same batch, and shared imports/setup code can drive different batches' agent prompts to converge on the same import-line finding. Dedup catches both. **Gate:** dedup runs only when there is more than one batch (`TOTAL > 1`) or when an RCI pass has produced an intermediate document — in diff mode (one dispatch, no RCI) dedup is a no-op and MUST be skipped so the merged document is byte-identical to the agent's output.
- `summary.files_reviewed`: sum each batch's `summary.files_reviewed`.
- `summary.findings_by_severity`: for each of the five keys (`critical`, `high`, `medium`, `low`, `info`), recompute counts from the POST-dedup findings list. Always emit all five keys even when the count is zero. Do not sum the per-batch counters — they can drift from the deduped findings.
- `summary.files_skipped`: the array recorded in Step 2b (binary + oversize) plus any `unreadable` entries that surfaced during Step 4's content capture. Each entry is `{path: <string>, reason: "binary" | "oversize" | "unreadable"}`. Always emit this key in full mode, even when the array is empty (i.e. `"files_skipped": []`). The empty-array case is the proof that the filters ran and dropped nothing — omitting the key would be ambiguous. Diff mode omits this key entirely (the full-mode filter pipeline does not run in diff mode).

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

### Step 4.6: Baseline suppression (when `BASELINE_PATH` is non-empty)

After the findings document is final (post-Step 4.5 if RCI ran, else post-Step 4), apply baseline suppression if `BASELINE_PATH` resolved to an existing file.

1. Load the baseline file via the `Read` tool. Parse as JSON. If parse fails OR the document doesn't conform to the schema `{schema_version: 1, acknowledged: [...]}`, print `Baseline file malformed — proceeding without suppression` and skip to Step 5.
2. Build a set of acknowledged fingerprints from `baseline.acknowledged[*].fingerprint`.
3. For each finding in the working document, compute `fingerprint = SHA256(vulnerability_class + "|" + file + "|" + line + "|" + first_80_chars_of_description)`. Use lowercase hex output.
4. Drop every finding whose fingerprint is in the acknowledged set. Add the dropped count to `summary.suppressed_count` (an integer, OMITTED entirely when no baseline is in play so byte-identical legacy output is preserved for non-baseline callers).
5. Recompute `summary.findings_by_severity` from the post-suppression findings list so the severity counters match the rendered output.
6. If `UPDATE_BASELINE=true`, AFTER suppression has run, gather every finding from the current run (the POST-suppression list), recompute their fingerprints, and write a new baseline file at `BASELINE_PATH` (defaulting to `.security-review-baseline.json` if unset). The file's `generated_at` is the current UTC ISO-8601 timestamp. If a baseline already exists at that path, prompt for overwrite confirmation as described in Step 1.

The fingerprint MUST be stable across runs: it must NOT incorporate severity, confidence, remediation prose, or any other field that the agent might revise between runs. The four-part hash (class + file + line + first-80-chars-of-description) was chosen so a finding whose description text has trivial whitespace edits still collides with a prior fingerprint; a renamed file or a moved line legitimately produces a fresh fingerprint, which the human reviewer should re-audit.

### Step 5: Render the output

**If `JSON_MODE=true`:** Print the raw JSON document to stdout. No header, no formatting, no trailing prose. Other tools may pipe the output, so emit only the JSON. This output is byte-for-byte identical in diff and full modes — the schema is the contract and is mode-independent. Stop.

**If `SARIF_MODE=true`:** Convert the findings document to SARIF v2.1.0 and print the resulting JSON to stdout. No header, no prose, no commentary — emit only the SARIF document. See "SARIF v2.1.0 mapping" subsection below for the exact field-by-field transform. The SARIF output is mode-independent (same shape from diff and full modes) and is the form GitHub Code Scanning, GitLab Security Dashboards, Azure DevOps, and most IDE SARIF viewers ingest natively. Stop.

**If both `JSON_MODE` and `SARIF_MODE` are false:** Print a human-readable report. Only the one-line header and the zero-findings short-circuit differ between modes; every other element is shared.

1. A one-line header that reflects the scan mode:
   - In **diff mode** (`FULL_MODE=false`): `Security review — N findings across M files`. `M` is the changed-file count from Step 2a.
   - In **full mode** (`FULL_MODE=true`): `Security review (full scan) — N findings across M files`. `M` is the post-filter file count from Step 2b — i.e., the count actually handed to the agent, which already excludes binaries and oversized files.
   - When `MAESTRO_MODE=true`, append the suffix ` — MAESTRO classification active` to the header so the reader knows the per-finding `maestro_layer` field is populated.
2. The `summary.findings_by_severity` counts as a single line: `Critical: a   High: b   Medium: c   Low: d   Info: e`. Identical in both modes. When baseline suppression ran (`summary.suppressed_count > 0`), append a second line: `Suppressed by baseline: <N>` so the user knows how many findings were filtered out of the rendered report.
3. For each severity tier in descending order (critical → high → medium → low → info), if the tier has any findings, print a section:
   - A heading: `## Critical` (or `## High`, etc.).
   - For each finding in that tier, print:
     - One bold line: `**[vulnerability_class]** file:line — confidence: high|medium|low` — optionally followed by ` — <CWE-IDs and OWASP categories>` when either `cwe` or `owasp` is non-empty. The reference string is the joined `cwe` array followed by the joined `owasp` array, comma-separated (e.g. `CWE-89, CWE-209, A03:2021`). When both arrays are empty, OMIT the trailing ` — ...` segment entirely so the line ends after the confidence.
     - When `MAESTRO_MODE=true` AND the finding's `maestro_layer` field is populated, append a third dash-segment ` — layer: <layer-id>` to the bold line (e.g. `... confidence: high — CWE-89, A03:2021 — layer: data-operations`). Omit when the field is missing.
     - The `description` as a paragraph below.
     - A `Fix:` line followed by the `remediation` text.
     - When `PATCHES_MODE=true` AND the finding has a non-empty `patch` field, render the patch as a fenced ```diff block immediately after the Fix line. Skip silently when `patch` is missing or empty — most findings won't have a surgical patch even with `--patches` set.
     - A blank line between findings.

   Section rendering is identical in both modes.
4. When `MAESTRO_MODE=true` AND at least one finding has a populated `maestro_layer`, after the severity-grouped sections print an additional summary section:
   - A heading: `## By MAESTRO layer`.
   - For each of the seven layers (in canonical order: foundation-models, data-operations, agent-frameworks, deployment-infrastructure, evaluation-observability, security-compliance, agent-ecosystem), if any finding maps to that layer, print one line: `**<layer-id>** (<count>): <comma-separated file:line references>`.
   - This subsection summarizes the scan by architectural layer so a reader can spot which MAESTRO tier needs the most attention without re-reading severity-grouped findings.
5. If there are zero findings, print the single mode-appropriate line:
   - Diff mode: `No findings. Reviewed M files.`
   - Full mode: `No findings. Reviewed M files in full-scan mode.`
6. **Skipped-files tail (full mode only).** If `summary.files_skipped` is non-empty, print a final block after every other section (and after the zero-findings line, when that branch fires):
   - Heading: `## Skipped` (one blank line above).
   - One line summarizing the totals by reason: `Skipped K files: binary=<a>, oversize=<b>, unreadable=<c>` — omit any reason whose count is zero. If only one reason has entries, the summary still uses this format (e.g., `Skipped 17 files: binary=17`).
   - A bulleted list of the skipped paths in enumeration order: `- <path> (binary)`, `- <path> (oversize)`, `- <path> (unreadable)`. Cap the list at 50 entries; if `K > 50`, render the first 50 followed by a single line `- ... and <K - 50> more` so the report stays readable on a screen.
   - When `files_skipped` is empty, OMIT the entire `## Skipped` block — do not print an empty heading. In diff mode the key isn't emitted in the first place, so this block never renders.

Do not invent any additional commentary, suggestions, or follow-up questions. The report is the deliverable.

#### SARIF v2.1.0 mapping

Active only when `SARIF_MODE=true`. The transform converts the agent's native findings JSON into a SARIF v2.1.0 document conforming to the OASIS schema at <https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json>. Emit a single JSON object with the shape below — no Markdown fence, no surrounding prose.

**Top-level shape:**

```json
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "stride-security-review",
          "version": "2.1.0",
          "informationUri": "https://github.com/cheezy/stride-security-review",
          "rules": [ /* one entry per distinct vulnerability_class present in findings */ ]
        }
      },
      "results": [ /* one entry per finding */ ]
    }
  ]
}
```

SARIF requires at least one `runs[]` entry, so emit the single-run object even when there are zero findings; in that case `results` is an empty array.

**Per-rule entry (deduplicated from findings):**

For each distinct `vulnerability_class` across the findings list, emit one rule entry:

```json
{
  "id": "<vulnerability_class>",
  "name": "<vulnerability_class>",
  "shortDescription": {"text": "<one-line human description>"},
  "helpUri": "https://github.com/cheezy/stride-security-review#what-it-catches"
}
```

**Per-result entry:**

For each finding emit one `results[]` entry:

```json
{
  "ruleId": "<vulnerability_class>",
  "level": "<error | warning | note>",
  "message": {"text": "<description>"},
  "locations": [
    {
      "physicalLocation": {
        "artifactLocation": {"uri": "<file>"},
        "region": {"startLine": <line>}
      }
    }
  ],
  "properties": {
    "tags": [/* every CWE-ID, every OWASP category, then "confidence:<value>" */],
    "security-severity": "<numeric severity score>"
  },
  "fixes": [
    {"description": {"text": "<remediation>"}}
  ],
  "partialFingerprints": {
    "stride/v1": "<SHA256 hex of vulnerability_class|file|line|first_80_chars_of_description>"
  }
}
```

**Severity → level mapping:**

| Finding severity | SARIF `level` | `security-severity` |
|---|---|---|
| `critical` | `error` | `9.0` |
| `high` | `error` | `7.0` |
| `medium` | `warning` | `5.0` |
| `low` | `note` | `3.0` |
| `info` | `note` | `1.0` |

The numeric `security-severity` is the convention GitHub Code Scanning uses to render severity badges; `level` is the SARIF-native field. Both are emitted so consumers that read either field render consistently.

**Tags array:** concatenate the finding's `cwe` array, then its `owasp` array, then a final string `confidence:<value>` (e.g. `confidence:high`). When `MAESTRO_MODE=true` AND the finding's `maestro_layer` is populated, append `maestro:<layer-id>` as a fourth element. Omit empty CWE/OWASP entries silently — never emit `null` inside the tags array.

**Fixes array:** always emit one entry whose `description.text` is the agent's `remediation` field. When `PATCHES_MODE=true` AND the finding's `patch` field is non-empty, additionally emit `artifactChanges[0].replacements[0]` describing the patch (the surgical-fix text); when patches are absent the `fixes[0]` entry carries only the description.

**partialFingerprints:** reuse the same fingerprint computation Step 4.6 uses for baseline matching — lowercase hex SHA-256 of the four-part string `vulnerability_class + "|" + file + "|" + line + "|" + first_80_chars_of_description`. Emit under the `stride/v1` key so future versions can introduce additional fingerprint algorithms without breaking dedup on prior runs.

**Mode-independence:** the SARIF document MUST be byte-shape-identical between diff and full modes. `files_reviewed`, `files_skipped`, and `findings_by_severity` from the agent's `summary` block do NOT round-trip into SARIF — SARIF carries no per-run summary aside from the `results` length. Consumers that need those counters can read the JSON via `--json` on a separate invocation.

### Step 6: Threshold gating (when `FAIL_ON_SEVERITY` is set)

This step runs ONLY when `--fail-on <severity>` was passed in Step 1. When unset, skip the step entirely — the command produces no Bash exit beyond Step 5's rendering and the caller observes the same exit code as before this flag existed.

When `FAIL_ON_SEVERITY` is set, evaluate the threshold against the FINAL post-Step 4.6 findings list (after RCI passes and baseline suppression have both run). The severity order is `critical > high > medium > low > info`. A finding "meets the threshold" when its `.severity` is greater than or equal to `FAIL_ON_SEVERITY`. So:

- `--fail-on critical` → fails on findings whose severity is `critical`.
- `--fail-on high`     → fails on findings whose severity is `critical` or `high`.
- `--fail-on medium`   → fails on findings whose severity is `critical`, `high`, or `medium`.
- `--fail-on low`      → fails on findings whose severity is `critical`, `high`, `medium`, or `low`.

`info`-only findings never trip a threshold (`--fail-on info` is not a valid value).

Procedure:

1. Count findings at or above `FAIL_ON_SEVERITY`. Call this `N_GATE`.
2. If `N_GATE == 0`, the command's work is done — no further action. Exit code stays at `0` (the default).
3. If `N_GATE >= 1`, run one Bash invocation: `exit 1`. The slash command's residual exit code is now `1`. The rendered report from Step 5 has already been printed to stdout, so the caller sees BOTH the human-readable report AND the non-zero exit signal.

Do NOT print an additional "Gated: N findings at/above <severity>" line — the per-severity counts on Step 5's `Critical: ... High: ... Medium: ...` line already communicate the count. Adding another line would diverge the human-readable output between `--fail-on`-set and `--fail-on`-unset callers.

**Exit code contract:**

| Exit | Meaning |
|---|---|
| `0` | No findings at/above `FAIL_ON_SEVERITY` (or `--fail-on` not set) |
| `1` | At least one finding at/above `FAIL_ON_SEVERITY` |
| `2` | Setup / usage error (invalid `--fail-on` value, bad input, agent dispatch failure) |

**CI note:** the exit code propagation through `claude -p` depends on the Claude Code CLI version. CI workflows that need a robust gate should ALSO emit `--json` and post-check the JSON with `jq` — see the README's "CI Integration" section for a belt-and-suspenders example.

## Operational rules

- **Honor every flag from Step 1.** `--full`, `--json`, `--maestro`, `--rci`, `--baseline`, `--update-baseline`, and `--patches` are all first-class options. If Step 1 sets `FULL_MODE=true`, you MUST execute Step 2b and Step 4b — do NOT fall back to diff mode under any circumstance, and do NOT invent a "this looks small, I'll just diff it" shortcut. The user opted in by passing the flag; honor it.
- **Diff mode is the default, not the only mode.** When no `--full` flag is present, scope to the working-tree diff against `HEAD` (Step 2a). When `--full` IS present, scope to every tracked text file under the size cap (Step 2b). Both modes are supported; neither is a footgun.
- **Diff-mode commands stay diff-mode.** The `git diff HEAD` invocations in Step 2a are diff-mode only — in full mode you use `git ls-files` (Step 2b) and never call `git diff`. Do not mix the two pipelines.
- **Don't embed the agent prompt here.** The `security-reviewer` agent owns its own prompt — your job is to gather the input and format the output, not to re-specify the analysis methodology.
- **Don't second-guess the agent's findings.** If the agent returns a finding you don't agree with, print it anyway. The user is the one who decides whether to act.
- **Binary files** are skipped automatically by `git diff` for diff content; the changed-files list will include them but the agent will see only the header lines. In full mode, binaries are explicitly filtered by the `grep -Il` step in Step 2b. Security review on binary blobs is out of scope in both modes.

## Invocation form

Claude Code ships with a built-in `/security-review` command (a diff-only, single-prompt review). It does NOT understand any of this plugin's flags — `--full`, `--json`, `--maestro`, `--rci`, `--baseline`, `--patches` are silently ignored.

This plugin lives at the namespaced slash command `/stride-security-review:security-review`. The bare `/security-review` belongs to the Claude Code built-in. To exercise any of this plugin's flags, use the namespaced form:

```
/stride-security-review:security-review --full
```

The v2.0.0 plugin rename (from `security-review` to `stride-security-review`) eliminated the namespace-level overlap with the built-in. Earlier plugin versions documented the same workaround under the previous namespace; if you have scripted invocations of the old form, update them to the new namespace.

## Examples

All examples below use the namespaced form `/stride-security-review:security-review` so the plugin's flags reach the plugin's command body and not the Claude Code built-in.

| Invocation | Effect |
|---|---|
| `/stride-security-review:security-review` | Reviews all working-tree changes (staged + unstaged) against HEAD (diff mode). |
| `/stride-security-review:security-review lib/auth.ex` | Reviews changes to `lib/auth.ex` only (diff mode). |
| `/stride-security-review:security-review lib/ test/` | Reviews changes under `lib/` and `test/` (diff mode). |
| `/stride-security-review:security-review --json` | Diff mode, raw JSON output. |
| `/stride-security-review:security-review --json lib/auth.ex` | Path-scoped diff review, raw JSON output. |
| `/stride-security-review:security-review --full` | Full-codebase scan: every tracked text file under the size cap, batched in groups of 10. |
| `/stride-security-review:security-review --full lib/` | Full-codebase scan scoped to `lib/`: every tracked text file under `lib/`. |
| `/stride-security-review:security-review --full --json` | Full-codebase scan, raw JSON output. |
| `/stride-security-review:security-review --full --maestro` | Full scan with MAESTRO 7-layer classification per finding. |
| `/stride-security-review:security-review --full --rci 2` | Full scan followed by 2 recursive-criticism passes. |
| `/stride-security-review:security-review --full --baseline ci-baseline.json` | Full scan with suppression file applied. |
| `/stride-security-review:security-review --fail-on critical` | Diff mode; exit non-zero if any critical finding is present. CI gate. |
| `/stride-security-review:security-review --full --json --fail-on high` | Full scan, JSON output, exit non-zero on any critical or high finding. |
| `/stride-security-review:security-review --base main` | Review every change on the current branch relative to `main` (PR-against-base scope). |
| `/stride-security-review:security-review --base origin/main --fail-on critical` | PR-against-base scope; exit non-zero on any critical finding. Canonical CI gate. |
| `/stride-security-review:security-review --sarif` | Diff mode; emit a SARIF v2.1.0 document on stdout. Pipe into GitHub Code Scanning or a SARIF viewer. |
| `/stride-security-review:security-review --full --sarif --fail-on critical` | Full scan; SARIF output; CI gate on critical findings. |
