# Changelog

All notable changes to the `stride-security-review` plugin are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.2.0] - 2026-05-13

### Changed

- **Added MAESTRO mapping guidance for non-AI framework findings.** The MAESTRO 7-layer subsection at `agents/security-reviewer.md` previously said to omit `maestro_layer` for classic web vulnerabilities — leaving per-run inconsistency in the `By MAESTRO layer` summary section. Now: data-flow vulnerabilities (injection, XSS, mass-assignment, SSRF, open redirect, deserialization) map to `data-operations`; access-control / audit / config vulnerabilities (missing auth, CSRF disabled, `DEBUG = True`, missing security headers) map to `security-compliance`. The other five layers remain AI-specific. `commands/security-review.md` was updated to reference this mapping rather than re-specify it.
- **Re-mapped mass-assignment rules from `input_validation` to `authorization`** in the Django (`Form.cleaned_data` direct write), Phoenix (`Ecto.Changeset.cast/3` with bulk allow-list), and Rails (`params.permit!`) packs. The actual harm of writing `:is_admin`, `:role`, or `:owner_id` via mass assignment is privilege escalation, not weak input validation; under the `authorization` class the severity rubric biases high/critical instead of low/medium, matching real-world impact. The `phoenix_mass_assignment.ex` fixture's EXPECTED.md entry was updated in lock-step (`authorization/high`, CWE-915, A04:2021). No rule prose, activation predicate, or non-trigger clause was changed — this is a class-mapping correction only.
- **Standardized "what to look for" prose across the Django, Phoenix, and Rails framework packs.** Every rule row now follows the 2-3 sentence template established by the v2.1.0 Phoenix mass-assignment rule: (1) positive pattern with concrete trust-boundary indicators, (2) discriminating signal or analog rule across packs, (3) explicit `Do NOT flag <X>` non-trigger clause where realistic look-alikes exist. Mapping columns and rule-name columns are unchanged. The longer form measurably reduces false positives on look-alike-but-safe code (literal-string `mark_safe`, parameterized `raw()`, JSON-API `@csrf_exempt`, dev-only `DEBUG = True`, allow-listed Strong Parameters, positional `fragment("? = ?")`, scoped `Repo.get`, constant-symbol `obj.send`).

## [2.1.0] - 2026-05-13

### Added

- **Eval runner (`scripts/run_eval.sh`).** POSIX bash + `jq` runner that dispatches the `security-reviewer` agent via `claude -p` against every fixture in `test/fixtures/` and asserts the expected `vulnerability_class` + `severity` from `test/fixtures/EXPECTED.md`. Output is [TAP 13](https://testanything.org/tap-version-13-specification.html); exit `0` only if every fixture produces its expected finding at the expected count (the Bitbucket multi-finding fixture requires both). Failing fixtures emit a diff-style expected-vs-actual block. CWE/OWASP mismatches are advisory (warn, no fail). Raw agent JSON for each fixture is written to `logs/` (gitignored). Flags: `--fixture <path>` (run one), `--dry-run` (no API call), `--verbose` (echo prompts + JSON to stderr), `--fixtures-dir <path>` (override location).
- **GitHub Actions workflow (`.github/workflows/eval.yml`).** Runs the eval on push to `main` and on PRs that touch `agents/`, `commands/`, `skills/`, `test/fixtures/`, the runner itself, or the workflow. Uploads `logs/` as a build artifact on failure. All third-party actions are pinned to 40-hex commit SHAs, in line with the plugin's own supply-chain rule.
- **README "Running the eval locally" section** documenting prerequisites, invocation, flags, and the assertion tolerance model.
- **`.gitignore` entry for `logs/`** so eval output stays untracked.
- **Phoenix mass-assignment rule** in the framework-aware pack at `agents/security-reviewer.md`. Flags `Ecto.Changeset.cast/3` calls reached from `Phoenix.Controller` actions or `Phoenix.LiveView` `handle_event` clauses whose allow-list is `__MODULE__.__schema__(:fields)`, `Map.keys(attrs)`, or an explicit list that includes privileged fields (`:role`, `:is_admin`, `:owner_id`, `:user_id`, `:permissions`). Maps to `input_validation`. Phoenix analog of the Rails `params.permit!` rule. Comes with `test/fixtures/phoenix_mass_assignment.ex` (positive control: controller updates a `User` schema via `cast(attrs, __MODULE__.__schema__(:fields))` exposing `:role` and `:is_admin` to client write) and an `EXPECTED.md` entry at severity `high`, `CWE-915`, `A04:2021`.
- **`--fail-on <severity>` flag and exit-code contract.** `commands/security-review.md` gains a `--fail-on critical | high | medium | low` flag and a new Step 6 that, when the flag is set, evaluates the final post-RCI / post-baseline findings list and runs `exit 1` via Bash when any finding meets the threshold. Default behavior (no `--fail-on`) preserves exit 0 always — byte-identical exit behavior for callers that do not opt in. Invalid `--fail-on` values produce exit 2 with a clear error. Severity ordering is `critical > high > medium > low > info`; `info`-only findings never trip a threshold.
- **GitHub Actions workflow `.github/workflows/security-review.yml`.** Reference CI gate for downstream repos (and the plugin's own PR check). Runs the slash command with `--json --fail-on ${FAIL_ON}` on every pull request, then post-checks the JSON with `jq` — the merge is blocked if EITHER `claude -p` exits non-zero OR jq counts at least one finding at/above the threshold. Robust to `claude -p` exit-code propagation variations across Claude Code CLI versions. Threshold defaults to `critical`, overridable via `workflow_dispatch` input or by editing the `FAIL_ON` env. Third-party actions pinned to commit SHAs. Uploads `review.json` and `review.stderr` as a build artifact on every run for triage.
- **README "CI Integration" section** documenting the exit-code contract, the belt-and-suspenders gate pattern, and how to tighten the threshold.
- **`--base <ref>` diff scope.** `commands/security-review.md` Step 1 gains a `--base <ref>` flag that, when set, makes Step 2a use the three-dot range `<ref>...HEAD` instead of `HEAD` — scoping the review to changes the current branch introduced over the named base. Validates the ref exists via `git rev-parse --verify`; invalid ref produces exit 2 (never silent fallback to HEAD). The flag is a no-op under `--full` (a stderr warning is printed and execution continues, since full mode uses `git ls-files` which is ref-independent). Two-dot range was rejected because it would include base-side commits since divergence. The reference workflow at `.github/workflows/security-review.yml` automatically passes `--base origin/${{ github.base_ref }}` on `pull_request` events. README "PR-against-base scope" subsection added under CI Integration.
- **`--sarif` output mode.** `commands/security-review.md` Step 1 gains a `--sarif` flag and Step 5 gains a SARIF v2.1.0 emission branch. The transform maps the agent's native findings to a SARIF document conforming to the OASIS schema: `vulnerability_class` → `ruleId`, severity → `level` (critical/high → error, medium → warning, low/info → note) and `properties.security-severity` (numeric 9.0/7.0/5.0/3.0/1.0), `file`/`line` → `physicalLocation`, `description` → `message.text`, `remediation` → `fixes[0].description.text`, `cwe` ∪ `owasp` ∪ `confidence:<value>` → `properties.tags[]`. Cross-run dedup uses the same Step 4.6 fingerprint algorithm, emitted as `partialFingerprints["stride/v1"]`. `--sarif` and `--json` are mutually exclusive (both → exit 2). MAESTRO and Patches modes compose: `maestro:<layer-id>` is appended to `properties.tags[]` when `--maestro` is set; surgical patches populate `fixes[0].artifactChanges` when `--patches` is set. Mode-independent (same shape from diff and full). README "SARIF output" subsection added under CI Integration with a `gh api repos/:owner/:repo/code-scanning/sarifs` upload recipe. New `schema/README.md` documents the field-mapping reference and the canonical SARIF schema URLs.

## [2.0.0] - 2026-05-13

### Changed

- **BREAKING: Plugin renamed from `security-review` to `stride-security-review`.** The previous name collided with Claude Code's built-in `/security-review` command. v1.2.2 documented a workaround (always invoke via the old namespaced form), but the namespace itself still contained the colliding token, which caused autocomplete confusion and made the bare form silently fall through to the built-in. Renaming the plugin removes the collision at the namespace level: the canonical invocation is now `/stride-security-review:security-review`, and the bare `/security-review` cleanly belongs to the Claude Code built-in with no overlap.
- **Marketplace entry renamed.** Users who installed via `stride-marketplace` should run `/plugin update stride-marketplace` after the marketplace v1.16.0 release; the manifest entry, source URL, and version all change in lockstep.
- **GitHub repository renamed** from `cheezy/security-review` to `cheezy/stride-security-review`. GitHub serves a redirect from the old URL, but the canonical repository name and `homepage` / `repository` fields in `plugin.json` now reference the new path.
- **All documentation, agent prompts, command files, skill prose, and test fixtures** have been updated to reference `/stride-security-review:security-review`. Inner artifact names (the `security-reviewer` agent, the `security-review-essentials` skill, the `commands/security-review.md` slash-command file) are intentionally unchanged — only the outer plugin namespace moved.

### Migration

- Replace any scripted invocations of the old namespaced form (the previous plugin name followed by `:security-review`) with `/stride-security-review:security-review`.
- CI/CD jobs that shelled out via the bare `/security-review` form were already getting the Claude Code built-in (not this plugin); no action needed there beyond switching to the namespaced form if you wanted this plugin's behavior.
- Re-installation: `/plugin uninstall security-review` then `/plugin install stride-security-review@stride-marketplace` (or `/plugin update stride-marketplace` if your marketplace cache picks up the manifest change).

## [1.2.2] - 2026-05-11

### Fixed

- **`--full` (and every other flag) silently ignored when users invoked `/security-review` without the plugin namespace.** Claude Code ships with a built-in `/security-review` command that handles a diff-only review and does not understand any of this plugin's flags (`--full`, `--json`, `--maestro`, `--rci`, `--baseline`, `--update-baseline`, `--patches`). When both commands exist on a machine, the unqualified name resolves to the built-in, so users typing `/security-review --full` got a diff-only review with no error message. The plugin's command body already parses `--full` correctly when actually invoked; the symptom was a name-collision, not a parsing bug. This release documents the conflict and standardizes every example, README block, skill block, and changelog entry on the namespaced invocation form `/stride-security-review:security-review` (originally documented under the old plugin name; updated alongside the v2.0.0 plugin rename). The command body also gains an explicit "Honor every flag from Step 1" operational rule that forbids falling back to diff mode when `FULL_MODE=true`, and a "Name-collision warning" section pointing readers at the namespaced form. Files: `commands/security-review.md`, `agents/security-reviewer.md`, `README.md`, `skills/security-review-essentials/SKILL.md`.

## [1.2.1] - 2026-05-11

### Fixed

- **`--full` mode now runs unattended under the slash command's `allowed-tools` whitelist.** The v1.1.0 enumeration documented a piped `git ls-files | while ...; do grep -Iq ...; wc -c < ...; done` loop. Claude Code's permission system matches the full Bash command string against `allowed-tools` prefixes, so a compound pipeline did not match any single entry and required a permission prompt on every invocation (or was skipped outright by the model, falling back to diff-mode behavior). Step 2b now uses two single-shot batched calls — `grep -Il . <files...>` for the binary filter and `wc -c <files...>` for the size filter — each covered by a dedicated `Bash(grep:*)` / `Bash(wc:*)` entry. The 256 KiB threshold and null-byte-in-prefix heuristic are unchanged; only the execution shape changes. Files: `commands/security-review.md`, `README.md`.

## [1.2.0] - 2026-05-11

A major capability release. Every existing finding shape stays valid; every new feature is opt-in via a flag, so callers that consumed v1.1.0 JSON continue to work without modification.

### Added

- **CWE and OWASP references on every finding.** Each finding now carries a `cwe` array (e.g., `["CWE-89"]`) and an `owasp` array (e.g., `["A03:2021"]`) so triage tools can group findings by canonical class without parsing prose. Both default to `[]` only when a finding doesn't map to any standard category.
- **`supply_chain` vulnerability class.** Five sub-rules covering floating-tag container base images, pipe-to-shell installers (`curl | sh`), CI/CD references by branch/tag instead of immutable SHA, manifest/lockfile drift, and typosquat/hallucinated package names. Multi-ecosystem coverage: npm, PyPI, RubyGems, Hex, crates.io, Maven, NuGet, Packagist, Go modules.
- **Five MAESTRO-derived agentic-AI vulnerability classes** that activate when the reviewed code imports a recognized LLM/agent/MCP SDK:
  - `prompt_injection` — untrusted text concatenated into LLM prompts without separation.
  - `tool_abuse` — agent function-call / MCP tool layers exposing file/shell/DB operations without per-tool authorization.
  - `agent_trust_boundary` — agent-to-agent message passing where one agent's output flows into another's prompt without quarantine.
  - `model_output_execution` — LLM response text flowing into `eval` / `exec` / `subprocess` / `Function()`.
  - `vector_store_poisoning` — user-controllable content embedded into vector DBs (Pinecone, Weaviate, Chroma, pgvector) without sanitization or source attribution.
  - Activation signals cover Python, JavaScript/TypeScript, Go, Ruby, Elixir, and Java/Kotlin SDKs.
- **Framework-aware rule packs** with three packs shipping at launch (alphabetical):
  - Django/Python — `mark_safe`, `extra`/`raw()` query interpolation, CSRF disabled, `DEBUG=True` in prod, `cleaned_data` mass-assignment.
  - Phoenix/Elixir — `Phoenix.HTML.raw/1`, missing `force_ssl`, `Plug.CSRFProtection` disabled, `Ecto.Query.fragment` string interpolation, LiveView event handlers trusting `phx-value-id`.
  - Rails/Ruby — `html_safe`/`raw()`, `find_by_sql` interpolation, `protect_from_forgery` disabled, `params.permit!` mass-assignment, `eval`/`send`/`instance_eval` with user input.
  - Activation is dual-gate (file extension AND import detection) so polyglot repos route each file to the right pack. Every per-pack rule maps to one of the existing universal `vulnerability_class` values — no per-framework enum proliferation.
  - "Adding a new framework pack" template documented in the agent prompt for contributors extending to Spring, Express, Gin, Laravel, FastAPI, etc.
- **CI/CD pipeline rule pack** covering eight platforms (alphabetical): Azure Pipelines, Bitbucket Pipelines, CircleCI, Drone, GitHub Actions, GitLab CI, Jenkins, Tekton. Five rules apply identically across every platform:
  1. External action / orb / template not pinned to an immutable SHA (`supply_chain`).
  2. Overly-broad permissions or scopes (`insecure_config`).
  3. Untrusted-ref or fork-PR build patterns (`insecure_config`).
  4. Secrets exposed alongside attacker-controlled input (`insecure_config`).
  5. Expression / interpolation injection in shell-step bodies (`injection`).
  - Activation is by file path (`.github/workflows/*.yml`, `.gitlab-ci.yml`, `.circleci/config.yml`, etc.) — generic YAML never triggers.
- **`--maestro` flag** — opt-in 7-layer threat classification using the Cloud Security Alliance MAESTRO taxonomy. Adds an optional `maestro_layer` field to each finding (`foundation-models`, `data-operations`, `agent-frameworks`, `deployment-infrastructure`, `evaluation-observability`, `security-compliance`, `agent-ecosystem`). Renders a `## By MAESTRO layer` summary section after the severity-grouped findings. Omitted entirely when the flag is not set.
- **`--rci [N]` flag** — Recursive Criticism & Improvement. Runs N additional critique-and-refine passes (default 1, clamped to 3) after the initial dispatch. Each pass receives both the prior pass's JSON findings AND the original input, and is asked to drop false positives and surface anything that was missed. `summary.rci_passes` integer records the pass count. OpenSSF documents this technique as reducing security-weakness count by up to an order of magnitude. Cost scales linearly.
- **`--baseline [PATH]` and `--update-baseline` flags** — baseline suppression. Acknowledged findings are filtered from the rendered report and counted in `summary.suppressed_count`. Baseline file schema: `{schema_version: 1, acknowledged: [...]}`. Fingerprint is `SHA256(vulnerability_class | file | line | first_80_chars_of_description)` — stable across runs even when severity or remediation prose changes.
- **`--patches` flag** — auto-remediation diff suggestions. Each finding gains an optional `patch` field containing a `git apply`-compatible unified diff, emitted only when the fix is surgical (1–20 lines, single file, no new deps, no API breaks), unambiguous, and verifiable from the supplied input alone. Most findings won't have a patch even with the flag set — that's the correct output, not a bug.
- **Cross-batch deduplication in full mode.** The merge step now runs an order-stable dedup pass keyed by `(file, line, vulnerability_class)`. Duplicates that surface across batches or RCI passes collapse to the first occurrence. `summary.findings_by_severity` is recomputed from the post-dedup list (not summed from per-batch counters, which drift after dedup).
- **`summary.files_skipped` in full mode** — array of `{path, reason}` records for every file the binary/size filters dropped. `reason ∈ {binary, oversize, unreadable}`. Always emitted in full mode (even as `[]` to prove the filter ran); omitted in diff mode. Human-readable report renders a `## Skipped` block capped at 50 entries with an `... and N more` overflow line.

### Changed

- The `vulnerability_class` enum gains six new values (`supply_chain` plus the five agentic classes). Callers that exhaustively switch on the enum need to handle the new values. Most callers consume the field as an opaque string and are unaffected.
- Full-mode contract: the "do NOT deduplicate" rule from v1.1.0 is replaced by the order-stable dedup pass described above. Diff mode is still a single dispatch where dedup is a no-op, so diff-mode JSON output is byte-identical to v1.1.0 for the same input.

### Notes

- All new flags compose. `--maestro --rci 2 --patches --baseline --full --json lib/` is a valid invocation.
- Cost discipline: `--rci 3 --full` over a 41-batch scan is 164 agent dispatches. The slash command does not warn about this — the trade-off is documented here and in the agent prompt; the user is in control.

## [1.1.0] - 2026-04-25

### Added

- **Full-codebase scan mode (`--full`).** Reviews tracked files end-to-end via `git ls-files`, batched at 10 files per agent dispatch. Composable with path arguments and `--json`. Diff mode remains the default.
  - Enumeration source: `git ls-files` (honors `.gitignore`, sparse-checkout, untracked-exclusions).
  - Binary filter via `grep -Iq .` null-byte detection.
  - 256 KiB size cap drops generated / vendored / minified files where the agent's signal-to-noise collapses.
  - Output schema is identical to diff mode; the human-readable header reads `Security review (full scan) — ...` so the mode is visible.
- A vulnerable-fixture smoke-test suite under `test/fixtures/` covering the universal vulnerability classes.

### Notes

- `--full` is explicitly opt-in. It does not become the default — diff mode remains the PR-gating workflow.
- Untracked files are intentionally out of scope; `git add -N` them first if you want them reviewed.

## [1.0.0] - 2026-04-13

Initial release.

### Added

- **`/security-review` slash command** — diff-aware security review of the working tree against `HEAD`. Both staged and unstaged changes reviewed in a single invocation.
- **`security-reviewer` agent** — semantic-analysis methodology covering nine universal vulnerability classes:
  - Injection (SQL, command, LDAP, NoSQL, XXE, template, header)
  - Authentication
  - Authorization
  - Data exposure
  - Cryptography
  - Input validation
  - Race conditions
  - XSS / code execution
  - Insecure configuration
- **JSON output schema** with per-finding `severity`, `file`, `line`, `vulnerability_class`, `description`, `remediation`, `confidence` and a `summary` block.
- **`--json` flag** for raw JSON output, suitable for piping into CI gates, Stride completion hooks, dashboards, or other tools.
- **Path scoping** — pass file or directory paths to limit the review.
- **False-positive filter** — deliberate exclusions for DoS-only, rate-limiting, memory-exhaustion, and pure-style concerns.
- **`security-review-essentials` skill** documenting the slash command's surface and customization knobs.

[2.0.0]: https://github.com/cheezy/stride-security-review/releases/tag/v2.0.0
[1.2.0]: https://github.com/cheezy/stride-security-review/releases/tag/v1.2.0
[1.1.0]: https://github.com/cheezy/stride-security-review/releases/tag/v1.1.0
[1.0.0]: https://github.com/cheezy/stride-security-review/releases/tag/v1.0.0
