# Changelog

All notable changes to the `security-review` plugin are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.2] - 2026-05-11

### Fixed

- **`--full` (and every other flag) silently ignored when users invoked `/security-review` without the plugin namespace.** Claude Code ships with a built-in `/security-review` command that handles a diff-only review and does not understand any of this plugin's flags (`--full`, `--json`, `--maestro`, `--rci`, `--baseline`, `--update-baseline`, `--patches`). When both commands exist on a machine, the unqualified name resolves to the built-in, so users typing `/security-review --full` got a diff-only review with no error message. The plugin's command body already parses `--full` correctly when actually invoked; the symptom was a name-collision, not a parsing bug. This release documents the conflict and standardizes every example, README block, skill block, and changelog entry on the namespaced invocation form `/security-review:security-review`. The command body also gains an explicit "Honor every flag from Step 1" operational rule that forbids falling back to diff mode when `FULL_MODE=true`, and a "Name-collision warning" section pointing readers at the namespaced form. Files: `commands/security-review.md`, `agents/security-reviewer.md`, `README.md`, `skills/security-review-essentials/SKILL.md`.

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

[1.2.0]: https://github.com/cheezy/security-review/releases/tag/v1.2.0
[1.1.0]: https://github.com/cheezy/security-review/releases/tag/v1.1.0
[1.0.0]: https://github.com/cheezy/security-review/releases/tag/v1.0.0
