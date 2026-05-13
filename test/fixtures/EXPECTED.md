# Expected findings

Smoke-test fixtures for the security-reviewer agent. Each fixture is a small piece of deliberately vulnerable code. Run `/stride-security-review:security-review` (or dispatch the `security-reviewer` agent directly) against each fixture and confirm the listed finding is produced. False positives or missing findings indicate a prompt regression.

## Fixtures

### Universal vulnerability classes

- [ ] `sql_injection.py` → injection (critical), `cwe: ["CWE-89"]`, `owasp: ["A03:2021"]` — string-concatenated SQL query with HTTP-supplied `username`.
- [ ] `hardcoded_secret.js` → data_exposure (critical), `cwe: ["CWE-798"]`, `owasp: ["A07:2021"]` — Stripe-shaped secret key literal committed to source.
- [ ] `weak_crypto.ex` → crypto (high), `cwe: ["CWE-327"]`, `owasp: ["A02:2021"]` — MD5 used (unsalted) for password hashing.
- [ ] `command_injection.rb` → injection (critical), `cwe: ["CWE-78"]`, `owasp: ["A03:2021"]` — HTTP-supplied `filename` interpolated unescaped into a shell command.

### Agentic vulnerability classes (require file to import an LLM/agent/MCP SDK)

- [ ] `prompt_injection.py` → prompt_injection (critical), `cwe: ["CWE-1427"]`, `owasp: ["A03:2021"]` — Flask handler concatenates HTTP-supplied `question` directly into an OpenAI chat-completions message body. Python ecosystem coverage.
- [ ] `prompt_injection.ts` → prompt_injection (critical), `cwe: ["CWE-1427"]`, `owasp: ["A03:2021"]` — Express handler concatenates HTTP-supplied `q` into an Anthropic Messages prompt. TypeScript ecosystem coverage — same shape, different ecosystem.
- [ ] `tool_abuse.py` → tool_abuse (critical), `cwe: ["CWE-78", "CWE-22"]`, `owasp: ["A01:2021"]` — LangChain agent exposes unrestricted `run_shell` and `read_file` tools to the LLM with no auth, validation, or confirmation gate.
- [ ] `tool_abuse.ts` → tool_abuse (critical), `cwe: ["CWE-22"]`, `owasp: ["A01:2021"]` — MCP server exposes `write_file` / `delete_file` tools accepting arbitrary paths from LLM clients. TypeScript / @modelcontextprotocol/sdk coverage.
- [ ] `vector_store_poisoning.go` → vector_store_poisoning (high), `cwe: ["CWE-915"]`, `owasp: ["A08:2021"]` — HTTP handler embeds user-supplied comment text directly into pgvector without sanitization or source attribution. Go ecosystem coverage.
- [ ] `model_output_execution.py` → model_output_execution (critical), `cwe: ["CWE-95", "CWE-94"]`, `owasp: ["A03:2021"]` — OpenAI chat-completion response passed directly to `exec()` with no AST check, no sandbox, no allow-list. Python ecosystem coverage.
- [ ] `agent_trust_boundary.ts` → agent_trust_boundary (high), `cwe: ["CWE-1427"]`, `owasp: ["A04:2021"]` — researcher-agent output piped into writer-agent prompt with no delimiter, no integrity check, no quarantine. TypeScript / @anthropic-ai/sdk coverage.

### Supply-chain class

- [ ] `Dockerfile.floating_tag` → supply_chain (medium), `cwe: ["CWE-1357"]`, `owasp: ["A06:2021"]` — production-bound container image pinned to floating tag `node:20` instead of an immutable digest.
- [ ] `curl_pipe_sh.sh` → supply_chain (medium), `cwe: ["CWE-494"]`, `owasp: ["A08:2021"]` — installer script pipes `curl` and `wget` output directly into `sh`/`bash` with no signature or checksum verification.
- [ ] `github_workflow_unpinned.yml` → supply_chain (medium), `cwe: ["CWE-1357"]`, `owasp: ["A08:2021"]` — GitHub Actions referencing third-party actions by `@v4` / `@main` floats instead of SHA. GitHub-Actions ecosystem coverage.
- [ ] `gitlab_ci_unpinned.yml` → supply_chain (medium), `cwe: ["CWE-1357"]`, `owasp: ["A08:2021"]` — GitLab CI `include` referencing a remote pipeline by branch/tag. GitLab CI ecosystem coverage — proves the rule is platform-neutral.

### Framework-aware rule packs

- [ ] `django_mark_safe_xss.py` → xss_or_code_exec (high), `cwe: ["CWE-79"]`, `owasp: ["A03:2021"]` — Django view wraps `request.GET.get("bio")` with `mark_safe`. Django/Python rule pack.
- [ ] `phoenix_raw_xss.ex` → xss_or_code_exec (high), `cwe: ["CWE-79"]`, `owasp: ["A03:2021"]` — Phoenix LiveView renders user-supplied `q` via `Phoenix.HTML.raw`. Phoenix/Elixir rule pack.
- [ ] `phoenix_mass_assignment.ex` → authorization (high), `cwe: ["CWE-915"]`, `owasp: ["A04:2021"]` — Phoenix controller pipes `user_params` into an `Ecto.Changeset.cast/3` whose allow-list is `__MODULE__.__schema__(:fields)`, exposing privileged `:role` and `:is_admin` fields to client write. Phoenix/Elixir rule pack — analog of Rails `params.permit!`. The actual harm is privilege escalation (writing `:is_admin`), so the class is `authorization`, not `input_validation`.
- [ ] `rails_html_safe_xss.rb` → xss_or_code_exec (high), `cwe: ["CWE-79"]`, `owasp: ["A03:2021"]` — Rails controller exposes `params[:comment]` for `.html_safe` rendering in the corresponding view. Rails/Ruby rule pack.

### Web defense-in-depth pack

- [ ] `django_missing_headers.py` → insecure_config (high), `cwe: ["CWE-614"]`, `owasp: ["A05:2021"]` — Django production settings with MIDDLEWARE list omitting SecurityMiddleware, `SESSION_COOKIE_SECURE = False`, `SESSION_COOKIE_HTTPONLY = False`, no `SECURE_HSTS_SECONDS`, no CSP. Asserts the cookie-flags finding at severity high; CSP/HSTS/X-Frame-Options at medium are bonus findings expected on the same file but not gated here.
- [ ] `phoenix_missing_headers.ex` → insecure_config (high), `cwe: ["CWE-614"]`, `owasp: ["A05:2021"]` — Phoenix Endpoint with no `force_ssl`, no `put_secure_browser_headers/2`, and `Plug.Session` opts of `secure: false, http_only: false`. Asserts the cookie-flags finding at severity high; CSP / HSTS / X-Frame-Options at medium are bonus findings expected on the same file but not gated here.

### CI/CD pipeline rule pack

- [ ] `ci_cd/github_unpinned.yml` → supply_chain (medium), `cwe: ["CWE-1357"]`, `owasp: ["A08:2021"]` — two unpinned action references (`@v4`, `@main`); third step pinned to a 40-hex SHA must NOT trigger (negative case). GitHub Actions ecosystem.
- [ ] `ci_cd/github_expression_injection.yml` → injection (high), `cwe: ["CWE-94", "CWE-78"]`, `owasp: ["A03:2021"]` — `${{ github.event.issue.title }}` and `${{ github.event.issue.body }}` interpolated into shell `run:` steps. GitHub Actions Rule 5.
- [ ] `ci_cd/gitlab_unpinned.yml` → supply_chain (medium), `cwe: ["CWE-1357"]`, `owasp: ["A08:2021"]` — two `include:` references using branch / tag refs instead of SHA. GitLab CI ecosystem.
- [ ] `ci_cd/circleci_unpinned.yml` → supply_chain (medium), `cwe: ["CWE-1357"]`, `owasp: ["A08:2021"]` — orb references using semver (`@4.1.0`) and `@volatile`; both are mutable. CircleCI ecosystem.
- [ ] `ci_cd/bitbucket_secrets_in_fork.yml` → insecure_config (high) AND insecure_config (high), `cwe: ["CWE-732", "CWE-200"]`, `owasp: ["A05:2021", "A01:2021"]` — pull-request pipeline runs with `deployment: production` (exposes the deploy secret on fork-triggered builds, Rule 3) AND embeds `$BITBUCKET_PR_TITLE` in the same `curl` call that carries `$PRODUCTION_DEPLOY_TOKEN` (Rule 4). Bitbucket Pipelines ecosystem.

## How to run the smoke test

1. In a Claude Code session with the `stride-security-review` plugin installed, `cd` into a clean clone of the `stride-security-review` repo.
2. Stage the fixtures so they appear in `git diff HEAD`:
   ```bash
   touch test/fixtures/SMOKE_TEST_RUN.flag
   git add test/fixtures/SMOKE_TEST_RUN.flag
   ```
   (The flag file just gives `git diff` something to anchor against — the fixtures themselves are committed.)
3. Run `/stride-security-review:security-review test/fixtures/` and confirm each expected finding appears with the documented vulnerability class and severity.
4. Run `/stride-security-review:security-review --json test/fixtures/` and confirm the JSON output parses and matches the same set of findings.

## Full-scan scenario

Full-scan mode (`--full`, added in v1.1.0) reviews whole files rather than hunks. Because the four fixtures above are deliberately vulnerable code, the expected findings are the **same set** whether they reach the agent through a diff or as whole-file content. The full-scan scenario adds two new things to verify: the file-enumeration filters and the human-readable header.

### Invocation

```bash
/stride-security-review:security-review --full test/fixtures/
```

This scopes `git ls-files` to `test/fixtures/`, applies the binary and 256 KiB filters, and dispatches the `security-reviewer` agent in `full_file` mode.

### Expected enumeration result

`git ls-files test/fixtures/` produces twelve tracked files: four universal-class fixtures, seven agentic-class fixtures across Python/TypeScript/Go, plus `EXPECTED.md`. All twelve are text files comfortably under 256 KiB, so all twelve survive the binary and size filters and are handed to the agent. The agent's `summary.files_reviewed` count should equal **12** in this scenario.

### Expected per-file findings

| Fixture | Severity | vulnerability_class | cwe | owasp | One-line rationale |
|---|---|---|---|---|---|
| `sql_injection.py` | critical | `injection` | `["CWE-89"]` | `["A03:2021"]` | HTTP-supplied `username` concatenated into a raw SQL query. |
| `hardcoded_secret.js` | critical | `data_exposure` | `["CWE-798"]` | `["A07:2021"]` | Stripe-shaped secret key literal committed to source. |
| `weak_crypto.ex` | high | `crypto` | `["CWE-327"]` | `["A02:2021"]` | MD5 (unsalted) used for password hashing. |
| `command_injection.rb` | critical | `injection` | `["CWE-78"]` | `["A03:2021"]` | HTTP-supplied `filename` interpolated unescaped into a shell command. |
| `prompt_injection.py` | critical | `prompt_injection` | `["CWE-1427"]` | `["A03:2021"]` | Flask + OpenAI: user `question` concatenated into chat-completions prompt. |
| `prompt_injection.ts` | critical | `prompt_injection` | `["CWE-1427"]` | `["A03:2021"]` | Express + Anthropic: user `q` concatenated into Messages prompt. |
| `tool_abuse.py` | critical | `tool_abuse` | `["CWE-78", "CWE-22"]` | `["A01:2021"]` | LangChain agent exposes shell + arbitrary file read tools. |
| `tool_abuse.ts` | critical | `tool_abuse` | `["CWE-22"]` | `["A01:2021"]` | MCP server exposes write_file / delete_file with arbitrary paths. |
| `vector_store_poisoning.go` | high | `vector_store_poisoning` | `["CWE-915"]` | `["A08:2021"]` | User comment embedded into pgvector without sanitization. |
| `model_output_execution.py` | critical | `model_output_execution` | `["CWE-95", "CWE-94"]` | `["A03:2021"]` | OpenAI response passed directly to `exec()`. |
| `agent_trust_boundary.ts` | high | `agent_trust_boundary` | `["CWE-1427"]` | `["A04:2021"]` | Researcher → writer agent pipe with no quarantine/delimiter. |
| `EXPECTED.md` | — | — | — | — | **Negative case:** documentation file. The agent must NOT produce a finding here. |

A passing full-scan smoke test:

- `summary.files_reviewed` is exactly `12` (eleven fixtures + this file).
- `summary.findings_by_severity` totals `{"critical": 7, "high": 4, "medium": 0, "low": 0, "info": 0}`.
- No finding is reported on `EXPECTED.md`.
- The human-readable header reads `Security review (full scan) — 11 findings across 12 files`.
- The `--json` variant produces the same JSON document as diff mode for the eleven findings, with `summary.files_reviewed` raised to 12.
- Each agentic fixture's finding sits under the matching `vulnerability_class` from the agent's "Agentic vulnerability classes" section.

### Regression checks specific to full mode

- **Enumeration regression:** if `summary.files_reviewed` is less than 5, either `git ls-files` is being misused (e.g., a filesystem walk crept back in and is excluding tracked files) or the size cap / binary filter is mis-thresholded.
- **Header regression:** if the header is missing the `(full scan)` qualifier or is reporting M files as a diff-line count, Step 5 of `commands/security-review.md` has lost its mode-aware branching.
- **False-positive regression on docs:** if `EXPECTED.md` produces a finding, the agent prompt's false-positive filter has weakened for prose-only files.
- **Schema drift:** the JSON document shape must be byte-for-byte identical between diff and full modes. The per-finding fields are: `severity`, `file`, `line`, `vulnerability_class`, `cwe`, `owasp`, `description`, `remediation`, `confidence`. Missing any of those fields, or introducing a new top-level key without updating this expectation, is a regression. The `cwe` and `owasp` fields were added in plugin v1.2.0 and must populate per the table above for every concrete finding — empty arrays only for true-defense-in-depth notes where no CWE/OWASP category applies.

## What a regression looks like

- **False positive:** the agent reports a finding on a fixture that is not listed above. Inspect the agent prompt's false-positive filter — did a new class slip in that shouldn't be flagged?
- **Missing finding:** the agent does not produce one of the listed findings. Inspect the agent prompt's vulnerability class list and methodology — did a class get dropped?
- **Wrong class:** the agent flags the issue but under a different `vulnerability_class`. Inspect the class taxonomy — did the enum change?
- **Wrong severity:** the issue is found and classified correctly but the severity does not match. Inspect the severity guidance — did the rubric language change?
- **Wrong or missing CWE/OWASP:** the agent reports the correct vulnerability_class but the `cwe` or `owasp` array doesn't match the expected per-fixture mapping. Inspect the agent prompt's "CWE and OWASP mapping requirements" subsection — was a CWE-ID dropped from the recognised list, or did a category mapping get inverted?
- **Agentic class regression:** the agent flags a `prompt_injection` / `tool_abuse` / `agent_trust_boundary` / `model_output_execution` / `vector_store_poisoning` finding on a file that imports NO LLM/agent/MCP SDK (e.g. a plain Flask handler with no AI imports). The "Agentic vulnerability classes" section's import-signal gate has weakened. Conversely, if the agentic fixtures (e.g. `prompt_injection.py`) produce only the universal-class findings (`injection` instead of `prompt_injection`), the agentic-class enum or detection rubric has been dropped from the agent prompt.
- **Cross-ecosystem coverage regression:** the agent detects a class only when the fixture is in one specific language (e.g. flags `prompt_injection.py` but misses `prompt_injection.ts`). The agentic rule is over-fit to a single ecosystem's SDK syntax — the per-language detection-signal list in the agent prompt has gone stale.
- **MAESTRO mode regression:** `/stride-security-review:security-review --maestro` against the agentic fixtures should populate `maestro_layer` on every finding (`data-operations` for prompt_injection and vector_store_poisoning, `agent-frameworks` for tool_abuse, `agent-ecosystem` for agent_trust_boundary, `agent-frameworks` or `data-operations` for model_output_execution). If `maestro_layer` is missing on findings when --maestro is set, the agent prompt's "MAESTRO 7-layer classification" subsection has been dropped or the dispatch directive isn't being passed. Conversely, if `maestro_layer` APPEARS on findings when --maestro is NOT set, the opt-in gate has weakened.

A passing smoke test is: all four checkboxes can be filled, no other findings appear, and the JSON output parses cleanly.
