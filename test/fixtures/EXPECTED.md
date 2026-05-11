# Expected findings

Smoke-test fixtures for the security-reviewer agent. Each fixture is a small piece of deliberately vulnerable code. Run `/security-review` (or dispatch the `security-reviewer` agent directly) against each fixture and confirm the listed finding is produced. False positives or missing findings indicate a prompt regression.

## Fixtures

- [ ] `sql_injection.py` → injection (critical), `cwe: ["CWE-89"]`, `owasp: ["A03:2021"]` — string-concatenated SQL query with HTTP-supplied `username`.
- [ ] `hardcoded_secret.js` → data_exposure (critical), `cwe: ["CWE-798"]`, `owasp: ["A07:2021"]` — Stripe-shaped secret key literal committed to source.
- [ ] `weak_crypto.ex` → crypto (high), `cwe: ["CWE-327"]`, `owasp: ["A02:2021"]` — MD5 used (unsalted) for password hashing.
- [ ] `command_injection.rb` → injection (critical), `cwe: ["CWE-78"]`, `owasp: ["A03:2021"]` — HTTP-supplied `filename` interpolated unescaped into a shell command.

## How to run the smoke test

1. In a Claude Code session with the security-review plugin installed, `cd` into a clean clone of the security-review repo.
2. Stage the fixtures so they appear in `git diff HEAD`:
   ```bash
   touch test/fixtures/SMOKE_TEST_RUN.flag
   git add test/fixtures/SMOKE_TEST_RUN.flag
   ```
   (The flag file just gives `git diff` something to anchor against — the fixtures themselves are committed.)
3. Run `/security-review test/fixtures/` and confirm each expected finding appears with the documented vulnerability class and severity.
4. Run `/security-review --json test/fixtures/` and confirm the JSON output parses and matches the same set of findings.

## Full-scan scenario

Full-scan mode (`--full`, added in v1.1.0) reviews whole files rather than hunks. Because the four fixtures above are deliberately vulnerable code, the expected findings are the **same set** whether they reach the agent through a diff or as whole-file content. The full-scan scenario adds two new things to verify: the file-enumeration filters and the human-readable header.

### Invocation

```bash
/security-review --full test/fixtures/
```

This scopes `git ls-files` to `test/fixtures/`, applies the binary and 256 KiB filters, and dispatches the `security-reviewer` agent in `full_file` mode.

### Expected enumeration result

`git ls-files test/fixtures/` produces five tracked files: the four fixtures plus `EXPECTED.md`. All five are text files comfortably under 256 KiB, so all five survive the binary and size filters and are handed to the agent. The agent's `summary.files_reviewed` count should equal **5** in this scenario.

### Expected per-file findings

| Fixture | Severity | vulnerability_class | cwe | owasp | One-line rationale |
|---|---|---|---|---|---|
| `sql_injection.py` | critical | `injection` | `["CWE-89"]` | `["A03:2021"]` | HTTP-supplied `username` concatenated into a raw SQL query — same finding as diff mode. |
| `hardcoded_secret.js` | critical | `data_exposure` | `["CWE-798"]` | `["A07:2021"]` | Stripe-shaped secret key literal committed to source — same finding as diff mode. |
| `weak_crypto.ex` | high | `crypto` | `["CWE-327"]` | `["A02:2021"]` | MD5 (unsalted) used for password hashing — same finding as diff mode. |
| `command_injection.rb` | critical | `injection` | `["CWE-78"]` | `["A03:2021"]` | HTTP-supplied `filename` interpolated unescaped into a shell command — same finding as diff mode. |
| `EXPECTED.md` | — | — | — | — | **Negative case:** documentation file. The agent must NOT produce a finding here. Markdown is text, so it passes the binary filter; but the file contains no executable code at a trust boundary. |

A passing full-scan smoke test:

- `summary.files_reviewed` is exactly `5` (the four fixtures + this file).
- `summary.findings_by_severity` totals `{"critical": 3, "high": 1, "medium": 0, "low": 0, "info": 0}` — the same four findings as diff mode.
- No finding is reported on `EXPECTED.md`.
- The human-readable header reads `Security review (full scan) — 4 findings across 5 files`.
- The `--json` variant produces the same JSON document as diff mode for the four findings, with `summary.files_reviewed` raised to 5.

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

A passing smoke test is: all four checkboxes can be filled, no other findings appear, and the JSON output parses cleanly.
