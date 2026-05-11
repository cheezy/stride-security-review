# Expected findings

Smoke-test fixtures for the security-reviewer agent. Each fixture is a small piece of deliberately vulnerable code. Run `/security-review` (or dispatch the `security-reviewer` agent directly) against each fixture and confirm the listed finding is produced. False positives or missing findings indicate a prompt regression.

## Fixtures

- [ ] `sql_injection.py` → injection (critical) — string-concatenated SQL query with HTTP-supplied `username`.
- [ ] `hardcoded_secret.js` → data_exposure (critical) — Stripe-shaped secret key literal committed to source.
- [ ] `weak_crypto.ex` → crypto (high) — MD5 used (unsalted) for password hashing.
- [ ] `command_injection.rb` → injection (critical) — HTTP-supplied `filename` interpolated unescaped into a shell command.

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

## What a regression looks like

- **False positive:** the agent reports a finding on a fixture that is not listed above. Inspect the agent prompt's false-positive filter — did a new class slip in that shouldn't be flagged?
- **Missing finding:** the agent does not produce one of the listed findings. Inspect the agent prompt's vulnerability class list and methodology — did a class get dropped?
- **Wrong class:** the agent flags the issue but under a different `vulnerability_class`. Inspect the class taxonomy — did the enum change?
- **Wrong severity:** the issue is found and classified correctly but the severity does not match. Inspect the severity guidance — did the rubric language change?

A passing smoke test is: all four checkboxes can be filled, no other findings appear, and the JSON output parses cleanly.
