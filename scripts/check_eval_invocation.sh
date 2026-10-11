#!/usr/bin/env bash
# Key-free checks on how scripts/run_eval.sh invokes the agent (W2274).
#
# The eval is only worth running if it dispatches THIS plugin's
# security-reviewer agent rather than base Claude. That is a property of the
# claude argv, so it can be checked without an API key or a real Claude CLI:
#
#   1. --dry-run prints the invocation, and it names --plugin-dir <repo root>
#      and --agent stride-security-review:security-reviewer.
#   2. A fake CLI records what run_eval.sh actually executed: the agent flag,
#      an isolated cwd (not the repo, so EXPECTED.md is out of reach), and a
#      considerations-mode prompt on stdin. A canned verdict scores `ok`.
#   3. With no ANTHROPIC_API_KEY and a CLI that is not logged in, the run
#      refuses with exit 2 instead of silently scoring nothing.
#   1b. The tool overrides (W2276): by default the run denies the file and
#      shell tools and allows nothing; with EVAL_TOOLS, EVAL_ALLOWED_TOOLS and
#      EVAL_DISALLOWED_TOOLS set, the argv carries exactly those lists plus
#      --setting-sources '', and never a permission bypass.
#   4. The CI gate in .github/workflows/eval.yml: its "Detect
#      ANTHROPIC_API_KEY" run script, extracted and executed with an empty key,
#      skips (exit 0, present=false) on pull_request — fork and Dependabot PRs
#      get no secrets — and fails (exit 1) on push and workflow_dispatch.
#
# Exit 0 when every check passes, 1 otherwise.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
RUN_EVAL="$SCRIPT_DIR/run_eval.sh"
FIXTURE="test/fixtures/considerations/token_logging_unmitigated.diff"
AGENT_ID="stride-security-review:security-reviewer"

TMP="$(mktemp -d "${TMPDIR:-/tmp}/check_eval_invocation.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

fail=0
check() { # $1=label; remaining args = a test command
  local label="$1"
  shift
  if "$@"; then
    echo "ok: $label"
  else
    echo "FAIL: $label"
    fail=1
  fi
}
contains() { grep -qF -- "$2" "$1"; }
lacks() { ! grep -qF -- "$2" "$1"; }

cd "$ROOT_DIR" || exit 1

# --- 1. dry-run prints the exact invocation --------------------------------
LOG_DIR="$TMP/dry-logs" bash "$RUN_EVAL" --dry-run --fixture "$FIXTURE" > "$TMP/dry.out" 2>/dev/null
grep '^# invocation:' "$TMP/dry.out" > "$TMP/dry.inv" || true

check "dry-run prints an invocation line"      test -s "$TMP/dry.inv"
check "the invocation loads this repo's plugin" contains "$TMP/dry.inv" "--plugin-dir $(printf '%q' "$ROOT_DIR")"
check "the invocation selects the plugin agent" contains "$TMP/dry.inv" "--agent $AGENT_ID"
check "the invocation turns tools off"          contains "$TMP/dry.inv" "--tools ''"
check "the invocation is not a bare claude -p"  lacks "$TMP/dry.inv" "claude -p --output-format"
check "dry-run reports its auth mode"           contains "$TMP/dry.out" "# auth: dry-run"
check "the default denies the file and shell tools" contains "$TMP/dry.inv" \
  "--disallowedTools $(printf '%q' 'Read Grep Glob Bash Edit Write NotebookEdit WebFetch WebSearch')"
check "the default allows nothing"              lacks "$TMP/dry.inv" "--allowedTools"
check "the default keeps setting sources"       lacks "$TMP/dry.inv" "--setting-sources"

# --- 1b. the tool overrides used for the with/without-Bash comparison -------
EVAL_TOOLS='Read,Grep,Glob,Bash' EVAL_ALLOWED_TOOLS='Read,Grep,Glob,Bash' \
  EVAL_DISALLOWED_TOOLS='Edit Write NotebookEdit WebFetch WebSearch' \
  LOG_DIR="$TMP/override-logs" bash "$RUN_EVAL" --dry-run --fixture "$FIXTURE" > "$TMP/override.out" 2>/dev/null
grep '^# invocation:' "$TMP/override.out" > "$TMP/override.inv" || true

check "the override sets --tools"               contains "$TMP/override.inv" "--tools Read\,Grep\,Glob\,Bash"
check "the override sets --allowedTools"        contains "$TMP/override.inv" "--allowedTools Read\,Grep\,Glob\,Bash"
check "the override drops the operator settings" contains "$TMP/override.inv" "--setting-sources ''"
check "the override sets the deny list"         contains "$TMP/override.inv" \
  "--disallowedTools $(printf '%q' 'Edit Write NotebookEdit WebFetch WebSearch')"
check "the override never bypasses permissions" lacks "$TMP/override.inv" "dangerously"
check "the override never sets a permission mode" lacks "$TMP/override.inv" "--permission-mode"

# --- 2. a fake CLI records what was really executed -------------------------
FAKE="$TMP/fake-claude"
cat > "$FAKE" <<'FAKE_EOF'
#!/usr/bin/env bash
if [ "${1:-}" = "auth" ]; then
  printf '{"loggedIn": %s}\n' "${FAKE_LOGGED_IN:-true}"
  exit 0
fi
printf '%s\n' "$@" > "$FAKE_REC/argv"
pwd > "$FAKE_REC/pwd"
cat > "$FAKE_REC/stdin"
cat <<'JSON'
```json
{"findings":[{"severity":"critical","file":"app/users.py","line":12,"vulnerability_class":"injection","cwe":["CWE-89"],"owasp":["A03:2021"],"description":"fake","remediation":"fake","confidence":"high"}],
 "consideration_verdicts":[{"consideration":"a","status":"unmitigated"},{"consideration":"b","status":"mitigated"}]}
```
JSON
FAKE_EOF
chmod +x "$FAKE"
mkdir -p "$TMP/rec"

env -u ANTHROPIC_API_KEY FAKE_REC="$TMP/rec" CLAUDE_CLI="$FAKE" LOG_DIR="$TMP/fake-logs" \
  bash "$RUN_EVAL" --fixture "$FIXTURE" > "$TMP/fake.out" 2>&1
fake_rc=$?

check "a canned verdict scores ok (exit 0)"     test "$fake_rc" -eq 0
check "the TAP line is ok"                      contains "$TMP/fake.out" "ok 1 - considerations/token_logging_unmitigated.diff"
check "a logged-in CLI is accepted without a key" contains "$TMP/fake.out" "# auth: claude.ai-login"
check "the CLI received --agent $AGENT_ID"      grep -qxF -- "$AGENT_ID" "$TMP/rec/argv"
check "the CLI received --plugin-dir"           grep -qxF -- "--plugin-dir" "$TMP/rec/argv"
check "the CLI ran outside the repo"            test "$(cat "$TMP/rec/pwd" 2>/dev/null)" != "$ROOT_DIR"
check "the prompt is in considerations mode"    contains "$TMP/rec/stdin" "/security-review invocation, mode: considerations"
check "the key-free run never printed a key"    lacks "$TMP/fake.out" "ANTHROPIC_API_KEY="

# --- 3. no key and no login refuses -----------------------------------------
env -u ANTHROPIC_API_KEY FAKE_LOGGED_IN=false FAKE_REC="$TMP/rec" CLAUDE_CLI="$FAKE" LOG_DIR="$TMP/noauth-logs" \
  bash "$RUN_EVAL" --fixture "$FIXTURE" > "$TMP/noauth.out" 2>&1
noauth_rc=$?
check "no key and no login exits 2"             test "$noauth_rc" -eq 2

# --- 4. the CI key gate: skip on pull_request, fail on main ----------------
# Extract the step's `run: |` block (everything indented deeper than `run:`)
# and execute it as GitHub would, with a temp GITHUB_OUTPUT and no key.
WORKFLOW="$ROOT_DIR/.github/workflows/eval.yml"
awk '
  /- name: Detect ANTHROPIC_API_KEY$/ { in_step = 1; next }
  in_step && !in_run && /^ +run: \|$/ { in_run = 1; match($0, /^ +/); ind = RLENGTH; next }
  in_run {
    if ($0 ~ /^[[:space:]]*$/) { print ""; next }
    match($0, /^ */)
    if (RLENGTH <= ind) exit
    print substr($0, ind + 3)
  }
' "$WORKFLOW" > "$TMP/detect.sh"

gate() { # $1=event name -> prints "<exit code> <GITHUB_OUTPUT contents>"
  : > "$TMP/gh_output"
  env -u ANTHROPIC_API_KEY ANTHROPIC_API_KEY="" EVENT_NAME="$1" GITHUB_OUTPUT="$TMP/gh_output" \
    bash "$TMP/detect.sh" > "$TMP/gate-$1.out" 2>&1
  printf '%s %s' "$?" "$(tr -d '\n' < "$TMP/gh_output")"
}
check "the CI key-gate script was extracted"    contains "$TMP/detect.sh" 'EVENT_NAME'
check "pull_request without a key skips"        test "$(gate pull_request)" = "0 present=false"
check "the PR skip emits a notice"              contains "$TMP/gate-pull_request.out" "::notice title=Agent eval skipped::"
check "push without a key fails"                test "$(gate push)" = "1 "
check "the push failure emits an error"         contains "$TMP/gate-push.out" "::error title=Agent eval cannot run::"
check "workflow_dispatch without a key fails"   test "$(gate workflow_dispatch)" = "1 "
: > "$TMP/gh_output"
ANTHROPIC_API_KEY="placeholder-not-a-real-key" EVENT_NAME=push GITHUB_OUTPUT="$TMP/gh_output" \
  bash "$TMP/detect.sh" > "$TMP/gate-key.out" 2>&1
check "a configured key runs the eval"          test "$? $(tr -d '\n' < "$TMP/gh_output")" = "0 present=true"
check "the gate never prints the key"           lacks "$TMP/gate-key.out" "placeholder-not-a-real-key"

# --- 5. CI scores the agent with its packs (W2285) -------------------------
# The agent reads packs/ and modes/ on demand, so the CI run must give it Read,
# scoped to a plugin copy without test/ so EXPECTED.md stays out of reach.
awk '
  /- name: Run eval$/ { in_step = 1; next }
  in_step && !in_run && /^ +run: \|$/ { in_run = 1; match($0, /^ +/); ind = RLENGTH; next }
  in_run {
    if ($0 ~ /^[[:space:]]*$/) { print ""; next }
    match($0, /^ */)
    if (RLENGTH <= ind) exit
    print substr($0, ind + 3)
  }
' "$WORKFLOW" > "$TMP/run-eval.sh"
check "CI copies the plugin without test/"      contains "$TMP/run-eval.sh" "--exclude=./test"
check "CI leaves .git out of the copy"         contains "$TMP/run-eval.sh" "--exclude=./.git"
check "CI leaves logs/ out of the copy"        contains "$TMP/run-eval.sh" "--exclude=./logs"
check "CI points the eval at the copy"          contains "$TMP/run-eval.sh" 'EVAL_PLUGIN_DIR="$copy"'
check "CI gives the agent Read"                 contains "$TMP/run-eval.sh" "EVAL_TOOLS=Read"
check "CI scopes Read to the copy"              contains "$TMP/run-eval.sh" 'EVAL_ALLOWED_TOOLS="Read(/$copy/**)"'
check "CI keeps the shell and writes denied"    contains "$TMP/run-eval.sh" "EVAL_DISALLOWED_TOOLS='Grep Glob Bash Edit Write NotebookEdit WebFetch WebSearch'"

if [ "$fail" -ne 0 ]; then
  echo "eval invocation: FAILED"
  exit 1
fi
echo "eval invocation: all checks passed"
