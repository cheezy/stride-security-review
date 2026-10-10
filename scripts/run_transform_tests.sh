#!/usr/bin/env bash
#
# run_transform_tests.sh — golden-file + spec-assertion tests for the
# deterministic transforms in scripts/sarif_transform.sh.
#
# The transforms (fingerprint, SARIF mapping, dedup, fail-on with its verdict
# gate, baseline suppression that keeps backing findings) are specified in
# prose in commands/security-review.md and have no other executable source of
# truth. This runner locks their behavior two ways:
#   1. Golden diffs — sarif_transform.sh output vs committed test/golden/*.
#   2. Explicit spec assertions — exact values from the prose contract
#      (fingerprint preimage, severity->level/security-severity table, dedup key,
#      fail-on counting, the verdict gate, the baseline rule for a finding that
#      backs a verdict) so a golden that drifts WITH the implementation can't
#      hide a spec violation.
#
# Pure: no network, no Claude CLI, no ANTHROPIC_API_KEY. Only jq + a SHA-256
# utility are needed, so it runs cheaply in CI on every push.
#
# Output is TAP version 13. Exit 0 only when every check passes.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
XFORM="$SCRIPT_DIR/sarif_transform.sh"
GOLDEN_DIR="$ROOT_DIR/test/golden"
INPUT="$GOLDEN_DIR/input_findings.json"
PLUGIN_JSON="$ROOT_DIR/.claude-plugin/plugin.json"

# The precomputed SHA-256 of the spec preimage for input_findings.json finding[0]:
#   injection|lib/users.py|42|<first 80 chars of description>
# Computed independently and pinned here so the fingerprint algorithm itself is
# locked, not just self-consistent with the implementation.
EXPECTED_FP0="572a40cc1e8fdb62e2974d1d29b83e9aad7e1631386db9878e6ffb14c379bef2"

command -v jq >/dev/null 2>&1 || { printf 'error: jq not found\n' >&2; exit 2; }

N=0
FAILS=0
plan_printed=0

ok()      { N=$((N+1)); printf 'ok %d - %s\n' "$N" "$1"; }
not_ok()  { N=$((N+1)); FAILS=$((FAILS+1)); printf 'not ok %d - %s\n' "$N" "$1"
            [ -n "${2:-}" ] && printf '  # %s\n' "$2" || true; }

# assert_eq <label> <expected> <actual>
assert_eq() {
  if [ "$2" = "$3" ]; then ok "$1"; else not_ok "$1" "expected [$2] got [$3]"; fi
}

# assert_golden <label> <golden-file> <actual-file>
assert_golden() {
  if diff -u "$2" "$3" >/dev/null 2>&1; then
    ok "$1"
  else
    not_ok "$1" "output differs from golden $2"
    diff -u "$2" "$3" | sed 's/^/  # /' >&2 || true
  fi
}

main() {
  printf 'TAP version 13\n'

  local tmp
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT

  # ---- fingerprint -------------------------------------------------------
  bash "$XFORM" fingerprint "$INPUT" > "$tmp/fp.out"
  assert_golden "fingerprint: output matches golden" "$GOLDEN_DIR/fingerprint.golden" "$tmp/fp.out"
  assert_eq "fingerprint: finding[0] equals precomputed SHA-256" "$EXPECTED_FP0" "$(head -1 "$tmp/fp.out")"

  # Independent re-derivation: hash the spec preimage ourselves and compare.
  local sha
  if command -v sha256sum >/dev/null 2>&1; then sha() { sha256sum | cut -d' ' -f1; }
  else sha() { shasum -a 256 | cut -d' ' -f1; }; fi
  local preimage rederived
  preimage="$(jq -rj '.findings[0] | .vulnerability_class + "|" + .file + "|" + (.line|tostring) + "|" + (.description[0:80])' "$INPUT")"
  rederived="$(printf '%s' "$preimage" | sha)"
  assert_eq "fingerprint: spec preimage hashes to the same value" "$EXPECTED_FP0" "$rederived"

  # ---- SARIF severity -> level / security-severity table -----------------
  bash "$XFORM" sarif "$INPUT" > "$tmp/sarif.out"
  # Pull (severity -> level/score) straight from the generated SARIF by joining
  # results back to the input severities by index.
  local pairs
  pairs="$(paste -d'|' \
    <(jq -r '.findings[].severity' "$INPUT") \
    <(jq -r '.runs[0].results[] | "\(.level) \(.properties["security-severity"])"' "$tmp/sarif.out"))"
  assert_eq "sarif: critical -> error/9.0" "critical|error 9.0" "$(echo "$pairs" | sed -n '1p')"
  assert_eq "sarif: high -> error/7.0"     "high|error 7.0"     "$(echo "$pairs" | sed -n '3p')"
  assert_eq "sarif: medium -> warning/5.0" "medium|warning 5.0" "$(echo "$pairs" | sed -n '4p')"
  assert_eq "sarif: info -> note/1.0"      "info|note 1.0"      "$(echo "$pairs" | sed -n '5p')"
  # low is not in input_findings.json; assert it directly via a one-off finding.
  echo '{"findings":[{"severity":"low","file":"a","line":1,"vulnerability_class":"insecure_config","cwe":[],"owasp":[],"description":"d","remediation":"r","confidence":"low"}]}' > "$tmp/low.json"
  assert_eq "sarif: low -> note/3.0" "note 3.0" \
    "$(bash "$XFORM" sarif "$tmp/low.json" | jq -r '.runs[0].results[0] | "\(.level) \(.properties["security-severity"])"')"

  # ---- SARIF golden (driver.version normalized) + driver.version wiring ----
  jq '.runs[0].tool.driver.version="PLUGIN_VERSION"' "$tmp/sarif.out" > "$tmp/sarif.norm.json"
  assert_golden "sarif: document matches golden (version-normalized)" "$GOLDEN_DIR/sarif.golden.json" "$tmp/sarif.norm.json"
  assert_eq "sarif: driver.version tracks plugin.json" \
    "$(jq -r '.version' "$PLUGIN_JSON")" \
    "$(jq -r '.runs[0].tool.driver.version' "$tmp/sarif.out")"
  assert_eq "sarif: spec version stays 2.1.0" "2.1.0" "$(jq -r '.version' "$tmp/sarif.out")"
  # The manifest description is what Claude Code's installed-plugin view renders;
  # keep it a short summary (W2288). jq counts characters, not bytes, and a
  # missing description counts as 0, which fails rather than passing.
  desc_len=$(jq -r '(.description // "") | length' "$PLUGIN_JSON")
  if [ "$desc_len" -gt 0 ] && [ "$desc_len" -le 300 ]; then
    ok "manifest: plugin.json description is 1-300 characters"
  else
    not_ok "manifest: plugin.json description is 1-300 characters" "description length $desc_len (want 1..300)"
  fi

  # ---- dedup --------------------------------------------------------------
  bash "$XFORM" dedup "$INPUT" | jq -S . > "$tmp/dedup.out"
  assert_golden "dedup: output matches golden" "$GOLDEN_DIR/dedup.golden.json" "$tmp/dedup.out"
  assert_eq "dedup: duplicate (file,line,class) collapses to one" "4" \
    "$(jq '.findings | length' "$tmp/dedup.out")"
  echo '{"findings":[{"file":"a","line":1,"vulnerability_class":"x"},{"file":"a","line":2,"vulnerability_class":"x"},{"file":"a","line":1,"vulnerability_class":"x"}]}' > "$tmp/dd.json"
  assert_eq "dedup: differing line stays two" "a:1 a:2" \
    "$(bash "$XFORM" dedup "$tmp/dd.json" | jq -r '[.findings[] | "\(.file):\(.line)"] | join(" ")')"

  # ---- fail-on counting ---------------------------------------------------
  assert_eq "failon: critical counts critical only" "2" "$(bash "$XFORM" failon critical "$INPUT" || true)"
  assert_eq "failon: high counts critical+high"      "3" "$(bash "$XFORM" failon high "$INPUT" || true)"
  assert_eq "failon: medium counts crit+high+medium" "4" "$(bash "$XFORM" failon medium "$INPUT" || true)"
  assert_eq "failon: low counts everything but info"  "4" "$(bash "$XFORM" failon low "$INPUT" || true)"

  # info-only input must trip nothing (count 0, exit 0).
  echo '{"findings":[{"severity":"info","file":"a","line":1,"vulnerability_class":"insecure_config","cwe":[],"owasp":[],"description":"d","remediation":"r","confidence":"low"}]}' > "$tmp/info.json"
  local info_exit
  assert_eq "failon: info-only trips no threshold (count 0)" "0" "$(bash "$XFORM" failon low "$tmp/info.json" || true)"
  if bash "$XFORM" failon low "$tmp/info.json" >/dev/null 2>&1; then info_exit=0; else info_exit=1; fi
  assert_eq "failon: info-only exits 0" "0" "$info_exit"
  # And a tripped threshold exits non-zero.
  if bash "$XFORM" failon critical "$INPUT" >/dev/null 2>&1; then info_exit=0; else info_exit=1; fi
  assert_eq "failon: tripped threshold exits non-zero" "1" "$info_exit"

  # ---- fail-on: considerations verdicts (W2279) ---------------------------
  # exit_of <cmd...> — prints 0 or 1 for the command's success/failure.
  exit_of() { if "$@" >/dev/null 2>&1; then printf '0'; else printf '1'; fi; }
  local v_unm v_mit
  v_unm='{"consideration":"c1","status":"unmitigated","evidence":"a.py:15-16","note":"n"}'
  v_mit='{"consideration":"c2","status":"mitigated","evidence":"c.py:9","note":"n"}'

  echo "{\"findings\":[],\"consideration_verdicts\":[$v_unm]}" > "$tmp/v_nofind.json"
  assert_eq "failon: unmitigated verdict with zero findings counts 1" "1" "$(bash "$XFORM" failon low "$tmp/v_nofind.json" 1 || true)"
  assert_eq "failon: unmitigated verdict with zero findings exits 1" "1" "$(exit_of bash "$XFORM" failon low "$tmp/v_nofind.json" 1)"

  echo "{\"findings\":[{\"severity\":\"low\",\"file\":\"a.py\",\"line\":16,\"vulnerability_class\":\"x\",\"description\":\"d\"}],\"consideration_verdicts\":[$v_unm]}" > "$tmp/v_low.json"
  assert_eq "failon: unmitigated verdict backed by a low finding trips --fail-on high" "1" "$(exit_of bash "$XFORM" failon high "$tmp/v_low.json" 1)"
  assert_eq "failon: unmitigated verdict trips --fail-on critical too" "1" "$(exit_of bash "$XFORM" failon critical "$tmp/v_low.json")"

  echo "{\"findings\":[{\"severity\":\"high\",\"file\":\"c.py\",\"line\":9,\"vulnerability_class\":\"z\",\"description\":\"f\"}],\"consideration_verdicts\":[$v_mit]}" > "$tmp/v_mit.json"
  assert_eq "failon: all mitigated + high finding passes --fail-on critical" "0" "$(bash "$XFORM" failon critical "$tmp/v_mit.json" 1 || true)"
  assert_eq "failon: all mitigated + high finding exits 0 under --fail-on critical" "0" "$(exit_of bash "$XFORM" failon critical "$tmp/v_mit.json" 1)"
  assert_eq "failon: all mitigated + high finding trips --fail-on high" "1" "$(bash "$XFORM" failon high "$tmp/v_mit.json" 1 || true)"

  echo '{"findings":[{"severity":"low","file":"a.py","line":16,"vulnerability_class":"x","description":"d"}],"consideration_verdicts":[{"consideration":"c","status":"partial","evidence":"a.py:16","note":"n"}]}' > "$tmp/v_part.json"
  assert_eq "failon: backed partial is gated by its finding's severity" "0" "$(bash "$XFORM" failon high "$tmp/v_part.json" 1 || true)"
  echo '{"findings":[{"severity":"low","file":"a.py","line":16,"vulnerability_class":"x","description":"d"}],"consideration_verdicts":[{"consideration":"c","status":"partial","evidence":"see note","note":"n"}]}' > "$tmp/v_part_unbacked.json"
  assert_eq "failon: partial that no finding backs fails closed" "1" "$(bash "$XFORM" failon high "$tmp/v_part_unbacked.json" 1 || true)"

  # W2282: a partial the considerations-mode tool budget left unverified carries
  # a `budget reached:` note and evidence with no file:line, and no finding backs
  # it — so it trips even the loosest threshold, with no findings or with an
  # unrelated info finding beside it.
  echo '{"findings":[],"consideration_verdicts":[{"consideration":"c","status":"partial","evidence":"not verified within the tool budget","note":"budget reached: the session store config was not read"}]}' > "$tmp/v_budget.json"
  assert_eq "failon: a budget-reached partial with no findings trips --fail-on critical" "1" "$(exit_of bash "$XFORM" failon critical "$tmp/v_budget.json" 1)"
  echo '{"findings":[{"severity":"info","file":"a.py","line":16,"vulnerability_class":"x","description":"d"}],"consideration_verdicts":[{"consideration":"c","status":"partial","evidence":"not verified within the tool budget","note":"budget reached: the caller of a.py was not read"}]}' > "$tmp/v_budget_info.json"
  assert_eq "failon: an info finding beside a budget-reached partial does not back it" "1" "$(bash "$XFORM" failon critical "$tmp/v_budget_info.json" 1 || true)"

  echo '{"findings":[]}' > "$tmp/v_missing.json"
  assert_eq "failon: missing verdicts in considerations mode fail closed" "1" "$(bash "$XFORM" failon critical "$tmp/v_missing.json" 1 || true)"
  echo '{"findings":[],"consideration_verdicts":[]}' > "$tmp/v_short.json"
  assert_eq "failon: short verdicts array fails closed" "1" "$(bash "$XFORM" failon critical "$tmp/v_short.json" 1 || true)"
  echo '{"findings":[],"consideration_verdicts":[{"consideration":"c","status":"not_applicable","evidence":"x","note":"n"}]}' > "$tmp/v_badstatus.json"
  assert_eq "failon: status outside the enum fails closed" "1" "$(bash "$XFORM" failon critical "$tmp/v_badstatus.json" 1 || true)"
  assert_eq "failon: legacy document without n is unchanged by the verdict rule" "2" "$(bash "$XFORM" failon critical "$INPUT" || true)"

  # Empty considerations: the command refuses an empty list (exit 2, Step 1), so
  # an n_considerations below 1 is a usage error here too, never a passing gate.
  local n0_rc
  set +e; bash "$XFORM" failon critical "$tmp/v_nofind.json" 0 >/dev/null 2>&1; n0_rc=$?; set -e
  assert_eq "failon: an empty considerations count is a usage error (exit 2)" "2" "$n0_rc"
  set +e; bash "$XFORM" suppress "$tmp/v_nofind.json" "$tmp/v_nofind.json" 0 >/dev/null 2>&1; n0_rc=$?; set -e
  assert_eq "suppress: an empty considerations count is a usage error (exit 2)" "2" "$n0_rc"

  # ---- baseline suppression keeps backing findings (W2279) ---------------
  # A: low a.py:16 backs the unmitigated verdict (evidence a.py:15-16)
  # B: medium b.py:3 backs nothing
  # C: high c.py:9 is named only by a mitigated verdict, which protects nothing
  local finds
  finds='[{"severity":"low","file":"a.py","line":16,"vulnerability_class":"x","description":"d"},{"severity":"medium","file":"b.py","line":3,"vulnerability_class":"y","description":"e"},{"severity":"high","file":"c.py","line":9,"vulnerability_class":"z","description":"f"}]'
  echo "{\"findings\":$finds,\"summary\":{\"files_reviewed\":3},\"consideration_verdicts\":[$v_unm,$v_mit]}" > "$tmp/s_doc.json"
  bash "$XFORM" fingerprint "$tmp/s_doc.json" > "$tmp/s_fp.txt"
  jq -R . "$tmp/s_fp.txt" > "$tmp/s_fp.lines"
  jq -s '{schema_version:1,generated_at:"2026-01-01T00:00:00Z",acknowledged:map({fingerprint:.})}' "$tmp/s_fp.lines" > "$tmp/s_base.json"
  bash "$XFORM" suppress "$tmp/s_base.json" "$tmp/s_doc.json" 2 > "$tmp/s_out.json"
  assert_eq "suppress: a finding that backs a verdict is never suppressed" "a.py:16" \
    "$(jq -r '[.findings[] | "\(.file):\(.line)"] | join(" ")' "$tmp/s_out.json")"
  assert_eq "suppress: non-backing and mitigated-only findings are still suppressed" "2" \
    "$(jq -r '.summary.suppressed_count' "$tmp/s_out.json")"
  assert_eq "suppress: severity counts recomputed after suppression" "0 0 0 1 0" \
    "$(jq -r '.summary.findings_by_severity | "\(.critical) \(.high) \(.medium) \(.low) \(.info)"' "$tmp/s_out.json")"

  echo "{\"findings\":$finds,\"consideration_verdicts\":[{\"consideration\":\"c1\",\"status\":\"unmitigated\",\"evidence\":\"see note\",\"note\":\"n\"}]}" > "$tmp/s_unres.json"
  assert_eq "suppress: an open verdict nothing backs protects every finding" "3 0" \
    "$(bash "$XFORM" suppress "$tmp/s_base.json" "$tmp/s_unres.json" 1 | jq -r '"\(.findings | length) \(.summary.suppressed_count)"')"
  echo "{\"findings\":$finds}" > "$tmp/s_legacy.json"
  assert_eq "suppress: without considerations every acknowledged finding is dropped" "0 3" \
    "$(bash "$XFORM" suppress "$tmp/s_base.json" "$tmp/s_legacy.json" | jq -r '"\(.findings | length) \(.summary.suppressed_count)"')"
  assert_eq "suppress: missing verdicts in considerations mode protect every finding" "3 0" \
    "$(bash "$XFORM" suppress "$tmp/s_base.json" "$tmp/s_legacy.json" 1 | jq -r '"\(.findings | length) \(.summary.suppressed_count)"')"
  echo '{"schema_version":2,"acknowledged":[]}' > "$tmp/s_bad_base.json"
  assert_eq "suppress: malformed baseline leaves the document unchanged" "3 null" \
    "$(bash "$XFORM" suppress "$tmp/s_bad_base.json" "$tmp/s_legacy.json" 2>/dev/null | jq -r '"\(.findings | length) \(.summary.suppressed_count)"')"

  # ---- corruption self-test ----------------------------------------------
  # A deliberately corrupted golden MUST be detected (assert_golden returns
  # non-zero / the diff is non-empty). This proves the runner actually fails on
  # mismatch rather than rubber-stamping.
  cp "$GOLDEN_DIR/fingerprint.golden" "$tmp/corrupt.golden"
  printf 'deadbeef\n' >> "$tmp/corrupt.golden"
  if diff -u "$tmp/corrupt.golden" "$tmp/fp.out" >/dev/null 2>&1; then
    not_ok "corruption self-test: corrupted golden is detected" "diff did not flag the corruption"
  else
    ok "corruption self-test: corrupted golden is detected"
  fi

  printf '1..%d\n' "$N"
  if [ "$FAILS" -gt 0 ]; then
    printf '# %d/%d checks failed\n' "$FAILS" "$N"
    exit 1
  fi
  printf '# all %d checks passed\n' "$N"
  exit 0
}

main "$@"
