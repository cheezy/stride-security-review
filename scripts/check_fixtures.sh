#!/usr/bin/env bash
#
# check_fixtures.sh — fast parity guard between test/fixtures/ and EXPECTED.md.
#
# The eval suite assumes every fixture file has exactly one EXPECTED.md row and
# every EXPECTED.md row names a fixture that exists on disk. That parity is
# maintained by hand, so it silently breaks the moment someone adds a fixture
# without a row (or deletes a fixture but leaves its row). This script fails
# fast and cheap when the two sets diverge — no API key, no Claude CLI, just a
# set comparison — so CI catches the drift before spending money on the eval.
#
# Exit 0 when the fixture files and the EXPECTED.md rows are in exact parity;
# exit 1 (listing the offenders) otherwise; exit 2 on a setup error.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
FIX_DIR="$ROOT_DIR/test/fixtures"
EXPECTED="$FIX_DIR/EXPECTED.md"

[ -d "$FIX_DIR" ] || { printf 'error: fixtures dir not found at %s\n' "$FIX_DIR" >&2; exit 2; }
[ -f "$EXPECTED" ] || { printf 'error: EXPECTED.md not found at %s\n' "$EXPECTED" >&2; exit 2; }

# Fixture files on disk, relative to test/fixtures/, excluding EXPECTED.md itself.
# Covers nested subdirectories (e.g. ci_cd/) since the paths in EXPECTED.md rows
# are likewise relative to test/fixtures/.
disk="$(cd "$FIX_DIR" && find . -type f ! -name 'EXPECTED.md' | sed 's|^\./||' | sort)"

# Fixture paths referenced by EXPECTED.md checkbox rows: the FIRST backtick-fenced
# token of each `- [ ] \`path\` → ...` row (same extraction run_eval.sh uses).
rows="$(awk '
  /^- \[[ x]\] `[^`]+`/ {
    match($0, /`[^`]+`/)
    print substr($0, RSTART + 1, RLENGTH - 2)
  }
' "$EXPECTED" | sort -u)"

# Set differences (comm needs sorted input, which both are).
missing_rows="$(comm -23 <(printf '%s\n' "$disk") <(printf '%s\n' "$rows") | sed '/^$/d')"
missing_files="$(comm -13 <(printf '%s\n' "$disk") <(printf '%s\n' "$rows") | sed '/^$/d')"

fail=0
if [ -n "$missing_rows" ]; then
  printf 'Fixture files with no EXPECTED.md row:\n' >&2
  printf '%s\n' "$missing_rows" | sed 's/^/  - /' >&2
  fail=1
fi
if [ -n "$missing_files" ]; then
  printf 'EXPECTED.md rows naming a fixture that does not exist:\n' >&2
  printf '%s\n' "$missing_files" | sed 's/^/  - /' >&2
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  printf 'FAIL: test/fixtures/ and EXPECTED.md are out of sync.\n' >&2
  exit 1
fi

count="$(printf '%s\n' "$disk" | sed '/^$/d' | wc -l | tr -d ' ')"
printf 'OK: %s fixtures, each with exactly one matching EXPECTED.md row.\n' "$count"
exit 0
