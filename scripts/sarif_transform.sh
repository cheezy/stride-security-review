#!/usr/bin/env bash
#
# sarif_transform.sh — reference implementation of the deterministic transforms
# specified in commands/security-review.md.
#
# The slash command's behavior is specified in prose for an LLM to execute, so
# the deterministic, bug-prone transforms have no executable source of truth.
# This script is that reference implementation: it performs each transform
# EXACTLY as the spec defines it, so run_transform_tests.sh can lock the
# behavior with golden files and explicit value assertions. If this script and
# the prose spec ever disagree, the SPEC is authoritative and this script must
# be corrected to match it (never the reverse).
#
# All transforms are pure: no network, no Claude CLI, no secrets. Only `jq` and
# a SHA-256 utility (`sha256sum` or `shasum -a 256`) are required.
#
# Usage:
#   sarif_transform.sh fingerprint <findings.json>   # one lowercase hex hash per finding, in order
#   sarif_transform.sh dedup       <findings.json>   # order-stable dedup by (file,line,vulnerability_class)
#   sarif_transform.sh sarif       <findings.json>   # SARIF v2.1.0 document
#   sarif_transform.sh failon <severity> <findings.json> [<n_considerations>]
#                                                    # prints N_GATE; exit 1 if >0, else 0
#   sarif_transform.sh suppress <baseline.json> <findings.json> [<n_considerations>]
#                                                    # Step 4.6 document with acknowledged,
#                                                    # non-backing findings dropped
#
# Input shape is the agent's native findings document: {"findings":[ {finding}, ... ], ...}.
#
# Spec references (commands/security-review.md):
#   - Step 4.6  fingerprint = SHA256(vulnerability_class|file|line|first_80_chars_of_description), lowercase hex
#   - Step 4b   dedup merge rule: order-stable, first-occurrence-wins, key (file,line,vulnerability_class)
#   - Step 5    SARIF v2.1.0 mapping (severity->level/security-severity, tags, partialFingerprints)
#   - Step 4    a finding that backs a verdict: file equal and line inside a path:line or
#               path:start-end reference in an open (partial/unmitigated) verdict's evidence;
#               an open verdict nothing backs, or missing/short/malformed verdicts, protect all
#   - Step 4.6  baseline suppression never drops a finding that backs a verdict
#   - Step 6    fail-on threshold: critical>high>medium>low>info; info never trips a threshold;
#               an unmitigated verdict, an unbacked partial verdict and missing or malformed
#               verdicts each trip the gate at every threshold (fail closed)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN_JSON="${PLUGIN_JSON:-$SCRIPT_DIR/../.claude-plugin/plugin.json}"

die() { printf 'error: %s\n' "$*" >&2; exit 2; }

require_cmd() {
  command -v jq >/dev/null 2>&1 || die "jq not found on PATH"
}

# sha256_hex — read bytes on stdin, print the lowercase hex SHA-256 digest only.
# Portable across Linux (sha256sum) and macOS (shasum -a 256).
sha256_hex() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | cut -d' ' -f1
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 | cut -d' ' -f1
  else
    die "no SHA-256 utility found (need sha256sum or shasum)"
  fi
}

# plugin_version — the driver.version SARIF reports; tracks .claude-plugin/plugin.json (see W1277).
plugin_version() {
  if [ -f "$PLUGIN_JSON" ]; then
    jq -r '.version' "$PLUGIN_JSON"
  else
    printf 'unknown'
  fi
}

# finger_string <findings.json> <index>
# Emits the exact 4-part fingerprint preimage for finding [index], no trailing newline:
#   vulnerability_class|file|line|first_80_chars_of_description
finger_string() {
  jq -rj --argjson i "$2" '
    .findings[$i]
    | ((.vulnerability_class // "") | tostring) + "|"
      + ((.file // "") | tostring) + "|"
      + ((.line // "") | tostring) + "|"
      + (((.description // "") | tostring)[0:80])
  ' "$1"
}

# fingerprint_one <findings.json> <index> — lowercase hex SHA-256 of the preimage.
fingerprint_one() {
  finger_string "$1" "$2" | sha256_hex
}

cmd_fingerprint() {
  local input="$1"
  local n
  n=$(jq '.findings | length' "$input")
  local i
  for ((i = 0; i < n; i++)); do
    fingerprint_one "$input" "$i"
  done
}

cmd_dedup() {
  # Order-stable, first-occurrence-wins, keyed on (file,line,vulnerability_class).
  # reduce preserves input order; `unique_by` would re-sort, so it is NOT used.
  jq '
    {findings:
      (reduce (.findings // [])[] as $f ({seen: {}, out: []};
        ( (($f.file // "") | tostring) + "|"
          + (($f.line // "") | tostring) + "|"
          + (($f.vulnerability_class // "") | tostring) ) as $k
        | if .seen[$k] then .
          else .seen[$k] = true | .out += [$f] end
      ) | .out)
    }
  ' "$1"
}

# rank <severity> — numeric ordering for fail-on. info=0 so it never meets any
# valid threshold (lowest valid threshold is `low`=1).
rank() {
  case "$1" in
    critical) printf '4' ;;
    high)     printf '3' ;;
    medium)   printf '2' ;;
    low)      printf '1' ;;
    info)     printf '0' ;;
    *)        die "invalid severity: $1" ;;
  esac
}

# VERDICT_JQ — the Step 4 "a finding that backs a verdict" definition, shared by
# failon and suppress. $n is the resolved consideration count, or null when the
# caller did not say (then only the verdicts actually present are checked).
#   refs($v)       every [path, start, end] reference in the verdict's evidence
#   backs($f; $v)  the finding's file equals a reference path and its line is in range
#   verdicts       the consideration_verdicts array, or [] when it is not an array
#   open           the partial and unmitigated entries
#   bad_status     entries that are not objects or whose status is outside the enum
#   malformed      1 when the array is missing/short/not an array (with $n), or
#                  present but not an array (without $n); else 0
#   unbacked($v)   true when no finding backs the open verdict $v
VERDICT_JQ='
  def refs($v):
    [ (($v.evidence // "") | tostring)
      | scan("([^\\s,;:`()]+):([0-9]+)(?:-([0-9]+))?")
      | [ .[0], (.[1] | tonumber), ((.[2] // .[1]) | tonumber) ] ];
  def backs($f; $v):
    ($f.line | type) == "number"
    and any(refs($v)[]; .[0] == (($f.file // "") | tostring)
                        and $f.line >= .[1] and $f.line <= .[2]);
  def verdicts:
    if (.consideration_verdicts | type) == "array" then .consideration_verdicts else [] end;
  def vstatus: if type == "object" then .status else null end;
  def open: [ verdicts[] | select(vstatus == "partial" or vstatus == "unmitigated") ];
  def bad_status:
    [ verdicts[] | select((vstatus == "mitigated" or vstatus == "partial"
                           or vstatus == "unmitigated") | not) ];
  def malformed:
    if $n != null then
      (if (.consideration_verdicts | type) != "array"
          or (.consideration_verdicts | length) != $n then 1 else 0 end)
    else
      (if has("consideration_verdicts")
          and (.consideration_verdicts | type) != "array" then 1 else 0 end)
    end;
  def unbacked($v): . as $doc | ([ ($doc.findings // [])[] | select(backs(.; $v)) ] | length) == 0;
'

# check_n <value> — the optional n_considerations argument must be an integer >= 1.
check_n() {
  case "$1" in
    ''|*[!0-9]*) die "n_considerations must be an integer of at least 1 (got: $1)" ;;
  esac
  [ "$1" -ge 1 ] || die "n_considerations must be an integer of at least 1 (got: $1)"
}

cmd_failon() {
  local threshold="$1" input="$2" n="${3:-null}"
  case "$threshold" in
    critical|high|medium|low) ;;
    *) die "--fail-on requires one of: critical, high, medium, low (got: $threshold)" ;;
  esac
  [ "$n" = null ] || check_n "$n"
  local tr
  tr=$(rank "$threshold")
  local count
  # N_GATE = findings at/above the threshold + verdicts that trip the gate. With no
  # consideration_verdicts key and no n the verdict terms are all 0, so the count
  # is exactly the severity-only count of earlier releases.
  count=$(jq --argjson tr "$tr" --argjson n "$n" "$VERDICT_JQ"'
    . as $doc
    | ([ ($doc.findings // [])[]
         | .severity
         | (if . == "critical" then 4 elif . == "high" then 3 elif . == "medium" then 2
             elif . == "low" then 1 else 0 end)
         | select(. >= $tr)
       ] | length)
      + ([ verdicts[] | select(vstatus == "unmitigated") ] | length)
      + ([ verdicts[] | select(vstatus == "partial") | select(. as $v | $doc | unbacked($v)) ] | length)
      + (bad_status | length)
      + malformed
  ' "$input")
  printf '%s\n' "$count"
  [ "$count" -gt 0 ] && return 1
  return 0
}

cmd_suppress() {
  local baseline="$1" input="$2" n="${3:-null}"
  [ "$n" = null ] || check_n "$n"
  # Step 4.6 step 1: a malformed baseline means no suppression at all (and no
  # suppressed_count, since no baseline is in play).
  if ! jq -e '(.schema_version == 1) and ((.acknowledged | type) == "array")' "$baseline" >/dev/null 2>&1; then
    printf 'Baseline file malformed — proceeding without suppression\n' >&2
    jq . "$input"
    return 0
  fi
  local ack fps
  ack=$(jq '[ .acknowledged[] | .fingerprint? // empty | tostring ]' "$baseline")
  fps=$(cmd_fingerprint "$input" | jq -R . | jq -s .)
  jq --argjson ack "$ack" --argjson fps "$fps" --argjson n "$n" "$VERDICT_JQ"'
    . as $doc
    | ( (open | any(.[]; . as $v | $doc | unbacked($v)))
        or ((bad_status | length) > 0)
        or (malformed > 0) ) as $protect_all
    | open as $open
    | [ ($doc.findings // []) | to_entries[]
        | .key as $i | .value as $f
        | { f: $f,
            drop: (($ack | index($fps[$i])) != null
                   and ($protect_all | not)
                   and (any($open[]; backs($f; .)) | not)) } ] as $marked
    | [ $marked[] | select(.drop | not) | .f ] as $kept
    | .findings = $kept
    | .summary = ((.summary // {})
        + { suppressed_count: ([ $marked[] | select(.drop) ] | length),
            findings_by_severity: (
              reduce ("critical", "high", "medium", "low", "info") as $s ({};
                .[$s] = ([ $kept[] | select(.severity == $s) ] | length))) })
  ' "$input"
}

cmd_sarif() {
  local input="$1"
  local version
  version=$(plugin_version)

  # Compute fingerprints in bash (jq has no SHA-256) and hand them to jq by index.
  local n fps
  n=$(jq '.findings | length' "$input")
  fps='[]'
  local i fp
  for ((i = 0; i < n; i++)); do
    fp=$(fingerprint_one "$input" "$i")
    fps=$(printf '%s' "$fps" | jq --arg fp "$fp" '. + [$fp]')
  done

  jq -S --argjson fps "$fps" --arg drv "$version" '
    def level($s):
      if   $s == "critical" then "error"
      elif $s == "high"     then "error"
      elif $s == "medium"   then "warning"
      else "note" end;
    def sevscore($s):
      if   $s == "critical" then "9.0"
      elif $s == "high"     then "7.0"
      elif $s == "medium"   then "5.0"
      elif $s == "low"      then "3.0"
      else "1.0" end;
    (.findings // []) as $f
    | {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
          {
            "tool": {
              "driver": {
                "name": "stride-security-review",
                "version": $drv,
                "informationUri": "https://github.com/cheezy/stride-security-review",
                "rules": (
                  [ $f[].vulnerability_class ] | unique
                  | map({
                      "id": .,
                      "name": .,
                      "shortDescription": {"text": .},
                      "helpUri": "https://github.com/cheezy/stride-security-review#what-it-catches"
                    })
                )
              }
            },
            "results": (
              [ $f | to_entries[]
                | .key as $i | .value as $x
                | {
                    "ruleId": $x.vulnerability_class,
                    "level": level($x.severity),
                    "message": {"text": ($x.description // "")},
                    "locations": [
                      {
                        "physicalLocation": {
                          "artifactLocation": {"uri": ($x.file // "")},
                          "region": {"startLine": ($x.line // 0)}
                        }
                      }
                    ],
                    "properties": {
                      "tags": (((($x.cwe // []) + ($x.owasp // [])) + ["confidence:" + ($x.confidence // "")])),
                      "security-severity": sevscore($x.severity)
                    },
                    "fixes": [ {"description": {"text": ($x.remediation // "")}} ],
                    "partialFingerprints": {"stride/v1": $fps[$i]}
                  }
              ]
            )
          }
        ]
      }
  ' "$input"
}

main() {
  require_cmd
  [ $# -ge 1 ] || die "usage: sarif_transform.sh <fingerprint|dedup|sarif|failon|suppress> ..."
  local mode="$1"; shift
  case "$mode" in
    fingerprint) [ $# -eq 1 ] || die "fingerprint <findings.json>"; cmd_fingerprint "$1" ;;
    dedup)       [ $# -eq 1 ] || die "dedup <findings.json>";       cmd_dedup "$1" ;;
    sarif)       [ $# -eq 1 ] || die "sarif <findings.json>";       cmd_sarif "$1" ;;
    failon)      { [ $# -eq 2 ] || [ $# -eq 3 ]; } || die "failon <severity> <findings.json> [<n_considerations>]"
                 cmd_failon "$@" ;;
    suppress)    { [ $# -eq 2 ] || [ $# -eq 3 ]; } || die "suppress <baseline.json> <findings.json> [<n_considerations>]"
                 cmd_suppress "$@" ;;
    *)           die "unknown mode: $mode" ;;
  esac
}

main "$@"
