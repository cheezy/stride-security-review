# SARIF schema reference

The slash command's `--sarif` flag emits a [SARIF v2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html) document.

The canonical schema lives at:

- **OASIS:** <https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json>
- **JSON Schema Store mirror:** <https://json.schemastore.org/sarif-2.1.0.json>

We do NOT ship a vendored copy of the schema in this repo to avoid drift against the published spec. Consumers that want to validate the slash command's output locally can fetch it once:

```bash
curl -sSLo sarif-2.1.0.schema.json \
  https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json

claude -p "/stride-security-review:security-review --sarif" \
  | ajv validate -s sarif-2.1.0.schema.json -d -
```

(`ajv` is `npm install -g ajv-cli`; any JSON Schema validator works.)

## Field mapping reference

The agent's native finding schema and the SARIF v2.1.0 result shape don't line up 1:1. See `commands/security-review.md` "SARIF v2.1.0 mapping" subsection for the full field-by-field transform. A summary:

| Finding field | SARIF field |
|---|---|
| `vulnerability_class` | `results[].ruleId` and `runs[0].tool.driver.rules[].id` |
| `severity` | `results[].level` (error/warning/note) and `results[].properties.security-severity` (numeric) |
| `file` | `results[].locations[0].physicalLocation.artifactLocation.uri` |
| `line` | `results[].locations[0].physicalLocation.region.startLine` |
| `description` | `results[].message.text` |
| `remediation` | `results[].fixes[0].description.text` |
| `cwe[]` ∪ `owasp[]` ∪ `confidence` | `results[].properties.tags[]` |
| `patch` (when `--patches`) | `results[].fixes[0].artifactChanges[0].replacements[0]` |
| `fingerprint` (Step 4.6 algorithm) | `results[].partialFingerprints["stride/v1"]` |
| `maestro_layer` (when `--maestro`) | appended to `results[].properties.tags[]` as `maestro:<layer-id>` |

`summary.files_reviewed`, `summary.files_skipped`, and `summary.findings_by_severity` do NOT round-trip into SARIF — SARIF has no per-run summary slot for those. Get them via a separate `--json` invocation.
