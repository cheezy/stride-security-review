#!/usr/bin/env python3
"""W2287: measure deep security-review dispatches from Claude Code transcripts.

Compares `stride-security-review:security-reviewer` dispatches across three
transcript windows, so that every figure has a named comparator:

  pre-g452   dispatches that started before 2026-10-03 -- the surviving part
             of the 2026-10-02 baseline (security-review 2.5.2, stride <= 1.81)
  2.6.0-era  2026-10-03 up to the 2.7.0 install -- security-review 2.6.0 with
             stride 1.82.0-1.85.x (W2280, W2281, W2284 already in effect)
  2.7.0      from the 2.7.0 install (2026-10-12T19:10Z) up to --until --
             security-review 2.7.0 with stride 1.86.0

Run the pre-g452 window first and compare it with the published baseline
(`docs/porting-g452-g454.md`, "The baseline"): that is the check that this
script measures what the baseline measured before it is trusted on new data.

Counting rules (stride/docs/token-baseline.md, "Counting rules"):

  * A dispatch is one `subagents/agent-*.meta.json` whose `agentType` is the
    security reviewer. Its transcript is the sibling `.jsonl`, summed in full.
  * A request is one assistant `message.id`. Usage is deduplicated by message
    id; the input-side fields are taken from the LAST record of a message
    (identical across its records), so a streamed response counts once.
  * Input-side tokens = input_tokens + cache_creation_input_tokens
    + cache_read_input_tokens. The `usage.cache_creation` object is ignored.
    Output tokens are not reported: a record's output_tokens can be the
    stream-start value, so no output-token claim is made from them.
  * Wall clock is the `<duration_ms>` of the dispatch's task notification,
    matched by the meta's `toolUseId`; the transcript's first-to-last record
    span is the fallback when no notification survives.
  * Returned bytes are what reached the dispatcher: the SubagentHandback
    `message` when the dispatch handed back, else the text of its final
    assistant message. The notification `<result>` is NOT used -- after a
    handback it is a fixed pointer of about 150 bytes.
  * A re-dispatch is every dispatch after the first for the same task
    identifier (from the meta `description`) within the window.
  * First-time parse is a PROXY: the dispatch's result document -- the last
    text it produced that names `consideration_verdicts` -- yields a JSON
    object (a ```json fence, a heredoc body, or the outermost braces). The
    baseline's own definition was not recorded.
  * Verdicts are the `status` values of `consideration_verdicts[]` in that
    result document; any value outside mitigated/partial/unmitigated is
    counted as `out-of-enum`.
  * Findings are the `severity` values of `findings[]` in that result
    document when it parses; any value outside critical/high/medium/low/info
    is counted as `out-of-enum`, so no transcript text becomes an output key.
  * Considerations per dispatch is the number of verdicts it returned. An
    all-mitigated dispatch returned at least one verdict and every one of
    them is `mitigated`.
  * Peak context is the largest input-side total of any one request.
  * Fixed-context share is, summed over dispatches, the first request's
    input-side total times the number of requests, divided by the total
    input-side tokens: the share spent re-sending the starting context.
  * Tool calls are unique tool_use blocks by id; Bash and Read are subsets.
  * A test-suite run is a Bash command that names `mix test`, `pytest`,
    `npm test`, `npm run test`, `npx jest`, `npx vitest`, `go test`,
    `cargo test` or `rspec`.
  * A working-tree edit is an Edit, Write, MultiEdit or NotebookEdit call
    whose path is outside a temporary directory and outside `.stride/`. Edits
    made through Bash are not seen.
  * Dispatch-prompt bytes are the UTF-8 size of the `prompt` input of the
    Agent tool_use that launched the dispatch, found by its id in any
    transcript.

Handling: transcripts carry full conversation text, including tool output.
This script prints aggregates and counts only -- never transcript text.

Usage:
  python3 w2287-deep-review.py --self-test
  python3 w2287-deep-review.py [--until ISO8601] [--project NAME] [--json]
"""
import argparse
import glob
import json
import os
import re
import statistics
import sys
from datetime import datetime, timezone

PROJECTS = os.path.expanduser("~/.claude/projects")
AGENT_TYPE = "stride-security-review:security-reviewer"

WINDOW_STARTS = (
    ("pre-g452", None),
    ("2.6.0-era", "2026-10-03T00:00:00Z"),
    ("2.7.0", "2026-10-12T19:10:00Z"),
)

TASK_RE = re.compile(r"\b([WDG][0-9]+)\b")
VERSION_RE = re.compile(r"stride-security-review/([0-9]+\.[0-9]+\.[0-9]+)/")
NOTIFY_ID_RE = re.compile(r"<tool-use-id>([^<]+)</tool-use-id>")
NOTIFY_DURATION_RE = re.compile(r"<duration_ms>([0-9]+)</duration_ms>")
FENCE_RE = re.compile(r"```json\s*\n(.*?)\n```", re.S)
HEREDOC_RE = re.compile(r"<<-?\s*'?\"?([A-Za-z_]+)'?\"?\n(.*?)\n\1\b", re.S)
STATUS_RE = re.compile(r'"status"\s*:\s*"([A-Za-z_-]+)"')
BUDGET_RE = re.compile(r"budget reached:")
TEST_RUN_RE = re.compile(r"\b(mix test|pytest|npm (run )?test|npx (jest|vitest)|go test|cargo test|rspec)\b")
EDIT_TOOLS = ("Edit", "Write", "MultiEdit", "NotebookEdit")
SCRATCH_PREFIXES = ("/tmp/", "/private/tmp/", "/var/folders/", "/private/var/folders/")

ENUM = ("mitigated", "partial", "unmitigated")
SEVERITIES = ("critical", "high", "medium", "low", "info")


def parse_ts(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def context_of(usage):
    return (usage.get("input_tokens", 0)
            + usage.get("cache_creation_input_tokens", 0)
            + usage.get("cache_read_input_tokens", 0))


def dedupe_usage(records):
    """One usage per message id, the last record's, in first-seen order."""
    seen, order = {}, []
    for record in records:
        if record.get("type") != "assistant":
            continue
        message = record.get("message") or {}
        usage, message_id = message.get("usage"), message.get("id")
        if not usage or not message_id:
            continue
        if message_id not in seen:
            order.append(message_id)
        seen[message_id] = usage
    return [seen[m] for m in order]


def blocks(record, kind):
    if record.get("type") != "assistant":
        return []
    content = (record.get("message") or {}).get("content") or []
    return [c for c in content if isinstance(c, dict) and c.get("type") == kind]


def tool_calls(records):
    """Unique tool_use blocks, by id, in order."""
    seen, out = set(), []
    for record in records:
        for use in blocks(record, "tool_use"):
            if use.get("id") in seen:
                continue
            seen.add(use.get("id"))
            out.append(use)
    return out


def returned_text(records, calls):
    """What the dispatcher received: the handback message, else the final text."""
    handbacks = [c for c in calls if c.get("name") == "SubagentHandback"]
    if handbacks:
        return (handbacks[-1].get("input") or {}).get("message", "") or ""
    last_id, texts = None, []
    for record in records:
        message = record.get("message") or {}
        if record.get("type") != "assistant":
            continue
        pieces = [b.get("text", "") for b in blocks(record, "text")]
        if not pieces:
            continue
        if message.get("id") != last_id:
            last_id, texts = message.get("id"), []
        texts.extend(pieces)
    return "\n".join(texts)


def candidate_texts(records):
    """Every text the dispatch produced, in record order: assistant text
    blocks and the string inputs of its tool calls, each tool call once."""
    out, seen = [], set()
    for record in records:
        if record.get("type") != "assistant":
            continue
        for block in (record.get("message") or {}).get("content") or []:
            if not isinstance(block, dict):
                continue
            if block.get("type") == "text":
                out.append(block.get("text", ""))
            elif block.get("type") == "tool_use" and block.get("id") not in seen:
                seen.add(block.get("id"))
                inp = block.get("input") or {}
                out.extend(inp[k] for k in ("command", "content", "message")
                           if isinstance(inp.get(k), str))
    return out


def result_document(texts):
    hits = [t for t in texts if "consideration_verdicts" in t]
    return hits[-1] if hits else None


def extract_json(text):
    """Return the result object if the document yields one, else None."""
    candidates = [m.group(1) for m in FENCE_RE.finditer(text)]
    candidates += [m.group(2) for m in HEREDOC_RE.finditer(text)]
    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end > start:
        candidates.append(text[start:end + 1])
    for raw in candidates:
        try:
            value = json.loads(raw)
        except ValueError:
            continue
        if isinstance(value, dict) and "consideration_verdicts" in value:
            return value
    return None


def verdicts(document, parsed):
    """Status values of consideration_verdicts[]; regex fallback when unparsed."""
    if parsed is not None:
        items = parsed.get("consideration_verdicts") or []
        return [str(i.get("status")) for i in items if isinstance(i, dict)]
    if document is None:
        return []
    tail = document[document.find("consideration_verdicts"):]
    closing = tail.find("]")
    return STATUS_RE.findall(tail if closing == -1 else tail[:closing])


def load_jsonl(path):
    """Parsed records of one transcript; [] when it vanished since the glob."""
    out = []
    try:
        with open(path, errors="replace") as handle:
            for line in handle:
                try:
                    out.append(json.loads(line))
                except ValueError:
                    continue
    except OSError:
        return []
    return out


def find_dispatches():
    out = []
    for meta_path in glob.glob(os.path.join(PROJECTS, "*", "*", "subagents", "agent-*.meta.json")):
        try:
            with open(meta_path) as handle:
                meta = json.load(handle)
        except (OSError, ValueError):
            continue
        if meta.get("agentType") != AGENT_TYPE:
            continue
        project = meta_path[len(PROJECTS) + 1:].split(os.sep)[0]
        out.append((meta_path[:-len(".meta.json")] + ".jsonl", meta, project))
    return out


def agent_prompt_sizes(line, tool_use_ids):
    """(tool-use id, prompt bytes) for each dispatching Agent call on one line."""
    if '"name":"Agent"' not in line and '"name": "Agent"' not in line:
        return []
    try:
        record = json.loads(line)
    except ValueError:
        return []
    return [(use["id"], len(((use.get("input") or {}).get("prompt") or "").encode("utf-8")))
            for use in blocks(record, "tool_use")
            if use.get("name") == "Agent" and use.get("id") in tool_use_ids]


def notification_durations(line, tool_use_ids):
    """(tool-use id, duration_ms) for each task notification on one line."""
    if "<duration_ms>" not in line or "<tool-use-id>" not in line:
        return []
    out = []
    for chunk in line.split("<task-notification>")[1:]:
        chunk = chunk.replace('\\"', '"')
        ident, dur = NOTIFY_ID_RE.search(chunk), NOTIFY_DURATION_RE.search(chunk)
        if ident and dur and ident.group(1) in tool_use_ids:
            out.append((ident.group(1), int(dur.group(1))))
    return out


def parent_facts(tool_use_ids):
    """Per tool-use id: duration_ms from its task notification, and the byte
    size of the dispatch prompt from the Agent tool_use that launched it."""
    durations, prompts = {}, {}
    paths = glob.glob(os.path.join(PROJECTS, "*", "*.jsonl"))
    paths += glob.glob(os.path.join(PROJECTS, "*", "*", "subagents", "*.jsonl"))
    for path in paths:
        try:
            with open(path, errors="replace") as handle:
                for line in handle:
                    prompts.update(agent_prompt_sizes(line, tool_use_ids))
                    durations.update(notification_durations(line, tool_use_ids))
        except OSError:
            continue
    return durations, prompts


def findings_by_severity(parsed):
    out = {}
    for item in (parsed or {}).get("findings") or []:
        if isinstance(item, dict):
            key = str(item.get("severity", "")).strip().lower()
            key = key if key in SEVERITIES else "out-of-enum"
            out[key] = out.get(key, 0) + 1
    return out


def edits_outside_scratch(calls):
    """True when an Edit/Write-family call targets a path outside a temp dir or .stride/."""
    for use in calls:
        if use.get("name") not in EDIT_TOOLS:
            continue
        path = str((use.get("input") or {}).get("file_path") or (use.get("input") or {}).get("notebook_path") or "")
        if not path.startswith(SCRATCH_PREFIXES) and "/.stride/" not in path:
            return True
    return False


def measure_dispatch(path, meta, project):
    records = load_jsonl(path)
    stamps = [r["timestamp"] for r in records if r.get("timestamp")]
    if not stamps:
        return None
    usages = dedupe_usage(records)
    calls = tool_calls(records)
    returned = returned_text(records, calls)
    document = result_document(candidate_texts(records))
    parsed = extract_json(document) if document else None
    raw = "\n".join(json.dumps(r) for r in records)
    versions = sorted(set(VERSION_RE.findall(raw)))
    task = TASK_RE.search(meta.get("description") or "")
    return {
        "project": project,
        "tool_use_id": meta.get("toolUseId"),
        "task": task.group(1) if task else None,
        "start": min(stamps),
        "span_ms": int((parse_ts(max(stamps)) - parse_ts(min(stamps))).total_seconds() * 1000),
        "requests": len(usages),
        "input_side": sum(context_of(u) for u in usages),
        "peak_context": max((context_of(u) for u in usages), default=0),
        "fixed_context": context_of(usages[0]) * len(usages) if usages else 0,
        "tool_calls": len(calls),
        "bash_calls": sum(1 for c in calls if c.get("name") == "Bash"),
        "read_calls": sum(1 for c in calls if c.get("name") == "Read"),
        "returned_bytes": len(returned.encode("utf-8")),
        "has_result": document is not None,
        "parsed": parsed is not None,
        "verdicts": verdicts(document, parsed),
        "budget_reached": bool(document and BUDGET_RE.search(document)),
        "findings": findings_by_severity(parsed),
        "test_runs": sum(1 for c in calls if c.get("name") == "Bash"
                         and TEST_RUN_RE.search((c.get("input") or {}).get("command") or "")),
        "edited_outside_scratch": edits_outside_scratch(calls),
        "versions": versions,
    }


def window_of(start, until):
    when = parse_ts(start)
    if until and when > parse_ts(until):
        return None
    name = WINDOW_STARTS[0][0]
    for label, bound in WINDOW_STARTS[1:]:
        if when >= parse_ts(bound):
            name = label
    return name


def median(values):
    return statistics.median(values) if values else None


def scaled_median(values, divisor, digits):
    middle = median(values)
    return None if middle is None else round(middle / divisor, digits)


def count_where(rows, predicate):
    return sum(1 for r in rows if predicate(r))


def tally(keys):
    out = {}
    for key in keys:
        out[key] = out.get(key, 0) + 1
    return out


def summarise_cost(rows):
    """Wall clock, tokens, tool calls and bytes for one window."""
    input_side = sum(r["input_side"] for r in rows)
    returned = [r["returned_bytes"] for r in rows]
    return {
        "median_wall_s": scaled_median([r["wall_ms"] for r in rows], 1000, 1),
        "total_wall_h": round(sum(r["wall_ms"] for r in rows) / 3_600_000, 1),
        "wall_from_span": count_where(rows, lambda r: r["wall_source"] == "span"),
        "median_requests": median([r["requests"] for r in rows]),
        "median_input_side": median([r["input_side"] for r in rows]),
        "total_input_side": input_side,
        "fixed_context_share": round(sum(r["fixed_context"] for r in rows) / max(input_side, 1), 3),
        "median_peak_context": median([r["peak_context"] for r in rows]),
        "tool_calls": sum(r["tool_calls"] for r in rows),
        "bash_calls": sum(r["bash_calls"] for r in rows),
        "read_calls": sum(r["read_calls"] for r in rows),
        "median_returned_bytes": median(returned),
        "mean_returned_bytes": round(statistics.mean(returned)) if returned else None,
        "total_returned_bytes": sum(returned),
    }


def summarise_rounds(rows):
    """Tasks, re-dispatches and the first-time-parse proxy for one window."""
    tasks = {(r["project"], r["task"]) for r in rows if r["task"]}
    with_task = count_where(rows, lambda r: r["task"])
    results = [r for r in rows if r["has_result"]]
    return {
        "tasks": len(tasks),
        "re_dispatches": with_task - len(tasks),
        "no_task_id": len(rows) - with_task,
        "with_result_document": len(results),
        "parsed_first_time": count_where(results, lambda r: r["parsed"]),
    }


def summarise_verdicts(rows):
    """Verdict mix, findings and the all-mitigated split for one window."""
    calm = [r for r in rows if r["verdicts"] and all(v == "mitigated" for v in r["verdicts"])]
    findings = {}
    for row in rows:
        for key, count in row["findings"].items():
            findings[key] = findings.get(key, 0) + count
    per_dispatch = [len(r["verdicts"]) for r in rows]
    return {
        "verdict_mix": tally(v if v in ENUM else "out-of-enum" for r in rows for v in r["verdicts"]),
        "mean_verdicts_per_dispatch": round(statistics.mean(per_dispatch), 2) if per_dispatch else None,
        "all_mitigated_dispatches": len(calm),
        "all_mitigated_median_wall_s": scaled_median([r["wall_ms"] for r in calm], 1000, 1),
        "all_mitigated_median_input_side": median([r["input_side"] for r in calm]),
        "budget_reached": count_where(rows, lambda r: r["budget_reached"]),
        "findings": findings,
    }


def summarise(rows):
    summary = {
        "dispatches": len(rows),
        "projects": tally(r["project"] for r in rows),
        "first": min((r["start"] for r in rows), default=None),
        "last": max((r["start"] for r in rows), default=None),
    }
    summary.update(summarise_cost(rows))
    summary.update(summarise_rounds(rows))
    summary.update(summarise_verdicts(rows))
    summary.update({
        "test_runs": sum(r["test_runs"] for r in rows),
        "edited_outside_scratch": count_where(rows, lambda r: r["edited_outside_scratch"]),
        "prompt_bytes_total": sum(r.get("prompt_bytes") or 0 for r in rows),
        "prompts_found": count_where(rows, lambda r: r.get("prompt_bytes") is not None),
        "version_paths": tally(v for r in rows for v in r["versions"]),
    })
    return summary


def measure(until, project=None):
    found = [d for d in find_dispatches() if project is None or project in d[2]]
    durations, prompts = parent_facts({m.get("toolUseId") for _, m, _ in found})
    windows = {label: [] for label, _ in WINDOW_STARTS}
    for path, meta, project_dir in found:
        row = measure_dispatch(path, meta, project_dir)
        if row is None:
            continue
        label = window_of(row["start"], until)
        if label is None:
            continue
        row["prompt_bytes"] = prompts.get(row["tool_use_id"])
        if row["tool_use_id"] in durations:
            row["wall_ms"], row["wall_source"] = durations[row["tool_use_id"]], "notification"
        else:
            row["wall_ms"], row["wall_source"] = row["span_ms"], "span"
        windows[label].append(row)
    return {label: summarise(rows) for label, rows in windows.items()}


def print_report(summary):
    labels = list(summary)
    keys = list(summary[labels[0]])
    print(f"{'metric':<24}" + "".join(f"{label:>22}" for label in labels))
    for key in keys:
        cells = []
        for label in labels:
            value = summary[label][key]
            cells.append(json.dumps(value, sort_keys=True) if isinstance(value, dict) else str(value))
        if any(len(c) > 21 for c in cells):
            print(f"{key}:")
            for label, cell in zip(labels, cells):
                print(f"  {label:<10} {cell}")
        else:
            print(f"{key:<24}" + "".join(f"{c:>22}" for c in cells))


def self_test():
    def assistant(message_id, usage, content):
        return {"type": "assistant", "timestamp": "2026-10-13T00:00:00Z",
                "message": {"id": message_id, "usage": usage, "content": content}}

    usage = {"input_tokens": 1, "cache_creation_input_tokens": 10,
             "cache_read_input_tokens": 100, "output_tokens": 5}
    usage_late = dict(usage, output_tokens=50)
    result = {"consideration_verdicts": [{"status": "mitigated"}, {"status": "partial"},
                                         {"status": "unmitigated"}, {"status": "maybe"}]}
    command = ("T=$(mktemp x.XXXX) && cat > \"$T\" <<'EOF'\n"
               + json.dumps(result) + "\nEOF\nmv \"$T\" \"${DEST}\"")
    records = [
        assistant("m1", usage, [{"type": "tool_use", "id": "t1", "name": "Bash",
                                 "input": {"command": command}}]),
        assistant("m1", usage_late, [{"type": "text", "text": "same message, second block"}]),
        assistant("m2", usage, [{"type": "tool_use", "id": "t2", "name": "SubagentHandback",
                                 "input": {"message": "ten lines"}}]),
        {"type": "user", "message": {"content": "tool result"}},
    ]
    usages = dedupe_usage(records)
    assert len(usages) == 2, usages
    assert usages[0]["output_tokens"] == 50, "last record of a message wins"
    assert sum(context_of(u) for u in usages) == 222
    calls = tool_calls(records + records[:1])
    assert len(calls) == 2, "tool_use deduplicated by id"
    assert returned_text(records, calls) == "ten lines", "handback message is what was returned"
    plain = [assistant("m3", usage, [{"type": "text", "text": "a"}]),
             assistant("m4", usage, [{"type": "text", "text": "b"}]),
             assistant("m4", usage, [{"type": "text", "text": "c"}])]
    assert returned_text(plain, []) == "b\nc", "final assistant message only"
    document = result_document(candidate_texts(records))
    parsed = extract_json(document)
    assert parsed is not None, "heredoc body parses"
    assert verdicts(document, parsed) == ["mitigated", "partial", "unmitigated", "maybe"]
    fenced = "Summary\n```json\n" + json.dumps(result) + "\n```\ntrailing prose {not json}"
    assert extract_json(fenced) is not None, "fenced block parses"
    broken = '{"consideration_verdicts": [{"status": "partial"}, {"status": "mitigated"}'
    assert extract_json(broken) is None, "truncated result does not parse"
    assert verdicts(broken, None) == ["partial", "mitigated"], "regex fallback"
    assert window_of("2026-10-02T23:59:59Z", None) == "pre-g452"
    assert window_of("2026-10-12T19:09:59Z", None) == "2.6.0-era"
    assert window_of("2026-10-12T19:10:00Z", None) == "2.7.0"
    assert window_of("2026-10-14T20:00:00Z", "2026-10-14T19:00:00Z") is None
    assert findings_by_severity({"findings": [{"severity": "High"}, {"severity": "low"}, {},
                                              {"severity": "token-abc"}]}) == \
        {"high": 1, "low": 1, "out-of-enum": 2}, "no transcript text becomes a key"
    ordered = [assistant("m5", usage, [{"type": "tool_use", "id": "t5", "name": "Bash",
                                        "input": {"command": "write consideration_verdicts A"}}]),
               assistant("m6", usage, [{"type": "text", "text": "final consideration_verdicts B"}])]
    assert result_document(candidate_texts(ordered)).endswith("B"), "record order, not text-first"
    assert load_jsonl("/nonexistent/w2287-self-test.jsonl") == [], "a vanished transcript is skipped"
    line = json.dumps(assistant("m7", usage, [{"type": "tool_use", "id": "t7", "name": "Agent",
                                               "input": {"prompt": "abcd"}}]))
    assert agent_prompt_sizes(line, {"t7"}) == [("t7", 4)] and agent_prompt_sizes(line, {"x"}) == []
    note = ("<task-notification><tool-use-id>t7</tool-use-id><usage><duration_ms>1234"
            "</duration_ms></usage></task-notification>")
    assert notification_durations(note, {"t7"}) == [("t7", 1234)]
    assert edits_outside_scratch([{"name": "Write", "input": {"file_path": "/tmp/probe/x.ex"}}]) is False
    assert edits_outside_scratch([{"name": "Write", "input": {"file_path": "/p/.stride/.security-W1-r1.json"}}]) is False
    assert edits_outside_scratch([{"name": "Edit", "input": {"file_path": "/p/lib/a.ex"}}]) is True
    assert TEST_RUN_RE.search("cd /p && mix test test/a_test.exs") and not TEST_RUN_RE.search("mix format")
    rows = [{"project": "p", "task": "W1", "start": "2026-10-13T00:00:00Z", "wall_ms": 1000,
             "wall_source": "notification", "requests": 1, "input_side": 1, "peak_context": 1,
             "tool_calls": 1, "bash_calls": 1, "read_calls": 0, "returned_bytes": 1,
             "fixed_context": 1,
             "has_result": True, "parsed": True, "verdicts": ["partial"],
             "budget_reached": False, "findings": {"low": 1}, "test_runs": 1,
             "edited_outside_scratch": False, "prompt_bytes": 10, "versions": []}] * 3
    summary = summarise(rows)
    assert summary["tasks"] == 1 and summary["re_dispatches"] == 2
    assert summary["all_mitigated_dispatches"] == 0, "a partial verdict is not all-mitigated"
    assert summary["findings"] == {"low": 3} and summary["prompt_bytes_total"] == 30
    assert summary["fixed_context_share"] == 1.0
    print("self-test: ok")
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--until", help="ignore dispatches that started after this ISO8601 time")
    parser.add_argument("--project", help="only dispatches whose project directory name contains this")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return self_test()
    summary = measure(args.until, args.project)
    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        print_report(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
