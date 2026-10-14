# Deep-review measurement after G452–G454 (W2287)

Measured 2026-10-14. This is the "after" for the baseline in
[`porting-g452-g454.md`](porting-g452-g454.md) § The baseline, which was taken
on 2026-10-02 from `stride-security-review` 2.5.2 transcripts.

**Read the comparator before any number.** Three things differ between the
baseline and the new dispatches besides the plugin version: the project mix, the
amount of work each dispatch was given, and how much of the change had already
shipped before 2.7.0. Every figure below names its comparator. The published
baseline is quoted only where the measured set is like it, and no single
"saving" percentage is quoted for the goal as a whole.

## The runs

All dispatches are `stride-security-review:security-reviewer` subagents found in
Claude Code transcripts under `~/.claude/projects/`, with transcripts frozen at
**2026-10-14T19:55:00Z** (`--until`). A dispatch is assigned to a window by the
timestamp of its first transcript record.

| Window | Plugin versions | Dispatches | Tasks | Dates |
|---|---|---:|---:|---|
| **Published baseline** | security-review 2.5.2, `stride` ≤ 1.81 | 257 (kanban 134, reachy-learn-language 123) | 142 | 2026-08-31 to 2026-10-02 |
| **pre-G452 survivors** | the same | 134 (kanban 82, reachy-learn-language 52) | 66 | 2026-09-13 to 2026-10-02 |
| **2.6.0 era** | security-review 2.6.0, `stride` 1.82.0–1.85.x | 179 (all kanban) | 120 | 2026-10-03 to 2026-10-12 |
| **2.7.0** | security-review **2.7.0**, `stride` **1.86.0** | 30 (all kanban) | 21 | 2026-10-12T19:43Z to 2026-10-14 |

- **The 2.7.0 window starts at the install, not the release.** 2.7.0 was released
  on 2026-10-10 but installed on 2026-10-12 at 19:10Z, and the first dispatch to
  run it started at 19:43Z. All 30 dispatches in the window read files under
  `stride-security-review/2.7.0/` (its packs and modes). None of the 313 earlier
  dispatches read a versioned plugin path.
- **Only 134 of the baseline's 257 dispatches still have transcripts.** Every
  dispatch from 2026-08-31 to 2026-09-12 and from 2026-09-18 to 2026-09-30 is
  gone, and the loss is uneven by project: 82 of 134 kanban dispatches survive,
  against 52 of 123 for reachy-learn-language.
- **The 2.6.0 era is a comparator of its own.** W2284 (the result file), W2280
  (parallel dispatch) and W2281 (scoped re-dispatch) shipped in 2.6.0 and
  `stride` 1.82.0, before 2.7.0. Comparing 2.7.0 only with the 2.5.2 baseline
  would credit 2.7.0 with their savings.
- **Like for like means kanban only.** Every 2.6.0-era and 2.7.0 dispatch was in
  the kanban project. Among the survivors, reachy-learn-language dispatches ran
  a median of 184 s and 1.85M input-side tokens, against 91 s and 491k for
  kanban. The published baseline is 48% reachy-learn-language, so comparing it
  with a kanban-only set overstates any saving. In the tables below, the
  **like-for-like comparators are the kanban survivors (n=82) and the 2.6.0 era
  (n=179).**

## Step 1: reproduce the baseline from the old transcripts

Before the script was used on new data, it was run on the surviving pre-G452
transcripts and compared with the published figures. **This is a partial
reproduction, not an exact one.** 123 of the baseline's transcripts no longer
exist, and the survivors under-represent the heavier project.

| Measure | Published (n=257) | Recomputed survivors (n=134) | Agreement |
|---|---|---|---|
| Wall clock per dispatch | median 140 s; 13.3 h total | median 112.8 s; 5.2 h total | lower; the survivors are 39% reachy-learn-language, against 48% |
| Requests per dispatch | median 10 | median 9 | close |
| Input-side tokens per dispatch | median 792k | median 717k | within 10% |
| Peak context per dispatch | 98.5k | median 97.9k | matches |
| Input-side tokens in total | 306M, about 1.19M per dispatch; the fixed starting context 52%, the 74 KB agent prompt about 21% | 163.4M, 1.22M per dispatch; the fixed starting context 50.2%; the agent prompt's share not measured | matches per dispatch; the agent prompt's own token count is not in a transcript |
| Tool calls | 4,402 (Bash 3,586, Read 736), 17.1 per dispatch | 2,192 (Bash 1,685, Read 415), 16.4 per dispatch | matches per dispatch |
| Test-suite runs | 283 | 70 | lower; see Caveats on the detector |
| Dispatch prompts written | 981 KB, about 3.8 KB per dispatch | 388 KB, 2.9 KB per dispatch | lower |
| Results returned | 1.94 MB, about 7.5–8.1 KB per dispatch | 1.13 MB; median 7.0 KB, mean 8.4 KB | matches |
| Verdicts | 694: 77.4% mitigated, 20.7% partial, 1.7% unmitigated, 1 out-of-enum | 386: 79.5% mitigated, 19.4% partial, 1.0% unmitigated, 0 out-of-enum | matches |
| Findings | 509 (0 critical, 21 high, 88 medium, 260 low, 140 info), 1.98 per dispatch | 265 (0 critical, 7 high, 54 medium, 145 low, 59 info), 1.98 per dispatch | matches per dispatch |
| Rounds | 142 tasks, 91 re-dispatches | 66 tasks, 61 re-dispatches | **definition differs** (see below) |
| Output parsing | 94% parsed on the first try | 126 of 127 (99%) under the proxy | **does not reproduce** |
| Working tree | 5 dispatches edited tracked files | 0 under the proxy | **does not reproduce** |
| Overlap with `stride:task-reviewer` | agreed 64% | not measured | needs per-task judgement, not a transcript count |

Per-dispatch shape (tool calls, tokens, peak context, returned bytes, verdict
mix, findings per dispatch) reproduces within about 10%. Three baseline metrics
had **no recorded definition**, and this script's proxies do not reproduce them,
so those rows below carry no before/after claim against the published figure:

- **Re-dispatches:** here, every dispatch after the first for the same task
  identifier. The published 91 is not dispatches minus tasks (257 − 142 = 115),
  so the baseline counted something narrower.
- **First-time parse:** here, whether the dispatch's own result document yields
  a JSON object. The baseline counted failures on the consuming side, five of
  them caused by asking for a side file, and a transcript of the subagent alone
  cannot see those.
- **Working-tree edits:** here, an `Edit`/`Write` call outside a temporary
  directory or `.stride/`. The baseline's five edited in place and then
  restored, which most likely happened through Bash and is invisible to this
  proxy.

## Before and after

Kanban dispatches only. Medians unless marked. Percentages compare 2.7.0 with
each named comparator.

| Measure | pre-G452 kanban (n=82) | 2.6.0 era (n=179) | 2.7.0 (n=30) | 2.7.0 vs pre-G452 kanban | 2.7.0 vs 2.6.0 era |
|---|---:|---:|---:|---:|---:|
| Wall clock per dispatch | 91.2 s | 47.6 s | 42.2 s | −54% | −11% |
| Input-side tokens per dispatch | 491k | 445k | 346k | −29% | −22% |
| Input-side tokens per dispatch (mean; window total) | 568k (46.6M) | 509k (91.1M) | 409k (12.3M) | −28% | −20% |
| Fixed starting context, share of input-side tokens | 63.9% | 70.2% | 50.2% | −13.7 points | −20.0 points |
| Peak context per dispatch | 90.8k | 84.3k | 68.6k | −24% | −19% |
| Requests per dispatch | 6 | 6 | 6 | **no change** | **no change** |
| Returned to the dispatcher | 5.9 KB | 802 B | 669 B | −89% | −17% |
| Tool calls per dispatch (mean) | 7.8 | 7.3 | 11.8 | **+51%** | **+62%** |
| … of which Read (mean) | 2.3 | 1.7 | 7.3 | **+213%** | **+337%** |
| … of which Bash (mean) | 4.4 | 4.6 | 3.5 | −22% | −25% |
| Test-suite runs (window total) | 0 | 1 | 0 | no change | no change |
| Dispatch prompt per dispatch (mean) | 1.7 KB | 1.8 KB | 3.2 KB | **+96%** | **+79%** |
| Re-dispatches per task (this definition) | 0.74 (35 in 47) | 0.48 (57 in 120) | 0.43 (9 in 21) | −42% | −10% |
| Result document yields JSON (proxy) | 75 of 75 | 178 of 179 | 30 of 30 | no measurable difference | no measurable difference |
| Considerations per dispatch (mean) | 1.88 | 2.51 | 3.37 | more work per dispatch | more work per dispatch |
| Partial or unmitigated verdicts | 22.1% (34 of 154) | 6.0% (27 of 449) | **0% (0 of 101)** | see below | see below |
| Findings per dispatch | 1.16 | 0.36 | **0.07** (2 info) | see below | see below |

Against the **published** baseline, which is about half reachy-learn-language,
2.7.0 is −70% wall clock (140 s to 42.2 s), −56% input-side tokens (792k to
346k) and about −92% returned bytes (8.1 KB to 669 B). These are upper bounds:
the like-for-like kanban figures above are the ones to quote.

## Where a metric did not improve

- **Requests per dispatch did not fall.** It was a median of 6 in every kanban
  window. The 2.7.0 saving is in context per request (peak context −19% against
  the 2.6.0 era, and the fixed starting context down from 70.2% to 50.2% of
  input-side tokens), not in the number of requests. This is what W2285 predicted:
  a smaller core prompt, paid for with extra `Read` calls for packs.
- **Tool calls rose.** The 2.7.0 dispatches made 11.8 tool calls on average,
  against 7.3 in the 2.6.0 era. The whole increase is `Read`, which went from
  1.7 to 7.3, while `Bash` fell from 4.6 to 3.5. W2282's 20-call budget was
  never reached: no 2.7.0 result reports `budget reached:`.
- **Dispatch prompts doubled in size**, from 1.8 KB to 3.2 KB on average against
  the 2.6.0 era. They are written by the dispatcher (`stride` 1.86.0), not by
  this plugin, and are still small next to the 346k input-side tokens a dispatch
  consumes.
- **Most of the returned-bytes saving shipped in 2.6.0, not 2.7.0.** Against the
  kanban survivors, returned bytes fell 86% by the 2.6.0 era (W2284's result
  file). 2.7.0 took a further 17% off that.
- **Test-suite runs did not change** among kanban dispatches: there were none
  before G452 and one in the 2.6.0 era. All 70 surviving baseline runs were in
  reachy-learn-language dispatches, so W2282's limit on test runs has nothing
  to show in a kanban-only comparison.
- **Parse rate, working-tree edits, the agent prompt's share and the
  task-reviewer overlap** have no measured "after" against the published
  figures (see Step 1).

## Does a change in verdict mix explain the saving?

**No.** A dispatch that finds something costs more: among the survivors, a
dispatch with any partial or unmitigated verdict ran a median of 140 s and 977k
input-side tokens, against 89 s and 612k for an all-mitigated one. Since 2.7.0
returned only mitigated verdicts, part of its lower median could in principle be
the easier mix. Comparing all-mitigated dispatches only (kanban) rules that out:

| All-mitigated dispatches | pre-G452 kanban (n=45) | 2.6.0 era (n=156) | 2.7.0 (n=30) |
|---|---:|---:|---:|
| Wall clock | 76.6 s | 45.4 s | 42.2 s |
| Input-side tokens | 476k | 450k | 346k |

The saving holds with the verdict mix held constant: −7% wall clock and −23%
input-side tokens against the 2.6.0 era. The 2.7.0 dispatches also handled
more considerations each (3.37, against 2.51), so this understates rather than
overstates the saving.

**The verdict mix itself did change, and that needs an owner.** Partial or
unmitigated verdicts fell from 22% (kanban survivors) to 6% (2.6.0 era) to 0%
across 101 verdicts in 2.7.0. Findings per dispatch fell from 1.16 to 0.36 to
0.07, and the only two 2.7.0 findings are `info`. The transcripts cannot say
whether the reviewed work got better (W2283 and the review fixes in `stride`
changed what arrives at the deep review) or the reviewer got less critical
(W2275's noise filter, W2282's budget and W2285's packs all change what it
reports). **No accuracy claim for 2.7.0 should rest on this measurement.** The
place to settle it is the eval: W2274's partial, injection and noise-class
fixtures, run against 2.7.0.

## Caveats

- **Small, single-project sample.** 30 dispatches over two days, from 21 tasks,
  all in one repository. Nine of the 30 are re-dispatches of the same tasks.
- **Most new dispatches are nested.** 28 of the 30 2.7.0 dispatches, and 138 of
  the 179 in the 2.6.0 era, were launched by a `stride:task-runner` (spawn depth
  2); every survivor was launched from the main loop (depth 1). Wall clock is
  the notification's `duration_ms` in all three windows, so it measures the
  dispatch itself, but a nested dispatch may share the machine with its
  runner's other work.
- **Test-suite runs** are counted from Bash commands that name a known test
  runner (`mix test`, `pytest`, `npm test` or `npm run test`, `npx jest`,
  `npx vitest`, `go test`, `cargo test`, `rspec`). The survivors show 70 of the published 283. All 70 are in
  reachy-learn-language; none of the 82 kanban survivors ran a suite. The
  detector misses runners invoked any other way.
- **No output-token figures.** A record's `output_tokens` can be the
  stream-start value, so no output-token claim is made.
- **Transcripts expire.** The baseline lost 123 of its transcripts in twelve
  days. A re-run of the script will find fewer pre-G452 dispatches and will not
  reproduce these exact figures. The frozen bound makes the new windows
  reproducible only while their transcripts exist.

## Reproduction

The script is [`scripts/w2287-deep-review.py`](scripts/w2287-deep-review.py).
It follows the counting rules in `stride/docs/token-baseline.md` (de-duplication
by message id, input-side as the sum of the three input counters, subagents
resolved through their `meta.json`). Its docstring states every definition used
above. It prints aggregates only, never transcript text.

```bash
python3 docs/scripts/w2287-deep-review.py --self-test
python3 docs/scripts/w2287-deep-review.py --until 2026-10-14T19:55:00Z
python3 docs/scripts/w2287-deep-review.py --until 2026-10-14T19:55:00Z --project elixir-kanban
```

The first run checks the extraction rules on synthetic records. The second
gives the all-project windows, including the Step 1 reproduction. The third
gives the like-for-like kanban windows. The per-project survivor split and the
spawn-depth counts came from the same per-dispatch rows, grouped by the meta
file's project directory and `spawnDepth`.
