# Porting the G452–G454 fixes to the other security-review variants

This guide covers the three improvement goals filed on 2026-10-02 after a
measured review of `stride-security-review` 2.5.2:

- **G452 — accuracy**
- **G453 — speed**
- **G454 — token usage**

The user's priority order was accuracy, then speed, then tokens. Each fix lands
first in this repository (the Claude Code edition) and, where it is a consumer
change, in `stride`'s deep security-considerations sub-step. This guide records,
for each fix, what changes, why, and what each variant needs to carry it.

**Port from landed fixes only.** When a task lands here, change its status below
to *landed* and replace its "Planned change" paragraph with what actually
shipped, including the commit and the release. A planned section describes
intent, not shipped behaviour. All of these tasks were *planned* on 2026-10-02.

## Status

| Task | Goal | Where it lands | Fix | Status |
|---|---|---|---|---|
| W2274 | G452 | plugin | The eval runs the plugin's own agent and fails loudly without its key; considerations fixtures for partial, a None placeholder, injection, noise-class and pre-existing-gap cases | planned |
| W2275 | G452 | plugin | Considerations-mode contradictions resolved; all reviewed content is data; credential-bearing considerations redacted; strict status enum | done in this repo, unreleased |
| W2276 | G452 | plugin | Read-only reviewer: no edits to tracked files, probes only in a temporary copy, Bash restricted or removed per the eval | done in this repo, unreleased; Bash kept under a written contract (eval comparison in the CHANGELOG) |
| W2277 | G452 | `stride` | `stride` consumes the specialist's `findings[]`; escalation severity comes from the backing finding, not always `critical` | planned |
| W2278 | G452 | both | Exact mode tag, diff-source rule, results in the final message, `considerations_match_ok` 1:1 check, `--considerations` in the skill inventory | done in both repos, unreleased |
| W2279 | G452 | plugin | The `/security-review` command's `--rci`, `--fail-on` and baseline interactions with considerations mode | done in this repo, unreleased |
| W2280 | G453 | `stride` | Dispatch the specialist in the same message as the task-reviewer; merge after both return | planned |
| W2281 | G453 | `stride` | Re-dispatch only for non-mitigated considerations or changed evidence files, scoped to them | planned (needs W2280) |
| W2282 | G453 | plugin | A tool budget for considerations mode; targeted reads; test runs only to confirm a claim | done in this repo, unreleased |
| W2283 | G453 | `stride` | The task-reviewer skips per-consideration verdicts when the deep review will run | planned (needs W2280) |
| W2284 | G454 | both | Full result written to `SECURITY_RESULT_PATH`; at most about 10 lines returned | planned |
| W2285 | G454 | plugin | A 12–15 KB core prompt plus packs loaded on demand; opt-in sections injected by flag | planned (claim after W2274) |
| W2286 | G454 | plugin | Trimmed always-loaded descriptions | planned |
| W2287 | G454 | measurement | Before and after against the 2026-10-02 baseline | planned (claim last) |

The "Where it lands" column decides who ports what:

- **Plugin** fixes port to the four variant repositories below.
- **`stride`** fixes port to each `stride` port's own deep security sub-step, not
  to the security-review variants.
- **Both** means both sides change together and must be ported together.

## The baseline

These figures were measured from session transcripts of the Claude Code edition
only, de-duplicated by message id. No variant has been measured.

| Measure | Value |
|---|---|
| Dispatches | 257 (kanban 134, reachy-learn-language 123), 2026-08-31 to 2026-10-02; 256 in considerations mode, all from `stride` Step 5; 0 command invocations |
| Wall clock per dispatch | median 140 s (17–920 s); 13.3 h in total |
| Requests and tokens per dispatch | median 10 requests, 792k input-side tokens, peak context 98.5k |
| Input-side tokens in total | 306M: the fixed starting context re-sent each request is 52%, and the 74 KB agent prompt alone about 21% |
| Tool calls | 4,402 (Bash 3,586, Read 736), including 283 test-suite runs |
| Main-loop cost | 981 KB of dispatch prompts written; 1.94 MB (about 486k tokens) of results returned |
| Verdicts | 694: 537 mitigated, 144 partial, 12 unmitigated, 1 out-of-enum |
| Findings | 509: 0 critical, 21 high, 88 medium, 260 low, 140 info. The main agent fixed nearly all, including low and info |
| Rounds | 142 tasks, 1–11 rounds each; 91 re-dispatches |
| Output parsing | 94% parsed on the first try; 5 of the 15 failures came from asking for a side file |
| Working tree | 5 dispatches edited tracked files in place, then restored them |
| Overlap with `stride:task-reviewer` | verdicts agreed 64% of the time; the specialist alone caught a real gap 28% of the time, the task-reviewer alone 8% |

## The variants, as checked on 2026-10-02

Each cell comes from `ls`, `grep`, `wc -c` or `git describe` run from the kanban
checkout. Re-check a cell before relying on it.

| Variant | Version | Agent file | Agent tools (frontmatter) | Turn bound | Command entry point | Eval / CI |
|---|---|---|---|---|---|---|
| `stride-security-review` (Claude Code) | v2.5.2 | `agents/security-reviewer.md`, 74,441 B | `Read, Grep, Glob, Bash`; `model: inherit` | none | `commands/security-review.md` | `scripts/run_eval.sh`, `.github/workflows/eval.yml`, `test/fixtures/` (64 entries) |
| `stride-gemini-security-review` | v0.1.1 | `agents/security-reviewer.md`, 74,442 B | `read_file, grep_search, glob, run_shell_command` | **`max_turns: 10`, which the runtime enforces** | `commands/security-review.toml` | no eval script or CI workflow found; `fixtures/` (65 entries) |
| `stride-opencode-security-review` | v0.1.1 | `agents/security-reviewer.md`, 74,452 B | `read, bash: true`, **`edit: false`** | none found | `commands/security-review.md` | no eval script or CI workflow found; `fixtures/` (65 entries) |
| `stride-copilot-security-review` | v0.4.2 | `agents/security-reviewer.agent.md`, 72,935 B | `["read", "search", "glob", "run"]` | none found | none found; the skill is `security-review-essentials` | `scripts/run_eval.sh`, which per its own header (lines 6–7) still calls `claude -p`; `.github/workflows/eval.yml`; `test/fixtures/` (62 entries) |
| `stride-codex-security-review` | v0.1.2 | `agents/security-reviewer.md`, 74,370 B | `["read", "search", "glob", "shell"]` | none found | `skills/stride-security-review/SKILL.md` | no eval script or CI workflow found; `fixtures/` (65 entries) |

What this table decides:

- **Every variant carries the same roughly 74 KB agent prompt**, so W2275 (rule
  contradictions), W2282 (budget) and W2285 (core plus packs) apply to all four
  variants nearly line for line. Each needs its own tool vocabulary.
- **Every variant gives the agent a shell.** That makes W2276 (read-only) relevant
  everywhere.
  - opencode already sets `edit: false`, but a shell can still write files.
  - gemini's `max_turns: 10` already bounds a dispatch hard; check whether W2282's
    budget makes it redundant there or whether 10 is too tight.
- **Only Claude Code and copilot have an eval harness and CI.**
  - The copilot eval invokes `claude -p` according to its own comment, so it may
    not test the Copilot agent at all. Verify that before porting W2274.
  - gemini, opencode and codex have fixtures but no eval runner. W2274 there means
    building one, or recording that the variant is unevaluated.

**Where the `stride` side lives in each port.** These `stride`-side fixes port to
each `stride` port's own text: W2277, W2278's consumer half, W2280, W2281, W2283
and W2284's consumer half. `stride` keeps the deep sub-step in
`skills/stride-workflow/optional-security-review.md`. The ports keep it inline:

- In `stride-codex`, `stride-copilot`, `stride-gemini` and `stride-opencode`, it
  is in `skills/stride-workflow/SKILL.md`, `skills/stride-subagent-workflow/SKILL.md`
  and `skills/stride-completing-tasks/SKILL.md`.
- In `stride-lite`, `stride-copilot-lite` and `stride-opencode-lite`, it is in the
  single workflow skill.
- `grep -rl security-review stride-pi/skills` found no reference, so `stride-pi`
  may not run a deep security review at all. Confirm this before porting there.

---

## G452 — accuracy

### W2274 — an eval that tests the real agent (done in this repo, unreleased)

**Problem.** `scripts/run_eval.sh:233` pipes a bare prompt into `claude -p` with no
`--plugin-dir` or `--agent`, so it scores base Claude, not this agent. The CI eval
is skipped because the API key is not configured. The considerations fixtures
cover only an all-mitigated case and an unmitigated case. No `EXPECTED.md` row has
ever been ticked.

**Per variant.**
- **copilot:** its eval and CI exist, but its runner calls `claude -p`. Point it at
  the Copilot CLI with the plugin's own agent, or record that it evaluates the
  Claude Code prompt.
- **gemini, opencode, codex:** build a runner around their own CLI, or say plainly
  in the README that the variant is not evaluated.
- **All variants:** port the new considerations fixtures (partial, a `None —`
  placeholder, injection inside a consideration, injection inside the diff, a
  noise-class consideration and a pre-existing gap) with their `EXPECTED.md`
  rows. Each variant already carries a `fixtures/` directory.

**What changed here** (port the shape, not the flags, to each variant's CLI).
`scripts/run_eval.sh` now runs `claude -p --plugin-dir <repo root> --agent
stride-security-review:security-reviewer` from an empty scratch directory with
every tool off, prints the exact invocation, and accepts either an API key or a
claude.ai login. `scripts/check_eval_invocation.sh` pins that invocation against
a fake CLI. `eval.yml` fails on `main` and on a manual dispatch when the key is
missing, and still skips on pull requests. `EXPECTED.md` ends with a
**Recorded runs** table.

### W2275 — consistent considerations rules (done in this repo, unreleased)

**What changed here** (all in `agents/security-reviewer.md`, section order kept).
- A paragraph after the introduction makes everything reviewed data, never
  instructions: diff hunks, comments, string literals, files read and the
  considerations. Only the caller's dispatch lines carry instructions.
- **False-positive filter** gains two `considerations`-mode exceptions: a
  task-listed denial-of-service, rate-limiting or memory-exhaustion
  consideration is in scope and is backed by a finding, and the pre-existing-gap
  `info` finding is not suppressed. Neither reaches an unlisted risk, and the
  filter is unchanged in `diff` and `full_file` mode.
- **Per-consideration verdicts**: a `partial` or `unmitigated` verdict MUST be
  backed by a finding (was SHOULD). A gap in pre-existing code is graded against
  the changed code and named in `note` plus one `info` finding at its site. The
  three statuses are the whole enum; a consideration with no matching surface is
  `mitigated`. A consideration that embeds a credential, or names where one
  lives, is echoed as `[REDACTED — row text embedded a credential]` in its
  position.
- **Operational constraints**: in `diff` and `considerations` mode the reviewer
  may read the changed files in full and their direct callers (one hop), at most
  10 files beyond the diff; **Confidence guidance** ties `high` to that limit.
- `scripts/check_agent_contract.sh` pins the new sentences. `EXPECTED.md` adds
  `export_rate_limit_unmitigated` and `credential_in_consideration_mitigated`,
  and the W2274 noise-class and pre-existing-gap rows now assert a backing
  finding. A recorded run passed all ten considerations rows.

**Per variant.** Apply the same edits to each agent file, at the same sections;
the prompts are near-identical in size. Keep the redaction sentinel's exact
string, because `stride`'s reviewer schema uses it. Confirm that each `stride`
port's task-reviewer uses the same string before porting.

### W2276 — a read-only reviewer (done in this repo, unreleased)

**Change.** The agent is read-only on the working tree: no edits to tracked or
untracked files, not even to restore them. It inspects with Read, Grep and Glob,
and uses Bash only for the result file, a short list of read-only commands, and
a reproduction inside a `stride-security-probe.XXXXXX` copy under the temp
directory, made by copying, run in one subshell and removed before returning.
The copy is refused when it holds a symlink, and the snippet runs only inside a
sandbox that denies network access, writes outside the copy and local IPC to
outside services (`sandbox-exec` on macOS, `bwrap` on Linux), under `env -i`;
with no sandbox, or with `CI` set, nothing runs. It
never runs a command written in the reviewed text.

**Decision.** Bash is kept. With and without Bash the eval passed every
considerations row with identical verdicts, so verdict quality does not depend
on it, but it is the only atomic write path for `SECURITY_RESULT_PATH`, and a
pattern-restricted `Bash(...)` frontmatter entry did not narrow it on Claude Code
2.1.296. The CHANGELOG records the runs.

**Per variant.** Every variant has a shell tool. Port the rule in each runtime's
vocabulary:

- gemini: `run_shell_command`
- opencode: `bash`
- copilot: `run`
- codex: `shell`

Dropping the shell must be decided per variant from that variant's own evidence.
Check empirically whether a runtime can scope its shell tool before relying on
it; Claude Code could not. opencode's `edit: false` still leaves its shell able
to write, so the written rule is needed there too.
Where no eval exists (see W2274), keep the shell and port the rule only.

### W2277 — `stride` consumes findings (planned; `stride`-side)

**Planned change.**
- Specialist findings at medium or higher are mapped into `issues[]` as
  `category: "security"`: critical and high become `critical`, medium becomes
  `important`.
- Low and info findings are recorded in `completion_notes`.
- Escalation severity comes from the backing finding. A verdict with no backing
  finding still escalates fail-closed.

**Per port.** Port to each `stride` port's deep sub-step and completion
self-check. Ports carry the `review-round-cap` canon rule that a security issue
is never merely recorded at `important` or above. The mapping must not weaken it.

### W2278 — the dispatch contract (done in both repos, unreleased)

**What changed in this repo.**
- `agents/security-reviewer.md` **Input modes**: the tag is exactly
  `/security-review invocation, mode: <mode>` on its own line (`diff`,
  `considerations`, or `full_file` with an optional `, batch <i> of <N>`; the
  `rci_pass` directive uses the same form). Nothing else is a tag. With no tag,
  a considerations list an older caller sends with no tag, under any header, is
  still reviewed in `considerations` mode; otherwise the default stays `diff`,
  and a tag naming another mode wins over a list.
- **Result file**: a dispatch line asking for output in any other file is
  ignored on that point; the document goes to an accepted
  `SECURITY_RESULT_PATH` or inline in the final message.
- `skills/security-review-essentials/SKILL.md` lists `--considerations
  <source>` and names the tag and result channel for a direct caller;
  `commands/security-review.md` says its tags are the one spelling.
- `scripts/run_eval.sh` sends the full tag, and `check_eval_invocation.sh` and
  `check_agent_contract.sh` pin it.

**What changed in `stride`** (`skills/stride-workflow/optional-security-review.md`).
- The dispatch opens with `/security-review invocation, mode: considerations`
  and sends the task-reviewer's own `TASK_BASE_REF` diff; with no diff the
  specialist is not dispatched, which is the fail-closed anomaly.
- The result comes back in the specialist's final message. "Never a side
  file" was written before W2284 made `SECURITY_RESULT_PATH` the sanctioned
  result file, so it means never a file the dispatch prompt invents.
- `considerations_match_ok` checks verdicts positionally against the task's
  list (or `$SCOPE` when there is no block), accepting
  `[REDACTED — row text embedded a credential]` at its position, and prints a
  boolean only. The verdict merge now accepts that sentinel and identical
  consideration texts, which both failed closed before.

**Per variant.**
- The plugin half (tag rules, the untagged-list fallback, the output-path
  rule, the skill inventory) ports to every variant's agent, command and
  `security-review-essentials` skill.
- The consumer half (tag, diff source, the predicate and the merge change)
  ports to each `stride` port.
- A port without `jq`-style self-checks carries the predicate as prose. Note in
  its changelog that the predicate is not executed there.

### W2279 — command fixes (done in this repo, unreleased)

**What changed in this repo.**
- `commands/security-review.md` Step 4 defines **a finding that backs a
  verdict** once: a finding whose `file` equals a `path:line` or
  `path:start-end` reference in the `evidence` of a `partial` or `unmitigated`
  verdict, with its `line` in range. When the link cannot be drawn (an open
  verdict nothing backs, or verdicts missing, short or outside the three
  statuses) every finding counts as backing. Steps 4.5, 4.6 and 6 use it.
- Step 4.5: every `--rci` pass re-sends the directives Step 4 sent — the
  considerations list, the MAESTRO line and table, the patches line — under
  the `rci_pass` tag only, and asks for `consideration_verdicts` back. A pass
  with missing or malformed verdicts exits 2.
- Step 4.6: baseline suppression never drops a finding that backs a verdict;
  `suppressed_count` counts only what was dropped.
- Step 6: an `unmitigated` verdict trips `--fail-on` at every threshold, even
  with no finding. A `partial` verdict that no finding backs, and missing or
  malformed verdicts, also trip it. A backed `partial` is gated by its
  finding's severity. The exit table says so.
- Step 5: the `--json` and `--sarif` branches go on to Step 6 instead of
  ending in "Stop.", so `--json --fail-on` gates.
- `agents/security-reviewer.md`: an `rci_pass` that re-sends a considerations
  list is a considerations-mode pass and keeps its verdicts and backing
  findings; a verdict's `evidence` names its backing finding's `file:line`.
- `scripts/sarif_transform.sh` gains a verdict-aware `failon` (optional
  consideration count) and a `suppress` mode; `run_transform_tests.sh` locks
  both (45 checks), and `check_agent_contract.sh` pins the new rules.
- `.github/workflows/security-review.yml` is unchanged: it never passes
  `--considerations`. The README says how to extend its `jq` gate if yours does.

**Per variant.**
- gemini (`commands/security-review.toml`) and opencode
  (`commands/security-review.md`) carry the command.
- codex carries it as the skill `stride-security-review`.
- copilot has no command entry point, so the fix does not apply there. Record that.
- The backing definition, the verdict gate and the baseline rule port as prose.
  A variant with no `sarif_transform.sh` has no executable check for them;
  say so in its changelog.
- The agent half (an `rci_pass` with a list is a considerations pass; evidence
  names the backing finding) ports to every variant's agent, copilot included.

The command had no recorded use, so this ports last.

---

## G453 — speed

### W2280 — parallel dispatch (planned; `stride`-side)

**Planned change.** Dispatch the specialist in the same message as the
task-reviewer, and merge into `$MERGED` only after both return. In the measured
window this already happened in 186 of 254 runs; the change makes it the
documented path.

**Per port.** This needs a runtime that can run two subagents at once. Check each
`stride` port's runtime. Where it cannot, keep the merge-after-both rule and run
the two in sequence.

### W2281 — gated re-verification (planned; `stride`-side)

**Planned change.** Re-dispatch the specialist only when the previous round had a
`partial` or `unmitigated` verdict, or when the fixes touched a file cited in a
verdict's `evidence`. Pass only those considerations, and carry the other verdicts
over unchanged from the previous merged result.

**Per port.** This is pure `stride`-side text. It ports to every port that runs
the deep sub-step.

### W2282 — a bounded dispatch (done in this repo, unreleased)

**Change.** In `considerations` mode a dispatch has a budget of 20 tool calls,
at most 2 of them reproductions. Writing the result file never counts and is
never skipped. Each `rci_pass` that re-sends the list is its own dispatch with
its own budget. `diff` and `full_file` mode have no budget. The agent grades
from the diff first and reads a changed file or its direct callers only when a
verdict needs more. It reads past them (a caller's caller, or a config file the
changed code reads) only when a verdict turns on it. That read counts toward the
shared 10-file limit and the budget, and the verdict's `note` names it. A
reproduction confirms one claim stated in a verdict or finding, inside the W2276
temporary copy. When the budget runs out first, the verdict is `partial` with a
`note` that begins `budget reached:`. It is never `mitigated`.

**Decision.** That `partial` is the one verdict no finding backs, and its
`evidence` cites no `file:line`. So the command's `--fail-on` gate fails on it at
every threshold, and `stride` escalates it `critical`. An `info` backing finding
was rejected because `info` never trips a threshold, so an unverified
consideration would have passed CI. The cost is that a dispatch which runs out of
budget blocks the task until a human or a further round settles it, which is
fail-closed by design. W2281's scoped re-dispatch gives such a consideration the
whole budget on the next round. The eval cannot observe tool calls, because it
runs tools-off in an empty directory, so W2287 measures the effect.

**Per variant.** Port the rule to every agent file, with the same numbers and
the same `budget reached:` marker. Callers fail closed on that verdict only
because its `evidence` cites no `file:line`. Neither `stride` nor the command
keys on the marker itself yet, so a port must keep the no-`file:line` rule. On gemini, reconcile the budget with the
runtime's `max_turns: 10`. That bound counts turns, not tool calls, and one turn
can carry several parallel calls, so the effective ceiling is the lower of the
two. Say so in the gemini agent, as the gemini exploratory-testing edition
already does for its own `max_turns`.

### W2283 — no duplicated consideration checks (planned; `stride`-side)

**Planned change.** When the deep review will run, `stride` tells the
task-reviewer to skip per-consideration verdicts and keep its security dimension
sweep. The section status then comes from the merge. If the specialist fails,
considerations are still assessed.

**Per port.** Port to each `stride` port's task-reviewer agent and its deep
sub-step together. Porting one side alone leaves considerations unassessed.

---

## G454 — token usage

### W2284 — result file and bounded summary (planned; both sides)

**Planned change.**
- When the caller supplies an absolute `SECURITY_RESULT_PATH`, the agent writes
  the full result there. The name is `.stride/.security-<IDENTIFIER>-r<N>.json`,
  following the same anchored-identifier rule as `REVIEW_BLOCK_PATH`.
- It returns at most about 10 lines.
- `stride` merges from the path it supplied, and deletes the file at Step 7.
- With no path supplied, the result stays inline.

**Per variant.** Every variant's agent needs a way to write one file:

- opencode has `edit: false`, so it needs a narrowly scoped write.
- The others can write through their shell under an explicit one-path rule.
  W2276 settled how that sits with the read-only rule: the result file is the
  one write in the repository, under `.stride/`, and a probe copy lives outside
  the repository and is removed before the agent returns.

Keep the variable name `SECURITY_RESULT_PATH` identical everywhere.

### W2285 — core prompt plus packs (planned; after W2274)

**Planned change.**
- A core of about 12–15 KB: methodology, classes, noise filter, schema, severity
  and verdicts.
- Framework, supply-chain and agentic packs in `agents/packs/<pack>.md`, loaded
  when the diff's languages or imports match.
- MAESTRO, patches and RCI text injected only when their flags are set.

**Per variant.** The packs are the same content in every variant, so port the
split mechanically. Check the pack-loading rule against each runtime's read tool,
and how that runtime resolves a path relative to the plugin: the
exploratory-testing review found that path does not resolve from the project
directory in Claude Code. Gate each variant's split on its own eval where one
exists. Where none exists, record that the split shipped unevaluated.

### W2286 — trimmed descriptions (planned)

**Planned change.** The agent description goes from about 2.4 KB to about 400
bytes, and the skill description shrinks to match, keeping the triggering
conditions.

**Per variant.** Trim each variant's agent and skill frontmatter. On codex, the
`stride-security-review` command-skill's description is always loaded too.

### W2287 — measurement (planned; last)

Measure at least ten deep-review dispatches against the baseline above, naming
the comparator for every figure. A variant's measurement needs that runtime's own
transcripts.

---

## Releasing a variant

One release per variant per batch. The release matrix for the family:

| Variant | Version manifest | Catalog |
|---|---|---|
| Claude Code | `.claude-plugin/plugin.json` | `stride-marketplace`: bump this plugin's pinned version in `.claude-plugin/marketplace.json` and its README row, then tag and release |
| gemini | `gemini-extension.json` | `stride-gemini-marketplace`: bump the entry in `extensions.json`, targeted by name, and the README table, then tag and release |
| opencode | none; the version lives in `CHANGELOG.md` | none; install is a GitHub ref |
| copilot | `plugin.json` at the repo root | `stride-copilot-marketplace` (vendored): rsync into `plugins/<name>/`, bump the entry in `.github/plugin/marketplace.json` and the README, then run its `RELEASE.md` verify and secret-scan |
| codex | `.codex-plugin/plugin.json` (easy to miss) | `stride-codex-marketplace` (vendored): rsync, README version cell only, then verify and secret-scan per its `RELEASE.md` |

Bump the manifest before tagging, and audit with
`find <repo> -name plugin.json -o -name '*-extension.json'`.

## Rules for this batch

1. **Port from landed sections only.**
2. **Port `stride`-side fixes to the `stride` ports, not to these variants.** The
   "Where it lands" column decides which.
3. **Verify every mechanism a ported sentence names exists in that variant**:
   shell tool, write permission, turn bound, eval runner, command entry point.
4. **Keep the shared strings identical across variants**: the redaction sentinel,
   the status enum, the mode tag, and `SECURITY_RESULT_PATH`. The `stride` ports
   key on them.
5. **Record what a variant cannot carry** in its changelog, so "not applicable"
   is distinguishable from "missed". Examples: no eval, no command, no parallel
   dispatch.
