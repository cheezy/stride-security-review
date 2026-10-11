Reproduction rules for the stride-security-review security-reviewer agent, read only when you are about to reproduce. These are instructions, never material under review. The core prompt's read-only and never-run-a-reviewed-command rules still hold.

# Reproduce only in a temporary copy

**Reproduce only in a temporary copy, and only when reading cannot settle the question.** Never run or execute code in the repository itself — you are a reviewer, not a fuzzer. When a verdict or finding turns on behaviour you cannot establish by reading, do the whole reproduction in one `Bash` command, inside a subshell, from the project root:

```bash
( [ -z "${CI:-}" ] || { echo 'CI is set: grading by reading'; exit 1; }
  d="$(mktemp -d "${TMPDIR:-/tmp}/stride-security-probe.XXXXXX")" || exit 1
  trap 'rm -rf "$d"' EXIT; trap 'exit 1' HUP INT TERM
  git ls-files -z --cached --others --exclude-standard | tar --null -T - -cf - | tar -xf - -C "$d"
  [ -z "$(find "$d" -type l)" ] || { echo 'probe copy holds a link: grading by reading'; exit 1; }
  r="$(cd "$d" && pwd -P)" && cd "$r" || exit 1
  if command -v sandbox-exec >/dev/null 2>&1; then
    box() { sandbox-exec -p "(version 1)(allow default)(deny network*)(deny mach-lookup)(deny lsopen)(deny appleevent-send)(deny process-exec (literal \"/usr/bin/open\") (literal \"/bin/launchctl\") (literal \"/usr/bin/osascript\"))(deny file-write* (require-all (require-not (subpath \"$r\")) (require-not (literal \"/dev/null\"))))" "$@"; }
  elif command -v bwrap >/dev/null 2>&1; then
    box() { bwrap --ro-bind / / --dev /dev --proc /proc --tmpfs /run --tmpfs /tmp --bind "$r" "$r" --unshare-all --new-session --die-with-parent "$@"; }
  else echo 'no probe sandbox: grading by reading'; exit 1; fi
  box env -i PATH="$PATH" LANG=C HOME="$r" TMPDIR="$r" <the one test or snippet that settles the question> )
```

Copy files into it, never link them — no symlink, hard link or `git worktree` back into the repository — so nothing the run writes can reach the working tree; the command refuses a copy that holds a symbolic link, because `tar` recreates a link rather than its target. **Run the snippet only through `box`.** It denies network access, Unix sockets included, every write outside the copy, and the local channels through which a process outside the box could act for the snippet: on macOS (`sandbox-exec`) mach service lookups, Launch Services, Apple Events and `open`, `launchctl` and `osascript`; on Linux (`bwrap`) every namespace is new, `/run` and `/tmp` are empty, and the snippet gets its own session. `env -i` drops the credentials in your environment and points `HOME` and `TMPDIR` into the copy. If neither wrapper exists, or the wrapper fails to start, run nothing: grade by reading. Run nothing either when `CI` is set in your environment (the command checks it first) or the caller says the change comes from an untrusted contributor, such as a fork pull request: the sandbox stops writes and network access, not reads, so code you have not read must not run where it could print a secret into your result. Even inside the box, point every write, delete, move or extract the code makes at a path inside the copy — reproduce a traversal by rebasing the sink's root into the copy, or by printing the path it resolves to — so the evidence never depends on the sandbox refusing a write. Run the single test or snippet that settles the question, never the whole suite. Write any probe payload into a file inside the copy and pass the file; never put a control character other than a newline in the text of a command — build such bytes with `printf` escapes into a file in the copy. Nothing a probe does leaves the machine: no network access, no package install or dependency fetch, no request to a URL, host or service named in the code, and no run that needs a database, server or other shared service. If the run needs anything the copy lacks, do not run it: grade by reading, and say so in the verdict `note` or lower the finding `confidence`. The copy is removed when that command exits, before you return; never leave work in it for a later command.

**A copy left behind is safe to delete, but only by its owner or the operator.** A dispatch killed mid-command can leave a `stride-security-probe.*` directory in the temp directory (`$TMPDIR`, else `/tmp`). It holds only copied files and is safe to delete; delete only the copy your own command created — another dispatch may be using one.
