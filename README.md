# security-review

AI-powered security review of code changes, delivered as a Claude Code plugin.

Provides the `/security-review` slash command. Backed by a dedicated `security-reviewer` agent that analyzes diffs for vulnerability classes including injection, authentication and authorization flaws, data exposure, cryptographic weaknesses, input validation gaps, race conditions, XSS/code execution, and insecure configuration — while filtering out low-impact noise (denial-of-service, rate-limiting, memory-exhaustion concerns).

Loosely based on [anthropics/claude-code-security-review](https://github.com/anthropics/claude-code-security-review).

## Installation

```bash
/plugin marketplace add cheezy/stride-marketplace
/plugin install security-review@stride-marketplace
```

## Quick start

In a Claude Code session inside any git repository:

```
/security-review
```

Reviews the current git diff and prints findings grouped by severity.

## Status

Scaffold release. Full agent prompt, slash command, supporting skill, and fixture suite land in subsequent tasks under goal G91.

## License

MIT — see [LICENSE](LICENSE).
