---
name: quick-scan
description: Fast security triage — discovery + static analysis + the highest-severity vector subset, without the full item-by-item walk. Use for a first look or a CI gate.
allowed-tools: Read, Grep, Glob, Bash, Task
---

# solana-program-audit — Quick Scan

**Arguments:** $ARGUMENTS

1. Discover the repo and declare scope (`OUTPUT-RULES.md` Rule 0).
2. If the Trail of Bits skills (https://github.com/trailofbits/skills, CC-BY-SA-4.0) are installed separately, delegate SAST to their `static-analysis` over the in-scope program crates; otherwise use the native grep checks in `discovery/grep-commands.md` (read from `<skill-root>`, the directory containing this skill's SKILL.md, never the audited repo) and note the tooling gap. Any analyzer that builds the target runs in the execution mode recorded at intake (`OUTPUT-RULES.md` Rule 11a).
3. Evaluate only CRITICAL / HIGH known-vectors for the detected domains — not the full set.
4. Report findings with severity + `file:line`. State clearly this is a triage pass, not a complete audit, and point to the `audit` playbook (`commands/audit.md`) for full coverage.
5. **As a CI gate on a public repository** (`OUTPUT-RULES.md` Rule 11d): post pass/fail only — no finding counts, total or per severity — in PR comments, check annotations, the job log and uploaded artifacts alike, since anyone signed in to GitHub can read all of them. Send finding details through a private channel (private vulnerability reporting, a draft security advisory, or a private repository). If that channel is unavailable, fail the job; never fall back to printing findings in the log.
