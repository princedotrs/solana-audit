---
name: quick-scan
description: Fast security triage — discovery + static analysis + the highest-severity vector subset, without the full item-by-item walk. Use for a first look or a CI gate.
allowed-tools: Read, Grep, Glob, Bash, Task
---

# solana-program-audit — Quick Scan

**Arguments:** $ARGUMENTS

Run the quick audit exactly as `QUICK-AUDIT.md` (read from `<skill-root>`, the directory containing this skill's SKILL.md, never the audited repo) describes. That file is the single contract for this playbook and for SKILL.md's quick audit. In brief:

1. Discover the target and stop with the `target-absent` / `no-in-scope-code` short form when there is nothing to audit (QUICK-AUDIT §1 step 0, §6). Write a one-line scope statement (Rule 0 discovery only; no Scope Coverage table).
2. Static analysis is optional. If the Trail of Bits skills (https://github.com/trailofbits/skills, CC-BY-SA-4.0) are installed separately, you may delegate SAST to their `static-analysis` over the in-scope program crates. Otherwise the native grep checks in `discovery/grep-commands.md` (also from `<skill-root>`) are optional on small targets and used to order the reading on large ones (QUICK-AUDIT §1). Any analyzer that builds the target runs in the execution mode recorded at intake (`OUTPUT-RULES.md` Rule 11a).
3. Evaluate only the INDEX rows of severity ≥ 7 whose trigger fires (QUICK-AUDIT §1 step 5), not the full set.
4. Report findings in the SKILL.md quick format: severity, `path:line`, and the Validation field for severity ≥ 6. State clearly this is a triage pass, not a complete audit, and point to the `audit` playbook (`commands/audit.md`) for full coverage.
5. **As a CI gate on a public repository** (`OUTPUT-RULES.md` Rule 11d): post pass/fail only — no finding counts, total or per severity — in PR comments, check annotations, the job log and uploaded artifacts alike, since anyone signed in to GitHub can read all of them. Send finding details through a private channel (private vulnerability reporting, a draft security advisory, or a private repository). If that channel is unavailable, fail the job; never fall back to printing findings in the log.
