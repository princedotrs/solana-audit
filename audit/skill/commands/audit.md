---
name: audit
description: Full scope-gated security audit of a Solana on-chain program repository (Rust / Anchor / native / Pinocchio) — discovery, context reconstruction, per-item checklist verdicts, false-positive validation, and a severity-ranked report.
argument-hint: "[path] [--scope full|program]"
allowed-tools: Read, Grep, Glob, Bash, Task
---

# solana-program-audit — Full Audit

**Arguments:** $ARGUMENTS

Run this skill end-to-end:

1. Read `OUTPUT-RULES.md` (mandatory output format, severity 1-10, the Rule 5b validation gate).
2. Follow `FULL-AUDIT.md` top to bottom, honoring **scope-gated loading** (Rule 0): discover the repo, declare scope, load only in-scope checklists/vectors on demand. Off-chain code (TS / Python / Go clients, backends, frontends) is out of scope for this skill.
3. Delegate: spawn `context-builder` (Phase 0.5) first, then `vuln-hunter` for the item-by-item walk, `economic-analyst` for checklist 06 + economic vectors, and `audit-reporter` to assemble the report.
4. Every in-scope checklist item and phase-triggered vector gets an explicit verdict (`[PASS]` / `[FAIL-N]` / `[PARTIAL]` / `[N/A]`). Findings with N≥6 must pass the Rule 5b validation gate or be downgraded to `[PARTIAL]` / `[UNCONFIRMED]`.
5. Emit `audit_<n>/REPORT.md`: executive summary (safe-to-deploy verdict), Scope Coverage table, findings, Phase 4.5 maturity scorecard, remediation roadmap.

If the Trail of Bits skills (https://github.com/trailofbits/skills, CC-BY-SA-4.0) are installed separately, delegate SAST / harnesses / coverage to them per `references/orchestration/boundary-map.md`; otherwise use the native grep checks in `discovery/grep-commands.md` and note the tooling gap. Read every corpus file and run every bundled tool from `<skill-root>` — the directory containing this skill's SKILL.md, never the audited repo.
