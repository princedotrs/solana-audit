# Report Format — Solana program audit

> Load at report assembly / Phase 5 / by `audit-reporter`.

This file holds the report-time layout details factored out of [OUTPUT-RULES.md](../OUTPUT-RULES.md) so the review-time floor stays small. The rules keep their canonical numbers in OUTPUT-RULES.md (Rule 2, Rule 6, Rule 8, Rule 9); their bodies live here and are loaded only when a report is being assembled.

---

## Rule 2 § Executive Summary

Every audit output — regardless of size — MUST start with an **Executive Summary** block. This goes at the very top of the report.

```markdown
## Executive Summary

**Repository:** {org/repo}
**Commit:** {short SHA}
**Date:** {YYYY-MM-DD}
**Scope:** {FULL / PROGRAM / OPSEC}
**Repository Risk Score:** {1-10} — {CRITICAL/HIGH/MEDIUM/LOW/MINIMAL}

### What We Found

{2-4 sentences in plain language. What was audited. What is the overall security posture.
Highlight the most important finding(s) if any critical/high exist.
State whether the code is safe to deploy or not.}

### Severity Distribution

| Score | Label | Count |
|-------|-------|-------|
| 10 | 🔴 CRITICAL | 0 |
| 9 | 🔴 CRITICAL | 0 |
| 8 | 🟠 HIGH | 0 |
| 7 | 🟠 HIGH | 0 |
| 6 | 🟡 MEDIUM | 0 |
| 5 | 🟡 MEDIUM | 0 |
| 4 | 🔵 LOW | 0 |
| 3 | 🔵 LOW | 0 |
| 2 | ⚪ INFO | 0 |
| 1 | ⚪ INFO | 0 |
| **Total Findings** | | **0** |

### Items Verified

| Metric | Count |
|--------|-------|
| Total checklist items | {N} |
| PASS | {N} |
| FAIL | {N} |
| PARTIAL | {N} |
| N/A | {N} |
| Completion | {%} |
```

---

## Rule 6 § Report Sections Order

Every full audit report follows this exact section order:

```
1. Executive Summary          (Rule 2 — always first)
2. Scope Coverage             (in-scope checklists / vector groups, items evaluated / total)
3. Scope & Methodology        (languages, files, LOC, checklists applied; Coverage & Limitations: run status, execution mode + outside services, tooling gaps — OUTPUT-RULES Rules 10, 11a/11b)
4. Findings                   (severity ≥ 4, full blocks, grouped by severity descending; then the unscored Notes & Nitpicks list — Rule 1)
5. Detailed Item Results      (all in-scope checklist items, item-by-item verdicts; then Known Vector Results — each in-scope KV with verdict — and the Rule 8 metrics)
6. Instruction Matrix         (on-chain only — if applicable)
7. State Model Verification   (on-chain only — if applicable)
8. Code Maturity Scorecard    (Phase 4.5 — 11 categories, gated WEAK/MODERATE/SATISFACTORY/STRONG)
9. Remediation Roadmap        (by severity; maturity categories rated WEAK first)
10. Re-Audit Checklist
11. Appendices                (tool versions, environment, disclaimer)
```

---

## Rule 8 § Metric Computation

The report MUST include computed metrics at the end of the Item Results section.

```markdown
### Audit Metrics

| Metric | Value |
|--------|-------|
| Total items evaluated | {N} |
| PASS | {N} ({%}) |
| FAIL | {N} ({%}) |
| PARTIAL | {N} ({%}) |
| N/A | {N} ({%}) |
| **Pass rate** (excl. N/A) | **{%}** |
| Highest severity found | {1-10} |
| Repository Risk Score | **{1-10}** |

### Known Vector Metrics

| Metric | Value |
|--------|-------|
| Total known vectors | {N — every vector in `known-vectors/INDEX.md`; non-triggered ones count as N/A} |
| PASS | {N} |
| FAIL | {N} |
| PARTIAL | {N} |
| N/A | {N} |
| Completion | {%} |

### Per-Checklist Summary

| # | Checklist | Items | Pass | Fail | Partial | N/A | Pass Rate |
|---|-----------|-------|------|------|---------|-----|-----------|
| 01 | Account Validation | 112 | | | | | % |
| ... | ... | ... | ... | ... | ... | ... | ... |
| **Total** | | **{N}** | | | | | **{%}** |
```

---

## Rule 9 § File Naming

| Output | Filename |
|--------|----------|
| Full audit report | `audit_{N}/REPORT.md` |
| Threat-model bootstrap evidence | `audit_{N}/bootstrap/` (working material, OUTPUT-RULES.md Rule 11d) |
| Remediation roadmap | `audit_{N}/roadmap.md` |
| Per-instruction worksheets | `audit_{N}/worksheets/{instruction_name}.md` |
| Context worksheets (Phase 0.5) | `audit_{N}/worksheets/context/{fn}.md` |
| Runtime-context sheet (FULL-AUDIT 0.1b) | `audit_{N}/runtime-context.md` |
| Checkpoint (session) | `audit-checkpoint.md` in the session scratchpad, else `audit_{N}/audit-checkpoint.md` (OUTPUT-RULES Rule 3) |

Where `{N}` is the highest existing `audit_*` number + 1; create the dir with `mkdir` (not `mkdir -p`) and stop if it exists. Reuse an existing `audit_*` only if git does not track it and it holds no symbolic links, after the human confirms which one. Never write into a tracked `audit_*`. The first file in each `audit_{N}/` is a `.gitignore` containing `*` (OUTPUT-RULES Rule 11d).

---

## Dedup & Assembly Gates

1. **Group key** = `program | instruction | bug-class`. Match exactly first, then merge synonymous bug classes *within the same (program, instruction)*.
2. **Canonical label (hard gate).** One label per bug class per (program, instruction): the label already in `audit-mem` for that instruction, else the majority label, else the shortest label naming the **defect**, not its consequence (`missing-token-program-pin`, not `attacker-drains-vault-via-fake-program`). Keeps `audit-mem` keys stable.
3. **Instruction isolation (hard gate).** Never merge across instructions. A cross-instruction echo is linked in a `Related:` field.
4. **Wide description.** A merged group with distinct mechanisms (different fix, cause or path) lists every mechanism. Then do a second pass per (program, instruction), ignoring bug class, so every mechanism in any constituent body appears in at least one final finding.
5. **Fix preservation (hard gate).** If constituent fixes differ in what they check, the direction, or the parameter, print them as **Option A / Option B …** verbatim. Never paraphrase a diff.
6. **Completeness (hard gate).** Print `Completeness: N unique (program, instruction) in raw, N covered in final.` Every raw (program, instruction) has at least one final item.
7. **Chains.** `Chain: [F-A] + [F-B]` at severity ≥ max, confidence = min.
8. **Never overstate coverage.** A subset is headed `top K of N`. Assemble from per-pass files deterministically, not by retyping at the end of a long context.
9. Do not add free-form "areas reviewed, no issues" prose. Rule 4 `[PASS]` lines with cited files remain required.

## Findings taxonomy in the final report

Separate five lists: **Confirmed findings** · **Hypotheses / Open questions** (never counted) · **Residual risks** (accepted, each with an owner and a report-ready rationale) · **Hardening notes** (no exploit path) · **Out-of-scope risks**.

## Report header additions

- **Run status:** `completed | build-blocked | tooling-blocked | policy-interfered` (OUTPUT-RULES Rule 10).
- **Verification lanes:** source review / compilation / PoC harness / Miri / fuzzing, each `passed | partial | blocked | failed | skipped`.
- **Runtime-context sheet:** link to `audit_<n>/runtime-context.md` (FULL-AUDIT 0.1b).

## Maturity scorecard (§8) — gated

Use the WEAK / MODERATE / SATISFACTORY / STRONG gated rubric from FULL-AUDIT Phase 4.5. Every rating cites evidence; "not assessed: <reason>" is allowed; no default scores.

*Sources: pashov/skills dedup-and-assembly (MIT, Copyright (c) 2024 AI Skills Contributors), adapted; beriktassuly/solana-audit-skill claim discipline (MIT, Copyright (c) 2026 Berektassuly); qedgen/solana-skills E4 (MIT, Copyright (c) 2025 QEDGen); Trail of Bits `code-maturity-assessor` [paraphrased, CC-BY-SA-4.0].*
