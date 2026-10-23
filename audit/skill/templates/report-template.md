# Audit Report Template

> Copy this template and fill it in during/after an audit.  
> The report is the final deliverable of a FULL audit (see FULL-AUDIT.md).  
> **ALL output rules in OUTPUT-RULES.md are mandatory.** This template implements them.

---

# 🔒 Security Audit Report

## 1. Executive Summary

**Repository:** <!-- org/repo -->  
**Commit:** <!-- short SHA -->  
**Branch:** <!-- branch name -->  
**Date:** <!-- YYYY-MM-DD -->  
**Auditor:** <!-- Agent or human name -->  
**Scope:** <!-- FULL / PROGRAM / SPECIFIC (programs/instructions) -->  
**Program ID:** <!-- On-chain program address (if applicable) -->  
**Framework:** <!-- Anchor <ver> / native solana-program / Pinocchio -->  
**Out of Scope (off-chain):** <!-- TS client, backend, frontend, keeper, scripts — not reviewed by this skill -->  
**Repository Risk Score:** <!-- 1-10 --> — <!-- CRITICAL/HIGH/MEDIUM/LOW/MINIMAL -->

### What We Found

<!-- 
2-4 sentences in plain language:
- What was audited (scope, size)
- Overall security posture
- Most important finding(s) if any severity ≥ 7 exist
- Whether the code is safe to deploy or not
-->

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
| Total checklist items | <!-- N --> |
| PASS | <!-- N --> |
| FAIL | <!-- N --> |
| PARTIAL | <!-- N --> |
| N/A | <!-- N --> |
| Completion | <!-- % --> |

---

## 2. Scope Coverage

> Which checklists and vector groups were in scope, and how many items were evaluated. Out-of-scope items render `[N/A — out of scope]` from the scope gate (Rule 0), not from reading each file.

| Checklist / vector group | In scope? | Items evaluated / total | Trigger / reason |
|---|---|---|---|
| 01–07 on-chain | Yes/No | N / N | `.rs` / `Anchor.toml` / `solana-program` / `pinocchio` |
| 11, 12, 16 always-on | Yes | N / N | any program repo |
| Known vectors | Yes | N / N | `known-vectors/INDEX.md` load-when markers |
| Off-chain code (TS / Python / Go / …) | No — out of scope for this skill | — | listed, not reviewed |

### Scope Metrics

| Metric | Count |
|---|---:|
| In-scope checklist items | <!-- N --> |
| Items with a verdict | <!-- N --> |
| In-scope known-vectors | <!-- N --> |
| Completion (in-scope) | <!-- % --> |

---

## 3. Scope & Methodology

### Files Audited

| Domain | Language | Files | Lines of Code |
|---|---|---|---|
| Solana Program | Rust | <!-- count --> | <!-- LOC --> |
| Program tests | Rust / TS | <!-- count --> | <!-- LOC --> |
| Build & config (`Cargo.toml`, `Anchor.toml`, toolchain) | Various | <!-- count --> | <!-- LOC --> |
| **Total** | | **<!-- count -->** | **<!-- LOC -->** |

### Checklists Applied

| # | Checklist | Items | Pass | Fail | Partial | N/A | Pass Rate |
|---|---|---|---|---|---|---|---|
| 01 | Account Validation | 90 | | | | | % |
| 02 | Access Control | 55 | | | | | % |
| 03 | Arithmetic Safety | 63 | | | | | % |
| 04 | CPI & PDA | 70 | | | | | % |
| 05 | State Machine | 74 | | | | | % |
| 06 | Economic & Logic | 92 | | | | | % |
| 07 | OpSec & Governance | 87 | | | | | % |
| 11 | Supply Chain | 62 | | | | | % |
| 12 | Secrets & OpSec | 53 | | | | | % |
| 16 | Formal Verification & Testing | 73 | | | | | % |
| | **Total** | **<!-- sum of applicable rows -->** | | | | | **%** |

> Note: Only applicable checklists are counted in totals. Non-applicable checklists are excluded entirely.

---

## 4. Findings

> Only items with severity ≥ 4 require a full finding block.  
> Items severity 1-3 are documented in the Item Results section (Section 4).

---

#### [F-XXX] Finding Title

| Field | Value |
|---|---|
| **Severity** | <!-- 1-10 --> — <!-- 🔴/🟠/🟡/🔵/⚪ CRITICAL/HIGH/MEDIUM/LOW/INFO --> |
| **Checklist Item** | <!-- XX-YYY --> |
| **Category** | <!-- e.g. Arithmetic, Access Control, Account Validation --> |
| **Program / Instruction** | <!-- program name :: instruction --> |
| **File** | <!-- path/to/file:line --> |
| **Status** | Open |

**Description:**  
<!-- What is the vulnerability? Be specific to the code found. -->

**Impact:**  
<!-- What can an attacker do? What is the worst case? Quantify if possible. -->

**Proof of Concept:**  
```
<!-- Minimal code/steps to reproduce the issue -->
```

**Recommendation:**  
```
<!-- Specific code fix — not just "fix this" -->
```

---

### Findings by Severity (10 → 4)

#### Severity 10 — 🔴 CRITICAL
<!-- List F-XXX findings or "None" -->

#### Severity 9 — 🔴 CRITICAL
<!-- List F-XXX findings or "None" -->

#### Severity 8 — 🟠 HIGH
<!-- List F-XXX findings or "None" -->

#### Severity 7 — 🟠 HIGH
<!-- List F-XXX findings or "None" -->

#### Severity 6 — 🟡 MEDIUM
<!-- List F-XXX findings or "None" -->

#### Severity 5 — 🟡 MEDIUM
<!-- List F-XXX findings or "None" -->

#### Severity 4 — 🔵 LOW
<!-- List F-XXX findings or "None" -->

---

## 5. Detailed Item Results

> **Every single checklist item** is listed here with its verdict.  
> This is the proof that the auditor verified each item individually.  
> Items are in checklist order. No items are skipped.

### Checklist 01 — Account Validation

```
[PASS]      AV-001: {reason — cite file that proves it}
[PASS]      AV-002: {reason}
[FAIL-8]    AV-003: {reason}
              File: {path:line}
              Impact: {what can go wrong}
              Fix: {what to change}
[N/A]       AV-004: {why not applicable}
...through AV-090
```

### Checklist 02 — Access Control

```
[PASS]      AC-001: {reason}
...through AC-055
```

### Checklist 03 — Arithmetic Safety

```
[PASS]      AR-001: {reason}
...through AR-063
```

### Checklist 04 — CPI & PDA

```
[PASS]      CPI-001: {reason}
...through RE-007
```

### Checklist 05 — State Machine

```
[PASS]      SM-001: {reason}
...through SM-074
```

### Checklist 06 — Economic & Logic

```
[PASS]      ECON-001: {reason}
...through ECON-092
```

### Checklist 07 — OpSec & Governance

```
[PASS]      OPS-001: {reason}
...through OPS-087
```

### Checklist 11 — Supply Chain

```
[PASS]      SC-001: {reason}
...through SC-062
```

### Checklist 12 — Secrets & OpSec

```
[PASS]      SEC-001: {reason}
...through SEC-053
```

### Checklist 16 — Formal Verification & Testing

```
[PASS]      FV-001: {reason}
...through FV-073
```

### Known Vectors Results (every vector in `known-vectors/INDEX.md`)

```
[PASS]      KV-001: {reason}
[FAIL-9]    KV-013: {reason}
              File: {path:line}
              Impact: {what can go wrong}
              Fix: {what to change}
...through the last vector in INDEX.md
```

---

### Audit Metrics

| Metric | Value |
|--------|-------|
| Total items evaluated | <!-- N --> |
| PASS | <!-- N --> (<!-- % -->) |
| FAIL | <!-- N --> (<!-- % -->) |
| PARTIAL | <!-- N --> (<!-- % -->) |
| N/A | <!-- N --> (<!-- % -->) |
| **Pass rate** (excl. N/A) | **<!-- % -->** |
| Highest severity found | <!-- 1-10 --> |
| **Repository Risk Score** | **<!-- 1-10 -->** |

### Known Vector Metrics

| Metric | Value |
|--------|-------|
| Total known vectors | <!-- N in INDEX.md --> |
| PASS | <!-- N --> |
| FAIL | <!-- N --> |
| PARTIAL | <!-- N --> |
| N/A | <!-- N --> |
| Completion | <!-- % --> |

---

## 6. Instruction Matrix

> For on-chain program audits. One row per instruction.

| Instruction | File | Signers | CPI Calls | PDA Seeds | Checked Math | State Changes | Findings |
|---|---|---|---|---|---|---|---|
| <!-- name --> | <!-- file --> | <!-- who signs --> | <!-- target programs --> | <!-- seeds used --> | <!-- all checked? --> | <!-- what changes --> | <!-- F-XXX --> |

---

## 7. State Model Verification

### Account Types

| Account | Discriminator | Space | Owner | Close Target |
|---|---|---|---|---|
| <!-- name --> | <!-- verified? --> | <!-- bytes --> | <!-- program? --> | <!-- constrained? --> |

### State Machine Transitions

```
<!-- State diagram or transition table for key lifecycles (fund, withdrawal, etc.) -->
```

### Invariants Verified

| Property | Description | Status |
|---|---|---|
| <!-- INV-01 --> | <!-- description --> | ✅ PASS / ❌ FAIL |

---

## 8. Code Maturity Scorecard

> Engineering-quality gate (Phase 4.5), orthogonal to the risk score. 0 absent · 1 ad-hoc · 2 partial · 3 good · 4 strong (weakest-link).

| # | Category | Score (0-4) | Evidence (file:line / artifact) | Gap to next level |
|---|----------|:-----------:|---------------------------------|-------------------|
| 1 | Access Controls | | | |
| 2 | Arithmetic | | | |
| 3 | Account & Type Safety | | | |
| 4 | Input Validation | | | |
| 5 | Testing | | | |
| 6 | Fuzzing & Property Tests | | | |
| 7 | Error Handling & DoS Resilience | | | |
| 8 | Upgradeability & Governance | | | |
| 9 | Monitoring & Incident Response | | | |
| **Weighted Maturity** | | **X.X / 4.0** | | |

Categories scoring ≤ 1 are prioritized in the Remediation Roadmap regardless of individual finding severity.

---

## 9. Remediation Roadmap

### Immediate — Severity 9-10 (Block Deploy)

| Finding | Severity | Fix | Effort | Owner |
|---|---|---|---|---|
| F-XXX | 10 | <!-- description --> | <!-- hours/days --> | <!-- who --> |

### Before Release — Severity 7-8

| Finding | Severity | Fix | Effort | Owner |
|---|---|---|---|---|
| F-XXX | 8 | <!-- description --> | <!-- hours/days --> | <!-- who --> |

### Within 2 Weeks — Severity 5-6

| Finding | Severity | Fix | Effort | Owner |
|---|---|---|---|---|
| F-XXX | 6 | <!-- description --> | <!-- hours/days --> | <!-- who --> |

### Next Sprint — Severity 3-4

| Finding | Severity | Fix | Effort | Owner |
|---|---|---|---|---|
| F-XXX | 4 | <!-- description --> | <!-- hours/days --> | <!-- who --> |

### Backlog — Severity 1-2

| Finding | Severity | Fix | Effort | Owner |
|---|---|---|---|---|
| F-XXX | 2 | <!-- description --> | <!-- hours/days --> | <!-- who --> |

---

## 10. Re-Audit Checklist

- [ ] All Critical findings fixed and verified
- [ ] All High findings fixed and verified
- [ ] Medium findings addressed or accepted with documented risk
- [ ] Regression tests added for each fix
- [ ] Program re-deployed and verified on-chain
- [ ] Binary hash matches source code

---

## 11. Appendices

### A. Tool Versions

```
solana-cli: 
anchor-cli: 
pinocchio: 
solana-program: 
node:        (only if Anchor TS tests were run)
rustc: 
cargo: 
```

### B. Environment

```
OS: 
Cluster tested: devnet / mainnet-beta
RPC Provider: 
Execution mode: isolated (<how>) / native   (OUTPUT-RULES Rule 11a)
Outside services: <tool → service → data sent> / none   (Rule 11b)
```

### C. Disclaimer

This audit report is provided as-is. It represents a point-in-time review of the codebase at the specified commit. No guarantee is made that all vulnerabilities have been found. The audit does not constitute financial or legal advice.
