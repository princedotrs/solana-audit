---
name: solana-program-audit
description: "**SOLANA PROGRAM AUDIT SKILL** — Security auditor for Solana on-chain programs written in Rust: Anchor, native solana-program, and Pinocchio. USE FOR: auditing Solana/Anchor/Pinocchio/native programs, reviewing smart contract security, finding vulnerabilities (missing signer / owner checks, unchecked accounts, type cosplay, discriminator confusion, reinitialization, account revival after close, duplicate mutable accounts, PDA seed collision and non-canonical bumps, arbitrary / unchecked CPI targets, CPI reentrancy, arithmetic overflow / underflow / rounding / precision loss, sysvar and instruction-introspection spoofing, precompile signature bypass, Token-2022 extension and transfer-hook abuse, ATA / token-account mismatch, flash loan and oracle manipulation, first-depositor share inflation, MEV / front-running, compute-budget DoS, governance and upgrade-authority backdoors, timelock bypass, durable-nonce abuse), DeFi protocol reviews (AMM/CLMM, lending, perps, stablecoins, liquid staking, bridges, launchpads, NFT marketplaces, multisig/custody), Cargo supply-chain and program-key secret hygiene, formal verification and test-quality review, PoC exploits and fix patches, differential/PR audits, spec-compliance audits, re-audits of fixes, and generating audit reports. Severity 1-10 scale, scope-gated micro-checklists with item-by-item verdicts, known Solana attack vectors, chunked file-by-file execution. DO NOT USE FOR: writing new features, general coding, non-security reviews, off-chain code (TypeScript/JavaScript clients, backends, frontends, Python, Go, or other languages), EVM/Solidity contracts, or live incident response."
---

# solana-program-audit — Solana On-Chain Program Security Audit Skill

> **Based on:** Superteam Brazil `auditor-skill` v7.6 (MIT) — see [ATTRIBUTION.md](ATTRIBUTION.md)\
> **Items:** every item in checklists 01–07, 11, 12, 16 (+ the known vectors in `known-vectors/`)\
> **Targets:** Solana on-chain programs in Rust — Anchor, native `solana-program`, Pinocchio\
> **Severity:** 1–10 numeric scale\
> **Designed for:** Autonomous AI auditor agent or human-guided review

---

## Quick Reference

Start with [security.md](security.md) — the core Solana vulnerability catalog (owner / signer checks, arbitrary CPI, reinitialization, PDA sharing, type cosplay, duplicate mutable accounts, revival, data matching, rounding and precision) with Anchor prevention patterns, a condensed program checklist, and the **Security Review Questions** to answer for every instruction. The checklists, known vectors and references below are the deep layer on top of it.

**Quick audit output.** When the user just asks for a quick audit (no full engagement), write the report to `audit.md` using the short format below; replace everything in square brackets. Full engagements (Mode 1, the audit flows) use the templates in `templates/` instead.

```markdown
## Program Summary

[explain your understanding of what the program is supposed to do]

## Findings

### [NAME_OF_ISSUE] [Severity level: Critical, High, Medium, Low]

**File**: [path/to/file]

**Description**: [describe the finding]

**Scenario**: [if applicable, write a scenario that exploits the issue]

**Recommendation**: [if applicable, include a recommended fix]
```

Severity words map to the 1–10 scale below (Critical 10–9, High 8–7, Medium 6–5, Low 4–1).

---

## SCOPE-GATED LOADING — Load What The Repo Needs

The skill does not read its whole corpus up front. It discovers the repo, declares a scope, loads only what that scope requires, then guarantees a verdict for every in-scope item.

**Step 1 — Discover (cheap, always).** Enumerate file extensions and markers (`Anchor.toml`, `Cargo.toml`, `programs/`, `solana-program` / `pinocchio` / `anchor-lang` dependencies). No checklists or vectors loaded yet.

**Step 2 — Declare scope.** Map the detected on-chain program code (+ any `--scope`) to the in-scope checklist set:

| Detected | Load checklists |
|----------|-----------------|
| `.rs` on-chain program / `Anchor.toml` (Anchor, native `solana-program`, Pinocchio) | 01–07 |
| **any repo** | 11, 12, 16 |

**Out of scope.** Off-chain code — TypeScript/JavaScript clients and SDKs, backends, frontends, Python, Go, and Rust off-chain services (keepers, indexers, bots) — is out of scope for this skill. Record it in the Scope Coverage table as `[N/A — out of scope: off-chain]`; only read it when needed to understand how an on-chain instruction is called.

Checklists outside this set are **never read**.

**Step 3 — Load on demand.** Load an in-scope checklist when its phase begins; load a known-vector only when its phase + domain trigger reaches it (`known-vectors/INDEX.md` groups vectors by domain section, each row with an `always (<phase>)` or feature-marker trigger). Beyond the phase gate, vectors and feature-specific checklist sections also load on **feature presence** via the INDEX **"Load when (markers)"** column and the prescan advisory manifest (`references/orchestration/pre-scan.md`): a vector/section whose feature markers are *provably absent* (empty prescan array or zero grep hits) is skip-deferred and renders `[N/A — feature absent]`. This is advisory only — it reopens on demand the instant a manual read surfaces the feature, and every in-scope item still gets a verdict (Rule 0).

**Completeness is output-side.** The audit is COMPLETE iff every in-scope item + phase-triggered vector has a verdict. Out-of-scope items render `[N/A — out of scope: <reason>]` from the gate. Every full report includes a **Scope Coverage** table. Full rule: see [OUTPUT-RULES.md](OUTPUT-RULES.md) Rule 0.

**Step 4 — Reference layer (progressive disclosure).** Beyond the checklists, load a `references/` file only when its trigger fires — deep coverage at zero cost when irrelevant:

| Reference | Load when (grep markers) |
|-----------|--------------------------|
| `references/framework-idioms/{anchor,native,pinocchio}.md` | that framework is detected |
| `references/framework-idioms/build-and-tooling.md` | build/toolchain errors or PoC-harness setup |
| `references/methodologies/amm-clmm.md` | `tick` · `sqrt_price` · `liquidity_net` · `fee_growth` · `bin_array` |
| `references/methodologies/lending.md` | `obligation` · `reserve` · `liquidation_threshold` · `borrow_index` · `ltv` |
| `references/methodologies/perps.md` | `funding_rate` · `mark_price` · `open_interest` · `maintenance_margin` · `vamm` |
| `references/methodologies/oracles.md` | `pyth` · `switchboard` · `PriceUpdateV2` · `PullFeed` · `confidence` |
| `references/methodologies/stablecoin.md` | `collateral_ratio` · `psm` · `cdp` · `debt_ceiling` · `redeem` · `peg` |
| `references/methodologies/liquid-staking.md` | `stake_pool` · `validator_list` · `exchange_rate` · `staker` · `withdrawer` · `restak` |
| `references/methodologies/governance.md` | `spl-governance` · `realm` · `proposal` · `vote_record` · `voter_weight` · `vsr` |
| `references/methodologies/bridges.md` | `guardian` · `vaa` · `post_vaa` · `verify_signatures` · `emitter` · `sequence` · `lz_receive` · `ism` · `attestation` |
| `references/methodologies/wallets-multisig-custody.md` | `threshold` · `multisig` · `member` · `propose` · `approve` · `execute_transaction` · `vault` · `guardian` · `recovery` · `spending_limit` |
| `references/methodologies/token-2022.md` | `token_2022` · `TokenInterface` · `transfer_hook` · `TransferFee` · `PermanentDelegate` · `ConfidentialTransfer` · `get_extension` · `spl_token_2022` · `token_acl` · `TACLkU6` · `gating_program` · `thaw_permissionless` |
| `references/methodologies/nft-marketplaces.md` | `metadata` · `listing` · `escrow` · `royalty` · `merkle` · `MplCore` · `auth_rules` · `collection` |
| `references/methodologies/launchpads.md` | `bonding_curve` · `reserve` · `graduate` · `virtual_reserves` · `route` · `swap` · `curve` |
| `references/invariant-catalog.md` | building an FV/fuzz harness or reconstructing per-function invariants (Phase 0.5) — reusable invariant menus per protocol class |
| `references/vuln-classes/zk-and-compression.md` | `groth16` · `spl-account-compression` · `bubblegum` · `merkle` · `nullifier` · `ConfidentialTransfer` |
| `references/vuln-classes/transaction-v1.md` | `getTransaction` · `getBlock` · `blockSubscribe` · `maxSupportedTransactionVersion` · `yellowstone` · `geyser` · `ComputeBudgetProgram` · `computeUnitPrice` · `feePayer` / `sponsor` / `paymaster` service · `load_instruction_at` · `transactionConfig` · `0x81` |
| `references/false-positives.md` | triaging any finding before reporting severity ≥ 6 |
| `references/orchestration/boundary-map.md` | delegating to the optional Trail of Bits tooling (see below) |
| `references/orchestration/pre-scan.md` | running the deterministic Rust pre-scanner (`audit-scan`) or the cross-audit memory store (`audit-mem`) |
| `references/orchestration/poc-harness.md` | building an executable PoC or fix patch (the `poc` / `patch` playbooks) — harness-framework selection or recording a `[PoC-*]` / `[FIX-*]` evidence tier |
| `references/audit-lifecycle/methodology.md` | running the `audit-cycle` or `audit-assist` playbook (our method) |
| `references/audit-lifecycle/firm-coverage.md` | choosing methodology / understanding firm practice |
| `references/audit-lifecycle/threat-model-bootstrap.md` | the `threat-model` playbook with `--bootstrap` or `--vulns` / `--seed` / `--parent`; or a trigger: intake §7 prior audit / incident · `fork of` · `forked from` · `white-label` (README/docs) · `security_txt!` `source_code` not among the remotes · prior `audit_*/REPORT.md` · audit / post-mortem / incident file in the tree |
| `references/report-format.md` | assembling the final report (Phase 5 / audit-reporter) |

**Optional Trail of Bits tooling.** This skill does not bundle third-party tooling. If the Trail of Bits skills (https://github.com/trailofbits/skills, CC-BY-SA-4.0) are installed separately, delegate the tasks listed in `references/orchestration/boundary-map.md` to them; otherwise use the native grep checks in [discovery/grep-commands.md](discovery/grep-commands.md) and note the tooling gap in the report.

**Bundled paths.** Every path this skill names for something it ships — `scripts/`, `tools/`, `templates/` and the corpus files above — is relative to `<skill-root>`: the directory containing this skill's SKILL.md, never the audited repo, which is usually the working directory. Playbooks (`commands/`) and agents run bundled executables from `<skill-root>` and read the corpus files they name relatively from it as well ([OUTPUT-RULES.md](OUTPUT-RULES.md) Rule 11e).

---

## Severity Scale (1–10)

- **10–9 🔴 CRITICAL** — fund drain / fund loss → **block deploy**
- **8–7 🟠 HIGH** — partial drain, privilege escalation, significant damage → **fix before release**
- **6–5 🟡 MEDIUM** — state corruption, DoS, logic bugs, moderate info leak → **fix soon**
- **4–1 🔵 LOW / ⚪ INFO** — minor leak, missing best practice, hardening, cosmetic → **next sprint / backlog**

Full severity table + decision guide: see [OUTPUT-RULES.md](OUTPUT-RULES.md) Rule 1.

---

## Core Principles

### 1. Walk The Code — Never One-Shot
Programs can be one file or hundreds. The auditor reads files **one at a time**, never guesses, and saves checkpoints between chunks. See [OUTPUT-RULES.md](OUTPUT-RULES.md) Rule 3.

### 2. Every Item Gets a Verdict
Every item in the in-scope checklists and every in-scope known vector appears in the report with an explicit verdict. Nothing is silently skipped. See [OUTPUT-RULES.md](OUTPUT-RULES.md) Rule 4.

### 3. Executive Summary First
Every report starts with a plain-language summary: what was audited, what was found, whether it's safe to deploy. See [OUTPUT-RULES.md](OUTPUT-RULES.md) Rule 2.

### 4. Framework Auto-Detection
The auditor detects the program framework (Anchor, native `solana-program`, Pinocchio) from markers and applies the matching checklists and framework idioms automatically. See [OUTPUT-RULES.md](OUTPUT-RULES.md) Rule 7.

### 5. Honesty Over Completeness
If context was lost, a file was too large, or a pattern is unfamiliar — say so. Never mark `[PASS]` without reading the code. See [OUTPUT-RULES.md](OUTPUT-RULES.md) Rule 10.

### 6. Operating Safety
Target-controlled code runs only in the execution mode chosen at intake (isolated recommended; native allowed, with a report caveat), the report names every outside service a tool contacts, a `.git/` the auditor did not clone is never allowed to run its config, audit output never reaches git or a public CI log, and bundled scripts, tools and corpus files resolve from `<skill-root>`, never from the audited repo. See [OUTPUT-RULES.md](OUTPUT-RULES.md) Rule 11.

---

## Audit Modes

- **Mode 1 — FULL Repository Audit.** Complete security review of every on-chain program in the repo. → Read [OUTPUT-RULES.md](OUTPUT-RULES.md), then follow [FULL-AUDIT.md](FULL-AUDIT.md) top to bottom (discovery, per-instruction review, report via [templates/report-template.md](templates/report-template.md)).
- **Mode 2 — Targeted Checklist Audit.** Review a specific domain or subset of files. → Read [OUTPUT-RULES.md](OUTPUT-RULES.md) + the relevant `checklists/` file, walk target files one at a time, record every verdict inline.
- **Mode 3 — Single Instruction Review.** Deep-dive into one instruction handler. → Read the source completely, fill [templates/instruction-worksheet.md](templates/instruction-worksheet.md), cross-reference shared-state code.
- **Mode 4 — Differential / PR-Scoped Audit.** A PR, commit range, or branch — not the whole tree. → The `diff-audit` playbook ([commands/diff-audit.md](commands/diff-audit.md)): changed-set → Phase 0.5 on changed fns + 1-hop → risk-classify + git-blame removed guards → in-scope items through Rule 5b → dependency lane (checklist 11 §11.11) when a manifest or lockfile changed → `audit_<n>/PR-REPORT.md`.
- **Mode 5 — Spec-Compliance Audit.** A spec / whitepaper / RFC is supplied and you need code-vs-spec conformance. → The `spec-audit` playbook ([commands/spec-audit.md](commands/spec-audit.md)): Spec-IR requirement list → map each instruction/state field → Compliance Matrix through the Rule 5b gate.

---

## Audit Flows (full engagement lifecycle)

Two flows run the traditional audit-company lifecycle over the skill's **existing** mechanisms (scope-gating → Phase 0.5 context → manual review → Rule 5b verification → Phase 4.5 maturity → report). Method: [references/audit-lifecycle/methodology.md](references/audit-lifecycle/methodology.md); how real firms work: [references/audit-lifecycle/firm-coverage.md](references/audit-lifecycle/firm-coverage.md). When a prior audit, an incident or a fork parent is detected, both flows also seed the threat model from history, offline ([references/audit-lifecycle/threat-model-bootstrap.md](references/audit-lifecycle/threat-model-bootstrap.md)).

- **The `audit-cycle` playbook** ([commands/audit-cycle.md](commands/audit-cycle.md)) — *fully automated audit team.* Runs the whole lifecycle autonomously: domain-partitioned `vuln-hunter` + `economic-analyst` (each self-triaging via Rule 5b + `false-positives.md` at the leaf) → independent `peer-reviewer` reconciliation on top-severity findings → `audit-reporter` synthesis → a client-facing report ([templates/audit-report.md](templates/audit-report.md)) at `audit_<n>/REPORT.md` (+ optional PDF via `"<skill-root>/scripts/report-to-pdf.sh"`, pandoc-gated — MD is always the deliverable).
- **The `audit-assist` playbook** ([commands/audit-assist.md](commands/audit-assist.md)) — *AI-assisted, human-in-the-loop.* Same lifecycle, pausing at checkpoints to surface confirmed findings + next-focus + the questions only a human can answer (business context, trust model, severity calls); iterates until the audit document converges.
- **The `re-audit` playbook** ([commands/re-audit.md](commands/re-audit.md)) — *fix-review.* Diffs against a prior report: per-finding `FIXED` / `STILL-OPEN` / `REGRESSED`, plus a sibling-patch-propagation sweep (grep the codebase for the same anti-pattern the fix closed).

Honestly scoped: this is audit-shaped automation / a rigorous first pass, not a substitute for a human firm audit. The client report follows firm convention — maturity narrative + trust-model caveats + disclaimer — and does **not** issue a "safe to deploy" guarantee. *(Precedents: Neodyme independent dual-review, Trail of Bits weekly progress reports + code-maturity, Sec3 shift-left, Zellic importance-ordering, Zenith delta review.)*

---

## Rationalizations to Reject

An auditor talks itself out of real findings with lines like these. Treat each as a RED FLAG that demands the Rule 5b gate — not a reason to skip:

- "It's only devnet / a test program." → Audit as if mainnet; devnet code ships.
- "The math can't overflow because values are always small." → Prove the bound (Rule 5b Math/State-Bounds) or report it.
- "`init_if_needed` is fine here." → It permits reinitialization; prove the guard or flag it.
- "Only the admin can call this." → Confirm the signer/authority check exists in code; "should be" is not "is".
- "The client validates it." → On-chain must not trust off-chain validation.
- "This `unwrap()` can't fail." → On attacker-supplied input or account data it can — that is a DoS.
- "It's the same as a well-known program." → Verify line-by-line; forks drift.

*(Scaffolding pattern credit: Trail of Bits `skill-improver`.)*

## When NOT to Use

- Writing new features or general (non-security) code — this skill only audits.
- Off-chain code (clients, SDKs, backends, frontends, keepers, other languages) or non-Solana contracts — out of scope for this skill.
- As the sole gate for a mainnet launch — it is a thorough first pass; pair it with a human audit for business-logic, economic-model, and legal-compliance review.
- As formal proof of correctness — it flags where proofs/harnesses are missing (and can orchestrate them via the optional Trail of Bits tooling when installed), but does not itself constitute a machine-checked proof.
- Post-incident detection and response (threat hunting over transaction history, containment) — out of scope for this skill.

---

## Framework → Checklist Mapping

Authoritative mapping → **Scope-Gated Loading, Step 2** (scope table) above. Any on-chain Solana program (Anchor, native, Pinocchio) → 01–07; always-applied (any repo): 11, 12, 16. Framework-specific idioms load from `references/framework-idioms/`.

---

## Checklists Reference

| # | Checklist | Items | Domain | File |
|---|-----------|-------|--------|------|
| 01 | Account Validation | 90 | On-chain | [01-program-account-validation.md](checklists/01-program-account-validation.md) |
| 02 | Access Control | 55 | On-chain | [02-program-access-control.md](checklists/02-program-access-control.md) |
| 03 | Arithmetic Safety | 63 | On-chain | [03-program-arithmetic-safety.md](checklists/03-program-arithmetic-safety.md) |
| 04 | CPI & PDA Safety | 70 | On-chain | [04-program-cpi-pda.md](checklists/04-program-cpi-pda.md) |
| 05 | State Machine & Lifecycle | 74 | On-chain | [05-program-state-machine.md](checklists/05-program-state-machine.md) |
| 06 | Economic & Logic Attacks | 92 | On-chain | [06-program-economic-logic.md](checklists/06-program-economic-logic.md) |
| 07 | OpSec & Governance | 87 | Operations | [07-program-opsec-governance.md](checklists/07-program-opsec-governance.md) |
| 11 | Supply Chain & Dependencies | 62 | DevOps | [11-supply-chain.md](checklists/11-supply-chain.md) |
| 12 | Secrets & Key Management | 53 | DevOps | [12-secrets-opsec.md](checklists/12-secrets-opsec.md) |
| 16 | Formal Verification & Testing | 73 | Testing | [16-formal-verification-testing.md](checklists/16-formal-verification-testing.md) |
| | **Total** | **719** | | |

Known attack vectors: [known-vectors/INDEX.md](known-vectors/INDEX.md).

---

## How to Use

### Quick audit
```
Audit the Solana program in programs/<your_program>/ and write the findings to audit.md
```

### Full repository audit
```
Audit the entire repository using the solana-program-audit skill with FULL scope
```

### Program-only audit
```
Audit the Solana program in programs/<your_program>/ using the solana-program-audit skill with PROGRAM scope
```

### Specific checklist
```
Run solana-program-audit checklist 03 (Arithmetic Safety) on programs/<your_program>/
```

---

## Recording Format

For every checklist item, record one of: `[PASS]` · `[FAIL-N]` · `[PARTIAL]` · `[N/A]`.

Full verdict-format rules (what each token must cite): see [OUTPUT-RULES.md](OUTPUT-RULES.md) Rule 4.

---

## Porting to Another Repository

This entire skill folder is self-contained and portable:

1. Install the whole skill directory outside the target repository, e.g. at a user-level skills path for your AI coding agent ([OUTPUT-RULES.md](OUTPUT-RULES.md) Rule 11e)
2. Record the target's folder structure at intake (`QUESTIONS.md` Q39 in-scope paths, Q44 exclusions) rather than editing `discovery/file-map.md`, which an update overwrites
3. Checklists 01-07: any Solana program (Anchor, native, Pinocchio)
4. Checklists 11, 12, 16: always applied — dependencies, secrets/keys, verification and test quality
5. OUTPUT-RULES.md: applies to every audit run with this skill

---

## References

- [Sealevel Attacks (coral-xyz)](https://github.com/coral-xyz/sealevel-attacks) — canonical Solana exploit examples
- [Neodyme: Common Pitfalls](https://neodyme.io/en/blog/solana_common_pitfalls/) — top 5 Solana contract vulnerabilities
- [Solana Security Course](https://solana.com/developers/courses/program-security) — official security curriculum
- QEDGen SPEC Format — formal verification methodology (create your own SPEC.md following this structure)
- [CertiK Audit Methodology](https://www.certik.com/products/security-audit) — manual review + formal verification + Skynet monitoring
- [Superteam Brazil auditor-skill](https://github.com/solanabr/auditor-skill) — upstream source of this skill's corpus (MIT)
