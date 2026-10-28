---
id: 3
title: "Reentrancy (CPI)"
severity: 10
category: crypto
---

### 3 — Reentrancy (CPI)
**Severity: 10** | **Real: The DAO ($60M), Curve ($70M)**

> **Solana model (read first).** The runtime rejects A → B → A (`ReentrancyNotAllowed`), including A → Token-2022 → hook → A; only direct self-recursion A → A is allowed (up to the CPI nesting limit: max instruction stack height 5, i.e. four nested CPIs; 9, i.e. eight nested CPIs, once SIMD-0268 `raise_cpi_nesting_limit_to_8` is active on the target cluster). <!-- verified: agave v4.4.0-beta.1 program-runtime/src/invoke_context.rs (ReentrancyNotAllowed unless caller == callee), program-runtime/src/execution_budget.rs (MAX_INSTRUCTION_STACK_DEPTH = 5, _SIMD_0268 = 9) --> The Ethereum examples in the header are analogies only. On Solana this vector covers: (1) **stale state after a CPI** (caller decides from a cached copy the callee changed); (2) **untrusted code in the caller's critical section** (hooks, caller-chosen CPI targets) acting on forwarded privileges or third programs while the caller's invariants are false — not by calling back; (3) **self-CPI** through a caller-chosen program id (RE-008) and Anchor exit write-back clobbering (RE-009/RE-010); (4) **cross-instruction sequencing** within one transaction. See FP-1.

*Sources: solana-foundation/solana-dev-skill `skills/solana-dev/references/security.md` "Self-Reentrancy (A → A)" (MIT, Copyright (c) 2026); qedgen/solana-skills `skills/qedgen-auditor/references/known-non-findings.md` reentrancy entry (MIT, Copyright (c) 2025 QEDGen); PlamenTSV/plamen `agents/skills/solana/flash-loan-interaction/SKILL.md` §5, `#[access_control]` claim corrected (MIT, Copyright (c) 2025-2026 Plamen Contributors).*

Malicious contract calls back during state change — Solana version: CPI to untrusted program that calls back before state is saved.

#### Verification Procedure

**Step 1: Find all CPI calls**
```
grep -rn --include="*.rs" "invoke(\|invoke_signed(\|CpiContext::new" programs/
```
- Record: Every CPI call with file:line

**Step 2: For each CPI, verify state is saved BEFORE the CPI**
```
# For each CPI location found in step 1, check the surrounding code
# State writes (to account data) must happen BEFORE invoke/invoke_signed
```
- ✅ PASS: All state mutations complete before CPI call (checks-effects-interactions pattern)
- ❌ FAIL: Any CPI call where state is written AFTER the call returns

**Step 3: Check for in-flight flags on multi-instruction flows (cross-instruction guards; `#[access_control]` is a precondition hook, not a reentrancy guard)**
```
grep -rn --include="*.rs" "ReentrancyGuard\|reentrancy_guard\|#\[account.*realloc" programs/
```
- ✅ PASS: Reentrancy guard is used on state-modifying instructions, OR program only CPIs to trusted programs (SPL Token, System)
- ⚠️ PARTIAL: No explicit guard, but all CPIs are to well-known programs

**Step 4: Verify CPI targets are trusted programs**
```
grep -rn --include="*.rs" -B3 "CpiContext::new" programs/ | grep -E "program|\.key\(\)"
```
- ✅ PASS: Every CPI target is a hardcoded well-known program (Token, System, Associated Token)
- ❌ FAIL: Any CPI target comes from user-supplied account or remaining_accounts

**Step 5: Check for callback patterns**
```
grep -rn --include="*.rs" "remaining_accounts.*invoke\|invoke.*remaining" programs/
```
- ✅ PASS: No CPIs to accounts from remaining_accounts
- ❌ FAIL: Program invokes unknown programs from remaining_accounts

**Overall verdict:**
- ✅: All state written before CPI, all CPIs to trusted programs, no user-controlled CPI targets
- ⚠️: CPIs to trusted programs only but state ordering is inconsistent
- ❌: CPI to user-controlled program AND state written after CPI
