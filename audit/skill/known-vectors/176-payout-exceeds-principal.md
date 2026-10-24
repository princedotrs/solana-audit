---
id: 176
title: "Payout Schedule Exceeds Recorded Principal"
severity: 8
category: crypto
---

### 176 — Payout Schedule Exceeds Recorded Principal

**Severity: 8 (HIGH → CRITICAL with a shared vault and permissionless claim)** | **Real: Ackee Solana Auditors Bootcamp CTF level-4 vesting; qedgen benchmark corpus**

Vesting, streaming, reward and interest payouts must never sum past the deposit. A formula wrong at the boundary passes every `checked_*` operation and still over-pays, so unchecked-arithmetic greps do not find it; with a shared vault the excess comes out of other depositors' principal ("the vault balance caps it" only means the last claimant absorbs the shortfall). Classic shape, defect from qedgen/solana-skills `skills/qedgen-auditor/references/category-catalog.md` `payout_exceeds_recorded_principal` [verbatim, MIT, (c) 2025 QEDGen]:
```rust
// periods counts the *current* period as already released
let periods = elapsed.checked_div(period_len)?.checked_add(1)?;
periods.checked_mul(per_period)?.checked_sub(already_paid)
```
The `+1` unlocks one full interval at `t = start` and runs one interval ahead of the linear curve. At `t = end` (or later, with `elapsed` clamped to `D`) it yields `floor(D/i) + 1` intervals. Without the clamp it keeps growing after `end`. So it over-pays whether or not `D` divides evenly. With `per_period = A·i/D`: A=1000, D=10, i=5 → 1500; i=3 → 1200. Also check `start`/`end` caller-supplied `u64` vs `i64` clock casts.

> Cross-ref: ECON-110, references/methodologies/vesting-streaming.md, invariant-catalog §11.

#### Verification Procedure
```
rg -n -i 'fn (claimable|releasable|vested|accrued|pending|unlocked)[a-z0-9_]*' programs/
rg -n 'checked_add\(1\)|/\s*[a-z_.]*interval\s*\+\s*1' programs/
rg -n '\.min\([a-z_.]*(amount|total|principal)' programs/      # absence near the payout fn is the smell
```
Evaluate each schedule at `now == start`, `now ≥ end` and the last period.
- ✅ PASS: payout clamped `min(computed, principal − already_paid)` before transfer; exact at end; property test (`unlocked(t) ≤ A`, monotone, `unlocked(start) == 0` unless a documented cliff/tranche, `unlocked(end) == A`)
- ❌ FAIL: any schedule can exceed principal

```rust
// FIXED
pub fn vested(total: u64, start: i64, end: i64, cliff: i64, now: i64) -> Option<u64> {
    if now < cliff.max(start) { return Some(0); }
    if now >= end { return Some(total); }                         // exact at end
    let elapsed = u128::try_from(now.checked_sub(start)?).ok()?;
    let dur = u128::try_from(end.checked_sub(start)?).ok()?;      // validated end > start at creation
    u64::try_from((total as u128).checked_mul(elapsed)?.checked_div(dur)?).ok()   // floor ≤ total
}
// claim: let claimable = vested(..)?.checked_sub(escrow.withdrawn)?;  assert withdrawn + claimable ≤ total
```

**Overall verdict:** ✅ Σ payouts ≤ principal at every t · ❌ boundary over-payment

*Sources: Ackee-Blockchain Solana-Auditors-Bootcamp `Capture-the-Flag/level-4` vesting [paraphrased, cited: https://github.com/Ackee-Blockchain/Solana-Auditors-Bootcamp/tree/master/Capture-the-Flag/level-4] with a corrected over-unlock condition; qedgen/solana-skills `skills/qedgen-auditor/references/category-catalog.md` `payout_exceeds_recorded_principal` (MIT, Copyright (c) 2025 QEDGen) — defect shape verbatim.*
