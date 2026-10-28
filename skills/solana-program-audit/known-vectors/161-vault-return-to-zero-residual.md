---
id: 161
title: "Vault Return-to-Zero Residual Capture"
severity: 7
category: crypto
---

### 161 — Vault Return-to-Zero Residual Capture

**Severity: 7 (higher when residual value is large or the vault re-opens predictably)** | **Real: Plamen `zero-state-return` audit class**

First-depositor protections (ECON-013..017/069, KV-006) usually run at genesis. A vault can **return** to `total_shares == 0` after everyone exits while value remains: accrued-but-undistributed rewards, locked/streaming profit, fee balances, high-water marks, rounding dust in the PDA token account. The next depositor then meets the first-depositor condition on a pre-seeded vault, often without the protections that ran only in `initialize`. Default-zero timestamps (`last_update = 0`) on re-entry also make `now - last_update` enormous and can drive accrual or decay math.

> Cross-ref: ECON-098, invariant-catalog §11, KV-006, KV-017.

#### Verification Procedure
```
rg -n 'total_shares\s*==\s*0|supply\s*==\s*0|shares\s*=\s*amount' programs/
rg -n 'locked_profit|acc_reward_per_share|pending_fees|high_water_mark|last_report|last_update' programs/
rg -n 'VIRTUAL_|DEAD_SHARES|MINIMUM_LIQUIDITY' programs/
```
- Can supply reach exactly 0 (are dead shares burned only in `initialize`, or is the protection keyed to `!initialized`)?
- On supply 0, which fields survive? Compute the exchange rate for a 1-unit re-entry with that residual.
- ✅ PASS: virtual offsets/dead shares apply on every mint path; residual value is swept or distributed when supply hits 0; timestamps reset on re-entry
- ❌ FAIL: 1:1 minting on `total_shares == 0` while residual value remains claimable

```rust
// VULNERABLE: residual rewards persist; 1:1 mint on empty supply
if vault.total_shares == 0 { shares = amount; }

// FIXED: rate always includes virtual offsets; u128 checked math; round shares DOWN on mint
let num = (amount as u128)
    .checked_mul((vault.total_shares as u128).checked_add(VIRTUAL_SHARES).ok_or(ErrorCode::Math)?)
    .ok_or(ErrorCode::Math)?;
let den = (vault_assets as u128).checked_add(VIRTUAL_ASSETS).ok_or(ErrorCode::Math)?;
let shares = u64::try_from(num.checked_div(den).ok_or(ErrorCode::Math)?).map_err(|_| ErrorCode::Math)?;
```

**Overall verdict:**
- ✅: no residual is claimable by the next minter at an unprotected rate
- ❌: return-to-zero reopens first-depositor extraction

*Sources: PlamenTSV/plamen `agents/skills/solana/zero-state-return/SKILL.md` (MIT, Copyright (c) 2025-2026 Plamen Contributors); fixed formula rewritten with u128 checked math.*
