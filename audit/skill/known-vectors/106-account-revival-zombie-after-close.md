---
id: 106
title: "Account Revival / Zombie After Close"
severity: 8
category: crypto
---

### 106 — Account Revival / Zombie After Close

**Severity: 8** | **Real: Solana close-account revival class (incomplete close → reuse of stale state)**

Closing an account safely requires, in the same instruction: transfer ALL lamports out, `assign` the account to the System Program, and `resize/realloc(0)` — modern Anchor `close = dst` does exactly this (since 0.26.0; the `CLOSED_ACCOUNT_DISCRIMINATOR` constant was removed in 0.30.0; FP-2). Older Anchor (sentinel era, ≤ 0.25) wrote `[255;8]` and left the owner unchanged. <!-- verified: anchor v0.25.0 vs v0.26.0 lang/src/common.rs close(); CLOSED_ACCOUNT_DISCRIMINATOR present in v0.29.0 lang/src/lib.rs, absent in v0.30.0 --> An incomplete close — manual lamport transfer without reassigning the owner and truncating the data, or leaving the account funded above rent-exemption — leaves a "zombie": the account still exists and can be deserialized later in the same transaction (or refunded by an attacker to survive GC), exposing stale balances/positions. Combined with `init_if_needed`, a closed account can be "revived" with attacker-favorable stale data.

#### Verification Procedure

**Step 1: Find all account closes**
```
grep -rn --include="*.rs" -E "close = |close_account|\.close\(|CLOSED_ACCOUNT_DISCRIMINATOR|\*\*lamports|try_borrow_mut_lamports" programs/
```
- Separate Anchor `close = dest` (safe) from manual lamport-draining closes (review each)

**Step 2: Manual closes do all three steps**
```
rg -n '\*\*\s*[A-Za-z_][\w.()]*\.lamports\.borrow_mut\(\)\s*=\s*0\b|try_borrow_mut_lamports|sub_lamports\(|set_lamports\(0\)' programs/
rg -n '\.assign\(|resize\(0|realloc\(0|CLOSED_ACCOUNT_DISCRIMINATOR|force_defund' programs/
```
- ✅ PASS: drain + `assign(&system_program::ID)` + `resize(0)` in one instruction, `dst != acct`; on sentinel-era code, a permissionless defund path exists for sentinel-marked accounts
- ❌ FAIL: lamports drained (or data zero-filled) but owner left as the program — a refunded account survives as program-owned; if any instruction initializes that type via `#[account(zero)]`, the zero-filled account is re-initializable with attacker fields (KV-142)

**Step 3: No stale access after close in the same transaction**
```
grep -rn --include="*.rs" -E "init_if_needed" programs/
```
- ✅ PASS: A closed account cannot be re-read or `init_if_needed`-revived with stale fields later in the tx
- ❌ FAIL: Subsequent instruction/CPI can read or re-init the closed account

**Step 4: Revival via lamport refund**
- For PDAs that gate a one-time action (claims, withdrawals): confirm that re-funding the closed address with lamports cannot resurrect stale "unclaimed" state
- ✅ PASS: State is re-derived/re-checked against authoritative source; refund cannot revive a claim
- ❌ FAIL: Re-funded address re-enables a completed action

**Step 5: Closed markers and families**
- ❌ FAIL: a one-shot marker PDA (claim receipt, nonce, vote record) is **closed** rather than kept, with seeds the same user can re-derive — `init` re-creates it with default fields and re-enables the action ("a closed marker equals an absent marker")
- ❌ FAIL: other state still references the closed account by key, or children seeded by it revive when the parent is re-created (KV-175)
- PoC: one transaction `[claim_and_close(entry), system_transfer(attacker → entry, rent)]`, then try the re-creation path separately

*Sources: coral-xyz/sealevel-attacks (repo `programs/9-closing-accounts`), crytic/solana-lints U6, Solana Foundation course U1/U7 [paraphrased, cited]; qedgen/solana-skills C2 (MIT, Copyright (c) 2025 QEDGen); Sealevel Sentinel (MIT, Copyright (c) 2026 Stan (stantheman0128)); workersio note (#2169, #2726).*

**Overall verdict:**
- ✅: All closes use Anchor `close` or a complete manual pattern (fully drained + assigned to System + resized to 0); no stale re-read/re-init
- ⚠️: Closes are safe but `init_if_needed` present without a revival guard
- ❌: Manual close leaves deserializable data, or refund can revive stale state
- N/A: Program never closes accounts
