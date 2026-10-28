---
id: 162
title: "Unbacked Pre-Funded Reserve at Initialization"
severity: 8
category: crypto
---

### 162 — Unbacked Pre-Funded Reserve at Initialization

**Severity: 8** | **Real: SPL stake-pool `process_initialize` (Sec3 X-ray finding; fixed by solana-program-library PR #2636 "Mint extra reserve lamports as pool tokens on init"): in the Sec3 PoC a 1 SOL deposit into a pool whose reserve already held 100 SOL withdrew about 98 SOL net; the post warns that forks may still carry it**

KV-006/KV-017 model an attacker donating *after* deployment. Here the protocol *starts* inconsistent: `total_assets > 0` while `total_shares == 0`, because initialization accepted a reserve/vault that already held value (lamports above the required minimum, tokens in the vault ATA, lamports sent to a PDA before `init`, a migrated account) and minted nothing for it. Whoever funded it loses; the next depositor captures it — no donation step needed.

> Cross-ref: ECON-106, KV-006, KV-017, liquid-staking.md §16.

#### Verification Procedure
```
rg -n -i 'fn (process_)?initiali[sz]e' programs/
rg -n -i 'reserve|vault|treasury' programs/ | rg -i 'lamports\(\)|amount|balance'
```
- ✅ PASS: init asserts the reserve/vault holds exactly the expected amount (rent minimum, or 0 tokens), or mints matching shares for any excess
- ❌ FAIL: init accepts an existing balance and sets `total_shares = 0` while assets are derived from live balances

```rust
// FIXED (native style). `floor` is the minimum the design requires the reserve to hold: the
// rent-exempt reserve for an undelegated reserve stake account (SPL stake-pool style), plus the
// minimum stake delegation only for an account that must stay delegated.
let floor = Rent::get()?.minimum_balance(reserve.data_len());
let excess = reserve.lamports().checked_sub(floor).ok_or(PoolError::BadReserve)?;
if excess > 0 {
    // either reject:
    // return Err(PoolError::ReserveNotEmpty.into());
    // or account for it by minting pool tokens 1:1 (SPL stake-pool's fix mints them to the
    // manager's fee account):
    mint_pool_tokens(manager_fee_account, excess)?;
    pool.total_lamports = excess;
    pool.pool_token_supply = excess;
}
```

**Overall verdict:**
- ✅: no pre-existing value is left unbacked at init
- ❌: the first depositor can capture pre-funded value

*Sources: sannykim/solsec → Sec3 "Solana Stake Pool: a semantic inconsistency vulnerability" [paraphrased, cited: https://www.sec3.dev/blog/solana-stake-pool-a-semantic-inconsistency-vulnerability-discovered-by-x-ray].*
