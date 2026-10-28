---
id: 163
title: "Wrapped-SOL `SyncNative` Balance Manipulation"
severity: 7
category: crypto
---

### 163 — Wrapped-SOL `SyncNative` Balance Manipulation

**Severity: 7 (inflation) / 5 (DoS via exact-equality reconciliation)** | **Real: SPL Token native-mint semantics (audit pattern)**

For a native-mint (wSOL) token account, `is_native = Some(rent_reserve)` and `amount = lamports − rent_reserve` after initialization or sync. Anyone can send lamports to any account, and **`SyncNative` takes only the writable token account (plus an optional Rent sysvar) and no signer**, so anyone can raise `amount`. This holds for SPL Token, p-token and Token-2022. `CloseAccount` on a native account succeeds with non-zero `amount` and sends all lamports; a non-native account must be empty first. A vault that prices shares from the vault's live `amount`, or asserts `vault.amount == state.total`, can be moved by a third party for the cost of the donation: share-price inflation without a token transfer (KV-006/KV-017), a 1-lamport DoS of exact-equality checks, or off-by-rent bugs when code mixes `lamports()` and `amount`. A `SyncNative` the program itself calls after its own deposit is normal; the finding is that **someone else** can call it.
<!-- verified: token HEAD program/src/processor.rs (process_sync_native; process_close_account NonNativeHasBalance only for non-native) and pinocchio/program/src/processor/sync_native.rs; token-2022 HEAD program/src/processor.rs process_sync_native -->

> Cross-ref: AV-112, ECON-105, AV-051, ECON-050, AR-055.

#### Verification Procedure
```
rg -n 'NATIVE_MINT|native_mint|So11111111111111111111111111111111111111112|sync_native|SyncNative|is_native' programs/
rg -n '\.amount\s*(==|!=)' programs/
rg -n 'lamports\(\).*amount|amount.*lamports\(\)' programs/
```
- ✅ PASS: internal accounting is the source of truth; balances only need to cover it (`>=`); virtual offsets in share math; `lamports()` and `amount` never mixed
- ❌ FAIL: live wSOL `amount` used for pricing, or exact-equality reconciliation

```rust
// VULNERABLE
let assets = ctx.accounts.wsol_vault.amount;             // attacker: system transfer + SyncNative
require!(ctx.accounts.wsol_vault.amount == ctx.accounts.state.total, ErrorCode::Desync);   // 1-lamport DoS

// FIXED
let assets = ctx.accounts.state.total_assets;            // changed only by deposit / withdraw / harvest
require!(ctx.accounts.wsol_vault.amount >= ctx.accounts.state.total_assets, ErrorCode::Insolvent);
```

**Overall verdict:**
- ✅: third-party lamport donations cannot move pricing or break reconciliation
- ❌: they can

*Sources: original analysis (behaviour checked against the SPL Token, p-token and Token-2022 processors).*
