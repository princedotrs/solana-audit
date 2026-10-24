---
id: 142
title: "Pre-Allocated Account Init Hijack / Re-Initialization"
severity: 8
category: crypto
---

### 142 — Pre-Allocated Account Init Hijack / Re-Initialization

**Severity: 8 (9 when the protocol's own deploy scripts use a split flow for a global config/market)** | **Real: Metaplex Candy Machine v1 re-initialization (4 Jan 2022): the attacker made itself authority on live machines and then drained the lamports they held via the authority-only withdraw (JonLu reports 3,470 of 4,410 targeted machines); the `mut`→`zero` fix is inferred from solsec's note**

Large accounts (zero-copy slabs, order books, config tables, merkle buffers) and keypair accounts are created **client-side** (`SystemProgram.createAccount`, owner = program; a top-level create can allocate up to 10 MiB) and then initialised by the program. Three failure shapes:
1. **Re-callable initializer.** The init target is constrained only by `#[account(mut)]` (or an `UncheckedAccount` written with `serialize`/`load_init()`): it accepts a live account and overwrites the authority.
2. **Front-run of `zero`.** `#[account(zero)]` proves the account is program-owned, writable, rent-exempt and has an all-zero discriminator — **not** that the caller allocated it. <!-- verified: anchor v1.2.1 lang/syn/src/parser/accounts/constraints.rs (zero implies mut + rent_exempt = enforce), lang/syn/src/codegen/accounts/constraints.rs generate_constraint_zeroed --> If allocation and init are in different transactions, anyone can initialise the funded account first.
3. **Revived zero-filled account.** A manual close that zero-fills data but leaves `owner == program` (refunded by an attacker in the same tx) passes `zero` again and can be re-initialised with attacker fields while other state still references its key.
Anchor aliasing: in every released anchor-lang checked (0.31.1, 1.2.1, 2.0.0-rc.2) `init` fields are created before any other constraint runs and the `zero` uniqueness scan looks only at fields declared *before* it, so a `zero` field declared before an `init` field (or a `zero`/`init` pair split across composite `Accounts` structs) accepts the same fresh account for both — two writable typed views of one buffer. Fixed by #4871 on the master branch (Oct 2026), not yet in a tagged release as of v2.0.0-rc.2. <!-- verified: anchor v0.31.1 and v1.2.1 lang/syn/src/codegen/accounts/constraints.rs (take_while before current field), try_accounts.rs (init_fields emitted before access_checks); commit 035797c6 (#4871) contained in no tag -->

> Cross-ref: AV-099, AV-100, KV-014, KV-106, KV-127 (opposite direction: pre-creation DoS), AN-016/AN-017.

#### Verification Procedure

**Step 1: Find client-allocated init targets**
```
rg -n '#\[account\([^)]*\bzero\b' programs/
rg -n 'load_init\(\)' programs/
rg -n -B2 -A6 -i 'pub fn (initialize|init|create|setup)' programs/ | rg '#\[account\(mut'
rg -n 'data_len\(\)\s*==\s*0|data_is_empty\(\)|is_initialized' programs/
rg -n 'createAccount|create_account' --glob '*.ts' --glob '*.js' --glob '*.rs' app/ client/ sdk/ scripts/ tests/ 2>/dev/null
```

**Step 2: Re-callable initializer**
- ✅ PASS: every `load_init()` / first manual write targets an account constrained by `zero` (native: owner == program and **all** discriminator bytes zero, flag set in the same write)
- ❌ FAIL: `mut`-only init target; native guard on `data_len() == 0` for a pre-allocated account; no guard

**Step 3: Binding to the creator**
- ✅ PASS: `#[account(zero, signer)]` (the new keypair must sign), or the address is a PDA created by the program
- ⚠️: creation and init are in one transaction in today's SDK/scripts but nothing on-chain enforces it (any integrator that splits them is exposed)
- ❌ FAIL: SDK/deploy scripts split `createAccount` and `initialize` across transactions with no signer requirement and a caller-chosen authority

**Step 4: Revival through `zero`**
- ❌ FAIL: a manual close for the same type that does not `assign(System)` + `resize(0)` while a `zero` initializer exists (KV-106 Step 2)

```rust
// VULNERABLE: re-callable initializer over a client-created zero-copy account
#[derive(Accounts)]
pub struct InitBook<'info> {
    #[account(mut)]                                  // passes for a LIVE book too
    pub book: AccountLoader<'info, OrderBook>,
    pub authority: Signer<'info>,
}
// init_book(): let mut b = ctx.accounts.book.load_init()?; b.authority = ctx.accounts.authority.key();

// FIXED: first init only, and only by whoever holds the new account's keypair
#[derive(Accounts)]
pub struct InitBook<'info> {
    #[account(zero, signer)]
    pub book: AccountLoader<'info, OrderBook>,
    pub authority: Signer<'info>,
}
```

**Overall verdict:**
- ✅: all client-allocated init targets use `zero` bound to the creator (signer or same-tx creation)
- ⚠️: `zero` used, creation and init atomic in today's SDK but not enforced on-chain
- ❌: a live or someone-else's pre-allocated account can be initialised by the caller

*Sources: coral-xyz/sealevel-attacks `4-initialization` [paraphrased, no licence, https://github.com/coral-xyz/sealevel-attacks]; sannykim/solsec → Solens and JonLu Candy Machine write-ups [paraphrased, cited: https://medium.com/@solens_io/smashing-the-candy-machine-for-fun-and-profit-a3bcc58d6c30 , https://jonlu.ca/posts/candy-machine]; crytic/solana-lints U6 [paraphrased, cited]; Ackee bootcamp #9 [paraphrased, cited]; solana-foundation/anchor commit 035797c6 (#4871; Apache-2.0, behaviour described, no code copied).*
