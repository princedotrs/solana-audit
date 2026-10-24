---
id: 143
title: "PDA Signer Sharing / Cross-Instance Vault Drain"
severity: 9
category: crypto
---

### 143 — PDA Signer Sharing / Cross-Instance Vault Drain

**Severity: 9 when the shared PDA custodies other users' funds** | **Real: Sealevel Attacks class 8 (`8-pda-sharing`); Ackee Solana Auditors Bootcamp CTF level-4 escrow drain**

KV-026 asks whether two logical accounts *collide* on one address. Here the sharing is deliberate: one PDA is the token authority for many vaults (all pools of a mint, all escrows: `seeds = [b"AUTH"]`). Any instruction that makes that PDA sign has authority over every vault it owns. The attacker never forges a PDA: they create their own valid state account (pool, position, escrow — often permissionlessly) that names the **victim's** vault and the attacker's destination. `has_one` passes because the attacker wrote those fields; the program signs with seeds that resolve to the shared PDA.

> Cross-ref: PDA-022, KV-026, KV-144, anchor.md §5 seeds row.

#### Verification Procedure

**Step 1: Signing sites, their seeds, and the accounts each PDA controls**
```
rg -n 'with_signer|new_with_signer|invoke_signed|signer_seeds' programs/
rg -n 'token::authority\s*=|associated_token::authority\s*=|set_authority|AuthorityType::' programs/
rg -n 'seeds\s*=\s*\[\s*b"[A-Za-z_]+"\s*(\.as_ref\(\))?\s*\]' programs/
```
For each signing PDA write: **authority domain** (every token/lamport account it controls), **seed scope** (constant / mint / pool / user), **binding path** (constraint tying the state account that supplies the seeds to this vault and destination).

**Step 2: Can a new instance make the same PDA sign for someone else's vault?**
- ✅ PASS: the PDA seeds include the key of the state object that owns the vault (`[b"pool_auth", pool.key()]`), the state account is itself seeds-verified, and vault/destination are bound (`has_one = vault`, `token::authority = pool_auth`, `address = escrow.vault`)
- ❌ FAIL: PDA seeds built only from shared values (constant, mint, program-wide config) while a caller-creatable state account names the vault. (Seeding by the destination is one safe pattern among several; per-instance seeding is the requirement.)

```rust
// VULNERABLE: authority PDA = [b"auth", mint] signs for every pool of that mint
#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(has_one = vault, has_one = recipient, has_one = authority)]   // attacker-created pool passes this
    pub pool: Account<'info, Pool>,
    pub authority: Signer<'info>,                                  // the attacker, owner of their own pool
    #[account(mut)] pub vault: Account<'info, TokenAccount>,      // victim's vault
    #[account(mut)] pub recipient: Account<'info, TokenAccount>,  // attacker's account
    /// CHECK: signer-only PDA
    #[account(seeds = [b"auth", pool.mint.as_ref()], bump)]
    pub auth: UncheckedAccount<'info>,
    pub token_program: Program<'info, Token>,
}

// FIXED: authority scoped per pool; vault bound to that authority. The binding that stops the
// drain is token::authority = auth with auth seeded by pool.key(): an attacker's pool derives a
// different auth, so it cannot name the victim's vault. (The pool's own seeds use its stored
// fields, which proves only that it is a genuine pool; see KV-144.)
#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(seeds = [b"pool", pool.mint.as_ref(), pool.creator.as_ref()], bump = pool.bump,
              has_one = vault, has_one = recipient, has_one = authority)]
    pub pool: Account<'info, Pool>,
    pub authority: Signer<'info>,
    #[account(mut, token::authority = auth)] pub vault: Account<'info, TokenAccount>,
    #[account(mut)] pub recipient: Account<'info, TokenAccount>,
    /// CHECK: signer-only PDA, unique per pool
    #[account(seeds = [b"pool_auth", pool.key().as_ref()], bump = pool.auth_bump)]
    pub auth: UncheckedAccount<'info>,
    pub token_program: Program<'info, Token>,
}
```
**PoC:** create a second pool/escrow pointing at the existing vault with the attacker's destination, then withdraw.

**Overall verdict:**
- ✅: every signing PDA is per-instance and bound to its vaults
- ⚠️: shared authority but every vault is bound to a trusted, non-creatable instance
- ❌: a caller-creatable instance can direct a shared PDA over another instance's vault

*Sources: coral-xyz/sealevel-attacks `8-pda-sharing` [paraphrased, cited: https://github.com/coral-xyz/sealevel-attacks/tree/master/programs/8-pda-sharing] <!-- verified: insecure signs with [pool.mint, bump]; secure seeds by withdraw_destination -->; Ackee bootcamp CTF level-4 [paraphrased, cited] (level-5 binds its vault); Sealevel Sentinel #5 (MIT, Copyright (c) 2026 Stan (stantheman0128)) with an added per-instance requirement; Solana Foundation course U8 [paraphrased, cited].*
