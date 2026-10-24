---
id: 164
title: "Adopted Token Account: Surviving Close Authority, Close and Re-Create"
severity: 7
category: crypto
---

### 164 — Adopted Token Account: Surviving Close Authority, Close and Re-Create

**Severity: 7 (High when deposits are redirected; Medium when the result is a permanent DoS)** | **Real: SPL Token `SetAuthority(AccountOwner)` semantics (audit pattern)**

`SetAuthority(AccountOwner)` resets `delegate` and `delegated_amount`, but resets `close_authority` **only for native accounts** (same in SPL Token, p-token and Token-2022). A protocol that **adopts** a caller-created token account as its vault ("pass a token account whose owner is our PDA", or "we `set_authority` it to our PDA in `init`") inherits whatever close authority the creator set while it still owned the account. Later: (1) when the vault reaches `amount == 0` (fully withdrawn, epoch start), the attacker closes it with its close authority and takes the rent; (2) the attacker re-creates an account at the same address with `owner = attacker` whenever it can: at a **keypair** address it still holds the keypair, and with SPL Token (whose `InitializeImmutableOwner` is a no-op) an **attacker-wallet ATA** handed over by `SetAuthority` is simply re-created by the ATA program with `owner = attacker wallet`; (3) if the protocol stores the vault by address only (`address = state.vault`) and does not re-check `vault.owner == pda` on deposit, new deposits flow to the attacker — otherwise the result is a permanent DoS. A delegate set before the handover does **not** survive the owner change. Token-2022 accounts with `ImmutableOwner` (all Token-2022 ATAs; opt-in on keypair accounts) reject the owner change entirely, and a Token-2022 account with CPI Guard enabled rejects it too.
<!-- verified: token HEAD program/src/processor.rs + pinocchio/program/src/processor/set_authority.rs; token-2022 HEAD program/src/processor.rs process_set_authority (ImmutableOwner, CpiGuardOwnerChangeBlocked, close_authority cleared only if is_native); associated-token-account HEAD program/src/processor.rs (initialize_immutable_owner; initialize_account3 with owner = wallet); token HEAD program/src/processor.rs process_initialize_immutable_owner (no-op on SPL Token); anchor v0.28.0 lang/syn/src/parser/accounts/constraints.rs ("token_program" constraint) -->


> Cross-ref: AV-103, AV-067, KV-016, KV-107.

#### Verification Procedure
```
rg -n -B6 '(token|associated_token)::authority\s*=' programs/   # a match without `init` is a validated-not-created vault; so is `init_if_needed` on an address that is not this program's PDA or the authority's ATA (a pre-created account there is accepted as is)
rg -n 'set_authority|SetAuthority|AuthorityType::AccountOwner' programs/
rg -n 'close_authority' programs/
```
- ✅ PASS: the program creates its vaults at a PDA address no one holds a key for (`init` + `seeds` + `token::authority`); or, if adoption is unavoidable, it rejects `close_authority.is_some() || delegate.is_some()` and re-checks `owner == vault_authority` (and not frozen) on every use
- ❌ FAIL: an adopted vault with an unchecked close authority, stored and used by address only

```rust
// FIXED (preferred; token::token_program and InterfaceAccount need Anchor ≥ 0.28)
#[account(init, payer = payer, seeds = [b"vault", state.key().as_ref()], bump,
          token::mint = mint, token::authority = vault_authority, token::token_program = token_program)]
pub vault: InterfaceAccount<'info, TokenAccount>,
// FIXED (adoption unavoidable)
require!(vault.close_authority.is_none() && vault.delegate.is_none(), ErrorCode::DirtyVault);
require!(vault.owner == vault_authority.key() && !vault.is_frozen(), ErrorCode::BadVault);
```

**Overall verdict:**
- ✅: vaults are program-created at PDA addresses, or adopted vaults are scrubbed and re-checked
- ❌: an attacker can close and re-create an adopted vault

*Sources: original analysis; Ackee-Blockchain Solana-Auditors-Bootcamp `Capture-the-Flag/level-4` smell, corrected (delegate cleared; ImmutableOwner) [paraphrased, cited: https://github.com/Ackee-Blockchain/Solana-Auditors-Bootcamp/tree/master/Capture-the-Flag/level-4].*
