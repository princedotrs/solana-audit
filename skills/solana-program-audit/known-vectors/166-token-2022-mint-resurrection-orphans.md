---
id: 166
title: "Token-2022 Mint Resurrection: Orphan Accounts with a Stale Extension Set"
severity: 7
category: crypto
---

### 166 — Token-2022 Mint Resurrection: Orphan Accounts with a Stale Extension Set

**Severity: 7 (higher when a fee, hook, pause or KYC gate is a security control)** | **Real: Neodyme Token-2022 audit for Anza (2024-04-22), ND-ANZ-IN-01 "Mint Resurrection Attacks" (Informational, Accepted — permanent behaviour integrators must handle)**

A mint with `MintCloseAuthority` can be closed when `supply == 0` — which does **not** mean no token accounts exist — and re-initialised at the same address with a different extension set. Existing token accounts keep the account-level extensions they were created with (`NonTransferableAccount`, `TransferHookAccount`, `TransferFeeAmount`, `PausableAccount`, `ImmutableOwner`) and their frozen/unfrozen state. Shapes (checked against `solana-program/token-2022` main, program crate 11.1.0):
1. **Stuck vault.** Attacker mint with `MintCloseAuthority` + `NonTransferable`; a DEX/vault/escrow creates its vault for it (gets `NonTransferableAccount`); the mint is closed and re-created **without** `NonTransferable` and seeded. Deposits succeed; withdrawals fail (Token-2022 checks `NonTransferableAccount` on the **source**) — a permanent lock / honeypot.
2. **KYC / DefaultAccountState bypass.** Accounts created while the mint had no `DefaultAccountState=Frozen` stay unfrozen after re-creation with it — insiders skip the thaw gate (also Token ACL gates, KV-134).
3. **Hook / fee / pause bypass (still works).** The plain `Transfer` instruction takes no mint account; Token-2022 rejects it only if the **source** has `TransferHookAccount`, `TransferFeeAmount` or `PausableAccount`. An orphan source created before re-initialisation lacks them, so it moves tokens with **no fee, no hook CPI and no pause check** to any account of that mint. Orphans can be funded via `mint_to` (among destination-account extensions it checks only the `NonTransferable` requirements; it does refuse while the mint is paused), by transfers between orphans, or by an ordinary `TransferChecked` into an orphan when the re-created mint has no hook and the transfer's fee is zero. Only `TransferChecked`/`TransferCheckedWithFee` turn into a DoS (`set_transferring` needs `TransferHookAccount` on both accounts; a transfer whose calculated fee is non-zero to a destination without `TransferFeeAmount` returns `InvalidState`). Rule: a hook, fee or pause guarantee is only as strong as the guarantee that every holder account carries the required account extension.
4. **Soulbound bypass (mostly mitigated).** `mint_to` requires `NonTransferableAccount` + `ImmutableOwner` on the destination; re-check on any Token-2022 fork or reimplementation.
"The mint has no `MintCloseAuthority` now" does not prove it was never closed and re-created.
<!-- verified: token-2022 HEAD e1a2592c program/src/processor.rs (process_transfer: NonTransferableAccount on source; MintRequiredForTransfer branch for unchecked Transfer; InvalidState when fee > 0 and destination lacks TransferFeeAmount; set_transferring on source and destination), process_mint_to (NonTransferable requires ImmutableOwner + NonTransferableAccount; PausableConfig paused check) -->

> Cross-ref: TK-013, TK-014, TK-022, TK-023, token-2022.md §3/§11, KV-105.

#### Verification Procedure
```
rg -n 'MintCloseAuthority|close_authority|NonTransferable|NonTransferableAccount|DefaultAccountState|Pausable' programs/
rg -n 'init_if_needed|associated_token::|create_associated_token_account(_idempotent)?' programs/
rg -n 'get_extension_types|get_extension::<' programs/ | rg -v 'Mint>'
```
- ✅ PASS (all of): every token account the protocol accepts — its own vaults **and** user-supplied source/destination accounts — passes an account-vs-mint consistency check on use (all account extensions the current mint requires are present; no stale restriction such as `NonTransferableAccount` without `NonTransferable`; vault not unexpectedly frozen); mints with `MintCloseAuthority` are refused at registration **or** the protocol records `(mint, registered_slot, extension-set fingerprint, supply_seen)` and re-validates on use; vaults are created by the program at PDA addresses (a plain `init` on an `associated_token` vault lets anyone pre-create it and block pool creation, KV-127). Refusing `MintCloseAuthority` alone is not a PASS: orphans from a re-creation that happened before registration still exist. If the protocol relies on `DefaultAccountState = Frozen` (KYC), note that no account extension marks an account created before the re-creation, so the consistency check cannot catch shape 2; the gate needs its own allowlist or thaw record
- ❌ FAIL: only mint extensions are inspected; pre-existing accounts accepted with no consistency check

```rust
// Consistency check sketch. Paths: `spl_token_2022_interface` (re-exported as
// `anchor_spl::token_2022::spl_token_2022` on Anchor ≥ 1.0); on Anchor 0.x use the `spl_token_2022` crate,
// which exposes the same `extension` / `state` modules.
// `ExtensionType::get_required_init_account_extensions` carries #[deprecated] from spl-token-2022-interface
// 3.1.0 on (attribute says since 3.0.1); the replacement there is
// `extension::account_len::try_for_each_required_init_account_extension(mint_tlv_data, f)`.
fn assert_account_matches_mint(acct: &AccountInfo, mint: &AccountInfo) -> Result<()> {
    use spl_token_2022_interface::extension::{BaseStateWithExtensions, ExtensionType, StateWithExtensions};
    use spl_token_2022_interface::state::{Account, Mint};
    let (m, a) = (mint.try_borrow_data()?, acct.try_borrow_data()?);
    let mint_s = StateWithExtensions::<Mint>::unpack(&m)?;
    let acc_s  = StateWithExtensions::<Account>::unpack(&a)?;
    require_keys_eq!(acc_s.base.mint, mint.key(), ErrorCode::MintMismatch);
    let mint_exts = mint_s.get_extension_types()?;
    let acct_exts = acc_s.get_extension_types()?;
    #[allow(deprecated)]
    let required = ExtensionType::get_required_init_account_extensions(&mint_exts);
    require!(required.iter().all(|e| acct_exts.contains(e)), ErrorCode::OrphanedTokenAccount);
    if acct_exts.contains(&ExtensionType::NonTransferableAccount) {
        require!(mint_exts.contains(&ExtensionType::NonTransferable), ErrorCode::OrphanedTokenAccount);
    }
    require!(!acc_s.base.is_frozen(), ErrorCode::VaultFrozen);
    Ok(())
}
```
<!-- verified: token-2022 interface@v3.0.1 vs interface@v3.1.0 interface/src/extension/mod.rs (deprecation attribute first present in 3.1.0), interface/src/extension/account_len.rs (replacement helper); anchor v1.0.0 spl/src/token_2022.rs (pub use spl_token_2022_interface as spl_token_2022) -->
Fingerprint: hash `u16::from(ext)` (`ExtensionType` is `#[repr(u16)]` with `IntoPrimitive`) for each mint extension **excluding** `TokenMetadata`, `TokenGroup`, `TokenGroupMember` (the mint authority may add them later), plus rotatable authority keys (hook program id, permanent delegate, freeze authority).

**PoC (LiteSVM):** mint with `MintCloseAuthority` + `NonTransferable`; create the pool vault; close the mint; re-create at the same keypair with no extensions; deposit; withdraw → `NonTransferable` error.

**Overall verdict:**
- ✅: resurrected mints or orphan accounts are rejected
- ❌: any of shapes 1–3 is reachable

*Sources: Neodyme "SPL Token-2022: Don't shoot yourself in the foot with extensions" and Neodyme Token-2022 audit for Anza [paraphrased, cited: https://neodyme.io/en/blog/token-2022 , https://www.neodyme.io/reports/Token%202022%20-%202024.pdf]; bypass-vs-DoS, ATA-init fix, fingerprint and deprecation corrected and re-checked against `solana-program/token-2022` main (e1a2592c).*
