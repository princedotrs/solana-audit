---
id: 167
title: "Transfer-Hook `Execute` Unauthenticated (Hook Program Author Side)"
severity: 8
category: crypto
---

### 167 — Transfer-Hook `Execute` Unauthenticated (Hook Program Author Side)

**Severity: 8 (critical when the hook mutates PDA state that gates value: allowlists, vesting locks, points, counters)** | **Real: Neodyme Token-2022 article (hook author checks); Solana Foundation solana-dev-skill security section**

The baseline covers the **integrator** of a hooked mint (KV-023, KV-105(c), EXT-012, T2). Many audited programs **are** hooks: royalty enforcers, KYC/allowlist gates, transfer counters, points, vesting locks. `Execute` is an ordinary public instruction; unless it proves it runs inside a real Token-2022 transfer of a supported mint, anyone can call it directly (or from their own mint whose hook points here) with arbitrary accounts and amounts — corrupting counters, consuming allowances, emitting spoofed events.

> Cross-ref: HOOK-01..HOOK-06 (checklist 22), KV-023, KV-105.

#### Verification Procedure
```
rg -n 'spl_transfer_hook_interface|TransferHookInstruction|ExecuteInstruction|SPL_DISCRIMINATOR|#\[interface\(|#\[instruction\(discriminator|fn (transfer_hook|execute|fallback)\(' programs/
rg -n 'TransferHookAccount|transferring' programs/            # absent in a hook program => FAIL
rg -n 'extra-account-metas|ExtraAccountMetaList' programs/
```
Anchor hook entrypoints: `#[interface(spl_transfer_hook_interface::execute)]` on 0.30.x (deprecated in 0.31.0, removed in 1.0.0); `#[instruction(discriminator = ExecuteInstruction::SPL_DISCRIMINATOR_SLICE)]` from 0.31.0; older hooks route through a `fallback` function. <!-- verified: anchor v1.0.0 CHANGELOG.md (#2728 add, #3195 deprecate, #4156 remove `#[interface]`; #3137 `#[instruction]` discriminator override in 0.31.0) -->
- ✅ PASS: (HOOK-01) the mint is one this hook serves, validated against a PDA keyed by the mint; (HOOK-02) source **and** destination have `TransferHookAccount.transferring == true` (Token-2022 sets it on both accounts just before the hook CPI and clears it after) **and** are owned by Token-2022 (otherwise a hand-made account with the flag set passes); (HOOK-03) `source.mint == destination.mint == mint`; (HOOK-05) the extra-account-metas PDA is `[b"extra-account-metas", mint]` under this program, initialisable/updatable only by the mint's intended authority, and every trusted extra account is re-validated (owner, seeds, discriminator); (HOOK-06) no authorisation decision rests on signer privilege of any `Execute` account, and no core account is assumed writable — Token-2022 passes the four core accounts (source, mint, destination, authority) and the validation PDA read-only and non-signer. Extra accounts carry the writable/signer flags of their `ExtraAccountMeta`, lowered only when the same key already appears earlier in the hook instruction without that privilege (for example an extra that repeats a core account). If the client did not pass an extra to the outer Token-2022 instruction with the privilege its meta asks for, the hook CPI fails with a privilege-escalation error, so the transfer reverts rather than running with a demoted account. Whether an extra can ever arrive as a signer depends on the interface helper: the SPL helper (`spl-tlv-account-resolution` 0.10 `de_escalate_account_meta`) keeps a requested signer flag when the outer instruction granted it, while the `pinocchio-transfer-hook-interface` 0.1.0 port always clears it. So do not build hook authorisation on a signer extra: depending on the helper the deployed Token-2022 uses, the flag may be cleared and every transfer then fails. Amount logic must handle `amount == u64::MAX`: Token-2022 passes that value when a confidential transfer invokes the hook <!-- verified: token-2022 program@v11.1.0 program/src/processor.rs (set_transferring/unset_transferring around invoke_execute), program/src/extension/confidential_transfer/processor.rs (invoke_execute with u64::MAX); spl-transfer-hook-interface 0.10.0 src/instruction.rs (core metas new_readonly) and spl-tlv-account-resolution 0.10.0 src/state.rs de_escalate_account_meta (de-escalates only against keys already in the CPI); pinocchio-transfer-hook-interface@v0.1.0 programs/transfer-hook-interface/src/instructions/execute.rs (core metas readonly, is_signer always false), src/lib.rs EXTRA_ACCOUNT_METAS_SEED -->
- Optional (HOOK-04): require the top-level instruction to be Token-2022 via introspection — this also rejects every transfer made from another program's CPI (vaults, AMMs); use only for deliberately non-composable tokens, with the sysvar address-pinned
- ❌ FAIL: any of HOOK-01/02/03/05 missing

```rust
// VULNERABLE
pub fn execute(ctx: Context<Execute>, amount: u64) -> Result<()> {
    ctx.accounts.points.total += amount;                 // anyone can call Execute directly
    Ok(())
}
// FIXED
// anchor_spl::token_2022::spl_token_2022 is the spl-token-2022 crate on 0.31/0.32 and
// spl_token_2022_interface on 1.x; both expose these paths.
use anchor_spl::token_2022::spl_token_2022::{
    extension::{transfer_hook::TransferHookAccount, BaseStateWithExtensions, StateWithExtensions},
    state::Account as SplTokenAccount,
};

pub fn execute(ctx: Context<Execute>, amount: u64) -> Result<()> {
    for ai in [ctx.accounts.source.to_account_info(), ctx.accounts.destination.to_account_info()] {
        require_keys_eq!(*ai.owner, anchor_spl::token_2022::ID, HookErr::WrongOwner);
        let data = ai.try_borrow_data()?;
        let acc = StateWithExtensions::<SplTokenAccount>::unpack(&data)?;
        require_keys_eq!(acc.base.mint, ctx.accounts.mint.key(), HookErr::MintMismatch);
        require!(bool::from(acc.get_extension::<TransferHookAccount>()?.transferring), HookErr::NotTransferring);
    }
    require_keys_eq!(ctx.accounts.mint.key(), ctx.accounts.config.mint, HookErr::UnsupportedMint);
    // amount == u64::MAX when a confidential transfer invokes the hook: decide explicitly
    // (reject, or skip amount-based accounting) instead of letting checked_add revert by accident
    require!(amount != u64::MAX, HookErr::ConfidentialUnsupported);
    ctx.accounts.points.total = ctx.accounts.points.total.checked_add(amount).ok_or(HookErr::Math)?;
    Ok(())
}
```

**Overall verdict:**
- ✅: `Execute` only acts inside real transfers of supported mints
- ❌: it can be driven directly

*Sources: solana-foundation/solana-dev-skill #5 (MIT, Copyright (c) 2026); Neodyme Token-2022 article §D [paraphrased, cited]; HOOK-06 extra-account privilege rule checked against the SPL and Pinocchio transfer-hook interface sources (the signer handling differs by helper); the confidential-transfer `u64::MAX` amount checked against the Token-2022 source.*
