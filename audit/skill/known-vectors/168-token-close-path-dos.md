---
id: 168
title: "Token Close-Path DoS: Dust, Withheld Fees, Confidential Balances"
severity: 5
category: crypto
---

### 168 — Token Close-Path DoS: Dust, Withheld Fees, Confidential Balances

**Severity: 5 (Medium when the close is mandatory on a user exit/settlement path; raise to High when the blocked exit permanently locks principal and no other path (sweep, admin rescue, alternate exit) recovers it; Low when the close is optional or best-effort)** | **Real: Zellic, Audius Claim & Rewards — "claimable token close can be subjected to denial of service via dust attack" (Low)**

Anyone can send 1 base unit to any token account without consent. `CloseAccount` fails for a non-native account with `amount != 0` (`NonNativeHasBalance`). Token-2022 adds: `TransferFeeAmount.withheld_amount != 0` (`AccountHasWithheldTransferFees` — every incoming fee-bearing transfer adds to the destination's withheld amount), non-zero `ConfidentialTransferAccount` pending/available balances (`ConfidentialTransferAccountHasBalance`), non-zero encrypted `ConfidentialTransferFeeAmount` (`ConfidentialTransferFeeAccountHasWithheldFee`), and — for an account whose user owner enabled CPI Guard — a close issued from a CPI must send the lamports to the owner (`CpiGuardCloseAccountBlocked`). If settle/claim/cancel/refund must close an escrow or vault token account in the same instruction, a dust or fee-bearing transfer bricks it. Plain withheld fees can be cleared by the permissionless `HarvestWithheldTokensToMint` (no signer; it also works on frozen accounts) or by the withdraw-withheld authority. The harvest only logs a per-account failure (for example a wrong mint) and still succeeds, so a program that relies on it must check `withheld_amount == 0` afterwards or the close fails. Encrypted withheld fees use the confidential-fee `HarvestWithheldTokensToMint`, which the mint's confidential-fee authority can switch off (`DisableHarvestToMint` → `HarvestToMintDisabled`); then only the confidential `WithdrawWithheldTokensFromAccounts`, signed by the `TransferFeeConfig` withdraw-withheld authority (with its ElGamal key and a proof), clears them. <!-- verified: token-2022 program@v11.1.0 program/src/processor.rs process_close_account; interface/src/extension/{transfer_fee,confidential_transfer,confidential_transfer_fee}/mod.rs closable(); program/src/extension/transfer_fee/processor.rs harvest_from_account (no frozen or signer check) and process_harvest_withheld_tokens_to_mint (per-account errors only logged); program/src/extension/confidential_transfer_fee/processor.rs harvest_to_mint_enabled, enable/disable gated by ConfidentialTransferFeeConfig.authority, process_withdraw_withheld_tokens_from_accounts gated by TransferFeeConfig.withdraw_withheld_authority -->

> Cross-ref: SM-091, TK-008..TK-010, KV-123 (lamport analogue).

#### Verification Procedure
```
rg -n 'close_account|CloseAccount|close\s*=' programs/
rg -n 'amount\s*==\s*0|require!\(.*amount\s*==\s*0' programs/
rg -n 'harvest_withheld|HarvestWithheldTokensToMint|withheld' programs/
```
- ✅ PASS: user exits do not depend on the close (close is best-effort or a separate crank); before closing, the program sweeps the **live** balance (after `reload()`), harvests withheld fees for fee mints, and handles confidential balances. Rejecting fee and confidential mints at initialization can replace the harvest and confidential steps, but never the live-balance sweep, because dust applies to every mint
- ❌ FAIL: close of a recorded (not live) amount; `require!(vault.amount == 0)` before a mandatory close; close of fee-mint accounts without harvest

```rust
// VULNERABLE: transfers the recorded amount, then closes — 1 unit of dust bricks cancel()
token::transfer(ctx.accounts.transfer_ctx().with_signer(signer), escrow.amount)?;
token::close_account(ctx.accounts.close_ctx().with_signer(signer))?;

// FIXED: harvest (fee mints), sweep the live balance, then close
//   harvest (mint and escrow_vault writable, no signer needed):
//   anchor_spl::token_2022_extensions::harvest_withheld_tokens_to_mint(
//       cpi_ctx /* HarvestWithheldTokensToMint { token_program_id, mint } */,
//       vec![ctx.accounts.escrow_vault.to_account_info()])?;
//   raw form: spl_token_2022::extension::transfer_fee::instruction::harvest_withheld_tokens_to_mint(
//       &token_program_id, &mint, &[&escrow_vault]) -> Result<Instruction, ProgramError>, then invoke
ctx.accounts.escrow_vault.reload()?;          // re-read after any earlier CPI in this handler
let live = ctx.accounts.escrow_vault.amount;
token_interface::transfer_checked(ctx.accounts.transfer_checked_ctx().with_signer(signer), live, ctx.accounts.mint.decimals)?;
token_interface::close_account(ctx.accounts.close_ctx().with_signer(signer))?;
// (the destination receives live − fee for TransferFee mints; account for it)
```

**Overall verdict:**
- ✅: no user exit depends on a close an outsider can block
- ❌: one does

*Sources: beriktassuly/solana-audit-skill U1/U2 (MIT, Copyright (c) 2026 Berektassuly), fix switched to `transfer_checked`; solana-foundation/solana-dev-skill #6c (MIT, Copyright (c) 2026); Neodyme Token-2022 §E [paraphrased, cited] with the real harvest API <!-- verified: anchor v0.31.1 and v1.2.1 spl/src/token_2022_extensions/transfer_fee.rs harvest_withheld_tokens_to_mint(ctx, sources: Vec<AccountInfo>) -->; Zellic Audius report [cited: https://reports.zellic.io/publications/claim-and-rewards-programs].*
