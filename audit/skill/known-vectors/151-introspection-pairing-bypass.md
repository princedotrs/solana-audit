---
id: 151
title: "Instruction-Introspection Pairing Bypass (Flash-Loan Repay, Many-to-One, CPI-Wrap)"
severity: 9
category: crypto
---

### 151 — Instruction-Introspection Pairing Bypass (Flash-Loan Repay, Many-to-One, CPI-Wrap)

**Severity: 9** | **Real: pattern class in introspection-based flash loans and pay-then-claim flows (no exploit of any named lending protocol is implied); Trail of Bits not-so-smart-contracts "Improper instruction introspection" (absolute-index many-to-one)**

KV-101/KV-102 cover *which* account is read and how a signature-precompile instruction is bound. This vector covers the *logic* of pairing instructions through the Instructions sysvar, for rules such as "borrow must be followed by repay" or "claim must be preceded by a payment".
- **Presence instead of sequence.** A rule of the form "some later instruction has the repay discriminator" accepts `borrow → borrow → repay` and `borrow → change_settings → repay`. It also accepts a repay sent to another program or for another reserve.
- **Many-to-one.** With an absolute index (`load_instruction_at_checked(0, ..)`) every consumer in the transaction validates the same producer, so one payment pays for N claims.
- **CPI wrapping.** The Instructions sysvar lists **top-level** instructions only. Under CPI, `load_current_index_checked` returns the index of the attacker's top-level instruction. A relative `-1` then points to the instruction before the wrapper, and an attacker program can CPI into the consumer K times inside one top-level instruction. Relative indexing alone does not stop this.
- **Shallow producer validation.** Checking only `program_id == spl_token::ID` accepts any token instruction, for example a 1-base-unit transfer to the attacker or an `approve`.
- **Gap mutators.** Withdraw, borrow, transfer/migrate account, close, liquidate or set-authority instructions placed between begin and end can make the end check run on an emptied account.

> Cross-ref: AV-091–AV-093, KV-101, KV-102, lending.md §6, CPI-036 (sibling introspection).

#### Verification Procedure

**Step 1: Introspection sites**
```
rg -n 'load_instruction_at(_checked)?|load_current_index(_checked)?|get_instruction_relative|sysvar::instructions' programs/
rg -n 'load_instruction_at(_checked)?\(\s*(0|1|2|[A-Z_]+)\s*(usize|as usize)?\s*,' programs/     # absolute indexes
rg -n 'get_stack_height|TRANSACTION_LEVEL_STACK_HEIGHT' programs/
rg -n -i 'flash_?(borrow|loan|repay)|in_flashloan|begin_|end_' programs/
```
Build one row per site: index source → stack-height guard? → program id checked? → discriminator checked? → accounts at fixed positions bound? → amount bound? → in-flight flag set/cleared? → mutators that ignore the flag.

**Step 2: Required properties**
- ✅ PASS: `get_stack_height() == TRANSACTION_LEVEL_STACK_HEIGHT` (constant `1`) is required, unless one of the alternative closures in the note below is in place; a top-level `program_id == crate::ID` check is only a supplement. The **first** later instruction to this program is the expected `repay`/`end`, for the same reserve/obligation/user accounts at fixed positions, with amount ≥ principal + fee. Producers are fully decoded per variant. Absolute indexes are < count and on the required side of the current index (after it for a borrow→repay rule, before it for a pay→claim rule), and no producer can satisfy two consumers. Nested begins are rejected. Every gap mutator rejects while the in-flight flag is set. The sysvar account is address-pinned. All byte and account access uses `.get()`.
- ❌ FAIL: any property missing
- Note: the stack-height guard makes the instruction uncallable through CPI (aggregators, vault wrappers). That is the intended trade-off, not a security finding. The reverse does not hold: if the protocol drops the guard to stay composable, the CPI-wrap and many-to-one paths must be closed some other way (a consumed-marker per producer, or a producer that itself records the pairing on-chain), or it is a FAIL.
<!-- verified: agave v1.18.26 sdk/program/src/instruction.rs (TRANSACTION_LEVEL_STACK_HEIGHT = 1, get_stack_height); solana-program/token program@v9.0.0 interface/src/instruction.rs (Transfer accounts: 0 source, 1 destination; TransferChecked: 0 source, 1 mint, 2 destination) -->

```rust
// FIXED (flash-loan borrow; sketch)
require!(get_stack_height() == TRANSACTION_LEVEL_STACK_HEIGHT, LendErr::NoCpi);
let ixs = ctx.accounts.instructions.to_account_info();     // #[account(address = sysvar::instructions::ID)]
let cur = load_current_index_checked(&ixs)? as usize;
let mut i = cur + 1;
loop {
    let ix = load_instruction_at_checked(i, &ixs).map_err(|_| LendErr::NoRepay)?;
    if ix.program_id == crate::ID {
        require!(ix.data.get(..8) == Some(&REPAY_DISC[..]), LendErr::NextIxNotRepay);
        let reserve_meta = ix.accounts.get(RESERVE_IDX).ok_or(LendErr::RepayMismatch)?;
        require_keys_eq!(reserve_meta.pubkey, ctx.accounts.reserve.key(), LendErr::RepayMismatch);
        let amt_bytes: [u8; 8] = ix.data.get(8..16).ok_or(LendErr::BadRepay)?.try_into().map_err(|_| LendErr::BadRepay)?;
        let amt = u64::from_le_bytes(amt_bytes);
        require!(amt >= principal.checked_add(fee).ok_or(LendErr::Math)?, LendErr::Underpay);
        break;
    }
    i += 1;
}
require!(!ctx.accounts.reserve.flash_loan_active, LendErr::Nested);
ctx.accounts.reserve.flash_loan_active = true;   // every gap mutator: require!(!reserve.flash_loan_active)

// FIXED (pay-then-claim consumer; decode per variant)
use spl_token::instruction::TokenInstruction;    // spl_token_interface::instruction in spl-token >= 8.1
require!(get_stack_height() == TRANSACTION_LEVEL_STACK_HEIGHT, ErrorCode::NoCpi);  // closes the CPI-wrap path
let ixs = ctx.accounts.instructions.to_account_info();     // address-pinned to the Instructions sysvar
let dep = get_instruction_relative(-1, &ixs)?;
require_keys_eq!(dep.program_id, spl_token::ID);   // deliberate: rejects Token-2022 payments
let (amount, dest) = match TokenInstruction::unpack(&dep.data)? {
    TokenInstruction::Transfer { amount } => (amount, dep.accounts.get(1)),
    TokenInstruction::TransferChecked { amount, .. } => (amount, dep.accounts.get(2)), // index 1 is the mint
    _ => return err!(ErrorCode::BadProducer),
};
require_keys_eq!(dest.ok_or(ErrorCode::BadProducer)?.pubkey, ctx.accounts.vault.key());
require_gte!(amount, PRICE);
```
**PoC:** against an absolute-index or presence-based consumer, `[transfer(PRICE → vault), claim, claim, claim]` mints three rewards. Against a relative-index consumer without the stack-height guard, deploy an attacker program that CPIs `claim` three times inside one top-level instruction placed after a single transfer.

**Overall verdict:**
- ✅: sequence, binding, CPI-entry and gap-mutator properties all hold
- ❌: any pairing can be satisfied without the economic action it is meant to prove

*Sources: PlamenTSV/plamen `agents/skills/solana/instruction-introspection/SKILL.md` (MIT, Copyright (c) 2025-2026 Plamen Contributors); solana-foundation/solana-dev-skill `skills/solana-dev/references/programs/design-patterns.md` "In-transaction credit (flashloan pattern)" (MIT, Copyright (c) 2026) with `.get()` fix; Trail of Bits not-so-smart-contracts "Improper instruction introspection" [paraphrased, AGPL-3.0, https://github.com/crytic/building-secure-contracts/tree/master/not-so-smart-contracts/solana/improper_instruction_introspection]. The CPI-wrap extension is our analysis; index and variant fixes.*
