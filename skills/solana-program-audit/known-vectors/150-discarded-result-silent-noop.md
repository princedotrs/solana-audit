---
id: 150
title: "Discarded Result, Built-but-Not-Invoked Instruction, Default-on-Error"
severity: 7
category: crypto
---

### 150 — Discarded Result, Built-but-Not-Invoked Instruction, Default-on-Error

**Severity: 7 (8–9 when the books record a payout/deposit that never happened)** | **Real: recurring audit finding class; SlowMist "error not handled" category**

When the callee of a CPI fails, the whole transaction aborts and the caller cannot catch the error. Some errors **are** returned to the caller, though, and discarding them turns a failed action into a silent no-op while the program carries on:
- **Pre-invoke CPI errors.** Before the syscall, `solana_program::program::invoke`/`invoke_signed` try to borrow every passed account named in the instruction's metas: lamports and data mutably for writable metas, immutably for read-only ones. Any live borrow of an account passed as writable, or a live mutable borrow of an account passed as read-only, makes `invoke` return `Err(ProgramError::AccountBorrowFailed)` **without running the CPI**. `let _ = invoke(..)` then skips the transfer while the handler still credits the user.
- **Builder errors.** The SPL Token instruction builders (`spl_token::instruction::transfer(..)`, or `spl_token_interface::instruction::*`, which spl-token ≥ 8.1 re-exports and recommends) return `Result<Instruction, ProgramError>`. They fail with `IncorrectProgramId` when the program id is not the legacy Token program. More often the instruction is built but **never invoked**.
- **Serializer write-back.** `state.serialize(&mut &mut data[..])` returns `Err` when the buffer is too small (the layout grew without a realloc). Dropping that error means the update never persists.
- **Default-on-error.** `Clock::get().unwrap_or_default()` gives timestamp 0, so a price reads as "never stale" and every `now <= deadline` check passes (an expired offer, auction or loan term still accepts). The sysvar getter practically never fails on-chain, so rate this by the logic it would corrupt and do not claim an attacker can force the failure. `.ok()`/`unwrap_or(0)` on an oracle read gives a zero price. `try_from_slice(..).unwrap_or_default()` turns attacker bytes into defaults.

`let _ = expr` silences rustc's `unused_must_use` warning, which fires only on a bare expression statement, so a warning-free build proves nothing. Clippy's `let_underscore_must_use` (restriction group, off by default) does flag it.
<!-- verified: agave v1.18.26 sdk/program/src/program.rs (invoke_signed RefCell pre-checks before invoke_signed_unchecked); solana-program/token program@v9.0.0 interface/src/lib.rs check_program_account -> IncorrectProgramId, program/src/instruction.rs deprecated since 8.1.0 in favour of spl_token_interface -->

> Cross-ref: CPI-039, US-008/US-009. FP-4 (atomic rollback) does **not** dismiss this vector: a discarded `Err` never reaches the runtime, so nothing is rolled back and the handler's later writes commit.

#### Verification Procedure

**Step 1: Discarded results**
```
rg -n 'let\s+_\s*=\s*(invoke|invoke_signed|anchor_spl::|token::|token_interface::|system_program::|\w+::cpi::)' programs/
rg -n 'let\s+_\s*=\s*.*\.(serialize|try_serialize|realloc|resize|exit)\(' programs/
rg -n '(invoke|invoke_signed|transfer|serialize|realloc)\([^;]*\)\s*\.ok\(\)\s*;' programs/
rg -n '(Clock|Rent|EpochSchedule)::get\(\)\s*\.(unwrap_or_default|unwrap_or|ok)\b' programs/
rg -n 'try_from_slice\(.*\)\.(ok|unwrap_or)|\.unwrap_or_default\(\)' programs/
rg -n 'spl_token(_2022|_interface)?::instruction::\w+\(' programs/ -A3 | rg -v invoke     # built, maybe never invoked
```

**Step 2: Can the discarded value actually be `Err` on a value-moving or state-persisting path?**
- ✅ PASS: every CPI and fallible helper propagates with `?` or maps to a custom error; tolerated failures are commented and cannot change balances or state
- ❌ FAIL: state mutated after a discarded CPI result that can be `Err`; an instruction built and never invoked; a default used in a value calculation

```rust
// VULNERABLE: live mutable borrow on a writable account → invoke's pre-check fails → ignored
let mut data = vault_token_ai.try_borrow_mut_data()?;       // still alive
let ix = spl_token::instruction::transfer(&spl_token::ID, vault_token_ai.key, user_token_ai.key,
                                          vault_auth.key, &[], amount)?;
let _ = invoke_signed(&ix, &[vault_token_ai.clone(), user_token_ai.clone(), vault_auth.clone()], &[seeds]);
state.paid_out += amount;                                     // books a payout that never happened

// VULNERABLE: built, never executed
let _ = spl_token::instruction::transfer(tp.key, src.key, dst.key, auth.key, &[], amount);
vault.deposits += amount;

// FIXED: scope borrows, propagate every Result, invoke what you build
let vault_amount = {
    let data = vault_token_ai.try_borrow_data()?;
    spl_token::state::Account::unpack(&data)?.amount        // needs `use solana_program::program_pack::Pack;`
};                                                            // borrow dropped before invoke
require!(vault_amount >= amount, ErrorCode::InsufficientVault);
let ix = spl_token::instruction::transfer(&spl_token::ID, vault_token_ai.key, user_token_ai.key,
                                          vault_auth.key, &[], amount)?;
invoke_signed(&ix, &[vault_token_ai.clone(), user_token_ai.clone(), vault_auth.clone()], &[seeds])?;
state.paid_out = state.paid_out.checked_add(amount).ok_or(ProgramError::ArithmeticOverflow)?;
```
**Rule 5b escape:** show the discarded `Result` can be `Err` on that path (the PoC holds the borrow, or undersizes the account) and that the post-state diverges from the books.

**Overall verdict:**
- ✅: no discarded fallible result on value or state paths
- ❌: any reachable silent no-op or default-on-error that affects value or authority

*Sources: Trail of Bits `plugins/rust-review/prompts/general/result-discarded-finder.md` [paraphrased, CC-BY-SA-4.0, https://github.com/trailofbits/skills] (credited; fixed example rewritten to a token transfer); sanbir/solana-auditor-skills `solana-auditor/references/attack-vectors/attack-vectors-2.md` V34, corrected (MIT, Copyright (c) 2024 AI Skills Contributors); SlowMist best practices `README.md` "Error not handled" [https://github.com/slowmist/solana-smart-contract-security-best-practices] (Apache-2.0, attributed to SlowMist), corrected.*
