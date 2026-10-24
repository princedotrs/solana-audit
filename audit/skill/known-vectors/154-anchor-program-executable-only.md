---
id: 154
title: "Anchor `Program` That Checks Only `executable`"
severity: 8
category: crypto
---

### 154 — Anchor `Program` That Checks Only `executable`

**Severity: 8** | **Real: GHSA-c6rc-8jpp-2fgc / CVE-2026-45137 (High, CVSS 8.2): `Program<'info, System>` accepted any executable on anchor-lang 1.0.0–1.0.1, fixed in 1.0.2**

This vector has two shapes:
1. **Untyped `Program<'info>`** (`Program<'info, ()>`, added in 1.0.0, #3878) checks **only** `executable`. It is meant for "whatever program the user wants to call" (routers, plugins), so it is an arbitrary-CPI surface by design.
2. **`Program<'info, System>` on 1.0.0–1.0.1.** These versions treated `T::id() == Pubkey::default()` as "accept any executable". The System Program id is the all-zero key, so `Program<System>` behaved like shape 1. Exposure exists **only** where code builds an `Instruction` with `program_id: ctx.accounts.system_program.key()`, forwards the unchecked account to a third-party program that CPIs through it, or uses the type as proof of identity. Anchor's own `system_program::{create_account, transfer, …}` helpers and the generated `init`/`realloc` code pass `system_program.key()` into `CpiContext`, but the helpers build the instruction with `system_instruction::*`, which hard-codes the System id. They are therefore **not** redirected. `system_instruction::*` + `invoke` is safe for the same reason. <!-- verified: anchor v1.0.0/v1.0.1 lang/src/accounts/program.rs `is_unit_type = T::id() == Pubkey::default()`; v1.0.2 splits impl for Program<'a, ()>; v1.0.1 lang/src/system_program.rs create_account/transfer use system_instruction::*; v1.0.1 constraints.rs CpiContext::new(system_program.key(), ..) -->

> Cross-ref: CPI-030, CPI-041, AN-002/AN-003, KV-009.

#### Verification Procedure

**Step 1: Find the types and the version**
```
rg -n "Program<'info *>|Program<'info, *\(\) *>" programs/
rg -n "Program<'info, *System>" programs/
rg -n -A1 '^name = "anchor-lang"' Cargo.lock
rg -n 'program_id:\s*\*?ctx\.accounts\.system_program\.(key|key\(\))|Instruction::new_with_[a-z]+\(\s*\*?ctx\.accounts\.system_program\.key' programs/
```

**Step 2: Usage**
- ✅ PASS: untyped `Program<'info>` targets are allowlisted (`address =` or a pinned id in config) and never receive PDA signer seeds or forwarded user signers; on 1.0.0–1.0.1, no instruction takes its program id from the `system_program` account
- ❌ FAIL: `invoke_signed`/`with_signer` to an untyped `Program<'info>`; or, on 1.0.0–1.0.1, a hand-built System instruction whose id comes from the account. PoC: pass the Compute Budget program in the `system_program` slot. That builtin's processor does nothing when invoked, so the "transfer" is a no-op and the program carries on as if it had been paid. <!-- verified: agave v4.3.2 programs/compute-budget/src/lib.rs process_instruction returns Ok(()) ("Do nothing") -->

```rust
// VULNERABLE (untyped program as an invoke target)
pub router: Program<'info>,                       // executable-only
invoke_signed(&Instruction { program_id: ctx.accounts.router.key(), accounts, data }, &infos, &[seeds])?;

// FIXED
#[account(address = JUPITER_V6_ID @ ErrorCode::BadProgram)]
pub router: Program<'info>,                       // or Program<'info, Jupiter> via declare_program!
```

**Overall verdict:**
- ✅: no executable-only program account steers a CPI
- ❌: one does, with signer privilege or value at stake

*Sources: otter-sec/anchor GHSA-c6rc-8jpp-2fgc, `lang/src/accounts/program.rs`, `lang/src/system_program.rs` (Apache-2.0, Copyright 2020 Anchor Maintainers), exposure narrowed; solana-foundation/solana-dev-skill #4a (MIT, Copyright (c) 2026).*
