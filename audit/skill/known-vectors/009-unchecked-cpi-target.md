---
id: 9
title: "Unchecked CPI Target"
severity: 9
category: crypto
---

### 9 — Unchecked CPI Target
**Severity: 9** | **Real: arbitrary signed CPI class (Neodyme "Arbitrary Signed Program Invocation"); Wormhole is KV-101 (sysvar spoofing) and Cashio is KV-146/KV-016 (unanchored collateral validation)**

CPI to wrong program — attacker passes their own program instead of SPL Token.

#### Verification Procedure

**Step 1: Find all CPI calls and their target programs**
```
grep -rn --include="*.rs" -B2 "CpiContext::new\|invoke(\|invoke_signed(" programs/*/src/instructions/
```
- Record: Every CPI with its target program source

**Step 2: Verify every CPI target is constrained in the Accounts struct**
```
grep -rn --include="*.rs" -A30 "#\[derive(Accounts)\]" programs/*/src/instructions/ | grep -E "Program<|program:.*Program|token_program|system_program"
```
- ✅ PASS: Every program account used in CPI is typed as `Program<'info, Token>` or `Program<'info, System>` (Anchor auto-validates the program ID)
- ❌ FAIL: Program account is `UncheckedAccount` or `AccountInfo` without explicit ID check

**Step 2b: Trace `Instruction.program_id` (not the AccountInfo slot)**
```
rg -n 'Instruction\s*\{[^}]*program_id\s*:\s*\*?[a-z_]+\.(key|key\(\))' programs/
rg -n 'Instruction::new_with_(bytes|borsh|bincode)\(\s*\*?[a-z_]+\.key' programs/
rg -n 'CpiContext::new(_with_signer)?\(\s*ctx\.accounts\.\w+\.key\(\)' programs/      # Anchor 1.x
rg -n 'CpiContext::new(_with_signer)?\(\s*ctx\.accounts\.\w+\.to_account_info' programs/   # Anchor 0.x
rg -n "Program<'info *>|Program<'info, *\(\) *>" programs/
rg -n 'spl_token(_2022)?::instruction::[a-z_]+\(\s*&?[a-z_.]+\.key' programs/          # builder-validated: downgrade
```
- ✅ PASS / downgrade: the id is a constant, or goes through an SPL builder that validates it (`spl_token::instruction::*` accepts only SPL Token; `spl_token_2022::instruction::*` core builders accept SPL Token or Token-2022, extension builders only Token-2022), or through `anchor_spl::token::*` (hardcodes `spl_token::ID`) or `anchor_spl::token_2022::*` / `token_interface::*` (pass the id to those validating builders) — missing `Program<Token>` / `Interface<TokenInterface>` is then hygiene (FP-7); still check that the program accepted is the one the protocol intends (SPL Token vs Token-2022)
- ❌ FAIL: hand-built instruction (`Instruction { program_id, .. }`, `Instruction::new_with_*`) with the id from an unchecked account; Anchor-generated `cpi::` client of a non-SPL program with an unchecked program account (0.29+ clients invoke `ctx.program`'s key, 1.x `CpiContext::new(unchecked.key())`, not `crate::ID`); untyped `Program<'info>` target; `Program<'info, System>` on anchor-lang 1.0.0–1.0.1 and 1.0.0-rc.3–rc.5 (the System id is `Pubkey::default()`, which those versions treat as the untyped "unit" case: executable-only check, KV-154) **when its key is used as a program id** (hand-built `Instruction`, a `cpi::` client, a `CpiContext` passed to a helper that invokes `ctx.program_id`) — `anchor_lang::system_program::*` helpers and generated `init`/`realloc` build with the hard-coded System id, so they are not affected by the substitution; id check not dominating the invoke on every path
<!-- verified: anchor v1.0.0 spl/src/token.rs (&spl_token::ID), spl/src/token_2022.rs (&ctx.program_id into spl_token_2022 builders), lang/src/context.rs (CpiContext::new(program_id: Pubkey, ..)); token-2022 interface@v2.1.0 (the spl-token-2022-interface "2" that anchor-spl 1.0.0 depends on) and interface@v3.1.2 interface/src/lib.rs check_spl_token_program_account / check_program_account; anchor v1.0.0–v1.0.1 lang/src/accounts/program.rs (is_unit_type = T::id() == Pubkey::default(), fixed in v1.0.2; also in v1.0.0-rc.3..rc.5); v1.0.0 lang/src/system_program.rs (every helper builds via system_instruction::*, hard-coded id); anchor v0.28.0 generated cpi uses crate::ID, v0.29.0–v0.31.1 ctx.program.key(), v1.0.0 ctx.program_id -->

*Sources: Trail of Bits skills U4 [paraphrased, CC-BY-SA-4.0]; Solana Foundation course U2, coral-xyz/sealevel-attacks (repo `programs/5-arbitrary-cpi`), Neodyme U3, crytic/solana-lints U3 [paraphrased, cited]; workersio note on Wormhole/Cashio attribution.*

**Step 3: Check for manual program ID verification (if UncheckedAccount is used)**
```
grep -rn --include="*.rs" -A5 "UncheckedAccount\|/// CHECK:" programs/*/src/instructions/
```
- For each `/// CHECK:` comment: verify there's an actual runtime check (`require_keys_eq!(account.key(), expected_id)`)
- ✅ PASS: Every `/// CHECK:` has corresponding runtime validation
- ❌ FAIL: `/// CHECK:` comments say "safe" but no actual validation code follows

**Step 4: Verify no CPI to user-provided program**
```
grep -rn --include="*.rs" "remaining_accounts" programs/*/src/instructions/ | grep -c ""
```
- Then check if any remaining_account is used as a CPI target
- ✅ PASS: remaining_accounts are only used as data accounts, never as CPI targets
- ❌ FAIL: A remaining_account is passed as the program to invoke

**Overall verdict:**
- ✅: All CPI targets are Anchor Program<> types with compile-time verification
- ⚠️: Some CPIs use manual checks that are correct but not compile-time enforced
- ❌: Any CPI target from user input without verification
