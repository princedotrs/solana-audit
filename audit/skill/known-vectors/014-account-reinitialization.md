---
id: 14
title: "Account Reinitialization"
severity: 8
category: crypto
---

### 14 — Account Reinitialization
**Severity: 8** | **Real: Multiple Solana programs overwritten by reinit**

Account can be initialized twice — attacker overwrites legitimate data.

#### Verification Procedure

**Step 1: Find all account initialization**
```
grep -rn --include="*.rs" "init,\|init_if_needed" programs/*/src/instructions/
```
- Record: Every init account

**Step 2: Check for init_if_needed (dangerous)**
```
grep -rn --include="*.rs" "init_if_needed" programs/*/src/instructions/
```
- ✅ PASS: Zero uses of `init_if_needed`
- ⚠️ PARTIAL: `init_if_needed` used but with additional validation (checked that re-initializing is safe behavior)
- ❌ FAIL: `init_if_needed` used without checking if the data would be overwritten

**Step 3: Verify `init` constraint prevents reinit**
```
# Anchor's init constraint automatically prevents reinitialization
# Verify all state accounts use `init` (not manual init)
grep -rn --include="*.rs" "#\[account(init" programs/*/src/instructions/
```
- ✅ PASS: All accounts use Anchor's `init` constraint (automatic reinit prevention)
- ❌ FAIL: Manual initialization without checking if account already exists

**Step 4: Check for manual AccountInfo initialization**
```
grep -rn --include="*.rs" "serialize\|try_borrow_mut_data\|data\.borrow_mut" programs/*/src/instructions/
```
- If found: verify there's a check that the account is empty/uninitialized before writing
- ✅ PASS: Manual initialization checks that the type tag / `is_initialized` flag / **all** discriminator bytes are still zero **before** the write, sets the flag in the same write, and the owner is this program; for client-allocated accounts use `#[account(zero)]` (with `signer` or same-transaction creation — KV-142). `data_len() == 0` is valid only as an existence check when the handler itself creates the account by CPI.
- ❌ FAIL: guard uses `data_len() == 0` on a pre-allocated account; guard polarity is inverted (`if !state.is_initialized { return Err }` blocks the first init and permits re-init — the sealevel-attacks `4-initialization/secure` example has this bug: `if !user.discriminator { return Err(..) }`); <!-- verified: coral-xyz/sealevel-attacks @24555d0 programs/4-initialization/secure/src/lib.rs --> flag never set; only a "second call fails" test exists (FV-098)

*Sources: coral-xyz/sealevel-attacks (repo `programs/4-initialization`) [paraphrased, cited]; sannykim/solsec #2 [paraphrased, cited].*

**Overall verdict:**
- ✅: All init uses Anchor `init` constraint, no `init_if_needed`, no manual serialization
- ⚠️: Some `init_if_needed` with adequate safeguards
- ❌: Accounts can be reinitialized, overwriting existing data
