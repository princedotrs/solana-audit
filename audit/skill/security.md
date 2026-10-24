# Solana Program Security

> Categories 1–9, the program checklist and the review questions are adapted, largely verbatim, from solana-foundation/solana-dev-skill `skills/solana-dev/references/security.md` [verbatim, MIT, Copyright (c) 2026 — see ATTRIBUTION.md].

## Core Principle

Assume the attacker controls:
- Every account passed into an instruction
- Every instruction argument
- Transaction ordering (within reason)
- CPI call graphs (via composability)

---

## Vulnerability Categories

### 1. Missing Owner Checks

**Risk**: Attacker creates fake accounts with identical data structure and correct discriminator.

**Attack**: Without owner checks, deserialization succeeds for both legitimate and counterfeit accounts.

**Anchor Prevention**:
```rust
// Option 1: Use typed accounts (automatic)
pub account: Account<'info, ProgramAccount>,

// Option 2: Explicit constraint
#[account(owner = program_id)]
pub account: UncheckedAccount<'info>,
```

**Pinocchio Prevention**:
```rust
if !account.is_owned_by(&crate::ID) {
    return Err(ProgramError::InvalidAccountOwner);
}
```

---

### 2. Missing Signer Checks

**Risk**: Any account can perform operations that should be restricted to specific authorities.

**Attack**: Attacker locates target account, extracts owner pubkey, constructs transaction using real owner's address without their signature.

**Anchor Prevention**:
```rust
// Option 1: Use Signer type
pub authority: Signer<'info>,

// Option 2: Explicit constraint
#[account(signer)]
pub authority: UncheckedAccount<'info>,

// Option 3: Manual check
if !ctx.accounts.authority.is_signer {
    return Err(ProgramError::MissingRequiredSignature);
}
```

**Pinocchio Prevention**:
```rust
if !self.accounts.authority.is_signer() {
    return Err(ProgramError::MissingRequiredSignature);
}
```

---

### 3. Arbitrary CPI Attacks

**Risk**: Program blindly calls whatever program is passed as parameter, becoming a proxy for malicious code.

**Attack**: Attacker substitutes malicious program mimicking expected interface (e.g., fake SPL Token that reverses transfers).

**Anchor Prevention**:
```rust
// Use typed Program accounts
pub token_program: Program<'info, Token>,

// Or explicit validation
if ctx.accounts.token_program.key() != &spl_token::ID {
    return Err(ProgramError::IncorrectProgramId);
}
```

**Pinocchio Prevention**:
```rust
if self.accounts.token_program.key() != &pinocchio_token::ID {
    return Err(ProgramError::IncorrectProgramId);
}
```

---

### 4. Reinitialization Attacks

**Risk**: Calling initialization functions on already-initialized accounts overwrites existing data.

**Attack**: Attacker reinitializes account to become new owner, then drains controlled assets.

**Anchor Prevention**:
```rust
// Use init constraint (automatic protection)
#[account(init, payer = payer, space = 8 + Data::LEN)]
pub account: Account<'info, Data>,

// Manual check if needed
if ctx.accounts.account.is_initialized {
    return Err(ProgramError::AccountAlreadyInitialized);
}
```

**Critical**: Prefer plain `init` for one-time setup. `init_if_needed` does not re-run `init` on an account that already exists: it skips creation and only validates the existing account (owner, type/discriminator, `space`, rent exemption, and any declared `token::` / `mint::` / `associated_token::` fields). The handler body, however, runs on every call, so a handler that unconditionally writes initial state (authority, balances, flags) resets that state on the second call. If `init_if_needed` is required, gate those writes on an initialized flag or on the stored authority (FP-5, AV-023/024, KV-014). Version notes: it needs the `init-if-needed` cargo feature since anchor-lang 0.21.0 (#1258); the existing-account constraint checks arrived in 0.19.0 (#1096) and the ATA and rent-exemption checks in 0.20.0 (#1221, #1250), so older versions validate less; on released versions up to and including 1.2.1 the `extensions::*` constraints of an existing Token-2022 mint are not re-checked on that path.
<!-- verified: anchor CHANGELOG at v0.32.1 (#906 in 0.18.0, #1096 in 0.19.0, #1221/#1250 in 0.20.0, #1258 in 0.21.0); v1.2.1 lang/syn/src/codegen/accounts/constraints.rs init_if_needed branch (ConstraintSpace, ConstraintOwner, ConstraintRentExempt on the existing-account path); Token-2022 extension gap per #4845, not in any tag through v1.2.1 -->


**Pinocchio Prevention**:
```rust
// Check discriminator before initialization
let data = account.try_borrow_data()?;
if data[0] == ACCOUNT_DISCRIMINATOR {
    return Err(ProgramError::AccountAlreadyInitialized);
}
```

---

### 5. PDA Sharing Vulnerabilities

**Risk**: Same PDA used across multiple users enables unauthorized access.

**Attack**: Shared PDA authority becomes "master key" unlocking multiple users' assets.

**Vulnerable Pattern**:
```rust
// BAD: Only mint in seeds - all vaults for same token share authority
seeds = [b"pool", pool.mint.as_ref()]
```

**Secure Pattern**:
```rust
// GOOD: Include user-specific identifiers
seeds = [b"pool", vault.key().as_ref(), owner.key().as_ref()]
```

---

### 6. Type Cosplay Attacks

**Risk**: Accounts with identical data structures but different purposes can be substituted.

**Attack**: Attacker passes controlled account type as different type parameter, bypassing authorization.

**Prevention**: Use discriminators to distinguish account types.

**Anchor**: Automatic 8-byte discriminator with `#[account]` macro.

**Pinocchio**:
```rust
// Validate discriminator before processing
let data = account.try_borrow_data()?;
if data[0] != EXPECTED_DISCRIMINATOR {
    return Err(ProgramError::InvalidAccountData);
}
```

---

### 7. Duplicate Mutable Accounts

**Risk**: Passing same account twice causes program to overwrite its own changes.

**Attack**: Sequential mutations on identical accounts cancel earlier changes.

**Prevention**:
```rust
// Anchor
if ctx.accounts.account_1.key() == ctx.accounts.account_2.key() {
    return Err(ProgramError::InvalidArgument);
}

// Pinocchio
if self.accounts.account_1.key() == self.accounts.account_2.key() {
    return Err(ProgramError::InvalidArgument);
}
```

---

### 8. Revival Attacks

**Risk**: Closed accounts can be restored within same transaction by refunding lamports.

**Attack**: Multi-instruction transaction drains account, refunds rent, exploits "closed" account.

**Secure Closure Pattern**:
```rust
// Anchor: Use close constraint
#[account(mut, close = destination)]
pub account: Account<'info, Data>,

// Pinocchio: Full secure closure
pub fn close(account: &AccountInfo, destination: &AccountInfo) -> ProgramResult {
    // 1. Mark as closed
    {
        let mut data = account.try_borrow_mut_data()?;
        data[0] = 0xff; // Closed discriminator
    }

    // 2. Transfer lamports
    *destination.try_borrow_mut_lamports()? += *account.try_borrow_lamports()?;

    // 3. Shrink and close
    account.realloc(1, true)?;
    account.close()
}
```

---

### 9. Data Matching Vulnerabilities

**Risk**: Correct type/ownership validation but incorrect assumptions about data relationships.

**Attack**: Signer matches transaction but not stored owner field.

**Prevention**:
```rust
// Anchor: has_one constraint
#[account(has_one = authority)]
pub account: Account<'info, Data>,

// Pinocchio: Manual validation
let data = Config::from_bytes(&account.try_borrow_data()?)?;
if data.authority != *authority.key() {
    return Err(ProgramError::InvalidAccountData);
}
```


### 10. Unfavorable Rounding of Token Amount From Signer to Program

**Risk**: Rounding down when calculating token amount to be sent from Signer to the Program.

**Attack**: Signer loops a set of instructions where they send less tokens than they would receive from the program resulting in a net gain for the Signer.

**Prevention**:

```rust
// round up when calculating amount for external address to send to program
let amount_to_receive = number_of_shares.checked_ceil_div(exchange_rate).ok_or(ProgramError::ArithmeticOverflow)?;
```

### 11. Unfavorable Rounding of Token Amount From Program to Signer

**Risk**: Rounding up when calculating token amount to be sent from Program to Signer

**Attack**: Signer loops a set of instructions where they receive more tokens than they would send to the program resulting in a net gain for the Signer.

**Prevention**:

```rust
// round down when calculating amount for program to send to external address
let amount_to_send = number_of_shares.checked_div(exchange_rate).ok_or(ProgramError::ArithmeticOverflow)?;
```

### 12. Missing Precision

**Risk**: Calculations are imprecise when dividing multiple times.

**Attack**: Normal use results in less accurate state

**Example**:

```rust
// Each division reduces precision
let value = number_1.checked_div(number_2).ok_or(ProgramError::ArithmeticOverflow)?.checked_div(number_3).ok_or(ProgramError::ArithmeticOverflow)?;
```

**Prevention**:

```rust
// Performing multiplication before single division improves precision
let denominator = number_2.checked_mul(number_3).ok_or(ProgramError::ArithmeticOverflow)?;
let value = number_1.checked_div(denominator).ok_or(ProgramError::ArithmeticOverflow)?;
```

---

## Program Checklist

### Account Validation
- [ ] Validate account owners match expected program
- [ ] Validate signer requirements explicitly
- [ ] Validate writable requirements explicitly
- [ ] Validate PDAs match expected seeds + bump
- [ ] Validate token mint ↔ token account relationships
- [ ] Validate rent exemption / initialization status
- [ ] Check for duplicate mutable accounts

### CPI Safety
- [ ] Validate program IDs before CPIs (no arbitrary CPI)
- [ ] Do not pass extra writable or signer privileges to callees
- [ ] Ensure invoke_signed seeds are correct and canonical

### Arithmetic and Invariants
- [ ] Use checked math (`checked_add`, `checked_sub`, `checked_mul`, `checked_div`)
- [ ] Avoid unchecked casts
- [ ] Re-validate state after CPIs when required
- [ ] Round in the correct direction
- [ ] Avoid unnecessary precision loss

### State Lifecycle
- [ ] Close accounts securely (mark discriminator, drain lamports)
- [ ] Avoid leaving "zombie" accounts with lamports
- [ ] Gate upgrades and ownership transfers
- [ ] Prevent reinitialization of existing accounts

---

## Security Review Questions

1. Can an attacker pass a fake account that passes validation?
2. Can an attacker call this instruction without proper authorization?
3. Can an attacker substitute a malicious program for CPI targets?
4. Can an attacker reinitialize an existing account?
5. Can an attacker exploit shared PDAs across users?
6. Can an attacker pass the same account for multiple parameters?
7. Can an attacker revive a closed account in the same transaction?
8. Can an attacker exploit mismatches between stored and provided data?
9. Can an attacker exploit improper rounding?

---

## Class index — where each class is checked

| Class | Checklist / vector IDs | Reference example (cite only) | Caveat |
|---|---|---|---|
| Owner checks | AV-001, AV-033, AV-095, AV-096, KV-015 | sealevel-attacks `2-owner-checks` | `Pack::unpack` / Borsh deserialization never checks `AccountInfo::owner`; a discriminator proves the type, not the owning program |
| Signer checks | AC-001..009, AC-059, KV-013 | sealevel-attacks `0-signer-authorization` | comparing a key with a hard-coded or stored admin key without `is_signer` is still a missing-signer bug |
| Arbitrary CPI | CPI-003..010, CPI-028..030, KV-009, KV-154 | sealevel-attacks `5-arbitrary-cpi` | the corpus `insecure` example is not exploitable as written: the `spl_token::instruction::transfer` builder rejects a non-SPL program id with `IncorrectProgramId` (FP-7). The class is real when `Instruction.program_id` is caller-chosen and no builder checks it |
| Reinitialization | AV-023/024/053/054, AV-099/100, KV-014, KV-142 | sealevel-attacks `4-initialization` | the corpus `secure` variant has inverted polarity: it rejects when the flag is *false*, so it blocks the first init and allows every re-init |
| PDA sharing | PDA-022, PDA-023, KV-143, KV-144 | sealevel-attacks `8-pda-sharing` | the requirement is per-instance seeding. The corpus passes the `Signer` as the transfer authority, so its PDA seeds are never actually used to sign |
| Type cosplay | AV-011..017, AV-097, KV-010, KV-027, KV-156, KV-159 | sealevel-attacks `3-type-cosplay` | a Borsh enum tag is the variant's declaration index by default. borsh 0.10 ignores explicit `= N` discriminants; borsh ≥ 1.0 refuses to compile an enum with explicit discriminants unless it states `#[borsh(use_discriminant = true \| false)]`, and only `true` makes the tag the `= N` value |
| Duplicate mutable accounts | AV-031, AV-108, AN-010/011, FP-6 | sealevel-attacks `6-duplicate-mutable-accounts` | Anchor rejects duplicates automatically only from 1.0.0, and only for `mut` fields of `Account`, `LazyAccount`, `InterfaceAccount` or `Migration` without a `dup` constraint (FP-6, AN-010). `AccountLoader`, `UncheckedAccount`, `AccountInfo`, `SystemAccount`, `Signer`, `dup` fields and `remaining_accounts` still need a manual key check. The corpus example omits `mut`, so even 1.0.0 would not reject it |
| Revival (closing) | AV-056, KV-106, KV-175, FP-2 | sealevel-attacks `9-closing-accounts` | the corpus pins anchor-lang 0.20.1 (closed-account sentinel era). Since 0.26.0 `close` reassigns to the System Program and truncates the data (FP-2) |
| Data matching | AV-020/021, AC-057, KV-016, KV-146, KV-147 | sealevel-attacks `1-account-data-matching` | the corpus `secure` variant still never checks that the token account is owned by the token program |
| Rounding — protocol-favourable both ways | AR-022, AR-023, AR-071, KV-012 | Neodyme SPL token-lending rounding disclosure | round-to-nearest / half-up on a value path lets one side gain on every operation; round each direction in the protocol's favour |
| Rounding — dust / round trips | AR-024, FV-103, invariant-catalog §8 | — | size the extractable value by compute units × transactions an attacker can afford |
| Precision loss | AR-010..017, AR-021, AR-074, AR-078, `references/methodologies/dimensional-analysis.md` | — | track units and scales per mint and per oracle |
| (extra) Bump canonicalization | KV-104, PDA-025 | sealevel-attacks `7-bump-seed-canonicalization` | reusing a stored bump with `create_program_address` is fine only when that bump came from `find_program_address` (or Anchor `bump`) at init and is read back from a program-owned, type-checked account. A bump taken from instruction data or an unchecked account is not (PDA-025) |
| (extra) Sysvar address | AV-068/069, KV-101, FP-8 | sealevel-attacks `10-sysvar-address-checking` | `Sysvar::from_account_info` and Anchor `Sysvar<'info, T>` check the sysvar id; prefer `Clock::get()` / `Rent::get()` |
| (extra) Instruction introspection | AV-091..094, KV-151 | Trail of Bits not-so-smart-contracts `solana/improper_instruction_introspection` | use the checked sysvar helpers, bind every field of the producer instruction, and reject CPI entry with a stack-height check (AV-092) |

Fuzz recipes per class: `templates/fuzz-trident/RECIPES.md`. Eval fixtures: `templates/evals/sealevel-attacks-labels.json`.
<!-- verified: sealevel-attacks HEAD 24555d0 programs/{1-account-data-matching,4-initialization,6-duplicate-mutable-accounts,8-pda-sharing}/secure|insecure/src/lib.rs; 5-arbitrary-cpi/insecure/Cargo.toml spl-token 3.1.1 (lock 3.2.0) — builder check added by SPL #1714 (commit 38751ab, 2021-05-12), token program@v3.5.0 program/src/instruction.rs L967 + lib.rs L82; 9-closing-accounts/*/Cargo.toml anchor-lang 0.20.1 -->
*Sources: coral-xyz/sealevel-attacks [cited, paraphrased; directory names only]; Sealevel Sentinel class-to-fixture mapping (MIT, Copyright (c) 2026 Stan (stantheman0128)); Solana Foundation Program Security course [cited, paraphrased]; Trail of Bits not-so-smart-contracts [cited, paraphrased, AGPL-3.0].*
