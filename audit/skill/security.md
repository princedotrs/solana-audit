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

> **Pinocchio API note.** The Pinocchio snippets use the ≤ 0.9 `AccountInfo` names. On Pinocchio 0.10 / 0.11 (`AccountView`, from `solana-account-view` 1.x / 2.x) read `.key()` as `.address()`, `.is_owned_by()` as `.owned_by()`, `try_borrow_data()` / `try_borrow_mut_data()` as `try_borrow()` / `try_borrow_mut()`, and `try_borrow_(mut_)lamports()` as `lamports()` / `set_lamports()`; on 0.11 the mutating methods take `&mut self`. See `references/framework-idioms/pinocchio.md` §6.
> Anchor handlers return `anchor_lang::Result`, so a `ProgramError` is returned with `.into()`.
<!-- verified: pinocchio@v0.9.2 sdk/pinocchio/src/account_info.rs (key, is_owned_by, try_borrow_data, try_borrow_mut_lamports, realloc deprecated since 0.9.0 in favour of resize, close); solana-account-view 1.0.0 / 2.1.0 src/lib.rs (address, owned_by, try_borrow, try_borrow_mut, lamports, set_lamports, close; 2.x takes &mut self); pinocchio@v0.11.2 Cargo.toml (solana-account-view 2.0) -->

### 1. Missing Owner Checks

**Risk**: Attacker creates fake accounts with identical data structure and correct discriminator.

**Attack**: Without owner checks, deserialization succeeds for both legitimate and counterfeit accounts.

**Anchor Prevention**:
```rust
// Option 1: Use typed accounts (automatic)
pub account: Account<'info, ProgramAccount>,

// Option 2: Explicit constraint (owner only: the data type is still unchecked)
#[account(owner = crate::ID)]
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
    return Err(ProgramError::MissingRequiredSignature.into());
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

// Or explicit validation (Anchor's `key()` returns a `Pubkey` by value)
if ctx.accounts.token_program.key() != spl_token::ID {
    return Err(ProgramError::IncorrectProgramId.into());
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
    return Err(ProgramError::AccountAlreadyInitialized.into());
}
```

**Critical**: Prefer plain `init` for one-time setup. `init_if_needed` does not re-run `init` on an account that already exists: it skips creation and only validates the existing account — for a program `#[account]` type the owner, discriminator, exact `space` and rent exemption; for a token account, mint or ATA the declared `token::` / `mint::` / `associated_token::` fields, the token program and (for an ATA) the derived address. The handler body, however, runs on every call, so a handler that unconditionally writes initial state (authority, balances, flags) resets that state on the second call. If `init_if_needed` is required, gate those writes on an initialized flag or on the stored authority (FP-5, AV-023/024, KV-014). Version notes: it needs the `init-if-needed` cargo feature since anchor-lang 0.21.0 (#1258); the existing-account constraint checks arrived in 0.19.0 (#1096) and the ATA and rent-exemption checks in 0.20.0 (#1221, #1250), so older versions validate less; on released versions up to and including 1.2.1 the `extensions::*` constraints of an existing Token-2022 mint are not re-checked on that path.
<!-- verified: anchor CHANGELOG at v0.32.1 (#906 in 0.18.0, #1096 in 0.19.0, #1221/#1250 in 0.20.0, #1258 in 0.21.0); v1.2.1 lang/syn/src/codegen/accounts/constraints.rs init_if_needed branches (program account: from_account_info + ConstraintSpace, ConstraintOwner, ConstraintRentExempt; token account / ATA: mint, owner, token program, ATA address; mint: mint_authority, freeze_authority, decimals, token program); Token-2022 extension gap per #4845 (commits 2bfd1fe0 / 1355c6f4), contained in no tag through v1.2.1 and v2.0.0-rc.2 -->


**Pinocchio Prevention**:
```rust
// Check discriminator before initialization: any non-zero tag means the account
// is already initialized (as this type or another), so reserve tag 0 for "uninitialized" (AV-100)
let data = account.try_borrow_data()?;
if data[0] != 0 {
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
    return Err(ProgramError::InvalidArgument.into());
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

// Pinocchio ≤ 0.9 (`AccountInfo`): Full secure closure
pub fn close(account: &AccountInfo, destination: &AccountInfo) -> ProgramResult {
    // 1. Mark as closed
    {
        let mut data = account.try_borrow_mut_data()?;
        data[0] = 0xff; // Closed discriminator
    }

    // 2. Transfer lamports (close() zeroes the lamport field, so move them first)
    *destination.try_borrow_mut_lamports()? += *account.try_borrow_lamports()?;

    // 3. Close: zeroes owner, lamports and data length; fails while any borrow is alive.
    //    No `realloc` / `resize` first: `realloc` is deprecated since 0.9.0 and close() sets the length to 0.
    account.close()
}

// Pinocchio 0.10 / 0.11 (`AccountView`; on 0.10 these methods take `&self`)
pub fn close(account: &mut AccountView, destination: &mut AccountView) -> ProgramResult {
    if account.address() == destination.address() {
        return Err(ProgramError::InvalidArgument);
    }
    // 1. Move every lamport out first
    let total = destination
        .lamports()
        .checked_add(account.lamports())
        .ok_or(ProgramError::ArithmeticOverflow)?;
    destination.set_lamports(total);
    // 2. Zero owner, lamports and data length; the runtime zeroes the data bytes
    //    at the end of the instruction, and the account is System-owned from then on
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
// (std `u64::div_ceil`, stable since Rust 1.73, panics on a zero divisor, so check it first.
//  There is no std `checked_ceil_div`; spl-math's `CheckedCeilDiv` is implemented for u128
//  and returns a `(quotient, adjusted_divisor)` tuple, not the amount)
if exchange_rate == 0 {
    return Err(ProgramError::ArithmeticOverflow);
}
let amount_to_receive = number_of_shares.div_ceil(exchange_rate);
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

### 13. Unvalidated `remaining_accounts`

**Risk**: Anchor applies no constraint to `ctx.remaining_accounts`, and native / Pinocchio trailing accounts are just as raw. Whatever the program reads from them is attacker-chosen.

**Attack**: Attacker appends a forged position, oracle or vault account (or the same account twice) to a batch instruction; the program deserializes it, counts it, or forwards it into a CPI.

**Prevention**:
```rust
// Anchor: validate count, owner + type, binding and distinctness of every entry
require!(ctx.remaining_accounts.len() == expected_len, MyError::AccountCount);
for acc in ctx.remaining_accounts.iter() {
    let pos = Account::<Position>::try_from(acc)?; // owner == crate::ID + discriminator
    require_keys_eq!(pos.owner, ctx.accounts.user.key(), MyError::WrongPosition); // bound to the caller
}
// and reject duplicate keys (sort, then compare neighbours)
```
Deep checks: AV-013, AV-014, AV-032, AV-036, AV-108, CPI-009.

### 14. Sysvar and Instruction-Introspection Spoofing

**Risk**: A sysvar passed as an account is only an account. A program that reads the Instructions sysvar (or Clock / Rent) from an unpinned account reads attacker bytes, and introspection logic ("an Ed25519 / repay instruction exists") can be satisfied by the wrong instruction, by one producer for many consumers, or from inside a CPI.

**Attack**: Attacker passes a fake Instructions sysvar to the deprecated `load_instruction_at`, so a signature check reads a forged verification (the Wormhole 2022 pattern); or wraps a flash-loan borrow in a CPI so the "repay follows" check matches an instruction that does not repay this loan.

**Prevention**:
```rust
// Anchor: pin the sysvar address
/// CHECK: address pinned to the Instructions sysvar
#[account(address = sysvar::instructions::ID)]
pub instructions: UncheckedAccount<'info>,

// Read only through the checked helpers (they verify the sysvar id), then bind every field
let ix = load_instruction_at_checked(index, &ctx.accounts.instructions.to_account_info())?;
require_keys_eq!(ix.program_id, ed25519_program::ID, MyError::WrongProgram);
// ... check the signer pubkey, message and offsets this instruction expects, once per producer
// Pairing / ordering checks must run at top level, never via CPI
require!(get_stack_height() == TRANSACTION_LEVEL_STACK_HEIGHT, MyError::CpiNotAllowed);
// Prefer Clock::get() / Rent::get() over sysvar accounts
```
Deep checks: AV-068, AV-069, AV-090 … AV-094, CPI-036, KV-101, KV-102, KV-151, FP-8.

### 15. CPI Return-Data Spoofing

**Risk**: `get_return_data()` returns the data of the program that **last** called `set_return_data`, with that program's id. After a CPI into A that calls B, where B sets data and A does not, the caller receives B's data.

**Attack**: Attacker routes the CPI through a program that sets a forged quote, amount or price, or returns nothing so a caller that treats `None` as zero mis-prices.

**Prevention**:
```rust
let (pid, data) = get_return_data().ok_or(MyError::NoReturnData)?;
require_keys_eq!(pid, EXPECTED_CALLEE_ID, MyError::ReturnDataSpoofed); // the pinned callee you invoked
let bytes: [u8; 8] = data.as_slice().try_into().map_err(|_| MyError::BadReturnData)?;
let out = u64::from_le_bytes(bytes);
require!(out > 0 && out <= max_reasonable, MyError::BadReturnData);
```
Anchor's generated `cpi::Return<T>::get()` checks the program id only from 1.1.0 (not on 1.0.x or the 2.0.0-rc tags), and only against the id the CPI was sent to, which is worthless when that id is caller-chosen. Deep checks: CPI-033, AN-025, KV-152.

### 16. Token-2022 Extension Handling

**Risk**: A program that accepts any mint under the Token-2022 program inherits its extensions: transfer fees (received ≠ sent), permanent delegate (vault balance can be taken), transfer hooks (arbitrary code and extra accounts on every transfer), default-frozen accounts, pausable mints, mint close authority (mint closed and re-created with different extensions), non-transferable tokens.

**Attack**: Attacker lists a fee-on-transfer or permanent-delegate mint in a pool that credits the requested amount, then withdraws more than arrived, or sweeps the vault through the delegate.

**Prevention**:
```rust
// Anchor: read the mint's extensions and allowlist them, so unknown future extensions are rejected
use anchor_spl::token_2022::spl_token_2022::{
    extension::{BaseStateWithExtensions, ExtensionType, StateWithExtensions},
    state::Mint,
};
let mint_info = ctx.accounts.mint.to_account_info();
let data = mint_info.try_borrow_data()?;
let mint = StateWithExtensions::<Mint>::unpack(&data)?;
for ext in mint.get_extension_types()? {
    require!(
        matches!(ext, ExtensionType::MetadataPointer | ExtensionType::TokenMetadata),
        MyError::UnsupportedMintExtension
    );
}
// Credit the measured balance delta (reload the vault after the transfer), never the requested amount
```
Deep checks: checklist 22 (TK-001 …, HOOK-01 …), EXT-012 … EXT-015, KV-018, KV-023, KV-105, KV-166, KV-167, `references/methodologies/token-2022.md`.

### 17. Initialization Front-Running and Pre-Funded Accounts

**Risk**: `init` makes an instruction one-time; it does not decide **who** calls it first or what already sits at the address. A singleton `initialize` with constant seeds stores whoever lands first as admin. An address anyone can derive can be pre-created or pre-funded.

**Attack**: Attacker calls `initialize` right after deployment and becomes admin or fee recipient; pre-creates a user's ATA or PDA so the honest `init` always fails (DoS); hands over a pre-allocated `zero` account it controls; or relies on initialization accepting a reserve or vault that already holds value, so that value is backed by no shares and the next depositor captures it.

**Prevention**:
```rust
// Anchor: only the upgrade authority of THIS program may initialize the singleton (KV-141)
#[account(
    seeds = [crate::ID.as_ref()], bump, seeds::program = bpf_loader_upgradeable::id(),
    constraint = program_data.upgrade_authority_address == Some(payer.key()) @ MyError::NotUpgradeAuthority,
)]
pub program_data: Account<'info, ProgramData>,
// User-derivable accounts: tolerate an existing account (idempotent ATA creation or
// `init_if_needed` with state validation) instead of failing on it.
// Pre-allocated `zero` accounts: also require the account itself as a `Signer`.
// Reserves and vaults: assert the exact expected balance at initialization.
```
Deep checks: AC-056, AV-087, AV-099, AV-100, ECON-106, KV-127, KV-141, KV-142, KV-162.

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
- [ ] Validate every `remaining_accounts` entry (count, owner, type, binding, distinctness)
- [ ] Pin sysvar addresses; use checked introspection helpers and bind every field
- [ ] Allowlist the Token-2022 extensions each accepted mint may carry

### CPI Safety
- [ ] Validate program IDs before CPIs (no arbitrary CPI)
- [ ] Do not pass extra writable or signer privileges to callees
- [ ] Ensure invoke_signed seeds are correct and canonical
- [ ] Check the program id, presence, length and bounds of CPI return data

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
- [ ] Gate who may run one-time initialization; tolerate pre-created and pre-funded accounts

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
10. Can an attacker append or duplicate `remaining_accounts` the program trusts?
11. Can an attacker spoof a sysvar or satisfy an introspection check with the wrong instruction?
12. Can an attacker forge or suppress the return data the program reads after a CPI?
13. Can an attacker use a Token-2022 mint whose extensions break the program's accounting or custody?
14. Can an attacker initialize first, or pre-create or pre-fund an account the program will initialize?

---

## Class index — where each class is checked

| Class | Checklist / vector IDs | Reference example (cite only) | Caveat |
|---|---|---|---|
| Owner checks | AV-001, AV-033, AV-095, AV-096, KV-015 | — | `Pack::unpack` / Borsh deserialization never checks `AccountInfo::owner`; a discriminator proves the type, not the owning program |
| Signer checks | AC-001..009, AC-059, KV-013 | — | comparing a key with a hard-coded or stored admin key without `is_signer` is still a missing-signer bug |
| Arbitrary CPI | CPI-003..010, CPI-028..030, KV-009, KV-154 | — | an instruction built by `spl_token::instruction::*` (spl-token ≥ 3.1.1) cannot be redirected: the builder rejects a non-SPL program id with `IncorrectProgramId` (FP-7). The class is real when `Instruction.program_id` is caller-chosen and no builder checks it |
| Reinitialization | AV-023/024/053/054, AV-099/100, KV-014, KV-142 | — | check the guard's polarity: a guard that rejects when the "initialized" flag is *false* blocks the first init and allows every re-init |
| PDA sharing | PDA-022, PDA-023, KV-143, KV-144 | — | the requirement is per-instance seeding. Judge the seeds actually passed to `invoke_signed`: when the transfer authority is a `Signer` rather than the PDA, the PDA's seeds never sign anything |
| Type cosplay | AV-011..017, AV-097, KV-010, KV-027, KV-156, KV-159 | — | a Borsh enum tag is the variant's declaration index by default. borsh 0.10 ignores explicit `= N` discriminants; borsh ≥ 1.0 refuses to compile an enum with explicit discriminants unless it states `#[borsh(use_discriminant = true \| false)]`, and only `true` makes the tag the `= N` value |
| Duplicate mutable accounts | AV-031, AV-108, AN-010/011, FP-6 | — | Anchor rejects duplicates automatically only from 1.0.0, and only for `mut` fields of `Account`, `LazyAccount`, `InterfaceAccount` or `Migration` without a `dup` constraint (FP-6, AN-010). `AccountLoader`, `UncheckedAccount`, `AccountInfo`, `SystemAccount`, `Signer`, `dup` fields and `remaining_accounts` still need a manual key check. A field without `mut` is outside the 1.0.0 check, though it is then never written back either |
| Revival (closing) | AV-056, KV-106, KV-175, FP-2 | — | quote the resolved anchor-lang version: before 0.26.0 `close` only wrote the closed-account sentinel (escape (a) of FP-2, scored by its severity rule). Since 0.26.0 `close` reassigns to the System Program and truncates the data (FP-2) |
| Data matching | AV-020/021, AC-057, KV-016, KV-146, KV-147 | — | matching the stored key or mint does not prove the account's program owner: `Pack::unpack` of an account a fake program owns succeeds and returns whatever fields its owner wrote, so check the owner too |
| Rounding — protocol-favourable both ways | AR-022, AR-023, AR-071, KV-012 | Neodyme SPL token-lending rounding disclosure | round-to-nearest / half-up on a value path lets one side gain on every operation; round each direction in the protocol's favour |
| Rounding — dust / round trips | AR-024, FV-103, invariant-catalog §8 | — | size the extractable value by compute units × transactions an attacker can afford |
| Precision loss | AR-010..017, AR-021, AR-074, AR-078, `references/methodologies/dimensional-analysis.md` | — | track units and scales per mint and per oracle |
| (extra) Bump canonicalization | KV-104, PDA-025 | — | reusing a stored bump with `create_program_address` is fine only when that bump came from `find_program_address` (or Anchor `bump`) at init and is read back from a program-owned, type-checked account. A bump taken from instruction data or an unchecked account is not (PDA-025) |
| (extra) Sysvar address | AV-068/069, KV-101, FP-8 | — | `Sysvar::from_account_info` and Anchor `Sysvar<'info, T>` check the sysvar id; prefer `Clock::get()` / `Rent::get()` |
| (extra) Instruction introspection | AV-090..094, CPI-036, KV-101, KV-151 | Trail of Bits not-so-smart-contracts `solana/improper_instruction_introspection` | use the checked sysvar helpers, bind every field of the producer instruction, and reject CPI entry with a stack-height check (AV-092) |
| `remaining_accounts` (13) | AV-013, AV-014, AV-032, AV-036, AV-108, CPI-009 | — | Anchor validates nothing in `remaining_accounts`, and its duplicate-account check (FP-6) does not cover them |
| CPI return data (15) | CPI-033, AN-025, KV-152 | — | the returning program id is the last setter, not necessarily the callee; Anchor `Return<T>::get()` checks it only from 1.1.0, and only against the id the CPI was sent to |
| Token-2022 extensions (16) | checklist 22 (TK-001.., HOOK-01..), EXT-012..015, KV-018, KV-023, KV-105, KV-166, KV-167 | — | an unpinned token program means any Token-2022 mint; an `init_if_needed` existing mint does not re-check `extensions::*` on anchor-lang ≤ 1.2.1 |
| Init front-running / pre-funded accounts (17) | AC-056, AV-087, AV-099, AV-100, ECON-106, KV-127, KV-141, KV-142, KV-162 | Ackee Solana Auditors Bootcamp `Lesson-6/initialization-frontrunning` | `init` decides "once", not "who first"; deploying and initializing in one go is not a mitigation |

Fuzz recipes per class: `templates/fuzz-trident/RECIPES.md`.
Categories 13–17 condense this skill's own checklist items and known vectors listed in their "Deep checks" lines; their sources are credited there.
*Sources: coral-xyz/sealevel-attacks [cited, paraphrased; class list only]; Sealevel Sentinel class-to-check mapping (MIT, Copyright (c) 2026 Stan (stantheman0128)); Solana Foundation Program Security course [cited, paraphrased]; Trail of Bits not-so-smart-contracts [cited, paraphrased, AGPL-3.0]; Ackee-Blockchain Solana-Auditors-Bootcamp [cited, paraphrased; directory name only].*
