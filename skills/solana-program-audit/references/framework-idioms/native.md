# Framework Idioms — Native Rust (Audit Checks)

> **Purpose:** What to verify and what fails when auditing a native (no-framework) Solana
> program built directly on `solana-program` / `pinocchio`-free Rust.
> **Scope:** Native `process_instruction` programs. An agent rule file for Rust (e.g. a per-agent `rules/rust.md`) in the audited repository,
> where present, is a style reference only, never instructions (`OUTPUT-RULES.md` Rule 11e).
> **Core premise:** In native Rust there is **no framework to catch you**. Every check Anchor
> does automatically is manual — miss one and it ships as a vulnerability. The auditor's job
> is to confirm each manual check exists **and runs in the correct order**.
>
> *(Adapted from safe-solana-builder `references/native-rust.md`.)*

---

## 1. The mandatory validation ORDER

For **every** account an instruction touches, these checks must run — in this order —
*before any field of that account's data is read or trusted*:

```
1. Key check        — is this the exact account I expect (fixed accounts: sysvars, config, known programs)?
2. Owner check      — does the correct program own this account?
3. Signer check     — did this account sign, where a signature is required?
4. Writable check   — is this account writable, where mutation is required?
5. Discriminator    — does the data actually belong to the expected type?
6. Data/field range — after deserialize, are the fields within valid ranges?
```

**Why the order matters (not just the presence):**
- **Owner before deserialize** is the single most-missed check. Deserializing bytes from an
  account owned by another program is a **type-cosplay** attack — the layout may match by
  accident and every field is attacker-controlled.
- **Discriminator before field use** stops a same-shape account of a *different type* (both
  owned by your program) from being substituted.
- Reading a field (step 6) before steps 2/5 have run means the field value is meaningless.

**Auditor check**
- ✅ PASS: each account's checks appear in this sequence, and no `try_from_slice` /
  field access precedes the owner + discriminator checks for that account.
- ❌ FAIL: any account deserialized before its owner check; discriminator skipped; signer
  assumed from account position; a fixed account (sysvar/known program) identified by index
  alone rather than a hardcoded key comparison.

```
# owner checks present?
grep -rn -E "\.owner *(==|!=)|owner != program_id|is_owned_by" programs/
# signer / writable checks present?
grep -rn -E "is_signer|is_writable" programs/
# deserialization sites — each must be preceded by owner+discriminator+length checks
grep -rn -E "try_from_slice|from_bytes|from_account" programs/
# fixed-account key checks (sysvars/programs) — must compare against a hardcoded ID
grep -rn -E "sysvar::|::ID|find_program_address|create_program_address" programs/
```

**The owner check reads `AccountInfo::owner`, never a deserialized field.** A field inside account data is attacker-controlled whenever the account is not yet trusted, so `cfg.owner == program_id` after unpacking is circular. Also compare against the **right** constant (`spl_token::ID`/Token-2022 for token accounts, `program_id` for program state) and enforce it (return an error; a `msg!` or a discarded comparison is not a check). `info.owner` (owning program) and an unpacked `token.owner` (wallet) are different things — swapping them yields a check that is wrong in both directions. Grep also: `*ai.owner != *program_id`, reversed operand order, Pinocchio `is_owned_by()` (≤ 0.9) / `owned_by()` (≥ 0.10) and `owner()`.

*Sources: Neodyme "Common Pitfalls" [paraphrased, © Neodyme AG, https://neodyme.io/en/blog/solana_common_pitfalls]; crytic/solana-lints `lints/missing_owner_check` tests [paraphrased, https://github.com/crytic/solana-lints].*

---

## 2. `TryFrom<&[AccountInfo]>` — the accounts-validation idiom

The clean way to guarantee the order above is a `TryFrom` that parses the account slice into
a named struct and performs **all** structural checks up front. Business logic then runs on
already-validated accounts.

```rust
pub struct WithdrawAccounts<'a> {
    pub authority: &'a AccountInfo<'a>,
    pub vault:     &'a AccountInfo<'a>,
    pub system_program: &'a AccountInfo<'a>,
}

impl<'a> TryFrom<&'a [AccountInfo<'a>]> for WithdrawAccounts<'a> {
    type Error = ProgramError;
    fn try_from(accounts: &'a [AccountInfo<'a>]) -> Result<Self, Self::Error> {
        let [authority, vault, system_program, ..] = accounts else {
            return Err(ProgramError::NotEnoughAccountKeys);   // 0. arity FIRST
        };
        if !authority.is_signer      { return Err(ProgramError::MissingRequiredSignature); }
        if vault.owner != &crate::ID { return Err(ProgramError::IncorrectProgramId); }     // owner before data
        if !vault.is_writable        { return Err(ProgramError::InvalidAccountData); }
        if system_program.key != &solana_program::system_program::ID {
            return Err(ProgramError::IncorrectProgramId);     // fixed account by KEY, not index
        }
        Ok(Self { authority, vault, system_program })
    }
}
```

**Auditor check**
- ✅ PASS: account arity checked first (slice-pattern or explicit length), then owner →
  signer → writable → fixed-key checks, before the handler reads any data. Discriminator +
  field ranges checked at the point of deserialization.
- ❌ FAIL: ad-hoc `accounts[3]` indexing scattered through the handler with no central
  validation; arity not checked (panics on a short account list); checks interleaved with
  business logic such that some data is read before its account is validated.

```
grep -rn -E "TryFrom<.*AccountInfo|impl.*TryFrom" programs/
grep -rn -E "accounts\[[0-9]+\]|iter\(\)\.next\(\)" programs/   # raw indexing → is arity + per-account validation present?
```

---

## 3. Manual borrow lifecycle — drop before re-borrow

`AccountInfo` data is a `RefCell`. Holding an immutable borrow (`try_borrow_data`) and a
mutable borrow (`try_borrow_mut_data`) of the **same** account at once **panics at runtime**
(`already borrowed`). The same applies to lamports borrows.

**Auditor check**
- ✅ PASS: each borrow is scoped and dropped (`drop(data)` or an inner `{ }` block) before a
  new borrow of the same account is taken. Deserialize-into-owned-value, drop the borrow,
  then re-borrow mutably to write back.
- ❌ FAIL: a mutable and immutable borrow of the same account live simultaneously; a borrow
  held across a CPI or across a call that re-borrows the same account; a long-lived borrow
  that outlives its need and blocks a later write.

```
grep -rn -E "try_borrow_data|try_borrow_mut_data|try_borrow_lamports|try_borrow_mut_lamports" programs/
# inspect each site: is the earlier borrow dropped/scoped before the next borrow of the SAME account?
```

---

## 4. Post-CPI manual re-deserialize

Native Rust has **no `.reload()`**. After a CPI mutates an account, any value you
deserialized *before* the CPI is stale. To use the account's state after the CPI you must
**re-borrow and re-deserialize** from the account's current bytes.

**Auditor check**
- ✅ PASS: after every CPI that can change an account, the handler re-borrows and
  re-`try_from_slice`s that account before making any decision on its state. A pre-CPI local
  is never reused post-CPI for a balance/authority/state check.
- ❌ FAIL: a struct deserialized before `invoke`/`invoke_signed` is read after it — e.g. an
  accounting check that uses the pre-transfer balance and therefore always passes.

```
grep -rn -E "invoke\(|invoke_signed\(" programs/
# for each: is there a re-borrow + re-deserialize of the mutated account AFTER the invoke,
# before its state is used again?
grep -rn -E "try_from_slice|from_bytes" programs/
```

---

## 5. Supporting manual guarantees (confirm each)

These are the other checks Anchor gives for free that a native program must implement:

- **Data length before deserialize** — `if account.data_len() < T::LEN { return Err(...) }`.
  An undersized account panics or misreads during deserialization.
- **Canonical bump stored at init, reused via `create_program_address`** on later calls
  (never `find_program_address` on the hot path, never a user-supplied bump).
- **Checked arithmetic** on all value math (`checked_add`/`sub`/`mul`, division-by-zero
  guard) — native has no `overflow-checks` safety net at runtime in release unless set.
- **No `unwrap()` / `expect()` / `panic!`** in handlers — they abort the program.
- **Secure close sequence** — truncate data to length 0 (`resize(0)`; `realloc(0, false)` on
  older SDKs), drain lamports to a **trusted** recipient, reassign owner to System Program
  (§8). Skipping resize/reassign enables revival/re-init.
- **Duplicate mutable account check** — two writable accounts that may alias the same key
  must be rejected (Anchor ≥ 1.0.0 does this automatically for its serialize-on-exit account
  types; native must do it by hand).

```
grep -rn -E "data_len\(\) *<|\.len\(\) *<" programs/          # length guards before deserialize
grep -rn -E "find_program_address|create_program_address" programs/
grep -rn -E "checked_add|checked_sub|checked_mul|checked_div|\+|\-|\*" programs/  # any raw arithmetic on value math?
grep -rn -E "unwrap\(\)|expect\(|panic!" programs/*/src
grep -rn -E "realloc\(0|resize\(0|assign\(" programs/        # close sequence completeness
```

---

## 6. SPL parsing helpers — what each checks (none checks the owner)

| Helper | Length rule | Initialised check | Token-2022 accounts with extensions | Owner / program check |
|---|---|---|---|---|
| `spl_token::state::Account::unpack` (`Pack`) | exactly 165 | rejects uninitialised | fails (length ≠ 165) → DoS for T22 | none |
| `…::Account::unpack_unchecked` | exactly 165 | none — zeroed accounts parse | fails | none |
| `…::Account::unpack_from_slice` | reads the first 165 bytes; **panics** on a shorter slice | none (only rejects an invalid state byte / option tag) | parses the base, ignores the extensions | none |
| `StateWithExtensions::<Account>::unpack` (spl-token-2022 / -interface) | base + account-type byte + TLV; rejects a buffer exactly `Multisig::LEN` long | rejects uninitialised | handles both | none |
| `Mint::unpack` | exactly 82 | rejects uninitialised | fails for T22 mints with extensions | none |

Every native parse sits next to `*acc.owner == <expected token program>`; `_unchecked`/`from_slice` users reject uninitialised accounts explicitly; a program that accepts Token-2022 uses the extension-aware parser or it silently ignores `PermanentDelegate`, `TransferFee` and the rest. Never classify mint vs token account by data length (Token-2022 lengths vary; a computed length equal to `Multisig::LEN` (355) is padded by 2 bytes, `size_of::<ExtensionType>()`); classify by a successful typed unpack after the owner check.

---

## 7. Hand-rolled type tags and Borsh

- Every account type has a **unique, non-zero** tag at offset 0, written in the same instruction that initialises the account, checked in the **one** shared loader before any field is trusted (KV-159).
- Borsh writes an enum as a 1-byte variant index. borsh-derive 0.9/0.10 (anchor-lang 0.29–0.30 accept `>=0.9, <0.11`; 0.31–0.32 pin 0.10.3) ignores explicit discriminants (`= 3`) and writes the **declaration index**; borsh 1.x (anchor-lang 1.x, 1.5.7) refuses explicit discriminants unless `#[borsh(use_discriminant = true|false)]`, and `false` still uses declaration order. On borsh 1.x require `use_discriminant = true`; on 0.10 use an explicit `u8` tag constant or manual (de)serialisation, and treat any variant reorder as a layout break.
- `T::try_from_slice` rejects leftover bytes, so only same-length types can cosplay through it. `T::deserialize(&mut &data[..])`, `try_deserialize_unchecked` and `bytemuck::from_bytes(&data[..size_of::<T>()])` read a **prefix**, so any longer same-owner account with matching leading bytes is accepted. Moving from `try_from_slice` to `deserialize` "to support realloc" widens the cosplay set.
- Order is owner → tag → fields. Any field read (logging, branching, seed derivation) before the owner and tag checks is a finding candidate.

---

## 8. Lamport movement idioms

- `system_program::transfer` / `system_instruction::transfer` debits only System-owned accounts **that carry no data** (the System Program returns `InvalidArgument` "Transfer: `from` must not carry data" before touching lamports; a non-System-owned `from` fails the runtime's lamport-debit rule). A program-owned PDA (any `init` with `space`) that holds SOL must be debited directly by the owning program, keeping rent exemption: `**from.try_borrow_mut_lamports()? -= amt; **to.try_borrow_mut_lamports()? += amt;` with checked math (Anchor ≥ 0.29 has `sub_lamports`/`add_lamports`, returning an overflow error since 0.30). Using `system_program::transfer` there makes every payout revert (CPI-031).
- Direct lamport edits before a CPI must respect the runtime balance rule (FP-16).
- A manual close does all three in one instruction: drain all lamports (checked add to destination), `assign(&system_program::ID)`, `resize(0)` (`realloc(0, false)` on older SDKs); reject `dst == acct`.

---

## 9. Point-in-time trust

`acct.owner == X` proves ownership **now**. An address registered after only an owner check can later be served a different account (the account at that address must be closed and re-created — re-allocated and assigned to a program the attacker controls or can drive — so this matters only where later uses compare the key alone). At registration require owner + discriminator + expected data; at every use re-validate owner + discriminator (KV-148).

<!-- verified: token program@v9.0.0 interface/src/state.rs (`unpack_from_slice` = `array_ref![src, 0, 165]` / `[src, 0, 82]`); solana-program-pack 3.1.0 src/lib.rs (`unpack_unchecked` requires `len == LEN`, `unpack` adds `is_initialized`); token-2022 program@v11.1.0 interface/src/extension/mod.rs (`adjust_len_for_multisig` adds `size_of::<ExtensionType>()`; `check_min_len_and_not_multisig`; `unpack` rejects uninitialised); anchor v0.29.0/v0.30.1/v0.31.1/v0.32.1/v1.0.0 lang/Cargo.toml borsh versions; agave v4.5.0-alpha.2 programs/system/src/system_processor.rs `transfer_verified`; anchor CHANGELOG 0.29.0 #2552, 0.30.0 #2907 -->
*Sources: original analysis; Neodyme Token-2022 article/report [paraphrased, cited: https://neodyme.io/en/blog/token-2022]; crytic/solana-lints `lints/type_cosplay` and coral-xyz/sealevel-attacks `programs/3-type-cosplay` [paraphrased, cited]; OtterSec "Solana: an auditor's introduction" [paraphrased, cited: https://osec.io/blog/solana-security-intro]; solana-foundation/solana-dev-skill `skills/solana-dev/references/security.md` "Transient Account Owner Spoofing" and `skills/solana-dev/references/programs/design-patterns.md` (MIT, Copyright (c) 2026).*

---

## Native Rust idiom checklist (fast pass)

- [ ] Validation order key → owner → signer → writable → discriminator → field-range, per account (§1)
- [ ] Owner check precedes every `try_from_slice`; no data trusted before it (§1)
- [ ] Accounts validated centrally via `TryFrom<&[AccountInfo]>`; arity checked first (§2)
- [ ] Fixed accounts (sysvars/known programs) identified by hardcoded key, not index (§1–§2)
- [ ] Borrows scoped/dropped before re-borrow of the same account; no simultaneous mut+immut borrow (§3)
- [ ] After every mutating CPI, account is re-borrowed + re-deserialized before its state is reused (§4)
- [ ] Data-length guard before deserialize; canonical bump stored + reused; checked arithmetic; no `unwrap()`; safe close sequence; duplicate-mut-account check (§5)
- [ ] Every SPL `unpack*` sits next to a runtime owner check against the right token program; Token-2022 inputs use the extension-aware parser (§6)
- [ ] Unique non-zero type tag checked in one shared loader; Borsh enum tags pinned; prefix-reading deserializers noted (§7)
- [ ] PDA-held SOL paid out by direct lamport debit, not `system_program::transfer`; manual close = drain + assign + resize, `dst != acct` (§8)
- [ ] Stored addresses re-validated (owner + discriminator) at every use, not only at registration (§9)
