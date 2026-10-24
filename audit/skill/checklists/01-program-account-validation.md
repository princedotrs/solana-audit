# 01 — Account Validation Checklist

> Domain: On-chain Solana Program  
> Severity if missed: CRITICAL to HIGH  
> References: Neodyme "Missing Ownership Check", Sealevel Attacks, Anchor Account Constraints

Every item below is a single verification step. Mark each `[PASS]`, `[FAIL-{severity}]`, `[PARTIAL]`, or `[N/A]`.

> **Feature-gated sections (advisory load).** The three sub-sections below are feature-specific: if the feature is *provably absent* (empty prescan array or zero grep hits — see `references/orchestration/pre-scan.md`), you may spot-defer the section and render its items `[N/A — feature absent: <marker>]`. Token-efficiency layer only — **every item still gets a verdict per Rule 0**, and the section reopens the instant a manual read surfaces the feature.
>
> | Section | Feature | Markers |
> |---------|---------|---------|
> | §1.8 SPL Token & Token-2022 Extension Safety | Token-2022 extensions | `token_2022` · `spl_token_2022` · `transfer_hook` · `TransferFee` · `get_extension` · `PermanentDelegate` |
> | §1.9 Sysvar & Precompile Account Safety | sysvar / precompile use | `sysvar` · `instructions_sysvar` · `ed25519` · `secp256k1` · `load_instruction_at` |
> | §1.10 Native / Pinocchio (No-Anchor) Program Safety | native / Pinocchio program | `pinocchio` · `p-token` · `no_std` · manual `AccountInfo` validation (absent when Anchor detected) |
>
> §1.1–1.7 and §1.11–1.13 are baseline account safety — evaluated for every on-chain program.

---

## 1.1 — Account Ownership Checks

- [ ] **AV-001**: Every account deserialized from `AccountInfo` has its `owner` field validated against the expected program ID
- [ ] **AV-002**: No account in `#[derive(Accounts)]` uses raw `AccountInfo<'info>` (deprecated in Anchor 1.0) — must use `UncheckedAccount<'info>` or typed `Account<'info, T>`
- [ ] **AV-003**: Every `UncheckedAccount<'info>` has a `/// CHECK:` doc comment that describes the ACTUAL runtime validation performed (not just "safe because...")
- [ ] **AV-004**: Every `/// CHECK:` comment corresponds to real code — grep for the validation logic referenced in the comment
- [ ] **AV-005**: Accounts typed as `Account<'info, T>` automatically check owner + discriminator — verify T matches the expected state struct
- [ ] **AV-006**: Token accounts use `Account<'info, TokenAccount>` or `InterfaceAccount<'info, TokenAccount>` — never raw `AccountInfo`
- [ ] **AV-007**: Mint accounts use `Account<'info, Mint>` — never raw `AccountInfo`
- [ ] **AV-008**: System program, token program, rent sysvar are typed with `Program<'info, System>`, `Program<'info, Token>`, `Sysvar<'info, Rent>` — not `AccountInfo`
- [ ] **AV-009**: No account marked as `Account<'info, T>` where T is a different program's state struct without explicit owner override
- [ ] **AV-010**: The program ID declared in `declare_id!()` matches the deployed program ID and the keypair file

## 1.2 — Account Discriminator & Type Cosplay

- [ ] **AV-011**: Every on-chain account uses Anchor's 8-byte discriminator (automatic with `#[account]` macro) — check no manual serialization bypasses it
- [ ] **AV-012**: No instruction accepts an account typed as struct A where struct B has the same memory layout prefix (type cosplay attack)
- [ ] **AV-013**: If `remaining_accounts` (or any `UncheckedAccount`/`AccountInfo`) are deserialized manually, the **owner is verified first**, then the discriminator (`try_deserialize`). The discriminator proves type, never provenance: a clone program with a struct of the same name produces identical bytes (default Anchor discriminator `sha256("account:<Name>")[..8]`; custom discriminators exist since 0.31).
- [ ] **AV-014**: If `remaining_accounts` are deserialized, verify the account address matches the expected PDA derivation — **discriminator checks alone are insufficient**
- [ ] **AV-015**: No account struct reuses the first 8 bytes of another account struct's discriminator (collision check)
- [ ] **AV-016**: Account structs use `#[account]` attribute (not manual `BorshSerialize`/`BorshDeserialize` without discriminator)
- [ ] **AV-017**: If accounts are migrated between versions, old discriminators cannot be confused with new ones

## 1.3 — Account Constraint Validation (Anchor `#[account(...)]`)

- [ ] **AV-018**: Every account that should be mutable is marked `#[account(mut)]`
- [ ] **AV-019**: No account is marked `#[account(mut)]` when it should be read-only (unnecessary mutability)
- [ ] **AV-020**: `has_one = field` constraints are used on accounts that reference other accounts (e.g., `has_one = manager`, `has_one = fund`)
- [ ] **AV-021**: `has_one` constraints are ALSO backed by runtime `require_keys_eq!` checks (defense-in-depth)
- [ ] **AV-022**: `init` accounts use `payer`, `space`, and `seeds` + `bump` correctly
- [ ] **AV-023**: `init_if_needed` is NOT used unless explicitly required — it opens reinitialization vectors
- [ ] **AV-024**: If `init_if_needed` IS used, there is a guard against reinitialization (e.g., checking a version/initialized flag)
- [ ] **AV-025**: `close = destination` constraints send lamports to the correct recipient — check destination is constrained
- [ ] **AV-026**: Closed accounts have their data zeroed (Anchor does this automatically with `close`, verify no manual close bypasses it)
- [ ] **AV-027**: `seeds` constraints use all necessary seed components (prevent PDA collision across different entities)
- [ ] **AV-028**: `bump` values are stored in state and reused (`bump = account.bump`) — not re-derived every time
- [ ] **AV-029**: `constraint = <expr>` custom constraints use proper error types, not generic `ConstraintRaw`
- [ ] **AV-030**: `realloc` constraints include `realloc::payer` and `realloc::zero` appropriately
- [ ] **AV-031**: No duplicate mutable accounts without explicit `#[account(mut, dup)]` opt-in (Anchor 1.0 rejects by default). This holds only in Anchor ≥ 1.0.0, and only for mutable `Account`/`LazyAccount`/`InterfaceAccount`/`Migration` fields without `dup` (plain `init` excluded, `init_if_needed` included; duplicates inside `remaining_accounts` are allowed). In every 0.x release (< 1.0.0), and in every version for `AccountLoader`, `UncheckedAccount`, `AccountInfo`, `Signer`, `SystemAccount` and `remaining_accounts`, distinct keys must be checked explicitly (FP-6, AV-108).

## 1.4 — Remaining Accounts Validation

- [ ] **AV-032**: All `remaining_accounts` are iterated and validated before use — no blind pass-through
- [ ] **AV-033**: For each remaining account, owner is verified (`account.owner == expected_program`)
- [ ] **AV-034**: For each remaining account used as a token account, mint and authority are verified
- [ ] **AV-035**: For each remaining account used as a PDA, the address is re-derived and compared
- [ ] **AV-036**: The count of remaining_accounts is validated (not more or fewer than expected)
- [ ] **AV-037**: Remaining accounts passed to external CPI (e.g., Jupiter) are at minimum program-ownership validated
- [ ] **AV-038**: No remaining account can be the same as a named account in the struct (duplicate account confusion)
- [ ] **AV-039**: If remaining accounts represent investor positions, each position's fund field matches the current fund

## 1.5 — Account Size & Rent

- [ ] **AV-040**: All `init` accounts allocate sufficient `space` — calculate manually: 8 (discriminator) + each field size
- [ ] **AV-041**: No account can be created with less than rent-exempt minimum lamports
- [ ] **AV-042**: Variable-length fields (Vec, String) in account structs have a maximum length enforced
- [ ] **AV-043**: `realloc`/`resize` stays within both limits: total size ≤ 10 MiB (`MAX_PERMITTED_DATA_LENGTH`), and growth per account per instruction ≤ 10,240 bytes (`MAX_PERMITTED_DATA_INCREASE`). Growth is measured from the account's length at the start of the instruction and shared by every realloc of that account in it, including reallocs in CPI callees. A caller-dependent growth with no upfront bound reverts on the only append/settle path → DoS.
- [ ] **AV-044**: No instruction allows reducing account size below the minimum required for its data

## 1.6 — Token Account Validation

- [ ] **AV-045**: Every token account used in transfers has its `mint` field validated against expected mint
- [ ] **AV-046**: Every token account used in transfers has its `owner`/`authority` field validated
- [ ] **AV-047**: Vault token accounts are verified as owned by the expected PDA (fund PDA)
- [ ] **AV-048**: Associated Token Accounts are derived correctly — `getAssociatedTokenAddressSync` or `associated_token::` seed derivation
- [ ] **AV-049**: Token accounts with `delegate` field — verify delegate authorization before using delegated_amount
- [ ] **AV-050**: Token accounts are checked for `frozen` state if freeze authority exists
- [ ] **AV-051**: WSOL (wrapped SOL) accounts use the correct native mint address (`So11111111111111111111111111111111111111112`)
- [ ] **AV-052**: Token-2022 accounts are not confused with original Token Program accounts (different program IDs)

## 1.7 — Reinitialization Protection

- [ ] **AV-053**: No instruction can re-initialize an already-initialized account (check `init` vs `init_if_needed`)
- [ ] **AV-054**: If manual initialization is used (not Anchor `init`), an `is_initialized` flag is checked. Check the polarity (AV-100).
- [ ] **AV-055**: After account closure, the same PDA seeds cannot be re-derived to create a new account with stale associations
- [ ] **AV-056**: Revival attack: after `close`, can an attacker send lamports to the closed account address to prevent garbage collection and re-use stale data? (see KV-106)
- [ ] **AV-057**: If an account is closed mid-transaction, subsequent instructions in the same transaction cannot access stale data from that account

## 1.8 — SPL Token & Token-2022 Extension Safety

- [ ] **AV-058**: Token program is identified correctly per account — classic `Token` vs `Token-2022` (`token_program` is constrained, not assumed); `InterfaceAccount`/`token_interface` used when both must be supported
- [ ] **AV-059**: Associated Token Accounts are enforced via Anchor `associated_token::mint`, `associated_token::authority` (+ `associated_token::token_program`) — not a bare `Account<TokenAccount>` where the canonical ATA is assumed (see KV-107)
- [ ] **AV-060**: Token transfers use `transfer_checked` / `mint_to_checked` / `burn_checked` (decimals + mint bound at runtime), not the unchecked legacy variants
- [ ] **AV-061**: Token `decimals` are read from the mint account, never hardcoded; cross-mint amounts are normalized before being added or compared (see KV-108)
- [ ] **AV-062**: Credited amounts are computed from vault balance deltas (after − before), so transfer-fee / fee-on-transfer tokens cannot over- or under-credit (see KV-018, KV-105)
- [ ] **AV-063**: If arbitrary mints are accepted, the program inspects Token-2022 mint extensions and rejects (or explicitly handles) `PermanentDelegate`, `DefaultAccountState::Frozen`, `MintCloseAuthority`, transfer-hook, confidential-transfer, and interest-bearing configs (see KV-105, KV-023)
- [ ] **AV-064**: Custodied/vault token balances are not exposed to clawback or freeze by an untrusted mint authority (permanent delegate / freeze authority risk is checked or the mint is allowlisted)
- [ ] **AV-065**: Mint `freeze_authority` and `mint_authority` status is considered for accepted tokens — frozen accounts cannot deadlock withdrawals (see AV-050, KV-019)
- [ ] **AV-066**: A mint allowlist (or explicit per-mint vetting) exists wherever the protocol cannot safely handle every possible mint/extension combination
- [ ] **AV-067**: Token account `close_authority`/`delegate` fields are validated — no unexpected delegate can move vault funds, and close authority cannot be weaponized. For token accounts the program did not create itself, see AV-103 / KV-164.

## 1.9 — Sysvar & Precompile Account Safety

> Instruction-introspection pairing: KV-151. Sibling-instruction introspection: CPI-036.

- [ ] **AV-068**: Clock/Rent/epoch data is obtained via syscalls (`Clock::get()`, `Rent::get()`) — not read from a passed-in account whose contents an attacker controls (see KV-101)
- [ ] **AV-069**: Sysvars are obtained via `Sysvar::get()` where available. A passed sysvar account is read only through an id-checking accessor (`Sysvar<'info, T>`; `Sysvar::from_account_info`, which checks the id; or `sysvar::instructions::*_checked`), or its address is asserted. FAIL only when bytes are read without an id check (raw bincode/bytemuck/offsets, unchecked `load_*`). Using `from_account_info` where `get()` exists is Informational (compute/tx-size) (FP-8).
- [ ] **AV-070**: Time-gated logic (cooldowns, vesting, auctions, oracle staleness windows) cannot be bypassed by a forged Clock account
- [ ] **AV-071**: If signatures are verified via Instructions-sysvar introspection, the precompile program ID (`ed25519_program` / `secp256k1_program`) is asserted (see KV-102). Include the secp256r1 precompile (`Secp256r1SigVerify1111111111111111111111111`, SIMD-0075) for passkey/P-256 flows; see AV-111.
- [ ] **AV-072**: Introspection-based signature checks bind the exact pubkey, full message, and signature offsets to the current action — not merely "a precompile instruction exists"
- [ ] **AV-073**: Introspected signed messages include a nonce/expiry/slot tied to state so they cannot be replayed across transactions or accounts
- [ ] **AV-074**: Instruction index used in introspection is computed safely (relative or validated) — no fixed-index assumption an attacker can shift by inserting instructions
- [ ] **AV-075**: Privileged accounts (treasury/authority/config) are bound via `has_one` / `seeds` / `address` / `require_keys_eq!` and never trusted by transaction position or ALT-resolved order (see KV-103)
- [ ] **AV-076**: PDA bumps are canonical (`find_program_address` / Anchor canonical bump), stored in state, and reused — no user-supplied bump is fed to `create_program_address` (see KV-104)
- [ ] **AV-089**: No `require!` / branch reads `ComputeBudgetProgram` instructions from the Instructions sysvar (priority-fee floor, CU-limit floor, "budget instruction must be first / only other instruction") — under transaction v1 those instructions are no-ops and the real config lives in the message header, which no sysvar or syscall exposes; such a gate is silently unenforced or rejects every v1 user (see KV-135)
- [ ] **AV-090**: Instruction-introspection loops and positional / count assumptions (`load_instruction_at`, `get_instruction_relative`, "exactly N instructions", `remaining_accounts.len() <= N`) are correct for up to 64 instructions and 64 inline accounts (v1 caps), tolerate the presence of no-op ComputeBudget instructions, and do not rely on address-lookup-table resolution (v1 has none — see KV-103, `references/vuln-classes/transaction-v1.md` V5)

## 1.10 — Native / Pinocchio (No-Anchor) Program Safety

> Applies to native, zero-copy, or **Pinocchio**-based programs (incl. **p-token**). Anchor provides owner/discriminator/signer/mut checks automatically; native programs do NOT — each must be verified by hand. (see KV-109)

- [ ] **AV-077**: Detect the framework — if the program is native/Pinocchio (`entrypoint!`, `no_std`, `pinocchio*` deps) rather than Anchor, every guarantee below is manual and must be individually confirmed
- [ ] **AV-078**: Every account that is deserialized or trusted has its `owner` explicitly verified against the expected program ID (no Anchor `Account<T>` auto-check exists here)
- [ ] **AV-079**: Signer authority is asserted via an explicit `is_signer` check on every value-moving / privileged account; mutated accounts assert `is_writable`
- [ ] **AV-080**: The number of passed accounts is validated, and every zero-copy byte-slice read is bounds-checked (`data.len() >= N`) before indexing — no fixed-index access or unchecked slice that can panic / read out of bounds
- [ ] **AV-081**: All `unsafe` blocks (raw pointer arithmetic, `from_raw_parts`, `get_unchecked`) are preceded by an explicit length/alignment guard — no undefined behavior on malformed input
- [ ] **AV-082**: Account type is disambiguated by owner + length + explicit tag — single-byte (or absent) discriminators cannot be confused with another account of similar layout (type cosplay)
- [ ] **AV-083**: If the Pinocchio `unsafe-account-resize` feature is used, the program itself validates the new size stays within permitted bounds (the framework does not)
- [ ] **AV-084**: For p-token / reimplemented SPL Token logic: behavior matches canonical SPL Token on edge cases (zero-amount, frozen account, multisig M-of-N parsing, `transfer_checked` decimals, immutable owner, exact error codes) — no CU optimization dropped a required check (ideally differential-tested against `spl-token`)

## 1.11 — Lamport Donation & Runtime-Level Account Safety

> Lamports can be transferred into any account permissionlessly, and feature-gate activations can demote a writable builtin/sysvar to read-only. Instructions must not assume they control an account's exact balance or writability. (see KV-123)

- [ ] **AV-085**: No instruction assumes an **exact** lamport balance on any account an attacker can donate into (use `>=` sufficiency checks, not `==`) — a donated balance must not force a runtime-rejected RentState transition that permanently bricks the instruction (rent-state bricking / "king-of-the-SOL", see KV-123)
- [ ] **AV-086**: No instruction requires **write access** to a builtin/sysvar/precompile account (or any account it does not actually modify) that a feature-gate may demote to read-only — an unnecessary `#[account(mut)]` on such an account breaks the instruction on demotion (see KV-123)

## 1.12 — Account Pre-Creation DoS & Unsafe Deserialization

> Two distinct integrity gaps observed repeatedly in real reports: (a) an honest `init` that an attacker can front-run by pre-creating the target account, and (b) `unsafe` deserialization that reads uninitialized or out-of-bounds memory. Both differ from the reinitialization angle in AV-023/024 — here the account either already exists (griefing) or its bytes were never fully initialized/validated.

- [ ] **AV-087**: Any instruction that `init`s a user-derivable account (especially an ATA) tolerates the account already existing — via `init_if_needed` plus explicit state validation, or by handling the pre-existing case — so an attacker cannot front-run the account's creation and permanently revert the honest instruction (permissionless pre-creation DoS, distinct from reinit; see KV-127)
- [ ] **AV-088**: `unsafe` deserialization on-chain (`Vec::set_len`, `MaybeUninit::assume_init`, manual/zero-copy flat-slab or `memmove`-based decoders) fully initializes and bounds-checks every byte before it is read — no read-past-initialized memory, no under-length `memmove`, no state corruption from malformed input

## 1.13 — Provenance, Layout & Initialization Hardening

<!-- verified: anchor v1.0.0 lang/syn/src/codegen/accounts/try_accounts.rs (dup-mut check: #3946, narrowed to Account/LazyAccount/InterfaceAccount/Migration by #4202, init_if_needed included by #4239); anchor v1.2.0 lang/src/accounts/account_loader.rs (new_unchecked); anchor v1.0.0 lang/src/accounts/migration.rs; anchor v2.0.0-rc.2 lang-v2/src (borrow_unchecked* = pinocchio AccountView borrow-tracking bypass); agave v1.18.26 sdk/program/src/{entrypoint.rs MAX_PERMITTED_DATA_INCREASE, system_instruction.rs MAX_PERMITTED_DATA_LENGTH, instruction.rs get_stack_height, sysvar/instructions.rs deprecated since 1.8.0}; agave v2.1.0 sdk/program/src/sysvar/instructions.rs (unchecked helpers removed); agave v3.0.0 precompiles/src/{ed25519.rs,secp256k1.rs,secp256r1.rs}; token-2022 main interface/src/extension/mod.rs (adjust_len_for_multisig, check_min_len_and_not_multisig) -->

- [ ] **AV-091**: An instruction-introspection consumer cannot be satisfied more than once by the same producer instruction. An absolute index (`load_instruction_at_checked(0, ..)`) with no consumed-marker or 1:1 pairing check is a FAIL (KV-151).
- [ ] **AV-092**: Every handler that uses Instructions-sysvar introspection to pair or order top-level instructions (flash-loan borrow/repay, "X must follow/precede", "no other instruction") rejects CPI entry by requiring `get_stack_height() == TRANSACTION_LEVEL_STACK_HEIGHT` (`solana_program::instruction`). A check that the current top-level instruction's `program_id == crate::ID` is only a supplement. Under CPI, `load_current_index_checked` returns the index of the outer top-level instruction, and an attacker can reach the handler at depth > 1 via a hook, an arbitrary-CPI target or a callback (KV-151). Precompile signature checks that bind the signer, message and offsets (AV-111) do not need this guard.
- [ ] **AV-093**: The introspected producer is fully decoded and bound: variant/discriminator, amount, destination == the consumer's own vault/PDA, mint and authority, read with bounds-checked `.get()` access. For SPL `Transfer` the destination is account index 1; for `TransferChecked` the mint is index 1 and the destination index 2. Checking `program_id` alone is a FAIL (KV-151).
- [ ] **AV-094**: No deprecated unchecked Instructions-sysvar helper (`load_instruction_at`, `load_current_index` without `_checked`) reads bytes from an account whose key is not asserted to be `sysvar::instructions::ID` on every path. These helpers were deprecated in solana-program 1.8.0, remain through the 1.x line and 2.0.x (verified 1.18.26, 2.0.0), and were removed in 2.1.0. Check `Cargo.lock` before calling them impossible. Grep: `rg -n "load_instruction_at\s*\(|load_current_index\s*\(" programs/`.
- [ ] **AV-095**: Every owner check is *correct*, not just present. It reads `AccountInfo::owner` (never a deserialized field), compares it with the right program id (the token program for token accounts, `program_id` for state), is enforced by an error return, and does not confuse the owning program with the unpacked wallet `owner` (KV-015).
- [ ] **AV-096**: Deserialization of an account the attacker can supply never relies on the discriminator alone (clone-program cosplay) and never trusts a `Signer<'info>` account's data without owner + discriminator checks.
- [ ] **AV-097**: For every privileged deserialization that skips a type-tag check (native/Pinocchio, `try_deserialize_unchecked`, `deserialize(&mut &data[8..])`, raw bytemuck), overlay every *donor* type on the victim type. A donor type is one whose fields a caller can set without privilege. If attacker-controlled bytes land on an authority, amount or destination field, it is exploitable. Account for variable-length Borsh fields, whose offsets depend on the donor's chosen contents (KV-159).
- [ ] **AV-098**: For every state struct whose fields changed since the deployed version while its name/tag stayed the same, existing accounts are handled in one of three ways: migrated by an instruction that covers every account; rejected by a version field that existed **since v1**; or the type was renamed (new discriminator) and migrated, e.g. with Anchor's `Migration<'info, From, To>` (Anchor ≥ 1.0.0). Inserted fields and type changes are Critical candidates. Appended fields in over-allocated accounts decode as zero, so each zero value must be proven safe (KV-160).
- [ ] **AV-099**: Every client-allocated init target (zero-copy slabs, large or keypair accounts) uses `#[account(zero)]` (or, natively, an all-zero discriminator check + owner check). **In addition**, the account must be required as a `Signer` (`#[account(zero, signer)]`) unless the client creates and initialises it in the same transaction, and nothing on-chain can enforce the same-transaction case. A `mut` initializer over a live account, or an init in a later transaction with no signer binding, is a FAIL (KV-142).
- [ ] **AV-100**: Every manual init guard has the right predicate and polarity. Write the truth table: uninitialized → allowed, initialized → rejected, flag set in the same write. `data_len() == 0` is the wrong predicate for a pre-allocated program-owned account; it is only an existence pre-check when the handler itself creates the account by CPI. For an 8-byte discriminator layout, all 8 bytes must be zero.
- [ ] **AV-101**: Anchor `space` for Borsh accounts is `8 + T::INIT_SPACE` (`#[derive(InitSpace)]`), never `size_of::<T>()`. Every `#[max_len(N)]` collection has `require!(v.len() < N, ..)` before each push. (`size_of` is right for `zero_copy`/bytemuck types.)
- [ ] **AV-102**: Accounts created through a CPI (`init`, or System `create_account`/`allocate` inside the program) have `space ≤ 10,240`. Larger accounts use a top-level client `createAccount` (up to 10 MiB) + `zero` (AV-099), or grow by ≤ 10,240 bytes per instruction afterwards.
- [ ] **AV-103**: A token account the program did not create is rejected unless `close_authority.is_none()` and `delegate.is_none()`, and its owner is re-checked on every use. This covers adopted vaults ("pass a token account whose owner is our PDA") and `set_authority` in `init`. Preferred: the program creates the vault at a PDA address (`init` + `seeds` + `token::authority`) (KV-164).
- [ ] **AV-104**: Native SPL parsing (`Account::unpack*`, `Mint::unpack`, `StateWithExtensions::unpack`) always sits next to an owner check against the expected token program. Callers of `_unchecked`/`unpack_from_slice` reject uninitialized accounts. Code that accepts Token-2022 uses the extension-aware parser (native.md §6).
- [ ] **AV-105**: Mint vs token-account vs multisig classification never uses data length (Token-2022 lengths vary). Token-2022 never produces a mint or token account of exactly 355 bytes (`Multisig::LEN`): a layout that would land there gets 2 extra bytes, and the extension parser rejects length 355. Classification uses a successful typed unpack after the owner check (TK-017).
- [ ] **AV-106**: Every passive-role token account (`recipient_*`, `beneficiary_*`, `claimant_*`, `<role>_token_account`, `to_*`) is anchored to the role with `token::authority = <role>`, `associated_token::authority = <role>` or `constraint = acct.owner == role.key()`, and the role itself is bound to stored state (`address = grant.recipient`). Owned-by-the-token-program alone is a FAIL (KV-147).
- [ ] **AV-107**: An address persisted as trusted (oracle, pool, vault, mint registry, signer list) was validated at registration (owner + discriminator + expected data, signer or canonical PDA where applicable) and is re-validated (owner + discriminator) at every use. A key match alone is insufficient (KV-148).
- [ ] **AV-108**: Duplicate-account distinctness is checked by **key comparison** for every pair the framework does not cover (FP-6) and for `remaining_accounts` (sort keys, reject adjacent duplicates). Leaving `mut` off one of the pair proves nothing. Anchor does not require a non-`mut` account to be read-only, and a key passed twice carries the same writable flag in both positions, so one writable account can fill both slots.
- [ ] **AV-109**: Anchor unchecked constructors on a user-suppliable account have adjacent manual owner and discriminator checks (AN-019). These are `AccountLoader::new_unchecked` (anchor-lang ≥ 1.2.0; no owner or discriminator check), `Account::try_from_unchecked` / `AccountLoader::try_from_unchecked` (owner checked, discriminator not) and `try_deserialize_unchecked` (no discriminator). Pinocchio / anchor-lang-v2 `borrow_unchecked*` are a different hazard: they skip the runtime's borrow tracking (aliasing), not validation (KV-182).
- [ ] **AV-110**: Constraints that compare against another account's key (`seeds::program`, `owner =`, `address =`, `token::authority =`, `has_one`-style, seeds containing `x.key()`) take that key only from an account that is itself pinned (`Program<'info, T>`, `address = KNOWN_ID`, canonical PDA/ProgramData). A `/// CHECK:` comment claiming "checked elsewhere" must point to a real check (KV-145).
- [ ] **AV-111**: Signature-precompile introspection pins the right precompile id per scheme (ed25519, secp256k1, secp256r1) and requires `num_signatures ≥ 1`. The ed25519 and secp256k1 precompiles accept an instruction with zero signatures (data of length 2 or 1); secp256r1 rejects it. It binds every offset/index field to the precompile instruction itself (KV-102), compares the signed message, and counts **distinct allowed** signers against a threshold (an "every signature is allowed" loop passes on an empty list). Never use signature bytes as replay keys. The secp256k1 precompile accepts both S forms (malleable); secp256r1 rejects high-S; ed25519 uses strict verification once SIMD-0152 (`ed25519_precompile_verify_strict`) is active. Put a nonce in the signed message instead.
- [ ] **AV-112**: Wrapped-SOL (native-mint) vaults: anyone can send lamports to the account and call the signer-less `SyncNative`, which raises `amount` to `lamports − rent_exempt_reserve`. Share pricing reads internal accounting (not the live `amount`); reconciliation uses `>=`, not `==`; code never mixes `lamports()` and `amount` (that counts the rent reserve twice or not at all) (KV-163).

*Sources: Trail of Bits not-so-smart-contracts §1/§2 [paraphrased, AGPL-3.0, cited] (corrected: stack-height guard required; deprecation scope); PlamenTSV/plamen §2 (MIT, Copyright (c) 2025-2026 Plamen Contributors); solana-foundation/solana-dev-skill #2/#7 (MIT, Copyright (c) 2026); crytic/solana-lints U5 [paraphrased]; Neodyme "Common Pitfalls" U1/U5 [paraphrased, cited]; Solana Foundation course U3/U8 [paraphrased, cited]; coral-xyz/sealevel-attacks #2/#3 [paraphrased, cited]; sannykim/solsec → Candy Machine write-ups [paraphrased, cited]; franpersanchez/solana-audits-skill #4 (MIT, Copyright (c) 2026 Fran Pérez); Ackee bootcamp #3/#9 [paraphrased, cited]; qedgen/solana-skills role-token-account and store-without-validate patterns (MIT, Copyright (c) 2025 QEDGen); otter-sec/anchor (Apache-2.0); original gap analysis. Version facts checked against anchor v1.0.0/v1.2.0/v2.0.0-rc.2, agave v1.18.26/v2.0.0/v2.1.0/v3.0.0 and token-2022 `main`.*
