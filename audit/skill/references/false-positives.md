# False Positives — "Vulnerabilities That Aren't" (Triage Catalog)

> **Load when:** triaging a candidate finding, or *before* reporting anything at High+
> severity (N ≥ 6). Read this first if a finding matches an EVM-brain reflex or a pattern that
> *looks* dangerous but is neutralized by the runtime or the framework.
>
> **Purpose:** Over-reporting is the primary failure mode of an AI auditor. This is a catalog
> of patterns that trip pattern-matchers but are **not** bugs on modern Solana — each with the
> concrete reason it's safe. It exists to *cut* false positives, not to excuse skipping work.
>
> **How to use — the gate discipline:** before you report **X**, confirm it is not one of the
> entries below. If it genuinely is that pattern, do **not** report it. If you believe you have
> a real instance anyway, the finding is only valid when the **Rule 5b** validation gate
> (`OUTPUT-RULES.md`) shows the **specific escape** — the concrete code path that defeats the
> protection described here, cited to `file:line`. "It could still be bad" is not an escape.
> A bare High-severity claim that matches an entry here, with no cited escape, must be
> downgraded to `[PARTIAL]` or `[UNCONFIRMED]`.
>
> **Quantify the barrier (symmetric discipline for *rejections*).** The same Rule 5b
> Math/State-Bounds rigor that a *finding* must survive also binds a **downgrade**. When you
> reject or downgrade a candidate on **economic infeasibility** ("not profitable") or a
> **precondition that cannot be met** ("not reachable / not exploitable"), you must show the
> **worked bound** that justifies it — the concrete numbers (capital required vs. maximum
> extractable, cost > gain by how much), or the **specific precondition** and *why* an attacker
> cannot satisfy it (which guard, which state, cited to `file:line`). A bare "not profitable" /
> "not exploitable" / "attacker gains nothing" with no worked math or named blocking precondition
> is **not a valid rejection** — it is exactly the corner AI auditors cut. Treat an
> unquantified dismissal like an unquantified High: it does not clear the gate, so the finding
> stays open (`[PARTIAL]` / `[UNCONFIRMED]`) until the barrier is actually computed. This mirrors
> the Rule 5b worked-case rejection example ("input ≥ 16 and header = 8 ⟹ … cannot underflow").
>
> *(Credit: public Solana security research and publicly disclosed audit findings.
> Paraphrased sources are re-expressed in our own words; every source and its licence is listed
> in the Sources line at the end of this file.)*

---

## How each entry is framed

- **The reflex** — what an auditor (often EVM-trained) is tempted to flag.
- **Why it's not a bug** — the runtime/framework property that neutralizes it.
- **The escape** — the *only* thing that makes it a real finding; what the Rule 5b gate must
  show, cited to `file:line`, before you report it.

---

## FP-1. Solana "reentrancy": indirect re-entry is impossible; look for stale state, self-CPI and untrusted callees instead

**The reflex.** "There's a CPI before the state write — classic reentrancy, like The DAO."

**Why the EVM shape does not apply.**
- The runtime rejects a CPI into any program already on the invocation stack unless it is the immediate caller: **A → B → A fails with `ReentrancyNotAllowed`**, and so does A → Token-2022 → transfer hook → A. A hook cannot call back into the program that started the transfer. <!-- verified: agave v4.3.2 program-runtime/src/invoke_context.rs InvokeContext::push ("Reentrancy not allowed unless caller is calling itself") -->
- **Direct self-recursion A → A is allowed** (up to the CPI nesting limit). That is the only re-entry the runtime permits.
- Nesting depth is bounded: the maximum instruction stack height is 5 (top-level instruction + 4 nested CPIs), and 9 (8 nested CPIs) once the SIMD-0268 feature `raise_cpi_nesting_limit_to_8` is active. Record which applies on the target cluster in the runtime-context sheet before quoting a number. <!-- verified: agave v4.3.2 program-runtime/src/execution_budget.rs MAX_INSTRUCTION_STACK_DEPTH = 5, MAX_INSTRUCTION_STACK_DEPTH_SIMD_0268 = 9; feature-set/src/lib.rs "SIMD-0268: Raise CPI nesting limit from 4 to 8" -->
- Token-2022 passes the source, mint, destination and authority (and the extra-account-metas validation account) to a transfer hook **read-only and without signer privilege**; only `ExtraAccountMeta` entries keep the flags they were configured with, and those can never exceed the privileges the account has in the outer transfer instruction. <!-- verified: token-2022 program@v10.0.0 program/src/processor.rs calls spl_transfer_hook_interface::onchain::invoke_execute; the interface's `execute` builder uses AccountMeta::new_readonly(.., false) for these accounts -->

**Where the real bugs are (report these instead).**
1. **Stale state after a CPI.** The callee changed an account the caller deserialized earlier, and the caller decides from the cached copy (RE-002/003, `.reload()` rules per Anchor version).
2. **Untrusted code inside the caller's critical section.** A hook or caller-chosen CPI target runs while the caller's invariants are temporarily false. It can CPI into *third* programs not on the stack, read the caller's accounts as last written back (for Anchor `Account<T>` fields, the state before the handler's in-memory edits unless the handler serialized them before the CPI), use forwarded signer/writable privileges, or simply fail (griefing / DoS). It cannot call back into the caller.
3. **Self-CPI.** The program CPIs into itself on purpose (routers, batching, `emit_cpi!`) or executes a caller-chosen instruction (multisig/DAO executors, generic routers) where the attacker picks the program itself (RE-008). With Anchor, an inner self-CPI write is overwritten by the outer instruction's `exit()` unless state was flushed and reloaded (RE-009/RE-010).
4. **Cross-instruction sequencing** inside one transaction (ix1 → ix2 → ix3, all top level): each sees the committed result of the previous one.

**The escape (report only if one holds).** (a) A named A → A path (self-CPI or caller-chosen target that can be `crate::ID`) reaches state not yet written; (b) a callee can mutate an account the caller later trusts without reload; (c) forwarded privileges let an untrusted callee act on other assets; (d) the untrusted callee CPIs into a **sibling program of the same protocol** (a different program id, so not blocked by the reentrancy rule) that reads or writes the state the caller has left half-updated. The Rule 5b Reachability block traces the edge. "CPI before write" alone is not a finding.

---

## FP-2. Anchor `close` revival — the sentinel is gone; know which version you are on

**The reflex.** "The account is closed by draining lamports — an attacker refunds it and the stale data deserializes again."

**What `close = dst` actually does, by version.**

| anchor-lang | `close = dst` / `common::close` | A same-tx refunded account looks like | Residual risk |
|---|---|---|---|
| older than 0.26.0 | drain lamports, then overwrite only the first 8 bytes with `CLOSED_ACCOUNT_DISCRIMINATOR` (`[255;8]`); the rest of the data is **not** zeroed; owner stays the program | program-owned, sentinel discriminator, old field bytes still present after byte 8; `Account<T>` fails the discriminator check | raw `AccountInfo`/`try_from_slice`/offset readers still see the old fields; the refunded account occupies the address (the PDA cannot be re-created) unless a permissionless "defund sentinel" path exists |
| 0.26.0 (#2169) – 0.29.x | drain lamports, `assign(System)`, `realloc(0)`; the constant is still exported (`__private::CLOSED_ACCOUNT_DISCRIMINATOR`) | System-owned, 0 bytes; `Account<T>` fails the owner check | **re-creation**: `init`/`init_if_needed` at the same PDA succeeds with fresh default state |
| ≥ 0.30.0 | same as above (`resize(0)` instead of `realloc(0, false)` from 0.32.0); the constant was removed (#2726) | same | same |

The `close = dst` constraint has rejected `dst == self` with `ConstraintClose` since at least 0.20.0. A manual `.close()` call (the `AccountsClose` trait, `common::close`) has no such guard in any tagged release (checked through v1.2.1 and v2.0.0-rc.2): closing an account into itself adds its lamports to itself, then zeroes them, so the balance is burned. The guard (#5202) is on anchor `master` (Unreleased) and on the `release-bump/1.2.2` branch; treat it as present only once the pinned version's `common.rs` contains it.

Check the boundary against `lang/src/common.rs` of the pinned version. <!-- verified: anchor v0.20.0, v0.24.2, v0.25.0, v0.26.0, v0.29.0, v0.30.0, v0.31.1, v0.32.0, v1.0.0, v1.2.1 lang/src/common.rs; CHANGELOG 0.26.0 #2169, 0.30.0 #2726; v0.20.0, v0.25.0, v0.30.1 and v1.2.1 lang/syn/src/codegen/accounts/constraints.rs generate_constraint_close; fix commit a528c030 / de580683 "reject closing an account into itself (#5202)" is not an ancestor of v1.2.1, v2.0.0-rc.1 or v2.0.0-rc.2 -->

**Why `close = dst` is usually not a revival finding.** A refunded account is an empty System-owned account; `Account<T>` rejects it on owner and discriminator.

**The escape (report only if one holds).** (a) Anchor older than 0.26.0 (sentinel era) with raw readers or no defund path; (b) a **manual** close (native, Pinocchio, hand-rolled Anchor) that does not do all three in one instruction: drain all lamports, `assign(&system_program::ID)`, `resize/realloc(0)`; (c) a manual close that zero-fills data but keeps `owner == program`, and some instruction initializes that type through `#[account(zero)]` (a refunded zero-filled program-owned account passes `zero`, KV-142); (d) a **one-shot marker** PDA (claim receipt, nonce, "already voted") that is *closed* rather than kept, with seeds the same user can re-derive: once closed, the marker is indistinguishable from one that never existed, so `init` re-enables the action; (e) other state still references the closed key. Do not report "does not write the closed discriminator" by itself.

---

## FP-3. Float non-determinism — sBPF emulates `f64` deterministically

**The reflex.** "This program uses `f64` — floating point is non-deterministic across nodes,
so it's a consensus-divergence bug."

**Why it's not automatically a bug.** The sBPF virtual machine executes floating-point
operations through a **deterministic software emulation**: every validator computes the *same*
bits for the same inputs. IEEE-754 `f64` under sBPF is reproducible, so float use **by itself**
is not a consensus fork risk. (It remains poor practice for *financial* math — rounding,
precision loss, and `NaN`/`Inf` edge cases are real correctness concerns — but those are
accuracy findings, judged on their own merits, not "non-determinism.")

**The escape (report the *right* finding).** Do not report "non-determinism." Report the actual
defect if present: precision loss / rounding in value math that lets an attacker extract funds
or corrupt accounting (quantify it via the Rule 5b Math/State-Bounds block), or an unhandled
`NaN`/`Inf` that reaches a comparison and bypasses a guard. Frame and severity follow the
economic impact, not the mere presence of `f64`.

---

## FP-4. Partial state on failure — Solana reverts the whole transaction atomically

**The reflex.** "If instruction 3 fails after instruction 2 wrote state, the account is left
in an inconsistent half-updated state."

**Why it's not a bug.** A Solana transaction is **atomic**: if *any* instruction in it returns
an error, the **entire transaction is rolled back** and **no** account changes from *any*
instruction in that transaction are committed. There is no "partial commit" of the earlier
instructions' writes. So "state left inconsistent after a failed instruction" is, for
in-transaction failures, a non-issue by construction.

**The escape (report only if it's genuinely cross-transaction).** A real inconsistency requires
state that is *intended* to span **multiple transactions** and can be left half-finished
**between** them — e.g. a multi-tx flow (init in tx A, finalize in tx B) where an attacker can
wedge the object in an exploitable intermediate state, or a griefing DoS that strands funds
until a second tx that an attacker can block. The Rule 5b Reachability block must show the
persistence boundary is a *transaction* boundary, not an instruction boundary. Within a single
tx, do not report it.

**Caught vs uncaught errors.** A *callee* failure inside a CPI aborts the whole transaction and cannot be caught. Errors raised **in the caller before the syscall** come back as `Err` and *can* be swallowed by `let _ =`, `.ok()` or `if let Err(..)`: the `RefCell` borrow checks in `invoke`/`invoke_signed` (`AccountBorrowFailed` when an account passed writable is already borrowed at all, or one passed read-only is currently mutably borrowed; the `*_unchecked` variants skip these checks), instruction-builder errors (`spl_token::instruction::*` returns `IncorrectProgramId` for a wrong program id), and framework/helper pre-checks. In those cases the CPI never ran and execution continues. That is a real finding class (KV-150), not a false positive.

---

## FP-5. `init_if_needed` is not always a bug

**The reflex.** "`init_if_needed` is present — reinitialization vulnerability."

**Why it's not automatically a bug.** `init_if_needed` is only dangerous when **re-invoking it
changes security-relevant state** — i.e. an attacker can pre-create (or re-run against) the
account to reset an authority, reset a balance/flag, or otherwise overwrite state the program
later trusts. If the handler **re-validates the pre-existing state** before trusting it (gates
on an `initialized` flag, or asserts the stored authority equals the caller), or if the
"create-or-reuse" is genuinely idempotent and touches no security field, the mere presence of
`init_if_needed` is not an exploit.

**The escape (report only if it changes security-relevant state).** A reachable call where
re-initialization **mutates a field the program relies on for authorization or accounting**
(authority, admin flag, balance, config) **without** a guard proving the account was fresh /
owned by the caller. The Rule 5b block must name the overwritten field and show the missing
guard @ `file:line`. If a reinit guard exists (e.g.
`require!(!state.initialized || state.authority == caller, ...)`), downgrade — it is
defense-present. (Aligns with `known-vectors/014` PARTIAL/PASS conditions and
`framework-idioms/anchor.md` §3.)

---

## FP-6. Duplicate mutable accounts — Anchor ≥ 1.0.0 rejects them, but only for some types

**The reflex.** "Two `mut` accounts of the same type could be passed the same address."

**What Anchor actually checks.** Default rejection arrived in **Anchor 1.0.0** (#3946; `dup` opts out). Anchor < 1.0.0 does **not** reject duplicate mutable accounts. 0.25–0.32 only reject duplicate *reallocs* (`AccountDuplicateReallocs`), and from 0.31.0 (#3409) a `zero` field must differ from every `zero`/`init` field declared **before** it in the same struct. In 1.x the check covers only fields that are **`mut`** (a read-only field aliasing a `mut` field is never checked; it just reads a stale copy) and whose type serializes on exit — `Account`, `LazyAccount`, `InterfaceAccount`, `Migration` (#4202) — plus `init_if_needed` fields (#4239), including such fields inside composite structs; all three changes shipped in 1.0.0. It does **not** cover `AccountLoader` (zero-copy), `UncheckedAccount`, `AccountInfo`, `SystemAccount`, `Signer`, `Program`, `Interface`, fields marked `dup`, pure `init` fields, or `remaining_accounts` versus named accounts. **`zero` + `init` aliasing:** all `init` constraints run before the other constraints and leave the new account program-owned and zero-filled (the discriminator is written only at exit), which is exactly what `zero` accepts. The `zero` uniqueness scan only looks at earlier fields of the same struct, so through 1.2.1 a `zero` field declared **before** an `init` field, or a `zero`/`init` pair split across composite structs, can bind the same fresh account; on 0.31.x–0.32.x a `zero`/`zero` pair split across composite structs can too (1.x catches that pair only through the duplicate-mutable check, so not for `AccountLoader`); before 0.31.0 any `zero`/`zero` or `zero`/`init` pair can. The fix (#4871) is on anchor `master` (Unreleased) and is not in any tagged release (checked through v1.2.1 and v2.0.0-rc.2; the 2.0 `lang-v2` crate was not checked). <!-- verified: anchor CHANGELOG 1.0.0 (#3946, #4202, #4239), 0.31.0 (#3409); v0.25.0–v0.32.1 lang/src/error.rs and constraints.rs AccountDuplicateReallocs (absent in v0.24.2); v0.30.1, v0.31.0, v1.2.1, v2.0.0-rc.2 lang/syn/src/codegen/accounts/constraints.rs generate_constraint_zeroed (take_while scan over AccountField::Field only); v1.2.1 try_accounts.rs generate_duplicate_mutable_checks (is_mutable && !is_dup && !is_pure_init, composite keys included); v0.29.0 exit.rs (only `mut` fields exit, in field order); fix commit 035797c6 "stop `zero` from aliasing an `init` account (#4871)" not an ancestor of v1.2.1 / v2.0.0-rc.2 -->

**Not a finding only if** anchor-lang ≥ 1.0.0 **and** both aliased fields are `mut` **and** both are `Account`/`LazyAccount`/`InterfaceAccount`/`Migration` **and** neither uses `dup` **and** the pair is not a `zero` field aliasing an `init` field (open through 1.2.1, see above).

**The escape (report if one holds and aliasing corrupts state).** Native/Pinocchio; Anchor < 1.0.0; a read-only typed field aliasing a `mut` one (stale read); `AccountLoader`, `UncheckedAccount`, `AccountInfo` or `SystemAccount` pairs; `remaining_accounts`; a `dup` field; a `zero` field declared before an `init` field, or split across composite structs, on ≤ 1.2.1 (any `zero`/`init` pair before 0.31.0). For Anchor `Account<T>` aliasing on < 1.0, the persisted result is the copy of the **last-declared `mut`** field (exit serializes only `mut` fields, in field order), so compute the outcome with two independent copies from the same snapshot and keep only the last field's writes. For `AccountLoader` aliasing, writes go to the shared buffer, so a straight sequential debit/credit nets to zero; double counting needs values cached before the writes (`a0`, `b0` read first, then `a = a0 - x; b = b0 + x`). Privileges are per transaction: if the same key fills a read-only slot and a writable slot, both `AccountInfo`s report writable, so `!b.is_writable` does not prove `b != a` (compare keys).

---

## FP-7. "Arbitrary CPI" through an unchecked token-program account — where `Instruction.program_id` comes from decides it

**The reflex.** "`token_program` is an unchecked `AccountInfo` — arbitrary CPI."

**Why it is often not exploitable.** `invoke`/`invoke_signed` dispatch on `Instruction.program_id`; the runtime requires the callee to be among the **caller instruction's** accounts (else `MissingAccount`, "Unknown program"), not in the `account_infos` slice. If the instruction is built with a constant id, a fake account in the slot cannot change the callee (the CPI just fails). <!-- verified: agave v4.3.2 program-runtime/src/invoke_context.rs prepare_next_cpi_instruction -->
- `spl_token::instruction::*` builders call `check_program_account(id)?` and return `IncorrectProgramId` for anything but `spl_token::ID` (verified in spl-token 3.5.0 and spl-token-interface 2.0.0; check the pinned crate for older versions). <!-- verified: token program@v3.5.0 program/src/instruction.rs transfer; interface@v2.0.0 interface/src/lib.rs check_program_account -->
- `spl_token_2022::instruction::*` builders for instructions shared with SPL Token (transfer, transfer_checked, mint_to, burn, approve, close_account, …) use `check_spl_token_program_account` (accepts Token or Token-2022); builders for Token-2022-only instructions (all extension builders, plus `reallocate`, `initialize_mint_close_authority`, `initialize_permanent_delegate`, `initialize_non_transferable_mint`, `withdraw_excess_lamports`, …) use `check_program_account` and accept Token-2022 only. Not arbitrary CPI, but program-family confusion — grade under KV-105 / token-2022 T6. <!-- verified: token-2022 interface@v2.0.0 interface/src/lib.rs, instruction.rs (transfer_checked uses check_spl_token_program_account; the Token-2022-only builders listed use check_program_account), extension/*/instruction.rs -->
- `anchor_spl::token::*` hardcodes `&spl_token::ID` when building the instruction (checked from 0.20.0 to 1.2.1): a `CpiContext` built from an unchecked program account and passed to these helpers is a false positive. <!-- verified: anchor v0.20.0, v0.29.0, v0.30.0, v0.32.1, v1.0.0, v1.2.1 spl/src/token.rs transfer -->
- `anchor_spl::token_2022::*` and `token_interface::*` (which re-exports the `token_2022` functions) take the program id from the context (`ctx.program.key` on 0.x, `ctx.program_id` on 1.x) but pass it to the `spl_token_2022::instruction` builders above, so a non-token id fails with `IncorrectProgramId` before the CPI. An unchecked token-program account there is program-family confusion (Token vs Token-2022, KV-105 / T6), not arbitrary CPI. <!-- verified: anchor v0.29.0 and v1.2.1 spl/src/token_2022.rs (every helper calls a spl_token_2022::instruction builder), v1.2.1 spl/src/token_interface.rs `pub use crate::token_2022::*` -->

**The escape (report as KV-009).** (a) a hand-built `Instruction { program_id: *acct.key, .. }` or `Instruction::new_with_*(*acct.key, ..)` where `acct` is caller-supplied; (b) Anchor-generated `cpi::` / `declare_program!` clients, which put the context's id straight into the instruction with no check — `ctx.program.key()` on 0.x (checked 0.29.0–0.32.1), `ctx.program_id` on 1.x — when that comes from an unchecked account; <!-- verified: anchor v0.29.0/v0.32.1/v1.0.0/v1.2.1 lang/syn/src/codegen/program/cpi.rs, v0.30.0/v1.2.1 lang/attribute/program/src/declare_program/mods/cpi.rs, lang/src/context.rs --> (c) on Anchor 1.x, `CpiContext::new(ctx.accounts.<unchecked>.key(), ..)` passed to such a generated client or to a raw `invoke`; (d) a non-SPL target (AMM, oracle, Metaplex, own sibling program) reached through raw `invoke`; (e) an untyped `Program<'info>` (KV-154); (f) the id check does not dominate the `invoke` on every path, or checks a different alias than the one put into the instruction. Missing `Program<'info, Token>` without (a)–(f) is Informational hygiene.

---

## FP-8. `Sysvar::from_account_info` is not sysvar spoofing

`Sysvar::from_account_info` checks the account key with `check_id` and returns `InvalidArgument` on a mismatch; Anchor `Sysvar<'info, T>` and `sysvar::instructions::load_*_checked` check the address too. The solana-lints `sysvar_get` lint flags `from_account_info` for compute and transaction-size cost, not security: report "use `Clock::get()` / `Rent::get()`" as Informational. **Escape:** sysvar bytes read without an id-checking accessor — raw `bincode::deserialize`, `bytemuck` casts or offsets on an unchecked "clock"/"slot_hashes" account; the deprecated unchecked `load_instruction_at` / `load_current_index` (Wormhole); a Pinocchio or hand-rolled reimplementation that skips the key comparison. Note the Instructions sysvar cannot be typed `Sysvar<'info, Instructions>` (it does not implement the `Sysvar` trait); the Anchor idiom is `UncheckedAccount` + `#[account(address = sysvar::instructions::ID)]`. <!-- verified: crytic/solana-lints lints/sysvar_get/README.md (efficiency rationale only) -->

---

## FP-9. "The program writes the account back, so a missing owner check is harmless" — only sometimes

A changing write to an account the program does not own fails (and a changing write to a read-only account fails with `ReadonlyDataModified`); when the `account_data_direct_mapping` feature is active on the cluster, the data region of any account the program may not change (read-only, **or not owned by the program**) is mapped read-only, so any store into it faults even if the bytes are unchanged. <!-- verified: agave v4.3.2 program-runtime/src/serialization.rs create_memory_region_of_account (writable region only when can_data_be_changed); transaction-context/src/instruction_accounts.rs can_data_be_changed (ReadonlyDataModified / ExternalAccountDataModified) --> The program cannot catch either failure: the whole transaction reverts. **It neutralises the missing owner check only if** every path that reads the account also reaches a write to it that the runtime rejects (a byte-changing write, or any store under direct mapping). **Report the finding when:** the write is on some branches only (an early `return Ok(())` after the read); the bytes written back are identical on the copy-in/copy-out path (no direct mapping); only lamports are moved (credits to non-owned accounts succeed). A successful write-back proves `owner == program_id` only — it says nothing about the account *type* (type cosplay is still open).

---

## FP-10. "No other account type fits this layout" is not a dismissal while legacy IDL instructions exist

If the program has the legacy Anchor IDL instructions (Anchor 0.x without the active `no-idl` feature, or Anchor ≥ 1.1.0 with `#[program(legacy_idl)]`; 1.0.x generates none), anyone can create a program-owned account and write arbitrary bytes after the IDL header (KV-153). A missing discriminator/type check cannot be downgraded on the grounds that no suitable layout exists. <!-- verified: anchor CHANGELOG 1.0.0 #3798; `legacy_idl` absent in v1.0.0–v1.0.3 and present from v1.1.0 in lang/syn/src/codegen/program/dispatch.rs -->

---

## FP-11. API presence is not a missing check

A grep or pre-scan hit on `AccountInfo<`, `UncheckedAccount<`, `invoke(`, `CpiContext::new(`, `find_program_address` or `.is_signer` only nominates a site (extends the "map, not a verdict" rule in `references/orchestration/pre-scan.md` to external tools). Report only when, on **at least one** attacker-reachable path, none of the Anchor constraints, `has_one`, `address =`, `Program`/`Interface` types, `require_keys_eq!` or called helpers enforces the guard, **and** something concrete is lost. Classic inversion: `if !authority.is_signer { return Err(MissingRequiredSignature) }` *is* the signer check.

---

## FP-12. Token self-transfer is not a free bypass

A token transfer with the same source and destination still checks the authority, mint, balance and frozen state, then returns without moving anything. The real issue, if any, is the caller's own accounting assuming two distinct accounts (duplicate-mutable aliasing, FP-6).

---

## FP-13. Default-pubkey sentinel in a signer array

Transaction signature verification uses strict Ed25519 verification, which rejects small-order public keys; the all-zero key decodes to a small-order point, so it can never sign a transaction. <!-- verified: agave v4.3.2 perf/src/sigverify.rs calls solana_signature::Signature::verify (solana-signature 3.5.2 per Cargo.lock; that crate verifies with ed25519-dalek verify_strict — crate source not cloned, re-check if the pinned crate differs); precompiles/src/ed25519.rs calls verify_strict directly --> Not a finding by itself. It is a finding when a separate non-signature comparison path accepts it, when a loop `break`s at the sentinel and skips later entries (Jet, SM-068), or when the program checks signatures by some route other than the transaction signature or the (strict) Ed25519 precompile, using a verifier that accepts small-order keys.

---

## FP-14. sBPF v3 classes on a program that stays on v0

A low-address (null) read faults on v0, so KV-181 variant (a) is not a finding for a v0 program that will not be upgraded; report it against the next upgrade. Exception: the stack-overrun variant (b) also applies to v0 programs once the SIMD-0460 feature `virtual_address_space_adjustments` is active, because Agave then disables stack frame gaps for every sBPF version. Record its activation status on the target cluster in the runtime-context sheet. <!-- verified: agave v4.3.2 syscalls/src/lib.rs `enable_stack_frame_gaps: !feature_set.virtual_address_space_adjustments`; feature-set/src/lib.rs "SIMD-0460: Virtual Address Space Adjustments" -->

---

## FP-15. cNFT canopy depth does not weaken verification

The canopy only shortens the proof a client must submit; it is a transaction-size/liveness question (report as DoS only when a required operation cannot land). Real cNFT bugs: leaf/asset id taken from the caller instead of recomputed from the signer; root supplied by the caller instead of read from the live tree; tree account not pinned; a proof cached across more mutations than `max_buffer_size`.

---

## FP-16. Lamports moved before a CPI that the runtime would reject

If a program edits lamports directly and then CPIs, the runtime fails the instruction ("sum of account balances before and after instruction do not match") when the **subset of changed accounts passed to the CPI** has a non-zero net delta (`UnbalancedInstruction`). Passing all of them, or none of them, works. <!-- verified: agave v4.3.2 transaction-context/src/transaction.rs push(): UnbalancedInstruction when the lamport delta synced so far is non-zero at CPI time --> Do not report "lamports moved before CPI" as theft when the runtime aborts it; do report a code path that is permanently bricked by this rule (liveness), with the fix "move direct lamport edits after the CPIs, or pass all/none of the changed accounts".

---

## FP-17. Account flags are per transaction, not per slot

Each unique key has one `is_signer`/`is_writable` value in the transaction message, shared by every top-level instruction that lists it; a CPI can pass it on with fewer privileges, never more (duplicate metas in a CPI are merged), with one exception: a caller can add signer privilege for its own PDAs through `invoke_signed`. Consequences: (1) two slots holding the same key report the same flags, so flags never prove two accounts are distinct — compare keys (FP-6); (2) when the program is reached by CPI, an account it receives read-only may be writable for the caller, which can change it before or after the call. Read-only in this instruction is not a freeze across the transaction.

---

## FP-18. Validation macro libraries count as checks

Saber `vipers` (`assert_keys_eq!`, `unwrap_int!`, `invariant!`) and Blockworks `checked-math` (`cm!`) perform real checks. Treat them as equivalent to `require_keys_eq!` / `checked_*` when present.

---

## FP-19. Owner-check lint noise on `Interface`/`InterfaceAccount`

solana-lints `missing_owner_check` does not list `Interface`/`InterfaceAccount` in its safe set, so `.to_account_info()` on them in Token-2022 code is a lint false positive. <!-- verified: crytic/solana-lints lints/missing_owner_check/README.md safe-type list (Account, Program, SystemAccount, AccountLoader, Signer, Sysvar) --> `InterfaceAccount<'info, T>` does check the owner (`T::check_owner`, which for the `anchor_spl` token types accepts either token program; bind mint, account and token program together, T6). <!-- verified: anchor v1.2.1 lang/src/accounts/interface_account.rs try_from; spl/src/token_interface.rs IDS -->

---

## FP-20. A green Trident / fuzz run is not evidence of authorization safety

TridentSVM does not verify signatures (Trident 0.12: `process_instructions` builds an unsigned `Transaction::new_with_payer` and executes it; re-check for the pinned version): any `AccountMeta` with `is_signer = true` counts as signed, including the real admin and PDAs. An attacker flow that passes the admin key "passes" access control (false positive); a harness that only ever passes the admin cannot find missing-signer bugs (false negative). Host-entrypoint runs are not SBF-faithful (compute, stack/heap, overflow-checks profile, alignment). See checklist 16 §16.9.

---

## FP-21. Do not discard solely because …

… the code uses Anchor constraints; the exploit is multi-step; impact depends on configuration; the path needs uncommon but valid Token-2022 extensions; a dependency is "standard SPL Token" (it may be Token-2022); the handler is `pub(crate)` (all handlers are reachable by CPI); it "requires authority" (the authority may be a single hot key).

---

## FP-22. Do not report

An admin doing documented admin things (no amplifier, Rule 5b); self-harm only; "admin can rug" with no mechanism; consistent protocol-favouring rounding that neither compounds nor rounds a user's whole value to zero; deployer-intent arguments in either direction.

---

## Triage fast pass (before any N ≥ 6 report)

- [ ] **Reentrancy?** A→B→A is runtime-rejected; only A→A self-CPI, stale state after a CPI, an untrusted callee acting on forwarded privileges, or an untrusted callee reaching a sibling program of the same protocol are real (FP-1). Nesting limit: 4 CPIs, or 8 with SIMD-0268 active.
- [ ] **Close/revival?** `close = dst` assigns to System and reallocs to 0 since 0.26.0. Real: pre-0.26 sentinel era, a manual close missing drain/assign/resize, a zero-filled program-owned account re-initialized via `zero`, or a closed one-shot marker that `init` re-creates (FP-2).
- [ ] Is this **float non-determinism**? sBPF `f64` is deterministic — report the real
      precision/`NaN` defect with impact, not "non-determinism" (FP-3).
- [ ] Is this **partial state on failure**? Single-tx failures roll back atomically — only
      report genuine *cross-transaction* half-states (FP-4).
- [ ] Is this **`init_if_needed`**? Only a bug if reinit changes a security-relevant field with
      no fresh-account guard (FP-5).
- [ ] **Duplicate-mutable?** Anchor ≥ 1.0.0 rejects only aliasing between `mut` `Account`/`LazyAccount`/`InterfaceAccount`/`Migration` (and `init_if_needed`) fields without `dup`; `zero` + `init` aliasing stays open through 1.2.1. Everything else is open (FP-6).
- [ ] For any survivor: the **Rule 5b gate shows the specific escape**, cited to `file:line`.
      No escape → downgrade to `[PARTIAL]` / `[UNCONFIRMED]`.
- [ ] For any **downgrade on "not profitable / not exploitable": the barrier is quantified** —
      worked numbers (cost vs. gain) or the named blocking precondition @ `file:line`. A bare
      dismissal fails the gate; the finding stays open until the bound is computed.
- [ ] **Arbitrary CPI?** Trace where `Instruction.program_id` comes from (FP-7).
- [ ] **Sysvar spoofing?** `from_account_info`/`Sysvar<T>`/`_checked` helpers check the id (FP-8).
- [ ] **Ignored CPI result?** Callee errors abort the tx; pre-invoke errors are swallowable (FP-4, KV-150).
- [ ] **Evidence source** of every dismissal is `[CODE]`/`[PROD-*]`, not `[MOCK]`/`[EXT-UNV]`/`[DOC]` (Rule 5b).
- [ ] **Version-scoped dismissal?** The resolved version is quoted from `Cargo.lock` and the Anchor matrix (KV-158) was checked.

---

*Sources: solana-foundation/solana-dev-skill (MIT, Copyright (c) 2026); qedgen/solana-skills Part C/F (MIT, Copyright (c) 2025 QEDGen); otter-sec/anchor CHANGELOG, `account-constraints.mdx`, SECURITY.md (Apache-2.0, Copyright 2020 Anchor Maintainers); Solana Foundation Program Security course [paraphrased, no licence, https://github.com/solana-foundation/developer-content/tree/main/content/courses/program-security]; coral-xyz/sealevel-attacks [paraphrased, no licence, https://github.com/coral-xyz/sealevel-attacks]; crytic/solana-lints [paraphrased, no licence, https://github.com/crytic/solana-lints]; Trail of Bits `rust-review` result-discarded finder [paraphrased, CC-BY-SA-4.0]; Neodyme "Common Pitfalls" [paraphrased, © Neodyme AG, https://neodyme.io/en/blog/solana_common_pitfalls]; Sealevel Sentinel (MIT, Copyright (c) 2026 Stan (stantheman0128)); sanbir/solana-auditor-skills and pashov/skills (MIT, Copyright (c) 2024 AI Skills Contributors); franpersanchez/solana-audits-skill (MIT, Copyright (c) 2026 Fran Pérez) — the "Do not discard solely because" list is adapted from it; awesome-solana-ai (CC0, discovery only); sannykim/solsec [paraphrased, cited]; Ackee-Blockchain/trident (MIT, Copyright (c) 2021 Ackee Blockchain); original analysis. Version facts re-checked against primary sources: solana-foundation/anchor tags v0.20.0–v1.2.1 and otter-sec/anchor CHANGELOG (Apache-2.0), anza-xyz/agave v4.3.2 (Apache-2.0), solana-program/token program@v3.5.0 / interface@v2.0.0 and solana-program/token-2022 interface@v2.0.0 / program@v10.0.0 (Apache-2.0).*
