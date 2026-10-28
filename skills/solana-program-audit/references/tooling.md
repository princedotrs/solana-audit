# Tooling for Solana program audits — what each tool can and cannot show

Rules for every tool here:
- A tool's output only **nominates** sites (FP-11). A tool's silence is never evidence of safety; record which checklist rows its output covers.
- Anything that **compiles the target** (dylint, clippy, kani, mutants, llvm-cov, Trident, Miri) runs under OUTPUT-RULES Rule 11f: scratch copy, sandbox without secrets, explicit user consent.
- Never upload client code to a closed SaaS tool without written client permission.
- Verify any tool or lint name against the upstream README at a pinned commit before citing it (a well-known scanner cited lint names that do not exist).

## 1. Static analysers

**crytic/solana-lints (Dylint; Trail of Bits).** Seven rustc-level lints. <!-- verified: crytic/solana-lints e0f31e2 (2025-05-15): lints/ has 7 crates, rust-toolchain `nightly-2025-01-09`, crate/diffs pin anchor-lang 0.30.1, no LICENSE file; missing_owner_check safe list in lints/missing_owner_check/src/lib.rs --> Last commit 2025-05-15, toolchain `nightly-2025-01-09`, UI tests pinned to anchor 0.30.1 — expect build friction on Anchor 1.x / split Solana crates; record a build failure as "tool not applicable", not a pass. Repository has no LICENSE (cite only; reproduce no config verbatim).

| Lint | Flags | Limits (where manual review takes over) |
|---|---|---|
| `missing_signer_check` | native fns touching `AccountInfo` without reading `.is_signer`; Anchor `AccountInfo`/`UncheckedAccount`/`SystemAccount` fields without `signer` | a *read* of `is_signer` counts even if not enforced |
| `missing_owner_check` | `AccountInfo` whose `.owner` is never referenced and `.key` never compared | only checks that `.owner` is referenced, not compared to the right program (AV-095); safe list = `Account`, `Program`, `SystemAccount`, `AccountLoader`, `Signer`, `Sysvar` — `Interface`/`InterfaceAccount` are **not** listed (FP-19); init/`init_if_needed` exemption behaviour unverified (code, doc and tests disagree) |
| `arbitrary_cpi` | `Instruction { program_id }` with no dominating equality check before `invoke`; `CpiContext::new*` heuristics written for Anchor ≤ 0.32 | not inter-procedural; checks in another fn missed; hardcoded-id wrappers false-positive; on Anchor 1.x trace the `Pubkey` passed to `CpiContext::new*` instead |
| `bump_seed_canonicalization` | `create_program_address` whose last seed traces to an unchecked value | native only; not inter-procedural; stored bumps passed between fns false-positive |
| `insecure_account_close` | `**x.lamports.borrow_mut() = 0` without a zero-assigning loop | any zero loop suppresses it; misses `set_lamports(0)`, `sub_lamports`, System-CPI drains, Pinocchio closes, missing owner reassignment |
| `type_cosplay` | Borsh reads without a discriminant; Anchor `Discriminator` types read without `try_deserialize` | native + Anchor-via-raw-Borsh; u8/bool discriminants false-positive; single-enum programs assumed safe (KV-159) |
| `sysvar_get` | `from_account_info` / `Sysvar<'info, T>` where `get()` exists | efficiency, **not** security (FP-8) |
Other open analysers exist (e.g. VRust, MIR-based research tool); none replaces manual review.

**Radar (Auditware).** Open-source rule-template analyser for Solana/Anchor Rust. Second-opinion pattern scan; findings are leads. Run from its own install against a scratch copy; check the rule templates' licence before vendoring any. Same blind spots as any AST matcher (§8).

**Sec3 X-ray** (already referenced in the baseline). **Soteria** is unmaintained — do not recommend its commands.

**crytic/anchorx-ray.** Renders each Anchor `Accounts` struct as a diagram (accounts, constraints, signers, `mut`). Use in recon to spot the sibling missing `has_one`/`seeds`.

**Sec3 IDLGuesser.** Recovers approximate IDLs for **closed-source Anchor** programs (relies on Anchor dispatch patterns). Useful when the audited program CPIs into an unverified Anchor program; output is heuristic. Not a build-verification tool — use `solana-verify` / `anchor verify` for that.

**anchor-version-detector.** Infers a compatible Rust / Solana CLI / Anchor toolchain triple before building a PoC.

**Ackee Solana VS Code extension.** Static detectors + Trident coverage view; secondary signal.

## 2. Fuzzing — Trident (Ackee Blockchain, MIT), v0.12

- Scope: Anchor programs (IDL-driven codegen). The CLI (`fuzz run|debug|refresh`) requires an `Anchor.toml` workspace; native/Pinocchio programs need hand-built `Instruction`s plus a stub Anchor workspace — prefer LiteSVM + proptest there.
- Engine: since 0.11 (0.11.0, 2025-08-14), manually guided stateful flow fuzzing on TridentSVM with a seeded RNG (`#[init]` / `#[flow]` / `#[end]`, `FuzzTest::fuzz(iterations, flows)`), multi-threaded; no coverage feedback, no corpus. Flows are uniform by default; `#[flow(weight = N)]` (all-or-none, summing to 100) and `#[flow(ignore)]` exist.
- Oracle: harness assertions. `trident fuzz run` exits 0 even when a harness assertion panics unless `--with-exit-code` is passed, so CI must always pass it. On-chain panics (`ProgramFailedToComplete`) are failed transactions; they fail CI only when metrics are enabled **and** the tx is named **and** `--with-exit-code` is used (exit 99). Otherwise assert them explicitly (FV-090).
- Reproduce: `trident fuzz debug <target> <seed>`; repeat a campaign with `trident fuzz run <target> [master_seed]`.
- Extras: SPL Token / Token-2022 helpers (confidential mint extensions are not available; the extension enum also mixes in account extensions), stake/vote helpers, clock control (`forward_in_time`, `warp_to_slot/epoch/timestamp`), mainnet program and account fixtures in `Trident.toml`, metrics dashboard (`trident server`), LLVM coverage for entrypoint-deployed programs only (`syscall-v2` feature), account-state regression diff (`trident compare`).
- Caveats: signatures are not verified (any `is_signer` meta counts as signed); fees not charged; `get_last_blockhash` unimplemented (blockhash/durable-nonce logic not fuzzable); host-entrypoint runs are not SBF-faithful (compute, stack/heap, overflow-checks profile, alignment).
- Templates: `templates/fuzz-trident/`. Soundness checks: checklist 16 §16.9.
<!-- verified: Ackee-Blockchain/trident 0.12.0 (0536566): crates/cli/src/command/fuzz.rs (run/debug/refresh, `--with-exit-code`), crates/fuzz/src/trident/flow_executor.rs `determine_exit_code` (99), crates/client/src/commander/mod.rs `handle_child` ((99, false) is accepted as success), crates/metrics/src/transactions/transaction_stats.rs (panicked txs), crates/syn/src/parser/trident_flow_executor.rs (all-or-none weights summing to 100), crates/fuzz/Cargo.toml `syscall-v2`, client.rs `get_last_blockhash` panics, documentation system-program.md (no signature verification) -->

## 3. Formal verification — Kani

Setup recipes:
1. Shrink state under `cfg(kani)`: `#[cfg(kani)] pub const MAX_ACCOUNTS: usize = 4;` / `#[cfg(not(kani))] … = 4096;` — smallest value that still exercises every branch (full, empty, wrap-around).
2. 128-bit wrappers: programs storing `u128`/`i128` as `[u64; 2]` (SBF alignment is 8, x86_64 is 16 since Rust 1.77) are expensive for the solver; swap in a `#[repr(transparent)]` native wrapper under `cfg(kani)` with the same API, and add one equivalence harness between the two implementations (the swap can hide a limb-carry bug).
3. `no_std` crates: `#![cfg_attr(all(not(test), not(kani)), no_std)]` and `#[cfg(kani)] extern crate kani;`.
4. Cargo metadata: `[workspace.metadata.kani.flags] tests = true`, `default-unwind = "10"`; unstable features via `-Z stubbing`, `-Z function-contracts`.
5. `Pubkey` is not `kani::Arbitrary`: `Pubkey::new_from_array(kani::any())`.
6. Stubbing CPIs: stub the **executor** the code actually calls, with its exact path and signature (solana-program 2.x re-exports `solana_cpi::invoke_signed`; Anchor ≥ 0.32 does not depend on solana-program and its `anchor_lang::solana_program::program::invoke_signed` shim re-exports `solana_invoke::invoke_signed`; Pinocchio has its own `invoke_signed`), model both `Ok` and `Err`, and put a `kani::cover!` inside the stub to prove it fired. A stub cannot model the CPI's effect on account data — post-CPI accounting proofs need symbolic reloaded values or a LiteSVM test.
7. Triage: `unwinding assertion` → `#[kani::unwind(N)]` with N = max iterations + 1; timeout → narrow with `assume` or try another SAT solver (kissat/cadical/minisat); OOM → smaller `cfg(kani)` constants, avoid `Box`, fewer symbolic variables; FAILED → `cargo kani -Z concrete-playback --concrete-playback=print --harness <h>` gives a counterexample to seed a LiteSVM PoC; SUCCESSFUL → still check `cover!` results.
8. Workflow: start unconstrained; add constraints only after timeout/OOM and `unwind` only after an unwinding error; order proofs cheap → expensive (pure fns, read-only, single-entity, multi-entity).
9. Do not use Kani for floats, async, I/O, deep recursion without contracts, or state above ~1000 elements — use proptest, bolero or Trident.
Harness shapes: `templates/kani/`. Soundness review: checklist 16 §16.8.

**OtterSec `onchor` (annotation-driven Anchor verification; github.com/otter-sec/solana-verify, blog "Formally Verifying Solana Programs", 2023).** Macros `#[succeeds_if]`, `#[errors_if]`, `#[invariant]` over a forked anchor-lang pinned to ~0.26, requiring a nightly toolchain. Per workersio's notes it does not model CPIs or account deserialisation and proves single-instruction properties only. Treat it as evidence for input-validation properties, not checklist 01/04 coverage.

## 4. Testing, coverage & mutation

- **cargo llvm-cov / tarpaulin:** instrument host-native tests (including `solana-program-test` native `processor!` mode); not SBF execution (LiteSVM, Mollusk, program-test BPF mode). Label results "measured" vs "estimated".
- **cargo-mutants:** mutate `require!`, `has_one` handlers and comparisons; surviving mutants on auth/accounting lines prove negative tests cannot fail (FV-104). It rebuilds and runs `cargo test`, so only tests that compile the program for the host see the mutant; tests that load a prebuilt `.so` (LiteSVM, Mollusk, program-test BPF mode) keep testing the unmutated binary unless the test step rebuilds it.
- **Miri:** `cargo +nightly miri test -- --test-threads=1` on host tests that call program Rust directly and touch `unsafe`; reports `Undefined Behavior` / Stacked Borrows violations; cannot see UB inside a `.so`.
- **LiteSVM / Mollusk / Surfpool:** see `references/orchestration/poc-harness.md`. `solana-bankrun` is deprecated upstream (its README: "DEPRECATED: use LiteSVM instead", checked 2026-10-24); prefer Mollusk as the GLIBC fallback and treat bankrun as legacy.

## 5. Supply chain

- `cargo audit --deny yanked` (yanked is otherwise a warning).
- `cargo deny check advisories bans sources`: fail on duplicate security-critical crates, `git` sources, yanked versions.
- `cargo geiger`: `unsafe` usage per crate (informational).
- Duplicate-version check: `cargo tree --duplicates` (`-d`), or offline `awk '/^name = /{n=$3} /^version = /{print n}' Cargo.lock | sort | uniq -d` to list crate names locked at more than one version.

## 6. Binary-level review of deployed sBPF

When the program or a CPI target is closed-source, when source and verified build disagree, or when you must show an unsafe bug survives compilation:
- `cargo build-sbf` leaves the unstripped ELF under `target/<triple>/release/` and writes a `--strip-all` copy to `target/deploy/` (the deployable file). The triple is `sbf-solana-solana` with platform-tools < v1.44, `sbpf-solana-solana` for `--arch v0` on ≥ v1.44, and `sbpfv1/v2/v3-solana-solana` for the newer architectures. Diff function boundaries against the deployed ELF from `solana program dump`. <!-- verified: agave v2.1.0 sdk/cargo-build-sbf/src/main.rs and v3.0.0 platform-tools-sdk/cargo-build-sbf/src/{post_processing.rs,toolchain.rs} `rust_target_triple`; Agave 4.x no longer ships the tool in-tree (wrapper script installs `cargo-build-sbf`), so re-check the layout for the toolchain in use -->
- Disassemble with an sBPF-aware tool (Binary Ninja + OtterSec's Solana plugin, Ghidra sBPF processors, platform-tools `llvm-objdump`, the `solana-sbpf` disassembler). Look for `callx` sites, `sol_invoke_signed_*` call sites and the stack loads (`ldxdw rX, [r10-N]`) feeding them; check whether `overflow-checks`, `panic = "abort"` or debug assertions survived. Address map: `references/framework-idioms/sbpf-vm-internals.md`.

## 7. Legacy names you will meet in older code and PoCs

Saber `vipers` (`assert_keys_eq!`, `unwrap_int!`, `invariant!` — real checks, FP-18); Blockworks `checked-math` (`cm!`); Neodyme `solana-poc-framework` (superseded by LiteSVM/Mollusk); OtterSec `sol-ctf-framework` (attacker-program + victim-program PoC pattern); Kudelski Solana semgrep rules (link rotted); Neodyme workshop (https://workshop.neodyme.io/) for calibration.

## 8. Limits of grep and AST detectors

- **Aliasing:** `let acct = &ctx.accounts.vault;` then `acct.owner`, `**acct.lamports.borrow_mut() = 0` — patterns tied to `ctx.accounts.<name>.` miss these; grep `let\s+(mut\s+)?\w+\s*=\s*&?\s*ctx\.accounts\.<name>` and re-run.
- **Cross-file handlers:** map each `#[derive(Accounts)]` struct to its handler file first.
- **Validation in helpers:** follow the call before flagging.
- **CPI-only mutation:** duplicate-account greps that count only direct writes miss same-type pairs mutated through CPI.
- **Unconventional names:** prefer role-based (AC-059) and type-based signals over names.

## 9. AI-assisted audit tools (second opinion only)

Discovery source: solana-foundation/awesome-solana-ai (CC0 directory, not an endorsement). Status as of 2026-10.

| Tool | Access | Use alongside this skill |
|---|---|---|
| Sealevel Guard (MIT) | open | specialist split mirrors checklists 01–07; anything only it reports is `[UNCONFIRMED]` until traced |
| sendaifun `vulnhunter` / `zz-code-recon` | open | recon can seed boundary-map; variant hunting complements known-vectors |
| tenequm `solana` plugin | open | compare report shape only |
| solana-foundation `solana-dev-skill` | open | shows what developers were told is enough — audit those assumptions |
| Trident Arena (Ackee / School of Solana) | closed SaaS | benchmark only; published detection/FP rates are vendor claims, unverified |
| Exo AI Audits | closed SaaS | benchmark only |
| Sentinel Code | open | **rejected** — its signer rule flags the correct `if !acct.is_signer` check, and its owner/CPI rules fire on every `AccountInfo`/`invoke` |
A docs oracle (Solana Developer MCP) may answer "what does constraint X do in version Y"; pin the answer to the `Cargo.lock` version and confirm in the framework source.
