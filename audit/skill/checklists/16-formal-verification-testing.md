# Checklist 16 — Formal Verification & Testing Quality

> **Items:** 106  |  **IDs:** FV-001 → FV-106  
> **Applies to:** Every Solana program repository (always-on) — the on-chain code and its test / verification suites, whatever language the tests are written in  
> **Sources:** CertiK formal verification methodology, EY QA/processing integrity, OWASP A06 (Insecure Design), OWASP A10 (Mishandling of Exceptional Conditions)

---

## 16.1 Formal Verification & Property Testing (FV-001 → FV-012)

| ID | Check | Severity |
|----|-------|----------|
| FV-001 | Critical state invariants are documented (e.g. "total shares == sum of all investor shares") | 7 |
| FV-002 | Invariant properties are encoded as assertions or property-based tests | 7 |
| FV-003 | Every arithmetic identity the protocol relies on has a proof or exhaustive test | 8 |
| FV-004 | State transition properties are specified: from every valid state, only valid transitions can occur | 7 |
| FV-005 | No reachable state violates documented invariants (tested via model checking or fuzzing) | 8 |
| FV-006 | Token conservation property verified: tokens in == tokens out across all instruction paths | 9 |
| FV-007 | Authority properties verified: only authorized signers can reach privileged instructions | 8 |
| FV-008 | Liveness properties checked: every initiated process can reach completion (no deadlocks) | 6 |
| FV-009 | Formal specs (if any) are kept in sync with code — spec drift is tracked | 5 |
| FV-010 | Mathematical proofs are machine-checked (Coq, Lean, SMT solver) when claiming "proven" | 6 |
| FV-011 | Custom formal verification properties are documented alongside the code they verify | 4 |
| FV-012 | Verification results are included in audit reports with pass/fail status | 3 |

---

## 16.2 Static Analysis (FV-013 → FV-022)

| ID | Check | Severity |
|----|-------|----------|
| FV-013 | At least one static analysis tool runs in CI (e.g. Clippy, ESLint security rules, Semgrep, Slither) | 5 |
| FV-014 | Static analysis findings are triaged — no unreviewed suppressions | 5 |
| FV-015 | Custom lint rules enforce project conventions (e.g. no `any`, no `unwrap` in production) | 4 |
| FV-016 | Compiler/linter warnings are treated as errors in CI — zero-warning policy | 4 |
| FV-017 | Security-focused rulesets are enabled (e.g. `clippy::pedantic`, `eslint-plugin-security`) | 5 |
| FV-018 | Dead code detection is enforced — unused functions/imports are flagged | 3 |
| FV-019 | Dependency vulnerability scanning runs in CI (e.g. `cargo audit`, `npm audit`, `safety`) | 6 |
| FV-020 | SAST (Static Application Security Testing) covers all production languages in the repo | 5 |
| FV-021 | No static analysis suppression comments without a justification comment | 4 |
| FV-022 | Static analysis config files are version-controlled and reviewed on change | 3 |

---

## 16.3 Fuzz Testing (FV-023 → FV-032)

| ID | Check | Severity |
|----|-------|----------|
| FV-023 | Fuzz testing is implemented for all parsing/deserialization functions | 6 |
| FV-024 | On-chain instruction handlers have fuzz targets covering malicious inputs | 7 |
| FV-025 | Fuzz corpus is persisted and grows over time (not regenerated from scratch each run). For Trident ≥ 0.11 there is no corpus: persist the failing seeds and keep them as fixed-seed regression runs (FV-089). | 4 |
| FV-026 | Fuzz campaigns have run for meaningful duration (not just quick smoke tests) | 5 |
| FV-027 | Crashes found by fuzzing are triaged, fixed, and regression tests added | 7 |
| FV-028 | Differential fuzzing is used where two implementations should agree (e.g. old vs new version) | 5 |
| FV-029 | Fuzz testing covers arithmetic edge cases: MAX, MIN, 0, 1, near-overflow values | 6 |
| FV-030 | API endpoints are fuzzed with malformed/oversized/unexpected payloads | 6 |
| FV-031 | Serialization round-trip fuzz: encode → decode → re-encode produces identical bytes | 5 |
| FV-032 | Fuzz testing infrastructure is documented and reproducible | 3 |

---

## 16.4 Test Coverage & Quality (FV-033 → FV-046)

| ID | Check | Severity |
|----|-------|----------|
| FV-033 | Test coverage is measured and reported (line coverage, branch coverage) | 4 |
| FV-034 | Critical paths (fund creation, deposit, withdrawal, swap) have ≥ 90% branch coverage | 6 |
| FV-035 | Unit tests exist for every public function/instruction | 5 |
| FV-036 | Integration tests cover multi-step workflows (e.g. create → deposit → swap → withdraw) | 6 |
| FV-037 | Edge case tests: zero amounts, max amounts, empty collections, boundary values | 6 |
| FV-038 | Negative tests: unauthorized callers, invalid states, rejected transactions | 7 |
| FV-039 | Regression tests exist for every previously-found bug | 5 |
| FV-040 | Tests run in CI on every PR — no merge without green tests | 6 |
| FV-041 | Test environment mirrors production config (same runtime version, same flags) | 4 |
| FV-042 | Flaky tests are tracked and fixed — no tests in permanent skip/ignore state without justification | 3 |
| FV-043 | Mutation testing has been run at least once to validate test suite effectiveness | 3 |
| FV-044 | Performance/load tests exist for critical endpoints to prevent DoS via expensive operations | 5 |
| FV-045 | Tests do not use hardcoded secrets, private keys, or real credentials | 7 |
| FV-046 | Test data is deterministic or seeded — tests are reproducible across environments | 3 |

---

## 16.5 Error Handling as Security Boundary (FV-047 → FV-058)

> **Source:** OWASP A10:2025 — Mishandling of Exceptional Conditions

| ID | Check | Severity |
|----|-------|----------|
| FV-047 | All external calls (network, DB, filesystem, CPI) have explicit error handling | 6 |
| FV-048 | Error messages do not leak internal paths, versions, stack traces, or database schemas | 5 |
| FV-049 | Panics/unhandled exceptions in production code are caught at the boundary and logged | 6 |
| FV-050 | Errors are distinguished: client errors (4xx) vs server errors (5xx) — no catch-all 500 | 4 |
| FV-051 | Resource exhaustion is handled gracefully: OOM, disk full, connection pool exhausted | 5 |
| FV-052 | Timeout handling exists for all external calls — no unbounded waits | 6 |
| FV-053 | Partial failure in multi-step operations is handled (rollback, compensation, or idempotent retry) | 7 |
| FV-054 | Error handling does not silently swallow errors — all catch blocks log or propagate | 5 |
| FV-055 | On-chain programs return specific error codes, not generic "ProgramError" | 4 |
| FV-056 | Error types are exhaustive — match/switch on error kinds covers all variants | 4 |
| FV-057 | Circuit breakers or fallbacks exist for critical external dependencies | 5 |
| FV-058 | Exceptional conditions in financial math (divide-by-zero, negative balances) are blocked, not wrapped | 8 |

---

## 16.6 On-Chain Test-Suite Verification — LiteSVM / Mollusk (FV-059 → FV-070)

> **Source:** LiteSVM / Mollusk in-process SVM testing methodology *(adapted from safe-solana-builder `references/litesvm.md`)*
> **Applies to:** Solana programs (Anchor / native / Pinocchio). Verify the **test suite itself** exercises these paths — a passing suite that never tests the failure side proves nothing.

| ID | Check | Severity |
|----|-------|----------|
| FV-059 | An in-process SVM suite (LiteSVM or Mollusk) exists and loads the actual compiled `.so` (built via `cargo build-sbf`), not a mock | 6 |
| FV-060 | Every time-locked / deadline instruction is tested on **both** sides: a before-deadline path that must fail AND an after-deadline path that must succeed | 8 |
| FV-061 | Time-dependent logic is tested via sysvar/clock control (`set_sysvar(Clock)` / `warp_to_slot`), not by real wall-clock waiting | 6 |
| FV-062 | Account-closure is verified on all three fields after close: `lamports == 0`, `data.len() == 0`, and `owner == system_program` (not just lamports) | 7 |
| FV-063 | Re-initialization is tested: double-initializing an existing account must fail (reinit-guard / `init` semantics proven) | 7 |
| FV-064 | Authorization negatives are tested: a wrong / missing signer causes the transaction to fail | 7 |
| FV-065 | Arithmetic edge cases are tested through the SVM: zero-amount, over-limit, and near-overflow inputs are rejected | 6 |
| FV-066 | Token balances are asserted with explicit `assert_eq!` after every transfer path (not merely "tx succeeded") | 5 |
| FV-067 | CU consumption is profiled and recorded for at least the initialize, primary action, and close instructions (regression baseline) | 4 |
| FV-068 | `expire_blockhash()` (or equivalent blockhash advance) is called after each send in multi-transaction tests — no reliance on a stale blockhash | 4 |
| FV-069 | Failure-path tests do NOT `unwrap()` the send result; they assert `result.is_err()` (and, where relevant, the specific `InstructionError`) | 5 |
| FV-070 | PDA derivations in tests use the same seeds as on-chain (documented in comments), and devnet/mainnet account replay is used only for fixtures — never for security-critical assertions | 4 |

---

## 16.7 Solana-Native Verification Tooling — Is the Suite Appropriate to the Risk? (FV-071 → FV-073)

> **Source:** Solana verification/fuzzing ecosystem. Turns "does a fuzz/FV suite even exist, and is it the right one?" into an actionable check. Verify the suite uses **at least one** tool appropriate to the protocol's risk profile — high-value DeFi math warrants equivalence/invariant proving, not just a unit-test smoke pass.

| ID | Check | Severity |
|----|-------|----------|
| FV-071 | The project uses at least one Solana-appropriate verification/fuzzing tool matched to its risk: **Trident** (stateful/guided fuzzing of instruction sequences), **Crucible** (sBPF invariant fuzzing, no source needed), **Riverguard** (mainnet-transaction mutation replay), **Certora CVL** (equivalence + invariant induction — expected for high-value DeFi math), **Kani** (bounded model-checking proofs), or **Mollusk/LiteSVM** (fast in-process harness). A high-value protocol whose only "verification" is a handful of happy-path unit tests fails this item. See references/tooling.md for solana-lints (scope and limits), Kani setup, and the OtterSec `onchor` note. | 6 |
| FV-072 | The suite exercises the **current transaction format**: readers / indexers round-trip a fixture block containing a v1 transaction (`maxSupportedTransactionVersion: 1`, `transactionConfig` persisted with correct units); fee sponsors / co-signers are tested with a v1 transaction whose fee lives in the config and which carries no-op ComputeBudget instructions (must be rejected above cap); on-chain programs are run under a runtime with the v1 gate active (`solana-test-validator` ≥ 4.2 / Surfpool ≥ 1.5) so 4,096-byte transactions and no-op budget instructions are covered (see KV-135) | 5 |
| FV-073 | Time-dependent tests model wall-clock, not slot counts: when a test advances time (`warp_to_slot`, `set_sysvar(Clock)`), `unix_timestamp` advances consistently with the live slot duration (200 ms since Oct 2026), and at least one test asserts each security-relevant duration (timelock, cliff, staleness bound, rate-limit window, interest accrued per year) in **seconds** against the documented policy, so the suite cannot pass with a timelock that is half as long on mainnet or an interest constant that accrues 2.5x the configured APR (see KV-138, SM-073, ECON-090) | 6 |

---

## 16.8 Kani / Model-Checking Harness Soundness (FV-074 → FV-088)

When a protocol claims "formally verified with Kani", review the harnesses before giving credit. Locate them with `rg -n '#\[kani::(proof|proof_for_contract|unwind|stub|stub_verified|solver)' --type rust`, `rg -n 'kani::(any|assume|cover|assert|any_where)'`, `rg -n 'cfg\(kani\)'` and `rg -n 'metadata\.kani' -g Cargo.toml`. Apply the checks by hand; do not install third-party Kani linters.

| ID | Check | Severity |
|----|-------|----------|
| FV-074 | Each harness that asserts on a fallible call forces the path (`match`, or helper macros such as `assert_ok!`/`assert_err!`). It never uses `if result.is_ok() { assert!(..) }`, or `let _ = op(..)` followed by assertions on unchanged state | 6 |
| FV-075 | Each harness with `kani::assume` has at least one `kani::cover!`, and the run reports it SATISFIED. UNSATISFIABLE means the cover location is reached but its condition can never hold (over-constrained assumptions); UNREACHABLE means the location is never reached, which is also what contradictory assumptions (`assume(false)` in effect) or dead code produce | 6 |
| FV-076 | No contradictory assumes on one variable, no `assume` on a non-symbolic value, no `assume` after the asserts | 5 |
| FV-077 | No assume–assert tautology (asserting what was assumed with no operation in between) | 5 |
| FV-078 | State is realistic: ≥ 2 active entities and non-zero symbolic balances. A fresh zeroed `::new()` makes invariants trivially true | 5 |
| FV-079 | Stubs are sound. A `#[kani::stub]` that replaces a fallible function (deserialize, CPI `invoke`/`invoke_signed`, oracle read) models both `Ok` and `Err`. Prefer `#[kani::stub_verified]` (the stub is the function's contract, proven by a `proof_for_contract` harness) over a hand-written stub. The stub targets the exact path the code calls, with an identical signature: `solana_program::program::invoke_signed` is a wrapper over `solana-cpi` in solana-program 2.1. Anchor ≥ 0.32 does not depend on `solana-program`, and its `anchor_lang::solana_program::program::invoke_signed` re-exports `solana_invoke::invoke_signed`. Pinocchio has its own `pinocchio::cpi::invoke_signed`. A `kani::cover!` inside the stub proves it fired | 6 |
| FV-080 | `proof_for_contract` harnesses contain no `kani::assume`; preconditions live in `#[kani::requires]` | 5 |
| FV-081 | Unwinding checks are not disabled, and each `unwind` bound is ≥ max iterations + 1. `cfg(kani)` overrides of `MAX_*` constants still exercise every branch (≥ 2 entities, full/empty boundaries). Loops with constant bounds unroll without an attribute. A bound that is too small FAILS the unwinding assertion rather than passing silently, unless `--no-unwinding-checks` is set | 4 |
| FV-082 | No assertions or covers after an unconditional `return`/`panic!` (dead assertions) | 4 |
| FV-083 | Symbolic `f32`/`f64` is absent, or NaN/±inf is handled (on-chain float math is KV-128) | 4 |
| FV-084 | `transmute` in harness or target code is checked with Kani's valid-value checks enabled | 3 |
| FV-085 | Inductive/delta proofs call the **production** arithmetic function. A proof that re-implements the arithmetic inline proves the model, not the program | 6 |
| FV-086 | The verified property is the one claimed: the README invariant equals the asserted expression, and a helper such as `check_all_invariants()` is not weaker | 4 |
| FV-087 | The host/SBF gap is acknowledged. Kani checks host-compiled Rust, so 4 KiB stack frames (KV-111), compute exhaustion (KV-025), realloc limits and 128-bit alignment differences still need LiteSVM/Mollusk tests. `u128`/`i128` are 16-byte aligned on x86_64 since Rust 1.77 and on aarch64, but 8-byte aligned on SBF | 4 |
| FV-088 | Every Kani-verified function that touches accounts has a matching runtime test. Proofs on extracted pure functions do not cover owner/signer/discriminator validation (checklist 01 and a PoC are still required) | 5 |

<!-- verified FV-079: agave v2.1.0 sdk/program/src/program.rs (wrapper fns over solana-cpi); anchor v0.32.0 lang/Cargo.toml (no solana-program dep) and lang/src/lib.rs `pub use solana_invoke::{invoke, invoke_signed, ..}`; pinocchio@v0.9.2 sdk/pinocchio/src/cpi.rs pub fn invoke_signed -->
*Sources: workersio/skills `plugins/kani-proof/skills/kani-proof/` (PR #9 tree) (MIT, Copyright (c) 2026 workers.io), adapted; stub paths verified against anchor v0.32.0 / agave v2.1.0 / pinocchio v0.9.2.*

---

## 16.9 Stateful-Fuzz Harness Soundness — Trident (FV-089 → FV-095)

| ID | Check | Severity |
|----|-------|----------|
| FV-089 | Fuzz findings are recorded reproducibly: tool version, harness commit, program build hash, failing seed, and the exact replay command (`trident fuzz debug <target> <seed>`). CI fails on findings (`--with-exit-code`, exit 99) | 5 |
| FV-090 | The harness fails on on-chain panics (`ProgramFailedToComplete`: overflow under overflow-checks, `unwrap` on `None`, out-of-bounds index), not only on its own assertions. That requires either an explicit check on every `process_transaction` result (no `let _ =`), or metrics enabled **and** every transaction named **and** `--with-exit-code`. An unnamed transaction, or metrics left off, makes on-chain panics silent | 7 |
| FV-091 | Failure paths are asserted. The error must be in a **per-flow** allowlist that includes the expected Anchor framework codes (2000-range constraints, 3000-range account errors such as 3002 `AccountDiscriminatorMismatch` and 3012 `AccountNotInitialized`) and legitimate non-custom rejections (`MissingRequiredSignature`, System `Custom(0)` = `AccountAlreadyInUse`). Watched accounts are byte-identical after a failed transaction or flow | 6 |
| FV-092 | Signer authority is modelled per actor. TridentSVM does not verify signatures (any `is_signer = true` meta counts as signed) and does not charge fees. So attacker flows mark only attacker-held keys as signers, and authorization invariants tie each privileged change to the stored authority (FP-20) | 8 |
| FV-093 | Adversarial substitution reaches the handlers: wrong-owner, wrong-type (other discriminator), cross-user PDA, non-canonical-bump PDA, substituted program ids, duplicate accounts. Non-canonical-bump PDAs are inserted by hand, because address storage yields canonical bumps only. Generated builders hard-code program ids and IDL meta flags, so override `accounts` or build raw `Instruction`s | 8 |
| FV-094 | Invariant reads verify the program's actual discriminator bytes and length (not a hard-coded 8) and assert missing/closed accounts explicitly. `get_account_with_type(key, discriminator_size)` skips the first `discriminator_size` bytes without comparing them. It returns `None` (so the check is skipped) for missing, closed, shrunk or undeserializable accounts, and `Some(zeroes)` for accounts that are zeroed but still allocated | 6 |
| FV-095 | Per-flow success counts and handler coverage are reported. No flow reverts in more than ~95 % of calls without justification; fix that with `#[flow(weight = N)]` (all flows weighted or none, weights summing to exactly 100) or `#[flow(ignore)]`. Coverage from host-entrypoint runs is labelled as such, and findings are re-confirmed on the SBF `.so` | 5 |

<!-- verified: Ackee-Blockchain/trident 0.12.0 crates/fuzz/src/trident/client.rs handle_tx_result (ProgramFailedToComplete counted only with FUZZING_METRICS and log_as), get_account_with_type; crates/fuzz/src/trident/flow_executor.rs determine_exit_code (99); crates/metrics/src/transactions/transaction_stats.rs get_exit_code; crates/syn/src/parser/trident_flow_executor.rs (weights sum to 100, ignore); crates/cli/src/command/fuzz.rs Debug {target, seed}; anchor v1.0.0 lang/src/error.rs codes 2001/2006/3002/3007/3012 -->
*Sources: Ackee-Blockchain/trident (MIT, Copyright (c) 2021 Ackee Blockchain).*

---

## 16.10 Test-Suite Evidence Quality (FV-096 → FV-106)

| ID | Check | Severity |
|----|-------|----------|
| FV-096 | Every instruction handler is exercised by at least one test. Untested value-moving handlers (deposit, withdraw, swap, liquidate, close, set_authority) are listed by name, and the mapping is labelled *measured* (tool output) or *estimated* (name match). The handler-list regex is `pub fn [a-z0-9_]+` | 5 |
| FV-097 | The project's negative tests can fail. No `try { await ix.rpc() } catch (e) { expect(e) }` without an `assert.fail` after the call. No client-side rejection mistaken for an on-chain one (`unknown signer`, `Missing signature for public key`). No acceptance of any error: the specific program error code is matched (e.g. `ConstraintHasOne` 2001, `ConstraintSeeds` 2006, `AccountDiscriminatorMismatch` 3002, `AccountOwnedByWrongProgram` 3007), and the failing instruction index and program are pinned | 6 |
| FV-098 | Init guards are tested in both directions: the first `initialize` succeeds **and** a second one on the same account fails (a guard that always fails passes a test of the second call only) | 5 |
| FV-099 | A fuzz/property target mixes accounts across users from small shared pools (2–4 entries per role) and treats an unexpected success as a failure | 6 |
| FV-100 | Every value-moving instruction has per-instruction pre/post invariants (e.g. vault decrease == user increase; authority unchanged unless the instruction is `set_authority`) | 5 |
| FV-101 | An error oracle asserts that expected rejections happen with the expected code and that spec-valid inputs are not rejected | 5 |
| FV-102 | CPI dependencies run as real binaries (dumped mainnet programs), not mocks, except where an adversarial mock is the point | 4 |
| FV-103 | Vaults and pools have an economic round-trip/cycle property: N cycles of deposit(X)→withdraw(all) never increase the actor's balance, for X ∈ {1, 2, 10^decimals − 1, u64::MAX/2} and under a donated exchange rate (invariant-catalog §8) | 6 |
| FV-104 | Mutation testing (e.g. `cargo mutants` on host tests, on a scratch copy) shows that removing auth/accounting checks makes tests fail. Surviving mutants on such lines show that the negative tests cannot fail | 5 |
| FV-105 | Each PoC/fuzz result states which runtime and feature set the harness emulated (runtime-context sheet). Time-dependent logic is driven by setting the Clock sysvar, not by sleeping | 4 |
| FV-106 | The scope of coverage tooling is stated. `cargo llvm-cov`/`tarpaulin` instrument host-native tests (including `solana-program-test` in native `processor!` mode) but not SBF execution (LiteSVM, Mollusk, program-test BPF mode). Miri runs only on host tests that touch `unsafe` and cannot see UB inside a `.so` | 4 |

*Sources: CDSecurity/cdsecurity-skills `rust-audit-prep/references/agents/testing-agent.md` (MIT, Copyright (c) 2026 CD Security); Solana Foundation course `content/courses/program-security/signer-auth.md` and `duplicate-mutable-accounts.md` labs [paraphrased, cited]; coral-xyz/sealevel-attacks `programs/4-initialization` [paraphrased, cited]; Ackee-Blockchain Solana-Auditors-Bootcamp `Lesson-3/trident-lesson-part-i` and `Lesson-4/trident-lesson-part-ii` [paraphrased, cited]; pashov/skills `fizz/agents/invariant-discovery/roundtrip-rounding-analyst.md` (MIT, Copyright (c) 2024 AI Skills Contributors); original analysis; qedgen/solana-skills `skills/qedgen-auditor/references/probe_orchestration.md` (MIT, Copyright (c) 2025 QEDGen).*
