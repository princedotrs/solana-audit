# 23 — Rust `unsafe`, Panics & Error Propagation Checklist (on-chain)

> Domain: On-chain Solana Program (every Rust program: Anchor, native, Pinocchio; memory-safety sections gated on `unsafe` / zero-copy markers)
> Severity if missed: CRITICAL (memory corruption) / MEDIUM (panics, swallowed errors)
> References: KV-150, KV-180, KV-181, KV-182; references/framework-idioms/sbpf-vm-internals.md; references/framework-idioms/pinocchio.md
> Load when: any on-chain Rust program (§23.2 panics and error propagation and §23.5 hygiene apply to every program).

Every item below is a single verification step. Mark each `[PASS]`, `[FAIL-{severity}]`, `[PARTIAL]`, or `[N/A]`.

> **Feature-gated sections (advisory load).** The sections below are feature-specific: if the feature is *provably absent* (empty prescan array or zero grep hits — see `references/orchestration/pre-scan.md`), you may spot-defer the section and render its items `[N/A — feature absent: <marker>]`. Token-efficiency layer only — **every item still gets a verdict per Rule 0**, and the section reopens the instant a manual read surfaces the feature. §23.2 and §23.5 are baseline for every program.
>
> | Section | Feature | Markers |
> |---------|---------|---------|
> | §23.1 Memory safety | `unsafe` code or raw pointers | `unsafe` · `from_raw_parts` · `transmute` · `as *const` · `as *mut` · `get_unchecked` |
> | §23.3 Borrows & unchecked CPIs | unchecked CPI or raw account views | `pinocchio` · `_unchecked(` · `sol_invoke_signed` · `borrow_unchecked` · `.view()` · `RefCell` · `Cell<` |
> | §23.4 Layout & VM assumptions | zero-copy casts or VM-layout reliance | `bytemuck` · `zero_copy` · `Pod` · `#[repr(C)]` · `transmute` · `RequestHeapFrame` · `global_allocator` · `custom-heap` |

---

## 23.1 — Memory safety

- [ ] **US-001**: No on-chain code turns attacker-influenced bytes (instruction data, account contents) into a raw pointer, a function pointer (`fn(..)`), or a `&T`/`&mut T` without a validated bounds + alignment proof.
- [ ] **US-002**: No dispatch table or indirect call is indexed through `get_unchecked`/raw pointers, and no function-pointer table lives in writable memory. (Safe `HANDLERS[i]` indexing panics on OOB — a DoS, not corruption.)
- [ ] **US-003**: Every `unsafe` write's destination is proven inside a buffer the program owns for the full write width (bounds on the source do not protect the destination).
- [ ] **US-004**: Confirmed memory corruption is rated with the Rule 5b memory-corruption rule (Critical with a controllable indirect call; otherwise by what it can corrupt) (KV-180).
- [ ] **US-005**: Every `unsafe` block has an adjacent `// SAFETY:` stating the invariant relied on (length, alignment, ownership, no-alias), and that invariant holds on **every** path that reaches it (KV-182).

## 23.2 — Panics & error propagation

- [ ] **US-006**: No crate-level `#![allow(..)]` of `clippy::arithmetic_side_effects` (renamed from `integer_arithmetic`), `cast_possible_truncation`, `cast_sign_loss`, `cast_possible_wrap`, `indexing_slicing`, `unwrap_used`, `expect_used`, `panic`; every local `allow` has a reason. Suppressed regions get AR-0xx / AV-081 re-run. (Suggested profile, scratch copy only: `cargo clippy -- -W clippy::arithmetic_side_effects -W clippy::cast_possible_truncation -W clippy::cast_sign_loss -W clippy::indexing_slicing -W clippy::unwrap_used -W clippy::expect_used -W clippy::panic`.)
- [ ] **US-007**: `unwrap`/`expect`/`checked_*().unwrap()`/indexing on user- or account-derived data are listed as panic sites; on liquidation, settlement, crank and withdrawal paths each is a liveness finding (AR-068).
- [ ] **US-008**: No discarded `Result` (`let _ =`, `.ok();`) from CPIs, builders, serializers or helpers on value/state paths (KV-150).
- [ ] **US-009**: No default-on-error on value paths: `Clock::get().unwrap_or_default()`, oracle `.ok()`/`unwrap_or(0)`, `try_from_slice(..).unwrap_or_default()`.

## 23.3 — Borrows & unchecked CPIs

- [ ] **US-010**: Every unchecked CPI (`invoke_*_unchecked`, Pinocchio unsafe CPI, raw `sol_invoke_signed_*`) has a justification and no live data/lamports borrow or view of a passed account across it (CPI-034).
- [ ] **US-011**: Raw `&mut` views are never created for two account slots that may hold the same key; duplicates are rejected first (the loader passes duplicates through).
- [ ] **US-012**: Account types own their values; no retained `&'info` references through interior mutability; no swapped lamports/data backing references (AN-027).

## 23.4 — Layout & VM assumptions

- [ ] **US-013**: `transmute` and `bytemuck` casts are validity-checked (no invalid bit patterns for bool/enums; `try_from_bytes`, not `from_bytes`, on untrusted data).
- [ ] **US-014**: Zero-copy layouts are `#[repr(C)]` with explicit padding, `space == discriminator length (8 by default) + size_of::<T>()`; `zero_copy(unsafe)` (and plain `zero_copy` on Anchor < 0.27) have their offsets walked; casts at a header offset respect `align_of::<T>()` (pinocchio.md §1).
- [ ] **US-015**: No safety depends on a null/near-null read faulting: on sBPF v3 the region at virtual address `0x0` is mapped (read-only data in solana-sbpf 0.23, the VM Agave 4.3 uses) (KV-181).
- [ ] **US-016**: No stack buffer is written through an unchecked pointer with an input-derived length (from sBPF v1 on, frames have no unmapped gaps — v1/v2 through SIMD-0166 dynamic stack frames, v3 with fixed frames and no gaps — so an overrun corrupts the neighbouring frame instead of faulting) (KV-181).
- [ ] **US-017**: Heap use is bounded: the runtime maps 32 KiB unless the transaction requests more with `RequestHeapFrame` (up to 256 KiB), and only an allocator that knows about the larger region uses it — solana-program's default bump allocator is fixed at 32 KiB, Pinocchio ≥ 0.10's `default_allocator!` spans 256 KiB and so relies on the request; dealloc is a no-op in both. No attacker-sized allocation on a liveness path. <!-- verified: pinocchio HEAD sdk/src/entrypoint/mod.rs (`MAX_HEAP_LENGTH = 256 * 1024`, `default_allocator!`; deprecated `HEAP_LENGTH = 32 * 1024`) -->

## 23.5 — Hygiene signals (Informational unless exploitable)

- [ ] **US-018**: Leftover sweep: `TODO|FIXME|HACK|XXX` near validation, blocks of commented-out `require!`/`if`/`constraint`/`has_one`/`checked_` lines (a removed check), `println!`/`dbg!` in program code — each gets a manual read of the surrounding function. Hits inside `cfg(test)` modules are removed by hand (a line filter cannot detect module scope).
- [ ] **US-019**: A Miri lane covers host tests that touch `unsafe` (processor / zero-copy code called directly); its scope limit (no visibility into the `.so`) is stated.
- [ ] **US-020**: No `#[cfg(test)]`/feature-gated helper or bypass leaks into the deployed program (OPS-089).
