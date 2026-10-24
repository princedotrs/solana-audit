---
id: 182
title: "Pinocchio / Unsafe-Protocol Hazards Around Unchecked Borrows and CPIs"
severity: 8
category: crypto
---

### 182 — Pinocchio / Unsafe-Protocol Hazards Around Unchecked Borrows and CPIs

**Severity: 8** | **Real: qedgen benchmark corpus (stale SAFETY comments, duplicate-account aliasing, lost writes)**

Pinocchio's `unsafe` `*_unchecked` loads and its `unsafe` unchecked CPIs drop owner, length, initialisation, discriminator, alias and borrow-guard guarantees. The loads are `AccountInfo::borrow_data_unchecked`/`borrow_mut_data_unchecked` in ≤ 0.9, `AccountView::borrow_unchecked`/`borrow_unchecked_mut` in 0.10+, and `from_bytes_unchecked` on pinocchio-token state and on sysvars. The CPIs are `invoke_unchecked`/`invoke_signed_unchecked`.
<!-- verified: pinocchio 0.9.2 src/account_info.rs, src/cpi.rs; solana-account-view 2.1.0 src/lib.rs; solana-instruction-view 2.1.0 src/cpi.rs; pinocchio-token 0.7.0 src/state -->
 KV-109 and pinocchio.md cover missing manual validation; these four sub-shapes are separate:
1. **Stale `// SAFETY:` comment.** It claims owner/length/initialisation/no-alias preconditions that are missing on at least one path reaching the unsafe call. Treat it as a claim to disprove.
2. **Duplicate-account assumption.** The handler assumes every account is non-duplicate, but the serialised input marks a repeated account with a duplicate-index byte. The entrypoint resolves it to the same underlying account (the lazy entrypoint yields `MaybeAccount::Duplicated(index)`). Two raw `&mut` views of one buffer are UB, and a self-transfer can mint or burn balance, or move nothing while the accounting still updates.
3. **Release-then-reacquire.** Write through one borrow, drop it, then build a fresh view from a stale copy or offset — the first write is lost while the handler returns `Ok`.
4. **Unchecked CPI with live views.** `_unchecked` CPIs skip the borrow check: Pinocchio's per-account borrow-state byte, or the `RefCell` borrows in `solana_program::program::invoke_signed_unchecked`, which is a safe fn. A view held across the call reads stale (compiler-cached) values or writes a stale struct back over the callee's update. Pinocchio documents this as UB when the callee writes borrowed data.
<!-- verified: solana-instruction-view 2.1.0 src/cpi.rs invoke_signed_unchecked "# Safety" -->


> Cross-ref: CPI-034, US-005, US-010, US-011, pinocchio.md §8.

#### Verification Procedure
```
rg -n -B2 -A8 'SAFETY:' programs/ --type rust
rg -n '_unchecked\(|from_raw_parts_mut|bytemuck::from_bytes_mut|transmute' programs/
rg -n 'invoke_unchecked|invoke_signed_unchecked|sol_invoke_signed_(c|rust)' programs/     # unchecked CPIs: no borrow-state validation
rg -n 'slice_invoke|invoke_with_bounds|invoke_signed_with_bounds' programs/              # Pinocchio checked variants: list them too, to map every CPI site
```
<!-- verified: pinocchio@v0.9.2 sdk/pinocchio/src/cpi.rs (the checked `invoke*`/`slice_invoke*`/`*_with_bounds` validate keys and borrow state; `invoke_unchecked` / `invoke_signed_unchecked` are `unsafe fn` and validate nothing; from 0.10 the CPI code lives in the `solana-instruction-view` crate behind the `cpi` feature); anchor v1.2.1 lang/src/lib.rs re-exports `solana_invoke::{invoke_unchecked, invoke_signed_unchecked}` -->
For each unsafe site verify every claimed precondition on every path; for each unchecked CPI list every live borrow/view of a passed account.
- ✅ PASS: preconditions hold on all paths; duplicate keys rejected before raw views; views re-derived after writes and CPIs; Miri lane run on host tests touching unsafe (it cannot see UB inside the `.so`)
- ❌ FAIL: any precondition false on a reachable path

```rust
// Pseudo-code (VULNERABLE): zero-copy view held across an unchecked CPI that mutates the same account
let state: &mut Pool = /* view into pool_ai data */;
invoke_signed_unchecked(&ix_touching_pool, infos, seeds)?;   // borrow guard skipped
state.reserve -= out;                                          // stale / aliased view
// FIXED: copy what you need out of a short-lived borrow, use the checked invoke, re-derive the view afterwards
let reserve_before = {
    let d = pool_ai.try_borrow_data()?;
    let bytes = d.get(..Pool::LEN).ok_or(ProgramError::InvalidAccountData)?;
    bytemuck::try_from_bytes::<Pool>(bytes).map_err(|_| ProgramError::InvalidAccountData)?.reserve
};                                                             // borrow dropped here
invoke_signed(&ix_touching_pool, infos, seeds)?;               // AccountBorrowFailed if a conflicting borrow is still live
let mut d = pool_ai.try_borrow_mut_data()?;
let bytes = d.get_mut(..Pool::LEN).ok_or(ProgramError::InvalidAccountData)?;
let state: &mut Pool = bytemuck::try_from_bytes_mut(bytes).map_err(|_| ProgramError::InvalidAccountData)?;
// Use the post-CPI value; keep `reserve_before` only for a delta / invariant check.
if state.reserve < reserve_before { return Err(ProgramError::InvalidAccountData); } // example invariant: the CPI may only add to the reserve
state.reserve = state.reserve.checked_sub(out).ok_or(ProgramError::ArithmeticOverflow)?;
```
<!-- verified: solana-program `invoke_signed` borrows every passed AccountInfo per its meta (try_borrow_mut_* for writable, try_borrow_* otherwise) before the syscall; `ProgramError::ArithmeticOverflow` exists in solana-program-error and in Pinocchio. The earlier FIXED line wrote `reserve_before - out` back after the CPI, which discards whatever the CPI changed (a stale write); corrected. -->

**Overall verdict:** ✅ every unsafe precondition holds on every path · ❌ any does not

*Sources: qedgen/solana-skills Pinocchio unsafe-protocol hazards (MIT, Copyright (c) 2025 QEDGen), Miri scope corrected; OtterSec VM post U3 [paraphrased, cited], narrowed to the unchecked-guard part and marked pseudo-code.*
