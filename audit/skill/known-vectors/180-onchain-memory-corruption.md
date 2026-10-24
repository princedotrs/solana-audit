---
id: 180
title: "On-Chain Memory Corruption Escalating to Signed CPI"
severity: 9
category: crypto
---

### 180 — On-Chain Memory Corruption Escalating to Signed CPI

**Severity: 9 (10 with a write-what-where plus a controllable indirect call; 7–9 for an attacker-offset write without one, rated by what it can corrupt)** | **Real: OtterSec Paradigm CTF 2023 write-up "Solana: jumping around in the VM"**

Auditors often file an unsafe write or OOB slice in a Solana program as "UB / robustness / Low". OtterSec's write-up shows the escalation: with an attacker-controlled write primitive **and** a corruptible indirect-call target (in the CTF, the program deliberately exposed caller-chosen function pointers), the attacker plants fake `StableInstruction`/`AccountInfo`/seed structures in instruction data (serialised into the input region at predictable addresses), writes pointers to them into stack slots a later frame reads, and jumps into the middle of `invoke_signed_unchecked` straight to the `sol_invoke_signed_rust` syscall. The runtime derives PDA signatures from the calling program's id plus the supplied seeds, so the forged CPI signs as **any PDA of the program** (every vault, mint and config authority) — chained by repeated indirect calls, bounded by compute, CPI limits and call depth. In sBPF, `call`/`exit` keep return addresses in the VM's internal frame stack, so a write alone cannot redirect a return. Escalation to arbitrary signed CPI needs a function pointer or `dyn` vtable pointer in writable memory, or a `callx` register taken from data. `callx` is bounds-checked against the text section only, with no check that it lands on a function entry, so mid-function gadgets stay reachable. The runtime still rejects writes to non-owned or read-only accounts and illegal owner/lamport changes.
<!-- verified: solana-sbpf 0.23.0 (Agave v4.3.2) src/interpreter.rs CALL_REG (check_pc bounds only; push_frame stores the return pc in VM call frames); src/jit.rs ANCHOR_INTERNAL_FUNCTION_CALL_REG (bounds check plus a reject only for pc_section slots marked unsupported, i.e. the second half of an lddw; no function-entry check) -->


> Cross-ref: US-001..US-004, Rule 5b memory-corruption severity, references/framework-idioms/sbpf-vm-internals.md, AV-081/AV-088.

#### Verification Procedure
```
rg -n 'transmute::<\[u8; *[0-9]+\], *(\*mut|\*const|fn\(|&)' programs/
rg -n 'as \*mut [A-Za-z0-9_]+|as \*const [A-Za-z0-9_]+' programs/
rg -n '\.write_volatile\(|ptr::write(_unaligned|_bytes)?\(|copy_nonoverlapping\(|\.add\(|\.offset\(' programs/
rg -n 'transmute.*fn\(|: *fn\([^)]*\) *->|\[fn\(|&dyn |Box<dyn ' programs/
rg -n 'get_unchecked(_mut)?\(|from_raw_parts(_mut)?\(|set_len\(|assume_init|borrow_mut_data_unchecked|borrow_data_unchecked|borrow_unchecked(_mut)?\(' programs/
```
<!-- verified: pinocchio 0.9.2 AccountInfo::borrow_{,mut_}data_unchecked; pinocchio 0.10+/solana-account-view 2.1.0 AccountView::borrow_unchecked{,_mut} -->

For each hit, trace whether the pointer value, offset, length or index can be influenced by instruction data or attacker-controlled (including cosplayed) account contents. A bounds check on the *source* buffer does not make a *destination* pointer safe. With the copy-based input serialisation, writing past one account's data (beyond its 10 KiB realloc padding) lands in the next serialised account header or in instruction data. With `account_data_direct_mapping` active, account data is mapped as separate regions and the result differs, so record the cluster's feature status (FULL-AUDIT 0.1b). Writing past a stack buffer lands in an adjacent frame, or faults in the guard gap where gaps exist (KV-181).
- ✅ PASS: no attacker-influenced raw pointer, function pointer or `&T`/`&mut T` without a validated bounds + alignment proof; dispatch never via `get_unchecked` or a writable fn-pointer table (safe indexing panics — a DoS, not corruption)
- ❌ FAIL: rate per the Rule 5b memory-corruption rule

```rust
// VULNERABLE: offset from instruction data, written through a raw pointer
let off = u64::from_le_bytes(ix[0..8].try_into().unwrap()) as usize;
let val = u64::from_le_bytes(ix[8..16].try_into().unwrap());
unsafe {
    let mut data = acc.try_borrow_mut_data()?;
    (data.as_mut_ptr().add(off) as *mut u64).write_unaligned(val);   // no bound on `off`
}
// FIXED: checked slice indexing, offset limited to a declared table
let idx = u16::from_le_bytes(ix.get(0..2).ok_or(ProgramError::InvalidInstructionData)?.try_into().unwrap()) as usize;
if idx >= MAX_SLOTS { return Err(ProgramError::InvalidArgument); }
let start = HEADER_LEN.checked_add(idx.checked_mul(8).ok_or(ProgramError::InvalidArgument)?).ok_or(ProgramError::InvalidArgument)?;
let val = ix.get(2..10).ok_or(ProgramError::InvalidInstructionData)?;
acc.try_borrow_mut_data()?.get_mut(start..start + 8).ok_or(ProgramError::AccountDataTooSmall)?.copy_from_slice(val);
```

**Overall verdict:** ✅ no attacker-reachable memory corruption · ❌ any attacker-reachable write primitive (severity per Rule 5b)

*Sources: OtterSec "Solana: jumping around in the VM" (2023) and "Solana: an auditor's introduction" (2022) [paraphrased, © Otter Audits LLC, cited: https://osec.io/blog/2023-12-11-jumping-around-in-the-vm , https://osec.io/blog/solana-security-intro]; severity rule narrowed (indirect-call target required for arbitrary signed CPI).*
