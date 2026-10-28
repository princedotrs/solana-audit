---
id: 181
title: "sBPF v3 / Gap-less Stack: Faults That Used to Protect Become Silent"
severity: 7
category: crypto
---

### 181 — sBPF v3 / Gap-less Stack: Faults That Used to Protect Become Silent

**Severity: 7 (rare but real; HIGH when the fault was the only guard)** | **Real: qedgen sandbox fixtures (`sbpf_v3_runtime.rs`) that toggle `virtual_address_space_adjustments` in Mollusk**

Relevant feature gates (Agave feature-set; activation is per cluster, so check with `solana feature status <id>` and record the result in the runtime-context sheet):
- `enable_sbpf_v3_deployment_and_execution` `5cC3foj77CWun58pC51ebHFUWavHWKarWyR5UUik7dnC`: SIMD-0178/0189/0377, SBPF v3.
- `virtual_address_space_adjustments` `7VgiehxNxu53KdxgLspGQY8myE6f7UokaWa4jsGcaSz`: SIMD-0460, first in Agave v4.0.0. While it is active the loader sets `enable_stack_frame_gaps: false`.
<!-- verified: agave v4.0.0 / v4.3.2 / master feature-set/src/lib.rs and syscalls/src/lib.rs (`enable_stack_frame_gaps: !feature_set.virtual_address_space_adjustments`); absent in v3.1.14 -->

Two behaviours change with newer sBPF memory layouts:
(a) **Null / near-null reads.** Under sBPF v0–v2, nothing is mapped at VM address 0: `.rodata` and bytecode share the program region at `0x1_0000_0000`. A read through an absolute null or near-null pointer therefore faults and the transaction fails. In the current SBPF v3 layout (SIMD-0189 `enable_lower_rodata_vaddr`, solana-sbpf 0.23.0 as used by Agave v4.3.x), `.rodata` is mapped read-only at VM address 0 and bytecode at `0x1_0000_0000`. Earlier solana-sbpf 0.13/0.14 drafts put bytecode at 0 instead. Under v3 the same read can **succeed** and return the program's own constant bytes, which the program then treats as data. The shape is a pointer whose *absolute* value is null or small: a zeroed pointer field, a stored or derived raw address, a null `Option`-like pointer. An offset into a valid buffer is not this shape. The read succeeds only inside the mapped `.rodata` length, so a program with empty or short `.rodata` still faults. In Rust a null read is already UB.
<!-- verified: solana-sbpf 0.23.0 src/ebpf.rs (MM_RODATA_START = 0, MM_BYTECODE_START = 1<<32), src/program.rs (enable_lower_rodata_vaddr: V3+), src/elf.rs; solana-sbpf 0.13.1 had MM_BYTECODE_START = 0 -->
(b) **Stack overrun.** With 4 KiB frames separated by unmapped gaps, writing past a frame faults (KV-111's DoS). Only SBPF v0 has frame gaps. v1/v2 use dynamic frames and v3 uses contiguous fixed frames, and none of them has gaps. v0 also loses its gaps once `virtual_address_space_adjustments` (SIMD-0460) is active. Without gaps, the write lands silently in the adjacent frame and can flip a check flag or an amount. Frames grow upward, so an overrun past the end of a buffer runs into the callee's frame above (qedgen's `stack_overrun` fixture corrupts the callee's locals), and an underrun reaches the caller's frame below. Checked operations (`copy_from_slice`, indexing, `split_at_mut`) still panic and are not this class.
<!-- verified: solana-sbpf 0.23.0 src/program.rs (stack_frame_gaps(): V0 only), src/interpreter.rs push_frame -->


> Cross-ref: US-015/US-016, KV-111, FP-14, sbpf-vm-internals.md, runtime-context sheet (FULL-AUDIT 0.1b).

#### Verification Procedure
```
rg -n 'read_unaligned|ptr::read|from_raw_parts|as \*const|0usize as \*const|core::ptr::null' programs/
rg -n 'ptr::copy_nonoverlapping|ptr::write_bytes|get_unchecked_mut|from_raw_parts_mut|\.add\([a-z_]+\)\.write' programs/
```
- Record the deployed sBPF version and the cluster's feature status (runtime-context sheet). Confirm with the program's actual build (`cargo build-sbf --arch v3` where applicable) and a harness with the cluster's feature set: (a) drive the pointer to 0 and compare v0 (access violation) with v3 (succeeds); (b) choose a length that crosses the frame — evidence is a wrong computed value or a skipped check; a fault is not this class.
- ✅ PASS: raw reads/writes are bounds- and null-checked against the real buffer; no unchecked stack-buffer writes with input-derived lengths
- ❌ FAIL: either shape reachable on the deployed or next-upgrade target

```rust
// VULNERABLE (b)
let mut buf = [0u8; 64];
fill(buf.as_mut_ptr(), ix_len);                          // ix_len from instruction data
fn fill(p: *mut u8, n: usize) { for i in 0..n { unsafe { p.add(i).write(0xAA) } } }
// FIXED
let mut buf = [0u8; 64];
let n = ix_len.min(buf.len());                           // or reject ix_len > buf.len()
buf[..n].fill(0xAA);
```

**Overall verdict:** ✅ no fault-dependent safety · ❌ safety relied on a fault the target layout no longer raises (a v0 program that will not be upgraded: report (a) against the next upgrade, FP-14)

*Sources: qedgen/solana-skills `skills/qedgen-auditor/references/category-catalog.md` `sbpf_v3_low_address_read` and `sbpf_v3_stack_overrun_no_fault` (MIT, Copyright (c) 2025 QEDGen); the low-address example replaced (absolute null pointer, `.rodata` length caveat); SIMD numbers, feature ids and the v3 memory map checked against Agave v4.0.0/v4.3.2 `feature-set` and `syscalls`, and against solana-sbpf 0.23.0 (`.rodata` at VA 0 under v3, which corrects the claim "bytecode at 0x0").*
