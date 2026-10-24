---
id: 152
title: "CPI Return-Data Spoofing"
severity: 7
category: crypto
---

### 152 — CPI Return-Data Spoofing

**Severity: 7 (9 when the value prices collateral or a swap)** | **Real: Anchor's generated `cpi::Return<T>::get()` (both the `#[program]` CPI module and `declare_program!`) read the live return-data buffer and discarded the returning program id in every release before 1.1.0, on the whole 1.0.x line (1.0.3, published two days after 1.1.0, still lacks it), and in the `anchor-lang-v1` crate (`lang/`, `publish = false`) at the v2.0.0-rc.1 and rc.2 tags, which are cut from a branch that does not contain the fix and are reachable only as a git dependency. The crates.io `anchor-lang` 2.0.0-rc.x is the separate v2 crate: its generated `Return<T>::get()` asserts the program id but reads the live buffer, so a CPI made between the call and `.get()` can still replace the value. The check is in the v1.1.0 tag, but 1.1.0 was never published to crates.io, so 1.1.1 is the first published release with it; it is present on the 1.1.x and 1.2.x lines: solana-foundation/anchor #4411, plus the snapshot follow-up that the CHANGELOG links as otter-sec/anchor #4624.**

`get_return_data()` returns `Option<(Pubkey, Vec<u8>)>`. The pubkey is the program that **last called `set_return_data`**, and `None` means the buffer is empty. At the start of every instruction, top-level or CPI, the runtime resets return data to (callee id, empty). The risk is therefore not a stale buffer left by an earlier call. Take A → B → C, where C sets return data and B sets nothing: when the CPI into B returns, A receives C's data tagged with C's id. A caller that ignores the pubkey, or treats `None` as zero, can be fed a forged quote, amount or price. Routers, AMM "simulate swap" calls and oracle adapters are typical consumers.
<!-- verified: agave v4.4.0-beta.1 program-runtime/src/invoke_context.rs (set_return_data(program_id, Vec::new()) before each executable chain); anchor v1.0.3 lang/syn/src/codegen/program/cpi.rs (get() discards key) vs v1.1.0 same file + lang/src/lib.rs CpiReturnData::get (panics on program_id mismatch); CHANGELOG at v1.1.0/v1.1.1 lists #4411/#4624 under 1.1.0 (the v1.2.x CHANGELOG moved them under 1.1.1); v1.1.0 cpi.rs builds Return { program_id: ctx.program_id, .. } with no check that ctx.program_id == crate::ID; agave v1.18.26 sdk/program/src/program.rs get_return_data returns None when size == 0; anchor v1.1.0, v1.1.1, v1.1.2, v1.2.0, v1.2.1 lang/syn/src/codegen/program/cpi.rs and lang/attribute/program/src/declare_program/mods/cpi.rs contain `self.return_data.get(self.program_id)`; v2.0.0-rc.1 and v2.0.0-rc.2 (not descendants of v1.1.0) still have the unchecked `get()` with `let (_key, data) = get_return_data().unwrap()` in both files; v1.1.0 get_unchecked() re-reads the live buffer, not the snapshot -->

> Cross-ref: CPI-033, AN-025.

#### Verification Procedure

**Step 1: Find consumers**
```
rg -n 'get_return_data|set_return_data|sol_get_return_data' programs/
rg -n 'Return<|\.get_unchecked\(\)|\)\?\s*\.get\(\)' programs/
rg -n -A3 '::cpi::[a-z_]+\(' programs/ | rg '\.get(_unchecked)?\(\)'          # multi-line CPI calls
```
Also list the program id each consumer CPIs into, and how that id is constrained.

**Step 2: Checks**
- ✅ PASS: the returned program id equals the pinned callee just invoked; `None` is an error; length and format are validated before decoding; the value is range-checked against protocol bounds (non-zero where zero is meaningless, at most the plausible maximum); the order and uniqueness of returned vectors are validated. Anchor users rely on `Return<T>::get()` only on a release that has the check, which aborts on a missing buffer or a program-id mismatch: 1.1.x or 1.2.x (≥ 1.1.0). It is **not** "any version ≥ 1.1.0": 2.0.0-rc.1 and rc.2 lack the check, so on those (and on ≤ 1.0.x) `get()` needs the manual checks above. Confirm against the pinned `anchor-lang` source, not the version number alone. That check compares against `ctx.program_id`, the id the `CpiContext` was built with, so it proves only that the data came from the program actually invoked. It passes only when that id is itself pinned (`Program<'info, T>`, `address = KNOWN_ID`, or a constant). `Return<T>::get_unchecked()` deliberately skips the check, re-reads the live buffer rather than the post-CPI snapshot (so a later CPI can replace it), and needs the manual checks above. Range and length checks on the decoded value are still the caller's job on every version.
- ❌ FAIL: id ignored, default on `None`, unchecked slice indexing
- ❌ FAIL: Anchor `get()` on ≤ 1.0.x (or a git dependency on the v2.0.0-rc tags' `anchor-lang-v1`) with no manual provenance check
- ❌ FAIL: Anchor 1.1.x/1.2.x `get()` on a `CpiContext` whose program id comes from a caller-supplied `UncheckedAccount`/`AccountInfo`. The attacker's program is "the program invoked", so its forged return data passes.

```rust
// VULNERABLE
let (_, data) = get_return_data().unwrap_or_default();
let out = u64::from_le_bytes(data[..8].try_into().unwrap());

// FIXED
let (pid, data) = get_return_data().ok_or(ErrorCode::NoReturn)?;
require_keys_eq!(pid, EXPECTED_AMM_ID, ErrorCode::ReturnDataSpoofed);
let bytes: [u8; 8] = data.as_slice().try_into().map_err(|_| ErrorCode::BadReturn)?;
let out = u64::from_le_bytes(bytes);
require!(out > 0 && out <= max_reasonable, ErrorCode::BadReturn);
```

**Overall verdict:**
- ✅: every consumer checks provenance, presence, length and bounds
- ❌: any consumer trusts unverified return data in a value decision

*Sources: PlamenTSV/plamen §3 (MIT, Copyright (c) 2025-2026 Plamen Contributors); solana-foundation/anchor v1.1.0 and v2.0.0-rc.2 `lang/syn/src/codegen/program/cpi.rs`, `lang/attribute/program/src/declare_program/mods/cpi.rs` and CHANGELOG (#4411, #4624) (Apache-2.0); pashov/skills boundary Q4, corrected (MIT, Copyright (c) 2024 AI Skills Contributors).*
