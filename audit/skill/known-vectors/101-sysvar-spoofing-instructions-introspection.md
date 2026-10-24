---
id: 101
title: "Sysvar Spoofing & Instructions-Sysvar Introspection Abuse"
severity: 8
category: crypto
---

### 101 — Sysvar Spoofing & Instructions-Sysvar Introspection Abuse

**Severity: 8** | **Real: Wormhole (Feb 2022, ~$326M) — verify_signatures read the Instructions sysvar through the deprecated unchecked load_instruction_at; plus the general sysvar-substitution class**

A program that reads a sysvar (Clock, Rent, RecentBlockhashes, SlotHashes, Instructions) from a passed-in `AccountInfo` instead of the runtime syscall (`Clock::get()`, `Rent::get()`) can be fed an attacker-controlled account with forged contents. Forged `Clock` enables timestamp/slot manipulation (bypass cooldowns, vesting, auction windows, staleness checks). Forged `Instructions` sysvar enables introspection bypass (see KV-102). Anchor's `Sysvar<'info, T>` validates the address, but raw `AccountInfo` or `UncheckedAccount` typed sysvars do not.

> Note (transaction v1, SIMD-0385): introspecting `ComputeBudgetProgram` instructions is unreliable even with a correctly pinned Instructions sysvar — under v1 those instructions are no-ops and the real compute / fee config lives in the message header, which no sysvar or syscall exposes. Any gate built on them is covered by KV-135 and AV-089.

#### Verification Procedure

**Step 1: Find all sysvar usage**
```
grep -rn --include="*.rs" -iE "Clock|Rent|RecentBlockhashes|SlotHashes|instructions::|Sysvar|sysvar" programs/*/src/
rg -n "load_instruction_at\s*\(|load_current_index\s*\(" programs/ | rg -v _checked
```
- Record every sysvar read and how it is obtained (syscall vs passed account)
- Cover the full sysvar set: `clock|rent|epoch_schedule|epoch_rewards|instructions|slot_hashes|slot_history|stake_history|last_restart_slot|recent_blockhashes|fees|rewards` (the last three are deprecated; `last_restart_slot` is current)

**Step 2: Prefer syscall reads over passed accounts**
```
grep -rn --include="*.rs" -E "Clock::get\(\)|Rent::get\(\)" programs/
```
- ✅ PASS: Time/rent obtained via `Clock::get()` / `Rent::get()` syscalls (cannot be spoofed)
- ❌ FAIL: `clock.unix_timestamp` / rent read from a passed-in account field

**Step 3: If a sysvar is passed as an account, verify its type and address**
```
grep -rn --include="*.rs" -E "Sysvar<'info,|UncheckedAccount.*[Cc]lock|AccountInfo.*[Cc]lock" programs/
```
- ✅ PASS: the sysvar is read via `Sysvar::get()`, `Sysvar<'info, T>`, `Sysvar::from_account_info` (checks the id), or `_checked` helpers; the Instructions sysvar is an `UncheckedAccount` with `address = sysvar::instructions::ID`
- ❌ FAIL: bytes read without an id check (raw bincode/bytemuck/offsets, unchecked `load_*`)

**Step 4: Check time-dependent logic for spoofing impact**
- For each cooldown / vesting / auction / TWAP-staleness / expiry check: confirm the timestamp source is non-spoofable
- ✅ PASS: All time-gated logic uses `Clock::get()`
- ❌ FAIL: A cooldown or staleness guard can be bypassed by passing a forged Clock account

**Introspection notes**
Sibling introspection (`get_processed_sibling_instruction`) returns already-processed instructions at the same stack height and with the same caller, index 0 = most recent, as program id + accounts + data only (no resulting account state or return data) — decode fully and prefer balance deltas (CPI-036). Pairing/flash-loan introspection logic: KV-151. Patch-gap lesson: Wormhole's fix was committed upstream but not deployed — compare deployed hash with the audited commit (KV-137).

*Sources: Trail of Bits not-so-smart-contracts `solana/sysvar_account_check` [paraphrased, AGPL-3.0, cited: https://github.com/crytic/building-secure-contracts/tree/master/not-so-smart-contracts/solana/sysvar_account_check]; crytic/solana-lints `lints/sysvar_get` [paraphrased, cited: https://github.com/crytic/solana-lints]; Sealevel Sentinel (stantheman0128/sealevel-sentinel) `src/detectors/sysvar-address.ts` sysvar list (MIT, Copyright (c) 2026 Stan (stantheman0128)), completed; original analysis.*

**Overall verdict:**
- ✅: All sysvar reads use syscalls, or passed sysvars are typed/address-checked
- ⚠️: Sysvars typed correctly but some time logic reads from passed account fields
- ❌: Any security-relevant sysvar read from an unchecked passed account
- N/A: Program reads no sysvars
