---
id: 153
title: "Anchor Legacy IDL Instruction Surface"
severity: 5
category: crypto
---

### 153 — Anchor Legacy IDL Instruction Surface

**Severity: 5 (Low/Medium; High when downstream signing or CPI decisions are built from the on-chain IDL, or when it enables cosplay against a missing type check)** | **Real: Accretion "Hidden IDL Instructions and How to Abuse Them"**

**Scope.** This applies to Anchor 0.x programs built **without the active `no-idl` cargo feature**. Declaring the feature in `[features]` is not enough, and `idl-build` or `anchor build --no-idl` say nothing about the on-chain instructions. It also applies to Anchor ≥ 1.1.0 programs that opt in with `#[program(legacy_idl)]` (#4455; the opt-in emits a deprecation warning). Anchor 1.0.0 (#3798) removed the legacy IDL instructions and moved IDLs to the Program Metadata program, and 1.0.x generates none. Legacy IDL accounts from a 0.x deployment stay on chain after an upgrade unless they are closed (OPS-088). <!-- verified: anchor v0.32.1 lang/syn/src/codegen/program/dispatch.rs `#[cfg(not(feature = "no-idl"))]`; v1.0.0 dispatch.rs has no IDL_IX_TAG branch; v1.1.0/v1.2.1 dispatch.rs generate_legacy_idl_dispatch gated on `args.legacy_idl` -->

The hidden set is `IdlCreateAccount`, `IdlCreateBuffer`, `IdlWrite`, `IdlSetBuffer` and `IdlSetAuthority`, plus `IdlClose` and `IdlResize` from 0.27.0. They are triggered by data starting with `IDL_IX_TAG` = `0x0a69e9a778bcf440` (little-endian bytes `40 f4 bc 78 a7 e9 69 0a`, decimal `64, 244, 188, 120, 167, 233, 105, 10`). With `event-cpi`, the `EVENT_IX_TAG` (`0x1d9acb512ea545e4`, first LE byte `0xe4`) self-CPI handler is another implicit entrypoint. <!-- verified: anchor v0.32.1 lang/src/idl.rs IDL_IX_TAG + IdlInstruction; v0.26.0 has no Close/Resize, v0.27.0 has both; v1.2.1 lang/src/event.rs EVENT_IX_TAG -->
1. **Cosplay primitive.** Anyone can create a zero-filled account owned by the program (System `create_account` with `owner = program_id`). `IdlCreateBuffer` (a `zero` constraint, authority = any signer) followed by `IdlWrite` then gives a **program-owned account whose bytes after a fixed 44-byte header the attacker controls**. The header is an 8-byte discriminator, a 32-byte authority and a 4-byte `u32` length. Any read that skips the discriminator check is exposed, so "no other account type has a usable layout" is not a valid dismissal of a missing type check (FP-10). <!-- verified: anchor v0.32.1 lang/syn/src/codegen/program/idl.rs IdlCreateBuffer `#[account(zero)]`, trailing_data `&d[44..]` -->
2. **IDL squatting.** The IDL account lives at `create_with_seed(find_program_address(&[], program_id).0, "anchor:idl", program_id)`, which is a seeded address, not a PDA. `__idl_create_account` sets `authority = from` for **any** signer and never checks the upgrade authority. This holds in every version that has the instruction, including the 1.1+ `legacy_idl` opt-in. It was never fixed by adding a check; the instruction was only removed from the default build in 1.0. Whoever creates the account first can publish a misleading IDL (renamed accounts, wrong signer/writable flags) for explorers, wallets and code generators, or block the real upload. <!-- verified: anchor v0.32.1 and v1.2.1 lang/syn/src/codegen/program/idl.rs `idl_account.authority = *accounts.from.key;` -->
3. **Dispatch order.** Up to 0.26 the IDL tag was tested with an `if` before the program's own instructions. From 0.27 to 0.30.x, dispatch is an exact 8-byte `match`, so order does not matter, but fallback data whose first 8 bytes equal a tag is intercepted. From 0.31.0, dispatch is a sequence of `starts_with` tests: the program's own discriminators first (in declaration order), then `IDL_IX_TAG`, then `EVENT_IX_TAG`, then `fallback`. On 0.31–0.32, data bound for the fallback that starts with a tag is intercepted. With `no-idl` the IDL tag returns `IdlInstructionStub`, and without `event-cpi` the event tag returns `EventInstructionStub`, so neither reaches the fallback. (On 1.x without `legacy_idl`, IDL-tag data does reach the fallback.) A short custom discriminator that is a prefix of a tag (`[0x40]` for the IDL tag, `[0xe4]` for the event tag) captures the tag's data and shadows the IDL or event instruction. <!-- verified: anchor v0.26.0 dispatch.rs `if cfg!(not(feature = "no-idl")) { if sighash == IDL_IX_TAG... }`; v0.27.0–v0.30.1 `match sighash` with IDL_IX_TAG_LE / EVENT_IX_TAG_LE arms; v0.31.0/v0.32.1 `data.starts_with` sequence, event arm `EventInstructionStub` when event-cpi is off; v1.1.0 dispatch.rs legacy IDL branch only under `args.legacy_idl` -->
4. **Custody.** The IDL authority is separate from the upgrade authority. It is often left on a developer hot key after the upgrade authority moves to a multisig.

> Cross-ref: OPS-088, OPS-096, AN-008/AN-009, FP-10.

#### Verification Procedure

**Step 1: Is the surface compiled in?**
```
rg -n 'anchor-lang' Cargo.lock -A1 | head            # resolved version
rg -n 'no-idl' programs/*/Cargo.toml                 # declared AND enabled in default features / build command?
rg -n 'legacy_idl' programs/*/src                    # 1.1.0+ opt-in
rg -n 'event-cpi|emit_cpi!' programs/
```

**Step 2: Cosplay exposure**
- ❌ FAIL: the legacy IDL instructions are present **and** some account read relies only on an owner check (`UncheckedAccount`/`AccountInfo` + `try_from_slice`/`data[8..]`, `try_deserialize_unchecked`, raw `bytemuck::from_bytes`/`try_from_bytes` on the account data). `AccountLoader::new_unchecked` (≥ 1.2.0) and `try_from_unchecked` skip the owner check, not the type check: `load()`/`load_mut()` still compare the discriminator, so the IDL buffer cannot pass as `T` through them. Report a missing owner check there under AV-001 instead. <!-- verified: anchor v1.2.0 lang/src/accounts/account_loader.rs new_unchecked (no checks), try_from_unchecked (owner only), load/load_mut compare T::DISCRIMINATOR -->

**Step 3: Squatting and custody (on-chain, read-only, run from outside any cloned repo)**
- Read the legacy IDL account at the seeded address above with any RPC `getAccountInfo` (or the 0.x CLI: `anchor idl fetch` / `anchor idl authority <PROGRAM_ID>`). On ≥ 1.0, also read the Program Metadata account. Does the IDL account exist, and is its authority the governance multisig?
- ✅ PASS: the IDL was created in the deploy flow by the deployer and its authority is the upgrade-authority multisig, or the IDL instructions are compiled out
- ❌ FAIL: the IDL account is absent while the instructions are present (anyone can claim it), or the authority is a hot key

**Step 4: Discriminator shadowing**
```
rg -n 'discriminator\s*=|fn fallback' programs/*/src
rg -n -i '0x0a69e9a778bcf440|64,\s*244,\s*188,\s*120|0x1d9acb512ea545e4' programs/
```
- ❌ FAIL (≥ 0.31): fallback logic expects data that may start with the IDL or event tag, or a custom instruction discriminator is a prefix of either tag

**Step 5: The instruction matrix and fuzzers include the implicit instructions** (FULL-AUDIT 0.3).

```toml
# FIXED (0.x): compile the IDL instructions out and publish the IDL off-chain / via Program Metadata
[features]
default = ["no-idl"]
no-idl = []
idl-build = ["anchor-lang/idl-build"]
```

**Overall verdict:**
- ✅: no legacy IDL surface, or the surface exists with the IDL claimed by governance and no cosplay or shadowing exposure
- ⚠️: IDL authority on a single key
- ❌: unclaimed IDL account, cosplay against a missing type check, or tag shadowing

*Sources: PlamenTSV/plamen §1 (MIT, Copyright (c) 2025-2026 Plamen Contributors); 0xMacro/awesome-solana-security → Accretion [paraphrased, cited: https://github.com/0xMacro/awesome-solana-security]; solana-foundation/solana-dev-skill #4i (MIT, Copyright (c) 2026); all version, dispatch-order, squatting and tag-byte facts checked against solana-foundation/otter-sec anchor source (Apache-2.0).*
