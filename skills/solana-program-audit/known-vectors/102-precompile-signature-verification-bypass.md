---
id: 102
title: "Precompile Signature Verification Bypass (Ed25519 / Secp256k1)"
severity: 9
category: crypto
---

### 102 — Precompile Signature Verification Bypass (Ed25519 / Secp256k1)

**Severity: 9** | **Real: Recurring Solana audit finding — instruction-introspection signature checks that fail to bind the message/signer**

Solana verifies Ed25519/Secp256k1 signatures via native precompiled programs. An on-chain program "consumes" the result by introspecting the Instructions sysvar to confirm a sibling `Ed25519Program`/`Secp256k1Program` instruction ran. This is a notoriously fragile pattern: it is bypassable if the program does not (a) verify the precompile **program ID**, (b) verify the instruction is at the **expected index / actually present**, (c) parse the precompile's data layout to bind the **exact pubkey, message, and signature** to the current action. Attackers craft a transaction with a valid-but-unrelated precompile instruction (signed over a different message) to satisfy a loose check and authorize an action they never signed.

#### Verification Procedure

**Step 1: Detect introspection-based signature verification**
```
grep -rn --include="*.rs" -iE "load_instruction_at|get_instruction_relative|instructions_sysvar|ed25519_program|secp256k1_program|load_current_index" programs/
```
- If none: likely N/A (program relies on native `Signer` only)
- If present: this pattern requires deep manual review

**Step 2: Verify the precompile program ID is checked**
- ✅ PASS: the precompile program id matches the scheme: `ed25519_program`, `secp256k1_program`, or the secp256r1 precompile `Secp256r1SigVerify1111111111111111111111111` (`solana_sdk_ids::secp256r1_program`; SIMD-0075 — the `enable_secp256r1_precompile` gate was removed in agave v4.1.0 (always enabled from then on); on a cluster running an older or forked validator confirm it is active) (33-byte compressed keys; ed25519-style offsets with u16 instruction-index fields; at most 8 signatures per instruction) <!-- verified: agave v4.4.0-beta.1 precompiles/src/lib.rs (registers solana_sdk_ids::secp256r1_program, feature None = always enabled), precompiles/src/secp256r1.rs; agave v4.0.0 still gated on enable_secp256r1_precompile; gate removed by #11116, first tagged in v4.1.0 -->
- ❌ FAIL: Program ID not checked — any instruction at that index satisfies the check

**Step 3: Verify message + pubkey binding**
- The precompile instruction data encodes offsets to the signed message, the pubkey, and the signature. The program MUST parse these and assert they equal the expected signer and the **exact message bytes** for THIS action (including a nonce/expiry to prevent replay).
- ✅ PASS: Pubkey, full message, and signature offsets are parsed and bound to the current instruction's parameters
- ❌ FAIL: Only "an ed25519 instruction exists" is checked — message/signer not bound (full bypass)

**Step 4: Verify index/position handling**
- ✅ PASS: Instruction index is computed safely (relative or validated absolute), no fixed-index assumption an attacker can shift
- ❌ FAIL: Hardcoded index that an attacker can offset by inserting instructions

**Step 5: Replay protection**
- ✅ PASS: Signed message includes a nonce/expiry/slot tied to state; replays rejected
- ❌ FAIL: Same signed payload can be replayed across transactions/accounts

**Step 6: Count and threshold**
- ❌ FAIL: the consumer only checks that a precompile instruction exists at index k — an ed25519 instruction whose data is exactly two bytes with `num_signatures == 0` (e.g. `[0, 0]`; the second byte is padding, no offset records) succeeds and verifies nothing; the same holds for secp256k1 with data exactly `[0]`. (secp256r1 rejects `num_signatures == 0`.)
- ❌ FAIL: "every signature is from an allowed signer" loop — vacuously true for an empty list
- ✅ PASS: `num_signatures ≥ 1`; every offset/index binds to the precompile instruction itself; message compared; **distinct** allowed signers counted against the threshold; signature bytes are not used as replay keys — secp256k1 accepts both `s` and `n − s` (malleable), while secp256r1 rejects high-S — so key replay protection on a nonce/counter inside the signed message
<!-- verified: agave v4.4.0-beta.1 precompiles/src/ed25519.rs (num_signatures == 0 allowed when data.len() == 2), precompiles/src/secp256k1.rs (count == 0 allowed when data.len() == 1; test signs with flipped S), precompiles/src/secp256r1.rs (num_signatures == 0 or > 8 rejected; s <= half_order) -->

*Sources: original analysis; precompile behaviour checked against agave v4.4.0-beta.1 `precompiles/src/{ed25519,secp256k1,secp256r1}.rs` (Apache-2.0, behaviour described, no code copied).*

**Overall verdict:**
- ✅: Program ID, signer, full message, offsets, and replay protection all verified
- ⚠️: Program ID + signer checked but message binding or replay protection weak
- ❌: Loose check (existence only) — signature can be satisfied by an unrelated precompile instruction
- N/A: No instruction-introspection signature verification used
