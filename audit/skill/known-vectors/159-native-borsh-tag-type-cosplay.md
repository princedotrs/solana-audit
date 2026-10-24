---
id: 159
title: "Native Borsh Enum / Hand-Rolled Tag Type Cosplay"
severity: 8
category: crypto
---

### 159 — Native Borsh Enum / Hand-Rolled Tag Type Cosplay

**Severity: 8 (same band as KV-027) when the confused type carries an authority or balance field** | **Real: Sealevel Attacks class 3 (`3-type-cosplay`); Trail of Bits (crytic) `type_cosplay` lint test layouts; Neodyme "Common Pitfalls" account confusion**

KV-027 is Anchor-centric. Native and Pinocchio programs tell account types apart with Borsh enums or hand-rolled tags, and several common layouts make two types byte-compatible. An owner check does not help, because both types are owned by the same program.
1. **Several small wrapper enums.** `enum PositionSlot { P(Position) }` and `enum NoteSlot { N(Note) }` both encode tag `0`, so payloads with the same layout cosplay as each other.
2. **Umbrella enum + bare struct.** Take `enum Record { Profile(Profile), Empty }` with `Profile { key: Pubkey }`, and a bare `struct Vault { kind: Kind, admin: Pubkey }` whose `Kind::Vault` is variant 0. `Record::Profile` encodes as `00 ‖ 32 bytes`, which also parses as `Vault { kind: Kind::Vault, admin }`.
3. **Tag misplaced or too small.** The tag must be the first field; a preceding `Vec`, `String` or `Option` lets an attacker shift a chosen byte under it. The tag must also have at least as many values as there are distinct account types.
4. **`#[account]` types read with plain Borsh** (`try_from_slice` on the full data, `deserialize(&mut &data[8..])`, `try_deserialize_unchecked`) skip the 8-byte check.
5. **Written-but-never-read types.** "Only one umbrella enum is ever deserialized" is safe only if no other type the program *writes* has a matching layout. If users can create an account holding type B that reads as umbrella enum A, the argument fails, so check every type the program writes.
6. **Ad-hoc `u8`/`bool` tags** are valid only if every type has a unique, non-zero value at offset 0 that is checked before any field is trusted.
7. **Tag stability.** Borsh writes the **declaration index**. borsh-derive 0.9/0.10 ignore explicit `= N` discriminants. borsh 1.x refuses them unless `#[borsh(use_discriminant = true|false)]` is set, and `false` still uses declaration order. Reordering or inserting variants in an upgrade therefore silently changes which on-chain accounts read as which type. On borsh 1.x, require `use_discriminant = true`; on 0.10, use an explicit `u8` tag constant. Never reuse a retired tag.
8. **Prefix decoding.** `try_from_slice` rejects leftover bytes, so only an encoding that consumes exactly the bytes passed can cosplay. That does not mean only fixed-size twins: with `Vec`, `String` or `Option` fields, the donor can choose contents that match the victim's length. `deserialize` and `from_bytes(&data[..size_of::<T>()])` read a prefix, so any longer same-owner type with matching leading bytes passes.

> Cross-ref: KV-010 Step 6 (donor overlay), KV-027, native.md §7, AV-097.

#### Verification Procedure
```
rg -n '([A-Z][A-Za-z0-9_]*)::(try_from_slice|deserialize|unpack(_unchecked)?)\s*\(' programs/
rg -n 'try_deserialize_unchecked|\.data\.borrow\(\)\[8\.\.\]|&data\[8\.\.\]' programs/
rg -n -A3 '#\[derive\([^)]*Borsh(De)?[Ss]erialize[^)]*\)\]' programs/ | rg 'enum |struct '
rg -n -B1 -A6 'enum\s+\w+\s*\{' programs/ | rg '=\s*[0-9]+' ; rg -n 'use_discriminant' programs/
```
Build a table with one row per account type: first-byte tag, payload layout, and who can create it. Two rows with the same tag and a compatible payload are a cosplay candidate; escalate if both are owned by this program.
- ✅ PASS: a single umbrella enum is the only on-chain encoding (with an explicit `Uninit` variant and distinct, stable tags) and is matched explicitly on every read; or unique non-zero tags are checked in one shared loader
- ❌ FAIL: any compatible pair, tag instability across versions, or a prefix decoder over a shared leading layout

```rust
// VULNERABLE: two containers, both tag 0, identical payloads
#[derive(BorshSerialize, BorshDeserialize)] pub enum VaultState { V(Vault) }   // Vault { admin: Pubkey }
#[derive(BorshSerialize, BorshDeserialize)] pub enum NoteState  { N(Note) }    // Note  { writer: Pubkey }
let VaultState::V(v) = VaultState::try_from_slice(&acc.data.borrow())?;      // a Note passes as a Vault

// FIXED: one umbrella enum, explicit match
#[derive(BorshSerialize, BorshDeserialize)]
pub enum ProgramAccount { Uninit, Vault(Vault), Note(Note) }                  // tags 0, 1, 2 by declaration order; never reorder
match ProgramAccount::try_from_slice(&acc.data.borrow())? {
    ProgramAccount::Vault(v) => { /* ... */ }
    _ => return Err(ProgramError::InvalidAccountData),
}
```
<!-- verified: solana-program-error 3.0.1 src/lib.rs `impl From<borsh::io::Error> for ProgramError` (borsh feature), so `try_from_slice(..)?` compiles in a ProgramResult handler -->

**Overall verdict:**
- ✅: no two program-owned types can be read as each other
- ❌: two can, on a privileged path

*Sources: crytic/solana-lints `type_cosplay` [paraphrased, no licence, https://github.com/crytic/solana-lints] (example type names changed from the lint's test layouts); coral-xyz/sealevel-attacks `3-type-cosplay` [paraphrased, cited] with the Borsh-discriminant correction; Neodyme "Common Pitfalls" [paraphrased, cited].*
