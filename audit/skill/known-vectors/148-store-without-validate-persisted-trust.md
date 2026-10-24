---
id: 148
title: "Store-Without-Validate / Persisted Point-in-Time Trust"
severity: 7
category: crypto
---

### 148 — Store-Without-Validate / Persisted Point-in-Time Trust

**Severity: 7 (Critical when combined with a permissionless init that captures fees — KV-141. For the point-in-time owner variant, rate by who can register and what later trusts the key: 7–8 when registration is permissionless (or takes a caller-chosen address) and the recreated account later feeds a price, balance or authority decision by key alone; 3–5 when only an admin can register (the admin would have to register a zero-lamport, zero-data account; apply the privilege lever) or when the later use is informational)** | **Real: qedgen benchmark corpus (`add_signer` storing off-curve or default keys; `init_config_field_unanchored`)**

The bug is in the write. The exploit is in a later handler that trusts the field.
1. **Store-without-validate.** `add_signer`, `add_member`, `set_authority`, `register` and `whitelist` store a caller-supplied pubkey with no predicate. The key may be `Pubkey::default()`, not a signer, not the canonical PDA, a duplicate in a list, or off-curve where a wallet signature will be required later (the slot is bricked and the threshold becomes unreachable). A permissionless `initialize` that stores a caller-supplied `fee_destination`/`creator_ata` lets a front-runner capture every later fee.
2. **Point-in-time trust.** `acct.owner == X` proves ownership *now*. Suppose an address is persisted as "a trusted X-owned account" after only an owner check. An attacker who holds a keypair can, inside one transaction, `Assign` that zero-lamport, zero-data address to X (System `Assign` needs only the keypair's signature) and call the victim while the owner reads X. Because the account holds no lamports it is purged when the transaction ends. Later the attacker recreates the same address and assigns it to a program they control. This matters only where later uses compare the key alone.

> Cross-ref: AC-062, AV-107, KV-141, FULL-AUDIT Step 1.5 P3.

#### Verification Procedure

**Step 1: Every persisted pubkey write**
```
rg -n '\.(authority|admin|owner|fee_(destination|receiver|recipient)|treasury|creator[a-z_]*|oracle|signers?\[.*\]|members?\[.*\])\s*=\s*' programs/
rg -n '\.push\(\s*[a-z_]+\s*\)' programs/ | rg -i 'signer|member|admin|whitelist'
rg -n '=\s*ctx\.accounts\.[a-z_]+\.key\(\);' programs/
```

**Step 2: Name the predicate that constrained each value before the write**
- ✅ PASS: the key is non-default; a signer or the canonical PDA where the role requires it; deduplicated; and on-curve when a wallet signature will be required. For the curve check use the curve25519 validation syscall (`sol_curve_validate_point`, wrapped as `solana_curve25519::edwards::validate_edwards`). `Pubkey::is_on_curve()` hits `unimplemented!()` on-chain (checked in solana-program 1.18 and solana-pubkey 2.1; confirm in the pinned crate for later versions). PDA members that sign through `invoke_signed` are legitimately off-curve. Init-config fields are bound to a `Signer` (`token::authority = creator` with `creator: Signer`) or derived canonically.
- ❌ FAIL: no predicate
<!-- verified: agave v1.18.26 sdk/program/src/pubkey.rs and v2.1.21 sdk/pubkey/src/lib.rs (bytes_are_curve_point: #[cfg(target_os = "solana")] unimplemented!()); agave v2.1.21 curves/curve25519/src/edwards.rs (on-chain validate_edwards -> sol_curve_validate_point) -->

**Step 3: Re-validation at use**
- ✅ PASS: persisted addresses are re-checked for owner + discriminator at every use (an Anchor `Account<'info, T>` / `InterfaceAccount` does this on load; `UncheckedAccount` / `AccountInfo` with `address = stored_key` does not)
- ❌ FAIL: later handlers compare the key only

```rust
// VULNERABLE
multisig.signers.push(new_signer);             // new_signer: Pubkey argument

// FIXED
require!(new_signer != Pubkey::default(), ErrorCode::InvalidKey);
require!(!multisig.signers.contains(&new_signer), ErrorCode::DuplicateSigner);
// if the member must sign as a wallet, validate the point on-chain:
// require!(solana_curve25519::edwards::validate_edwards(
//     &solana_curve25519::edwards::PodEdwardsPoint(new_signer.to_bytes())), ErrorCode::OffCurveSigner);
multisig.signers.push(new_signer);
```

**Overall verdict:**
- ✅: every persisted key has a predicate and is re-validated at use
- ❌: any later privileged decision trusts an unvalidated or point-in-time-checked key

*Sources: qedgen/solana-skills store-without-validate pattern (MIT, Copyright (c) 2025 QEDGen) with the is_on_curve correction; solana-foundation/solana-dev-skill #7 (MIT, Copyright (c) 2026) with an added precondition.*
