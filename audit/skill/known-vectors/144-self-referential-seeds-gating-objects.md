---
id: 144
title: "Self-Referential Seeds & Permissionless Gating Objects"
severity: 8
category: crypto
---

### 144 — Self-Referential Seeds & Permissionless Gating Objects

**Severity: 8** | **Real: Ackee Solana Auditors Bootcamp `pda-privileges`, CTF level-3 (faction gate) and level-5 (guardian set) drains**

Two false assurances that baseline `has_one` items (AC-003/007, AV-020/075) do not name:
1. **Self-referential seeds.** `seeds = [b"vault", vault.owner.as_ref()], bump = vault.bump` derives from fields stored in the account being validated. It passes for **every** account the program ever created with that layout: it proves the PDA is *genuine*, not that it is *the caller's*. If the handler then signs as that PDA or pays the signer, any user can act on any other user's PDA.
2. **Permissionless gating objects.** A gate that checks "member of *a* faction / approved by *a* guardian set / listed in *a* market" passes when the attacker can create their own faction, mint, guardian set or market. The gate must pin *the* intended instance.

> Cross-ref: PDA-023, AC-003, KV-143, KV-145.

#### Verification Procedure

**Step 1: Seeds that reference the constrained account's own fields**
```
rg -n -A4 '#\[account\(' programs/ | rg 'seeds\s*=\s*\[[^]]*\b([a-z_]+)\.[a-z_]+(\.key\(\))?\.as_ref\(\)'
rg -n -A3 'signer_seeds|with_signer|new_with_signer' programs/ | rg '\.(creator|owner|authority|recipient|user)\.as_ref\(\)'
```
Confirm the referenced object is the field being constrained (self-reference).

**Step 2: Binding**
- ✅ PASS: the seed is derived from the `Signer` (`seeds = [b"vault", caller.key().as_ref()]`), or the stored field is bound (`has_one = owner` with `owner: Signer`, or `constraint = vault.owner == caller.key()`)
- ❌ FAIL: self-referential seed + value move or privileged state change + no signer binding

**Step 3: Gating objects**
- For each gate, ask: can the attacker create their own instance of the gating object? If yes, ✅ PASS only if the gate pins the instance through stored or global state (`address = config.faction`, seeds including a trusted key).

```rust
// VULNERABLE: any genuine vault passes; the signer is never tied to vault.owner
#[account(seeds = [b"vault", vault.owner.as_ref()], bump = vault.bump)]
pub vault: Account<'info, Vault>,
pub caller: Signer<'info>,

// FIXED (either)
#[account(seeds = [b"vault", caller.key().as_ref()], bump = vault.bump)]
pub vault: Account<'info, Vault>,
// or
#[account(seeds = [b"vault", vault.owner.as_ref()], bump = vault.bump, has_one = owner)]
pub vault: Account<'info, Vault>,
pub owner: Signer<'info>,
```

**Overall verdict:**
- ✅: every self-referential PDA and gate is bound to the caller / intended instance
- ❌: a genuine-but-foreign PDA or a self-made gating object passes

*Sources: Ackee-Blockchain Solana-Auditors-Bootcamp item 2 [paraphrased, no licence, cited], narrowed to the two new angles.*
