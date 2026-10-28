---
id: 146
title: "Parent-Substitution Authority Bypass (Root-Anchor Chain)"
severity: 9
category: crypto
---

### 146 — Parent-Substitution Authority Bypass (Root-Anchor Chain)

**Severity: 9 when the child holds or prices user funds** | **Real: Solend "malicious lending market" (19 Aug 2021): reserve parameters on the real USDC/SOL/ETH/BTC reserves were changed through an attacker-owned market (liquidation threshold 80→1, liquidation bonus 5→90, min borrow rate 0→250); Solend's own bot liquidated, no user funds lost, about $2M at risk. Cashio ($52M, 2022): an unanchored collateral/mint validation chain.**

The signer check is present and correct, but anchored to an account the attacker chose: `signer → P.authority` is meaningful only if the mutated child C belongs to P (`C.parent == P.key()`), and P to its own parent, up to a trusted root. Chains of comparisons only among passed-in accounts (`A.key() == B.field`, `B.key() == C.field`) prove internal consistency, not authority; at least one link must compare against a trusted program-owned account field or a hard-coded constant. Common in multi-tenant programs: markets/reserves, pools/positions, DAOs/proposals, managers/strategies, games/rounds. (For Solend, the exact missing comparison is reconstructed, not quoted from the incident report.)

> Cross-ref: AC-057, AV-020/AC-003 (this vector extends them with the chain walk), FULL-AUDIT Step 1.5 P2.

#### Verification Procedure

**Step 1: Handlers that authorise through another account's field**
```
rg -n 'has_one\s*=\s*(owner|authority|admin)' programs/
rg -n '(market|pool|vault|config|dao|realm|group)\.(owner|authority|admin)\s*==' programs/
rg -n 'has_one\s*=\s*(lending_market|market|pool|vault|config|group|realm)' programs/
```

**Step 2: Walk the chain for every mutated child**
- ✅ PASS: each link is bound — `has_one = parent`, or seeds containing `parent.key()` — up to a PDA-derived/program-owned root or a constant
- ❌ FAIL: the child is mutated under the authority of a parent it is not bound to; the chain closes only among passed-in accounts

```rust
// VULNERABLE: signer owns *a* market, not necessarily this reserve's market
#[derive(Accounts)]
pub struct UpdateReserveConfig<'info> {
    #[account(mut)] pub reserve: Account<'info, Reserve>,
    #[account(has_one = owner)] pub lending_market: Account<'info, LendingMarket>, // attacker's market
    pub owner: Signer<'info>,
}
// FIXED: bind child to parent, then parent to signer
#[derive(Accounts)]
pub struct UpdateReserveConfig<'info> {
    #[account(mut, has_one = lending_market @ ErrorCode::WrongMarket)] pub reserve: Account<'info, Reserve>,
    #[account(has_one = owner @ ErrorCode::NotOwner)] pub lending_market: Account<'info, LendingMarket>,
    pub owner: Signer<'info>,
}
```

**Overall verdict:**
- ✅: every privileged mutation is anchored to a trusted root
- ❌: any privileged instruction accepts an attacker-created parent

*Sources: sannykim/solsec → Solend incident report and reconstruction [paraphrased, cited: https://docs.google.com/document/d/1-WoQwT1QrPEX-r4N-fDamRQ50LM8DsdsOyq1iTabS3Q , https://hackmd.io/54qwl3oeT4CYuREUgxQ2zQ]; qedgen/solana-skills `skills/qedgen-auditor/references/category-catalog.md` `field_chain_missing_root_anchor` (MIT, Copyright (c) 2025 QEDGen).*
