---
id: 170
title: "Sibling-Path Guard Asymmetry (Cap, Fee, Pause, Accounting Bypass)"
severity: 7
category: crypto
---

### 170 — Sibling-Path Guard Asymmetry (Cap, Fee, Pause, Accounting Bypass)

**Severity: 7 (5–8 by what the guard protects; oracle-depth caps and insurance sizing rank higher)** | **Real: recurring audit and contest pattern — the "forgotten sibling instruction" (an alternate path that re-implements a write without the guard)**

The same economic action has different protections on different paths: `deposit` checks the cap but `deposit_and_stake`, `batch_deposit`, `migrate_position`, `compound` or a referral variant re-implements the increment without it; `withdraw` applies the fee, reward settlement and denominator update but `emergency_withdraw`/`force_close`/`liquidate_self` does not. Results: cap bypass, fee bypass, ghost denominators (`total_staked` never decremented on the emergency path, diluting every later reward forever), rewards accrued while paused that no path can sweep. ECON-064 (reward formula on every payout path), ECON-065 and SM-069 cover parts; this vector is the parity sweep.

> Cross-ref: ECON-093/094, AC-058, SM-075..078, FULL-AUDIT 0.3 sibling-drift pass.

#### Verification Procedure

**Step 1: List writers and exits**
```
rg -n '\.([a-z_]+)\s*([-+*/]?=)[^=]' programs/ | rg 'total_|minted|borrowed|supply|staked|shares'
rg -n '<=\s*[a-z_.]*(cap|limit|max_)' programs/
rg -n 'pub fn (withdraw|redeem|exit|emergency|force|migrate|close|unstake|liquidate)[a-z0-9_]*' programs/
```

**Step 2: Parity table** — rows: capped/accounting fields and exits; columns: handlers; cells: cap check, fee, haircut, cooldown, pause check, settle, denominator update.
- ✅ PASS: every cell matches across siblings, or a guard difference is documented and intended (an emergency path that deliberately forfeits rewards or skips a fee). Accounting and denominator writes get no such exemption: a documented path that skips them is still a FAIL. One helper (`add_assets()`, `compute_exit()`) used by all writers/exits
- ❌ FAIL: an unexplained missing guard or accounting write on any sibling

```rust
// VULNERABLE: emergency path skips the denominator update the normal path does
pub fn emergency_withdraw(ctx: Context<Unstake>) -> Result<()> {
    let amt = ctx.accounts.position.amount;
    ctx.accounts.position.amount = 0;          // pool.total_staked NOT decremented → ghost stake
    transfer_out(&ctx, amt)
}
// FIXED: forfeit rewards, but mirror every accounting write
pub fn emergency_withdraw(ctx: Context<Unstake>) -> Result<()> {
    let pool = &mut ctx.accounts.pool;
    update_pool(pool, Clock::get()?.unix_timestamp)?;
    let pos = &mut ctx.accounts.position;
    let amt = pos.amount;
    pool.total_staked = pool.total_staked.checked_sub(amt).ok_or(ErrorCode::Math)?;
    pos.amount = 0;
    pos.reward_debt = 0;
    transfer_out(&ctx, amt)
}
// FIXED (caps): one helper for every writer
impl Vault {
    pub fn add_assets(&mut self, amt: u64) -> Result<()> {
        let n = self.total_assets.checked_add(amt).ok_or(ErrorCode::Math)?;
        require!(n <= self.deposit_cap, ErrorCode::CapExceeded);
        self.total_assets = n; Ok(())
    }
}
```

**Overall verdict:**
- ✅: guard and accounting parity across all siblings
- ❌: any sibling bypasses a guard or skips an accounting write

*Sources: pashov/skills `solidity-auditor/references/hacking-agents/invariant-agent.md` and `solidity-auditor/references/hacking-agents/asymmetry-agent.md` (variant-path cap, pause path) (MIT, Copyright (c) 2024 AI Skills Contributors), narrowed; sanbir/solana-auditor-skills `solana-auditor/references/attack-vectors/attack-vectors-3.md` V64 (MIT, Copyright (c) 2024 AI Skills Contributors); PlamenTSV/plamen `prompts/solana/phase4b-scanner-templates.md`, `agents/skills/solana/flash-loan-interaction/SKILL.md` §5b and `prompts/solana/generic-security-rules.md` Rule R17 (MIT, Copyright (c) 2025-2026 Plamen Contributors); franpersanchez/solana-audits-skill `skill/SKILL.md` instruction matrix (MIT, Copyright (c) 2026 Fran Pérez).*
