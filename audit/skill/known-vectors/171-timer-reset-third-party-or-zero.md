---
id: 171
title: "Timer / Cooldown Reset by Third-Party or Zero-Amount Writes"
severity: 6
category: crypto
---

### 171 — Timer / Cooldown Reset by Third-Party or Zero-Amount Writes

**Severity: 6 (5–6 when it blocks other users; 7 when reward timing can be gamed for profit)** | **Real: contest findings on lock/cooldown griefing (pattern)**

An instruction that writes `cooldown_start`, `lock_start`, `unlock_at`, `last_deposit_ts` or `last_claim_ts` unconditionally can be called (a) by a third party on the victim's position — a dust top-up every period means the victim never unlocks — or (b) by the user with `amount = 0` to reset a reward or JIT window in their favour. ECON-002/AC-044 cover cooldowns, not this griefing angle.

> Cross-ref: ECON-095.

#### Verification Procedure
```
rg -n '(cooldown|unlock|lock_until|lock_start|last_deposit|last_claim)[a-z_]*\s*=\s*.*(unix_timestamp|slot|clock|Clock::get)' programs/
```
For each hit: must the position owner sign? Is `amount > 0` (or a minimum) enforced?
- ✅ PASS: only the owner can move the timer; or per-deposit lots; or third-party top-ups never move the timer and have a minimum size; zero-amount calls never refresh windows
- ❌ FAIL: a non-owner or zero-amount call resets someone's timer
- Note: a weighted unlock such as `max(old_unlock, now + lock·amt/new_amount)` is a design trade-off, not a fix — newly added funds unlock early (a top-up equal to the old balance near expiry is locked for only about half of `lock`).

```rust
// VULNERABLE
#[derive(Accounts)]
pub struct TopUp<'info> {
    #[account(mut)] pub payer: Signer<'info>,
    /// CHECK: any beneficiary
    pub owner: UncheckedAccount<'info>,
    #[account(mut, seeds = [b"stake", owner.key().as_ref()], bump)]
    pub stake: Account<'info, StakePos>,
}
// top_up(): s.amount += amt; s.lock_start = Clock::get()?.unix_timestamp;   // dust each period → never unlocks

// FIXED (one option)
require!(amt >= MIN_TOP_UP, StakeError::TooSmall);
if ctx.accounts.payer.key() == ctx.accounts.stake.owner {
    ctx.accounts.stake.lock_start = Clock::get()?.unix_timestamp;          // only the owner resets
}
```

**Overall verdict:**
- ✅: nobody else can move a user's timer; zero-amount calls are inert
- ❌: they can

*Sources: sanbir/solana-auditor-skills B3 (MIT, Copyright (c) 2024 AI Skills Contributors); pashov/skills timer-reset pattern (same copyright) with an added weighted-unlock caveat.*
