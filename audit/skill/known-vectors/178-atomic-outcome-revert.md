---
id: 178
title: "Atomic Outcome Revert (Same-Transaction Settlement)"
severity: 8
category: crypto
---

### 178 — Atomic Outcome Revert (Same-Transaction Settlement)

**Severity: 8 (HIGH/CRITICAL when the treasury pays out above the house edge; MEDIUM when only fairness is affected)** | **Real: COPE Roulette (Arrowana): the author reports 207 wins out of 207 attempts**

KV-120 is about *predictable* entropy. This works even with unpredictable entropy: if the outcome is observable and final inside the caller's atomic transaction, the caller makes the transaction conditional on it — a later instruction that only succeeds if the bet won, or a wrapper program that CPIs in and checks the result. Losses revert; only fees are paid. Simulate-then-send works whenever the entropy is the same in simulation and execution, and **Jito bundles are all-or-nothing**, so a later transaction in the same bundle can assert the result and drop the bundle on a loss even if the program rejects CPI callers and requires being the last instruction. Affects lotteries, loot boxes, mystery mints, gacha/trait rolls, random-winner auctions, "spin" or "claim a random reward" instructions.

> Cross-ref: ECON-107, KV-120.

#### Verification Procedure
```
rg -n -i 'roll|spin|lottery|raffle|jackpot|loot|mystery|gacha|random|winner|reward_tier|rarity' programs/
rg -n -i 'request_randomness|commit|reveal|settle|consume_randomness|fulfill|pending_(bet|roll|request)' programs/
rg -n -i 'get_stack_height|TRANSACTION_LEVEL_STACK_HEIGHT|load_current_index_checked|get_instruction_relative' programs/
```
- ✅ PASS: two-phase — tx A escrows a non-refundable stake and records a request; tx B (a later slot) settles via a **permissionless or oracle-driven** path with VRF output bound to the request; an unsettled request **forfeits on timeout** (otherwise the player declines to settle a known loss once the VRF output is public)
- ❌ FAIL: one instruction derives the outcome and pays it; CPI-caller rejection and last-instruction checks alone (bundles and simulation still work)

```rust
// FIXED (shape)
pub fn request_spin(ctx: Context<RequestSpin>, bet: u64) -> Result<()> {
    escrow_stake(&ctx, bet)?;                         // locked now, not refundable on demand
    let req = &mut ctx.accounts.request;
    req.player = ctx.accounts.player.key(); req.bet = bet;
    req.request_slot = Clock::get()?.slot; req.state = RequestState::Pending;
    request_vrf(&ctx)                                 // fulfilled in a LATER tx
}
pub fn settle_spin(ctx: Context<SettleSpin>) -> Result<()> {  // permissionless / oracle callback
    let req = &mut ctx.accounts.request;
    require!(req.state == RequestState::Pending, ErrorCode::AlreadySettled);
    require!(Clock::get()?.slot > req.request_slot, ErrorCode::SameSlot);
    let r = verified_vrf_output_bound_to(req)?;       // KV-120
    req.state = RequestState::Settled;
    payout_or_forfeit(&ctx, r)
}
// plus: expire_request() — after a timeout, anyone can settle as a forfeit
```

**Overall verdict:** ✅ the outcome cannot be vetoed by the caller · ❌ revert-if-lose is possible

*Sources: sannykim/solsec → COPE Roulette [paraphrased, cited: https://github.com/Arrowana/cope-roulette-pro], with added Jito-bundle and forfeit/permissionless requirements.*
