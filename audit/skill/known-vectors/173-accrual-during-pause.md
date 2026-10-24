---
id: 173
title: "Accrual Keeps Running While Paused"
severity: 6
category: crypto
---

### 173 — Accrual Keeps Running While Paused

**Severity: 6** | **Real: lending/perps audit pattern**

Pause blocks repay and top-up, but `accrue_interest` (or funding, rewards, decay) keeps using `now − last_accrual`. On unpause, borrowers are instantly liquidatable for debt they could not service; time-based grace periods expire during the pause; rewards that accrued while paused may have no path to be distributed or swept.

> Cross-ref: ECON-096, lending.md §10, KV-170.

#### Verification Procedure
```
rg -n 'fn accrue|last_accrual|last_update_ts|last_funding' programs/
rg -n 'paused|is_paused' programs/
```
- ✅ PASS (any documented design): accrual skips paused time (`if pool.paused { pool.last_accrual = now; }` and unpause resets `last_accrual` — lenders forgo the paused period); or interest accrued while paused is capped/deferred; or repay/top-up remain allowed while paused. Liquidation/auction timers exclude paused time. Paused-period rewards are distributable or sweepable.
- ❌ FAIL: users are penalised for a period in which the protocol blocked their remedy

**Overall verdict:**
- ✅: pause is economically neutral (or the trade-off is documented)
- ❌: unpause creates instant liquidations or stranded rewards

*Sources: sanbir/solana-auditor-skills `solana-auditor/references/attack-vectors/attack-vectors-4.md` V100 (MIT, Copyright (c) 2024 AI Skills Contributors), presented as options; pashov/skills `solidity-auditor/references/hacking-agents/invariant-agent.md` pause-path pattern, paused-reward part (same copyright).*
