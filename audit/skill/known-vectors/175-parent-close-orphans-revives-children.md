---
id: 175
title: "Parent Close with Live Children: Orphaned or Revived Child PDAs"
severity: 7
category: crypto
---

### 175 — Parent Close with Live Children: Orphaned or Revived Child PDAs

**Severity: 7** | **Real: `solana-program/rewards` (now `solana-foundation/rewards`; OtterSec audit 2026, `audits/2026-ottersec-solana-foundation-rewards-audit.pdf`): a full-delete `CloseDirectDistribution` let the distribution PDA be re-created at the same seeds, reviving its `DirectRecipient` children. PR #32 (merged 2026-04-22) keeps the PDA instead: close shrinks it to a 3-byte `DirectDistributionClosed` record (1-byte marker discriminator, version, bump) and refunds the excess rent, `create_direct_distribution` then rejects the address with `DistributionPermanentlyClosed`, and `CloseDirectRecipient` still works after the parent is closed so child rent stays recoverable. Also contest findings on closable pools with open stakes**
<!-- verified: github.com/solana-program/rewards/pull/32 diff (fetched 2026-10-24): state/direct_distribution_closed.rs, create_distribution/processor.rs `is_closed` check, close_distribution/processor.rs `close_in_place`. The PR summary text mentions a separate tombstone account, but the merged code reuses the same PDA. The PR does not carry the advisory id "OS-SPR-ADV-01" that qedgen uses, so the id is dropped here. -->


Two failure modes of a parent (pool, market, distribution, campaign) and child accounts seeded with or bound to it:
1. **Orphaned children.** `close_pool` succeeds while `UserStake` PDAs (`seeds` with `pool.key()`, `has_one = pool`) still hold balances; every later `unstake` fails its constraints and funds are stranded. (PDA-013 covers a different orphaning: mutable seeds.)
2. **Revived children.** A full-delete close leaves the parent address re-creatable at the same deterministic seeds. Children never closed become live again under the new parent with their pre-close state (claimed amounts, allocations, votes).

> Cross-ref: SM-085, KV-106, KV-024.

#### Verification Procedure
```
rg -n 'seeds\s*=\s*\[[^]]*(parent|campaign|distribution|pool|market)\.key\(\)' programs/
rg -n 'close\s*=' programs/
rg -n 'open_positions|active_children|total_staked\s*==\s*0' programs/
```
- ✅ PASS: parent close requires `open_children == 0` (incremented on every child init, decremented on every child close) and zero balances; a closed parent is tombstoned (program-owned terminal state, so `init` cannot re-create it) or its seeds carry a monotonically increasing generation that every child's seeds include, with the counter stored in an account that is never closed (a global config or registry; a counter kept in the parent itself resets when the parent is deleted and re-created, so it is not a guard)
- ❌ FAIL: the parent closes with live children, or can be re-created so stale children revive

```rust
// FIXED (orphan guard)
#[account(mut, close = admin, has_one = admin,
          constraint = pool.open_positions == 0 && pool.total_staked == 0 @ ErrorCode::PoolNotEmpty)]
pub pool: Account<'info, Pool>,
// FIXED (revival guard): close-in-place tombstone (keep the account program-owned and rent-exempt)
distribution.state = DistState::Closed;    // terminal; every handler rejects Closed
// `init` at the same address then fails: the account is program-owned, so the System Program's
// allocate/assign step inside `init` rejects it. A closed-marker discriminator (rewards PR #32) works the same way.
```

**Overall verdict:** ✅ no orphan or revival path · ❌ either exists

*Sources: sanbir/solana-auditor-skills B5 (MIT, Copyright (c) 2024 AI Skills Contributors); qedgen/solana-skills parent-close revival pattern (MIT, Copyright (c) 2025 QEDGen); incident checked against the merged diff of https://github.com/solana-program/rewards/pull/32 (the advisory id is omitted because the PR does not state it).*
