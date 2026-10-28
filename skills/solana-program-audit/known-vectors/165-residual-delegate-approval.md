---
id: 165
title: "Residual SPL Delegate Approval on a Program-Owned Token Account"
severity: 7
category: crypto
---

### 165 — Residual SPL Delegate Approval on a Program-Owned Token Account

**Severity: 7 (8 if the delegate can be driven by anyone, e.g. through a permissionless instruction on the delegate program)** | **Real: approve/consume mismatch pattern (approves out + fee, consumes out − fee)**

A program approves a delegate on a PDA-owned token account so an external program (aggregator, lending CPI, legacy integration) can pull tokens. If the callee pulls less than approved, `delegated_amount` stays above zero after the instruction; the delegate — or anyone who can make the delegate act — spends the remainder later. (The token program clears the delegate automatically only when `delegated_amount` reaches exactly 0.) CPI-026/027 check approve/revoke correctness, not the post-CPI residual. Note SPL `approve` *replaces* the delegated amount (CPI-038).

> Cross-ref: CPI-037, CPI-041, CPI-026/027.

#### Verification Procedure
```
rg -n 'token(_interface)?::approve(_checked)?\(' programs/
rg -n 'token(_interface)?::revoke\(' programs/
rg -n 'delegated_amount|delegate\.is_none' programs/
```
- ✅ PASS: approve exactly what is consumed, revoke after the CPI, `reload()` and assert `delegate.is_none() && delegated_amount == 0`; or move the exact amount into a per-operation account. PDA-signer CPIs (instead of approvals) only to a pinned, trusted program — lending the PDA's signer privilege to a third party lets it act as the PDA, for the whole CPI, over every PDA-controlled account passed into that CPI
- ❌ FAIL: an approval can outlive the instruction

```rust
// VULNERABLE
token::approve(ctx.accounts.approve_ctx().with_signer(signer), amount + fee)?;
external::swap(ctx.accounts.swap_ctx(), amount - fee)?;            // 2·fee allowance remains

// FIXED
token::approve(ctx.accounts.approve_ctx().with_signer(signer), amount)?;
external::swap(ctx.accounts.swap_ctx(), amount)?;
token::revoke(ctx.accounts.revoke_ctx().with_signer(signer))?;
ctx.accounts.vault.reload()?;
require!(ctx.accounts.vault.delegate.is_none() && ctx.accounts.vault.delegated_amount == 0, ErrorCode::ResidualDelegate);
```

**Overall verdict:**
- ✅: no residual allowance survives
- ❌: one does

*Sources: pashov/skills `solidity-auditor/references/hacking-agents/execution-trace-agent.md` and `solidity-auditor/references/hacking-agents/numerical-gap-agent.md` (MIT, Copyright (c) 2024 AI Skills Contributors), Solana-ported; the "use invoke_signed instead" advice removed.*
