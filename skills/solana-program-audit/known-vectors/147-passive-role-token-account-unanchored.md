---
id: 147
title: "Passive-Role Token Account Not Anchored to the Role"
severity: 9
category: crypto
---

### 147 — Passive-Role Token Account Not Anchored to the Role

**Severity: 9 when the payout can be triggered permissionlessly (crank, keeper, "anyone can disburse") and the role is passive: any caller redirects the role's funds. 7 when only the grant/vesting authority can trigger it (revoke, clawback): the trust model protects the role from that authority, but Rule 1's privilege lever applies; state the lever ("impact 9, needs the grant authority → 7"). 2 (hardening) when the role itself signs and picks the destination: the owner choosing where its own tokens go is not a program bug, and a malicious UI gains nothing it could not get with a follow-up transfer in the same transaction** | **Real: audit-finding class seen in rewards/vesting revoke and clawback handlers (qedgen benchmark corpus)**

A missing *runtime* owner check asks whether the account is owned by the token program. This vector asks a different question: is the SPL account's recorded **wallet** (the `owner` field, bytes 32..64 of the 165-byte base layout) the role the parameter names, such as recipient, claimant or beneficiary? Any token account of the right mint passes `owner == token program` and `token::mint = mint`. KV-016 binds mints and *source* authorities. Payout **destinations** named after a passive role are the gap. An authority-signed revoke, clawback or disbursement can then send the role's tokens to any same-mint account the authority controls.

> Cross-ref: AV-106, KV-016, FULL-AUDIT Step 1.5 P2.

#### Verification Procedure

**Step 1: Role-named token accounts**
```
rg -n -B8 'pub (recipient|claimant|beneficiary|destination|to)[a-z_]*_(token_account|ata|tokens?)\b' programs/
rg -n '(recipient|claimant|beneficiary|destination)[a-z_]*' programs/ | rg -i 'unpack|from_account_info|next_account_info'   # native
```
Anchor constraints sit in the `#[account(..)]` block *above* the field, hence `-B8`. Do not filter the output on `token::authority`: read each attribute block and confirm that the authority it names is the role and that the role is bound to stored state.

**Step 2: Anchoring**
- ✅ PASS: `token::authority = <role>` / `associated_token::authority = <role>` / `constraint = acct.owner == role.key()` (native: unpack the token account and compare `owner`), with `<role>` itself bound to stored state (`address = grant.recipient` or `has_one = recipient`)
- ❌ FAIL: only `token::mint` (and the token-program owner) is checked
- ❌ FAIL: `token::authority = recipient` is present but `recipient` is itself unconstrained (any `SystemAccount`/`UncheckedAccount` the authority picks). That anchoring is circular and is not a pass.

```rust
// VULNERABLE: authority-signed revoke pays "recipient", but any same-mint account passes
#[account(mut, token::mint = mint)]
pub recipient_token_account: Account<'info, TokenAccount>,
pub recipient: SystemAccount<'info>,
pub authority: Signer<'info>,

// FIXED
#[account(has_one = authority)]
pub grant: Account<'info, Grant>,
#[account(mut, token::mint = mint, token::authority = recipient)]
pub recipient_token_account: Account<'info, TokenAccount>,
#[account(address = grant.recipient)]
pub recipient: SystemAccount<'info>,
pub authority: Signer<'info>,
```

**Overall verdict:**
- ✅: every role-named destination is anchored to the role
- ❌: a privileged path can pay a role's value to any same-mint account

*Sources: qedgen/solana-skills `skills/qedgen-auditor/references/category-catalog.md` `token_account_role_anchoring` (MIT, Copyright (c) 2025 QEDGen). The corpus's advisory identifier and PR number could not be checked against a primary source, so they are omitted.*
