---
id: 157
title: "Anchor Optional-Account Gate Bypass"
severity: 8
category: crypto
---

### 157 — Anchor Optional-Account Gate Bypass

**Severity: 8** | **Real: Anchor optional-accounts convention (the executing program's own id encodes `None`)**

With `Option<Account<'info, T>>` (and `Option<Signer>`, `Option<UncheckedAccount>`, …), the **client** decides whether the account is present. It passes the program's own id as a placeholder, which decodes as `None`. Omitting trailing optional accounts also decodes as `None`, but only when anchor-lang's `allow-missing-optionals` feature is on. That feature is off by default, and then a missing account fails with `AccountNotEnoughKeys`. Constraints on the field run only when it is `Some`. A mandatory check written as `if let Some(x) = … { check }` therefore becomes voluntary; typical victims are allowlist entries, fee configs, oracles, referrer caps and KYC records. (The program's own id always decodes as `None`, so it can never be passed as a real `Some`.) <!-- verified: anchor v1.2.1 and v0.29.0 lang/src/accounts/option.rs: `if accounts.is_empty()` returns `Ok(None)` only under `cfg!(feature = "allow-missing-optionals")`, else `AccountNotEnoughKeys`; `if accounts[0].key == program_id { Ok(None) }` -->

> Cross-ref: AN-004.

#### Verification Procedure
```
rg -n 'Option<(Box<)?(Account|InterfaceAccount|Signer|UncheckedAccount|AccountLoader|Program)' programs/
rg -n 'if let Some\(.*ctx\.accounts\.|\.as_ref\(\)\.map|\.is_none\(\)' programs/
```
- ✅ PASS: wherever policy requires the account (the pool is gated, the fee applies), the handler requires `Some` (`ok_or(ErrorCode::Required)?`) before applying the check
- ❌ FAIL: passing `None` skips a gate, fee or cap

```rust
// VULNERABLE
#[account(seeds = [b"allow", user.key().as_ref()], bump)]
pub allow_entry: Option<Account<'info, AllowEntry>>,
// if let Some(e) = &ctx.accounts.allow_entry { require!(e.active, ErrorCode::NotAllowed); }   // None skips the gate

// FIXED
if pool.gated {
    let e = ctx.accounts.allow_entry.as_ref().ok_or(ErrorCode::AllowEntryRequired)?;
    require!(e.active, ErrorCode::NotAllowed);
}
```

**Overall verdict:**
- ✅: no required check depends on the caller choosing `Some`
- ❌: a required check does

*Sources: solana-foundation/solana-dev-skill #3 (MIT, Copyright (c) 2026).*
