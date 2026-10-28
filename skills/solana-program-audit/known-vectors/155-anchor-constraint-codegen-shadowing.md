---
id: 155
title: "Anchor Constraint Codegen Identifier Shadowing"
severity: 8
category: crypto
---

### 155 — Anchor Constraint Codegen Identifier Shadowing

**Severity: 8** | **Real: anchor PR #5105 "Improve macro hygiene to address potential issues with key validation" and #5209 "use hygienic bindings for init_if_needed mint checks". Every tagged release through 1.2.1 is affected. The 2.0.0-rc.1/rc.2 tags still carry the old codegen in their v1 crate, which is renamed `anchor-lang-v1` with `publish = false`, so only a git dependency on those tags reaches it; `anchor-lang` 2.0.0-rc.* is the separate v2 crate and is not covered by this vector. The fix is in 1.2.2, prepared on the `release-bump/1.2.2` branch with a CHANGELOG dated 2026-10-22; no `v1.2.2` tag existed on 2026-10-24, so confirm on crates.io. No GHSA was among the three published advisories reviewed.** <!-- verified: anchor origin/release-bump/1.2.2 CHANGELOG [1.2.2] lists #5105; release-bump/1.2.2 contains 71c84c81 (#5105) and a8a2cd6c (#5209); v2.0.0-rc.2 lang/Cargo.toml `name = "anchor-lang-v1"`, `publish = false`, lang-v2/Cargo.toml `name = "anchor-lang"`; v2.0.0-rc.2 lang/syn/src/codegen/accounts/constraints.rs still `let my_key = #my_key;` and `.map(|fa| ...)` -->

The `#[derive(Accounts)]` codegen declared its temporaries with call-site hygiene, so they shared a namespace with user identifiers. #5105 moved more than forty generated locals to private identifiers. The verified collisions below make a check compare a value with itself. Treat the list as a minimum, not the complete set:
- `has_one = X` binds `my_key` (the stored field) and then evaluates `target_key = X.key()`. If the target is named `my_key` (account and data field), `my_key.key()` resolves to the stored pubkey (`Pubkey: Key`), so the check always passes.
- `owner = EXPR` binds `my_owner` before it evaluates `EXPR`. An `EXPR` that mentions `my_owner` resolves to the owner just read.
- `address = EXPR` binds `actual` before it evaluates `EXPR`. An `EXPR` that mentions `actual` resolves to the account's own key.
- `associated_token::authority = my_owner` sees the binding `my_owner = <token account>.owner` and passes trivially. The ATA address is then derived from that same owner, so any wallet's ATA for the mint is accepted.
- `mint::freeze_authority = fa` with `init_if_needed`. When an existing mint is reused, the generated freeze-authority check runs inside a closure `|fa| …`, so `fa.key()` resolves to the mint's actual freeze authority. Any mint that has *some* freeze authority passes, including one whose freeze authority the attacker holds. A fresh `init` is unaffected. This is fixed by #5209 (1.2.2) and is present from at least 0.26.

(`target_key`, `owner_address` and `expected` cannot collide, because each is bound from the user expression itself. Other bindings, for example `pa`, `owner_program` and `cpi_program_id` in the `init`/`init_if_needed` token and mint paths, mostly fail closed or break the fresh `init` path, which testing would catch. Underscore-prefixed internals are low risk.) <!-- verified: anchor v1.2.1 lang/syn/src/codegen/accounts/constraints.rs generate_constraint_has_one / _owner / _address / _associated_token, init_if_needed mint path `pa.freeze_authority.as_ref().map(|fa| #freeze_authority.as_ref()...)` with `#freeze_authority` = `Option::<&Pubkey>::Some(&#fa.key())`; same closure in v0.26.0..v1.2.1; v1.2.1 lang/src/lib.rs `impl Key for Pubkey`; commit bce16223 (#5105) replaces my_key/target_key/my_owner/owner_address/actual/expected/wallet_address/pa/owner_program/... with private_ident; a8a2cd6c (#5209) replaces `fa`/`expected_fa` -->

```rust
#[account] pub struct Role { pub my_key: Pubkey }
#[derive(Accounts)]
pub struct CloseRole<'info> {
    #[account(mut, has_one = my_key, close = my_key)]   // no-op has_one on ≤ 1.2.1
    pub role: Account<'info, Role>,
    #[account(mut)] pub my_key: Signer<'info>,          // any signer closes any Role and takes the rent
}
```

> Cross-ref: AN-007, KV-158.

#### Verification Procedure

**Step 1: Version and names**
```
rg -n -A1 '^name = "anchor-lang"' Cargo.lock
rg -n '\bpub +(my_key|my_owner|actual|fa) *:' programs/
rg -n 'has_one\s*=\s*my_key\b|owner\s*=\s*[^,)]*\bmy_owner\b|address\s*=\s*[^,)]*\bactual\b|associated_token::authority\s*=\s*my_owner\b|mint::freeze_authority\s*=\s*fa\b' programs/
```
Confirm by expanding the macro and reading the generated comparison (`cargo expand` runs the target's proc-macros, so use the execution mode from Rule 11a/11f). On ≤ 1.2.1, also check any constraint target or expression whose name matches a non-underscore local in the expanded block, beyond the names grepped above.

- ✅ PASS: anchor-lang includes #5105 and #5209 (1.2.2 or later), or no constraint target or expression uses a name the generated block binds
- ❌ FAIL: ≤ 1.2.1 (or a git dependency on the 2.0.0-rc tags' `anchor-lang-v1`) with a colliding name in a security constraint. Fix: rename the field (e.g. `authority`) and add a negative test (a different signer must fail with `ConstraintHasOne`; a reused mint with a foreign freeze authority must fail with `ConstraintMintFreezeAuthority`)

**Overall verdict:**
- ✅: no self-comparing constraint
- ❌: a constraint compares a value with itself

*Sources: otter-sec/anchor CHANGELOG and PR #5105 diff of `lang/syn/src/codegen/accounts/constraints.rs` (Apache-2.0, Copyright 2020 Anchor Maintainers); example written for this skill from the pre-fix codegen; collision list checked against v1.2.1 source (associated-token case and the #5209 `fa` case added).*
