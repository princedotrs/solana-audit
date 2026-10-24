---
id: 160
title: "Upgrade Layout Drift / Unmigrated Accounts"
severity: 8
category: crypto
---

### 160 — Upgrade Layout Drift / Unmigrated Accounts

**Severity: 8 (Critical when a privileged or value field misreads; at least Medium when funds are stranded with no recovery)** | **Real: "ghost state" after program upgrades (a 2026 Cantina write-up cited by beriktassuly/solana-audit-skill; not independently checked); Neodyme "Common Pitfalls" format-version note**

Upgrades keep every existing account; the new code must read old accounts correctly or migrate them. Anchor's default account discriminator is `sha256("account:<StructName>")[..8]`, so it depends only on the struct **name** (a custom `#[account(discriminator = …)]`, Anchor ≥ 0.31.0, is equally fixed). Changing fields keeps the discriminator, and `Account<'info, T>` accepts old accounts under the new layout:
- **Field inserted, reordered or retyped** — exactly sized old accounts usually **fail to deserialize** (every handler bricks for them); accounts with slack bytes (over-allocated `space`, padded `INIT_SPACE`, realloc headroom) are **silently misread** (old `balance` bytes become part of `authority`). Anchor's Borsh load does not require the buffer to be fully consumed, so trailing bytes never cause a rejection.
- **Field appended with slack** — the new field decodes from leftover bytes (usually zero): `paused = false`, `fee_bps = 0`, `delegate = Pubkey::default()`, `max_ltv = 0` may be unsafe.
- **Field appended, no slack** — permanent DoS on old accounts without a migration path; funds may be stranded.
- **Enum variants reordered** (Borsh tags by declaration index), `Vec`/`String` sizes changed, PDA seed schema changed (`[b"vault_v2", user]` can no longer sign for `[b"vault", user]` accounts and their token accounts), handler renamed (new instruction discriminator: breaks CPI callers and SDKs), struct renamed without migration (every existing account fails the discriminator check).
- **Zero-copy** — a new struct larger than the allocation makes `AccountLoader::load`/`load_mut` panic on the out-of-range slice (DoS), not misread; fields inserted or reordered within the allocated size are misread silently, as with Borsh. The `bytemuck::Pod` derive rejects implicit padding.
<!-- verified: anchor v0.29.0 / v1.0.0 lang/src/accounts/account_loader.rs (load slices data[8..size_of::<T>()+8] after the discriminator check); v0.31.0 lang/attribute/account/src/lib.rs (discriminator override) -->

> Cross-ref: AV-098, OPS-098..OPS-103 (checklists/07 §7.14), references/methodologies/upgrades-and-migrations.md.

#### Verification Procedure

**Step 1: Diff state against the deployed version**
```
git diff <deployed_tag> -- 'programs/**/state*.rs' 'programs/**/state/**' | rg '^[+-]\s+pub\s+\w+:\s'
rg -n -A15 '#\[account(\(zero_copy[^)]*\))?\]' programs/
rg -n 'migrat|legacy|version|realloc|resize\(|Migration<|#\[account\(.*discriminator' programs/
```
Also compare the on-chain IDL with the source: `anchor idl fetch <PROGRAM_ID>` reads the legacy IDL account with an Anchor 0.x CLI and the Program Metadata account with an Anchor ≥ 1.0 CLI. The ≥ 1.0 CLI does this by running `npx --yes --package=@solana-program/program-metadata@<pinned version> -- program-metadata …`, so it downloads and executes an npm package: run it only where executing third-party code is acceptable, and never from inside a cloned repository.

**Step 2: For each changed struct whose name/tag is unchanged**
- ✅ PASS: renamed type (new discriminator) migrated with Anchor ≥ 1.0.0 `Migration<'info, From, To>` (owner check, then deserializes only as `From`; an already-migrated account is rejected only because it fails `From`'s discriminator check, so `From` and `To` must have different discriminators; `exit` returns `AccountNotMigrated` if the handler did not migrate) or a manual migration over `UncheckedAccount`; or a `version` field that existed **since the first deployment** and is checked on every load; or append-only with no slack plus a migration instruction; every new field's zero value proven safe
- ❌ FAIL: inserted/reordered/retyped fields without migration; appended fields read from slack with unsafe zero defaults; a migration whose `From` and `To` share a discriminator (an already-migrated account is accepted and migrated again from misread bytes); a "fix" that adds `version: u8` at offset 0 of an existing struct (old accounts supply their first byte as `version`; ~1 in 256 pass)
<!-- verified: anchor v1.0.0 lang/src/accounts/migration.rs (struct Migration<'info, From, To>; AccountAlreadyMigrated; AccountNotMigrated on exit) -->

**Step 3: Cross-era path matrix** — for each account type × era (old, new, **in-flight at upgrade** such as pending unstake requests), list the close/withdraw paths that still work; any state with no working exit is stranded assets (≥ Medium).

**Step 4: User-blocks-admin** — check whether users can stop a migration from completing: by creating token accounts whose authority is a protocol PDA and leaving dust in them (a migration that must close every PDA-owned token account then fails on `close_account`), by creating many small accounts so a single migration loop exceeds the compute budget, or by holding in-flight operations that the migration requires to be empty.

```rust
// FIXED (manual migration sketch, Anchor ≥ 0.32: PositionV1 { owner, amount } → PositionV2 { owner, amount, fee_tier })
// PositionV1 is the deployed type: it must keep its original struct name (or pin the original discriminator
// with #[account(discriminator = …)]) so that try_deserialize checks the discriminator old accounts carry.
// Both types derive InitSpace.
#[derive(Accounts)]
pub struct MigratePosition<'info> {
    /// CHECK: owner and V1 discriminator verified in the handler
    #[account(mut)] pub position: UncheckedAccount<'info>,
    #[account(mut)] pub owner: Signer<'info>,
    pub system_program: Program<'info, System>,
}
pub fn migrate_position(ctx: Context<MigratePosition>) -> Result<()> {
    let ai = ctx.accounts.position.to_account_info();
    require_keys_eq!(*ai.owner, crate::ID, ErrorCode::WrongOwner);
    let old: PositionV1 = {
        let data = ai.try_borrow_data()?;
        // try_deserialize checks the V1 discriminator, so an account already rewritten as PositionV2
        // (different name => different discriminator) is rejected here. Do not use the data length as the
        // "already migrated" marker: V1 accounts allocated with slack would be misjudged.
        PositionV1::try_deserialize(&mut &data[..])?
    };                                                           // borrow dropped before resize
    require_keys_eq!(old.owner, ctx.accounts.owner.key(), ErrorCode::Unauthorized);
    let new_len = 8 + PositionV2::INIT_SPACE;                    // default 8-byte discriminator; growth per instruction ≤ 10,240 bytes
    let top_up = Rent::get()?.minimum_balance(new_len).saturating_sub(ai.lamports());
    if top_up > 0 {
        // Anchor ≥ 1.0: CpiContext::new takes the program id (Pubkey);
        // on 0.x pass ctx.accounts.system_program.to_account_info() instead.
        anchor_lang::system_program::transfer(
            CpiContext::new(
                anchor_lang::system_program::ID,
                anchor_lang::system_program::Transfer { from: ctx.accounts.owner.to_account_info(), to: ai.clone() },
            ),
            top_up,
        )?;
    }
    ai.resize(new_len)?;                                         // Anchor ≤ 0.31: ai.realloc(new_len, true)?
                                                                 // (also truncates V1 slack, so a later appended field reads zeros, not stale bytes)
    let new = PositionV2 { owner: old.owner, amount: old.amount, fee_tier: DEFAULT_FEE_TIER };
    let mut data = ai.try_borrow_mut_data()?;
    new.try_serialize(&mut &mut data[..])?;                      // writes PositionV2's discriminator
    Ok(())
}
// Exits during the mixed window: two code paths, or a loader that dispatches on the discriminator (not on length).
```
<!-- verified: anchor v1.0.0 lang/src/context.rs (CpiContext::new(program_id: Pubkey, ..)); v1.0.0 lang/src/system_program.rs (ID, transfer, Transfer { from, to }); v0.31.1 vs v0.32.1 lang/src/common.rs (realloc(0, false) -> resize(0)) -->

**Overall verdict:**
- ✅: every live account is readable by the deployed binary or rejected cleanly and migratable; no stranded era
- ⚠️: migration exists but is not resumable (a re-run on a migrated account fails without a clean per-account error) or not pausable (OPS-099/OPS-101)
- ❌ (not ⚠️): a re-run re-migrates an already-migrated account from misread bytes (shared `From`/`To` discriminator, or a length-only marker)
- ❌: misread privileged/value fields, unsafe zero defaults, or stranded funds

*Sources: PlamenTSV/plamen `migration-analysis` (MIT, Copyright (c) 2025-2026 Plamen Contributors); beriktassuly/solana-audit-skill U3 (MIT, Copyright (c) 2026 Berektassuly); Neodyme "Common Pitfalls" U5 [paraphrased, cited]; every FIXED snippet from those sources was replaced (an `Account<NewLayout>` cannot load old, shorter accounts; a retrofitted version byte is unsafe). Migration snippet checked against anchor v0.32.1/v1.0.0.*
