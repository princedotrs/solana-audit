# Program upgrades & account migrations

Upgrades keep every existing account. The new code must read every old account correctly or migrate it safely; otherwise funds strand or state is misread. Vector: KV-160. Checklist: AV-098, OPS-088, OPS-098..OPS-103 (checklists/07 §7.14).

## 1. Classify every layout diff (deployed tag ↔ audited source)
Appended field (lower risk) vs inserted, reordered, removed or retyped field, changed enum variant order (Borsh tags by declaration index), changed `Vec`/`String` sizing (`INIT_SPACE`), changed PDA seeds, changed owner, renamed struct (new default discriminator — every old account becomes undeserializable unless migrated), renamed handler (new instruction discriminator — CPI callers and SDKs break), custom discriminator changes.
```bash
git log -p -- 'programs/*/src/state/*.rs' | rg '^[+-]\s+pub [a-z_]+:'      # no --follow: it needs exactly one path
rg -n 'migrat|legacy|v1|v2|version|realloc|resize\(|Migration<|#\[account\(.*discriminator' programs/*/src
rg -n 'seeds\s*=' programs/*/src
```
Diff the on-chain IDL (or Program Metadata) with the audited source: account and instruction names, field order.

## 2. Outcomes for old accounts
Exactly sized + inserted field → fails to deserialize (brick). Slack bytes → silent misread. Appended field with slack → decodes as zero (check every zero default: authority, cap, fee, pause, oracle). No slack + no migration → DoS on old accounts.

## 3. Safe patterns
- Version marker **in data, since v1** (a discriminator proves type, not layout version). Retrofitting `version: u8` at offset 0 of an existing struct is unsafe.
- Or rename the type (new discriminator) and migrate: Anchor ≥ 1.0.0 `Migration<'info, From, To>` (checks owner == `From::owner()`, the account must deserialize as `From` — one already in `To` format is rejected — and `exit` errors unless `migrate()` ran; typically paired with `realloc`) <!-- verified: anchor v1.2.1 lang/src/accounts/migration.rs doc comment and `fn exit` -->, or a manual migration over `UncheckedAccount` with owner + V1 discriminator + V1 length checks, rent top-up, `resize`, write V2 (KV-160 sketch). `Account<'info, NewLayout>` cannot load an old, shorter account — deserialisation runs before any `realloc` constraint.
- Idempotent and resumable migrations; a migration pause; copy-to-new-PDA for destructive changes; growth ≤ 10,240 bytes per account per instruction.
- Mixed-version window: exits, claims and emergency actions work for both versions (two code paths or a dispatching loader).
- Code rollback is not data rollback: archive the previous binary and state what it can no longer read.

## 4. Cross-era path matrix
For each account type × era (old, new, **in flight at upgrade** — pending unstake requests, open orders), list the close/withdraw paths that still work. Any state with no working exit = stranded assets (≥ Medium).

## 5. PDA seed changes
If V2 derives `[b"vault_v2", user]`, can V2 still sign for and close V1 `[b"vault", user]` PDAs and their token accounts?

## 6. User-blocks-admin
Users can pre-create protocol-PDA-owned token accounts (non-zero balance blocks `close_account`), create many small accounts so an admin migration loop exceeds compute, or hold in-flight operations a migration requires to be empty.

## 7. Deprecated instructions & immutability endgame
Deprecated instructions still callable with weaker checks than their replacements are sibling-asymmetry findings (KV-170). Before revoking the upgrade authority: config frozen sane, recovery/sweep path for every account type (OPS-097).

## 8. Evidence
Prove migrations against realistic state: mainnet-dumped accounts in LiteSVM/Mollusk, byte-diff of carried fields, negative test on already-migrated accounts.

*Sources: PlamenTSV/plamen `agents/skills/solana/migration-analysis/SKILL.md` (MIT, Copyright (c) 2025-2026 Plamen Contributors); beriktassuly/solana-audit-skill `skill/references/taxonomy/upgrade-admin-governance.md` (MIT, Copyright (c) 2026 Berektassuly); rewritten and extended, as in KV-160.*
