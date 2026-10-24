---
id: 141
title: "Unbound Singleton Initialize Front-Run"
severity: 6
category: crypto
---

### 141 — Unbound Singleton Initialize Front-Run

**Severity: 6 (default Medium; 8–9 when the singleton controls funds, fees, oracle or pause and the deploy flow does not check `config.admin` after init, or the program is immutable)** | **Real: Lombard (M2), Onre (L2) audit findings; Ackee Solana Auditors Bootcamp CTF**

A global config/admin/treasury account with constant-only seeds (`seeds = [b"config"]`) is created by an `initialize` that records `admin = signer`. Anchor's `init` makes the instruction **one-time**; it does not control **who calls it first**. Deployment and the first `initialize` are separate transactions (a program deployed or upgraded in slot N is invocable only from slot N+1, and a deploy needs several buffer-write transactions), so a watcher can call `initialize` first and become the permanent admin, fee recipient or oracle authority. Recovery needs an emergency upgrade (new seed or reset path) or, if the program is immutable, a new program id. This is different from KV-127 (pre-creation DoS) and KV-014 (re-initialization): here the init *succeeds* and captures the role. A permissionless init that stores a caller-supplied `fee_destination`/`creator_ata` has the same shape (KV-148).

> Cross-ref: AC-056, KV-004 Step 6 (fixed), KV-091/KV-020 (whoever holds the upgrade key holds this gate), OPS-097.

#### Verification Procedure

**Step 1: Find singleton init accounts and caller-derived authorities**
```
rg -n 'seeds\s*=\s*\[\s*b"[A-Za-z_]+"\s*\]' programs/
rg -n '(authority|admin|owner|fee_[a-z_]+|treasury|oracle)\s*=\s*ctx\.accounts\.[a-z_]+\.key\(\)' programs/
```

**Step 2: Look for a deployer gate in the same Accounts struct**
```
rg -n 'programdata_address|upgrade_authority_address|ProgramData|bpf_loader_upgradeable|ADMIN_PUBKEY|address\s*=' programs/
```
- ✅ PASS: `program_data.upgrade_authority_address == Some(signer.key())` with `program_data` pinned to **this** program's ProgramData (`seeds = [crate::ID.as_ref()], bump, seeds::program = bpf_loader_upgradeable::id()`, or `program.programdata_address()? == Some(program_data.key())`); or a hard-coded admin pubkey checked with `address =`; or a creator-namespaced PDA (`[b"config", creator.key()]`) where every consumer resolves the config by the expected creator
- ❌ FAIL: constant-only seeds + caller stored as authority + no gate. "Deploy and init atomically" is not a mitigation

**Step 3: Loader version**
- Loader-v4 programs keep the authority in the program-account header and have no ProgramData; check the gate reads the right place. If the upgrade authority is already `None`, a ProgramData gate makes init impossible — initialise before finalising.

```rust
// VULNERABLE
#[derive(Accounts)]
pub struct InitConfig<'info> {
    #[account(mut)] pub payer: Signer<'info>,                       // whoever lands first
    #[account(init, payer = payer, space = 8 + Config::INIT_SPACE, seeds = [b"config"], bump)]
    pub config: Account<'info, Config>,
    pub system_program: Program<'info, System>,
}
// handler: ctx.accounts.config.admin = ctx.accounts.payer.key();

// FIXED: only the current upgrade authority of THIS program can initialise
use anchor_lang::solana_program::bpf_loader_upgradeable; // re-exported in anchor-lang 0.31 and 1.x
#[derive(Accounts)]
pub struct InitConfig<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(init, payer = payer, space = 8 + Config::INIT_SPACE, seeds = [b"config"], bump)]
    pub config: Account<'info, Config>,
    // without these seeds an attacker passes the ProgramData of a program they deployed
    #[account(
        seeds = [crate::ID.as_ref()], bump, seeds::program = bpf_loader_upgradeable::id(),
        constraint = program_data.upgrade_authority_address == Some(payer.key()) @ ErrorCode::NotUpgradeAuthority,
    )]
    pub program_data: Account<'info, ProgramData>,
    pub system_program: Program<'info, System>,
}
```
<!-- verified: anchor v0.31.1 and v1.0.0 lang/src/bpf_upgradeable_state.rs (ProgramData { upgrade_authority_address: Option<Pubkey> }, owner = bpf_loader_upgradeable::ID); agave v4.4.0-beta.1 program-runtime/src/program_cache_entry.rs DELAY_VISIBILITY_SLOT_OFFSET = 1 -->
Native/Pinocchio (loader-v3): derive ProgramData with `find_program_address(&[program_id.as_ref()], &bpf_loader_upgradeable::id())`, assert the key and the loader owner, decode `UpgradeableLoaderState::ProgramData { upgrade_authority_address, .. }`, require `== Some(*signer.key)` and `signer.is_signer`.

**PoC:** deploy, then call `initialize` from a fresh keypair; assert the attacker is stored as admin.

**Overall verdict:**
- ✅: every singleton init is deployer-gated, or no singleton init exists
- ⚠️: gate present but deploy runbook does not verify `config.admin` immediately after init
- ❌: a singleton init stores the first caller as a privileged role

*Sources: sanbir/solana-auditor-skills `solana-auditor/references/attack-vectors/attack-vectors-1.md` V24 (MIT, Copyright (c) 2024 AI Skills Contributors); Ackee-Blockchain Solana-Auditors-Bootcamp `Lesson-6/initialization-frontrunning` [paraphrased, no licence, https://github.com/Ackee-Blockchain/Solana-Auditors-Bootcamp/tree/master/Lesson-6/initialization-frontrunning]; Helius "A Hitchhiker's Guide to Solana Program Security", "Insecure Initialization" section [paraphrased, © Helius, https://www.helius.dev/blog/a-hitchhikers-guide-to-solana-program-security]; severity, recovery and atomicity statements corrected.*
