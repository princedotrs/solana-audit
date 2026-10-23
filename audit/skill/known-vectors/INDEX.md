# Known Attack Vectors — Index

One line per vector. Click to see the full multi-step verification procedure.

Scope: Solana on-chain programs (Anchor / native `solana-program` / Pinocchio) plus the operational vectors that directly threaten a deployed program (key custody, upgrade authority, vendored program provenance). Off-chain web / backend / frontend / AI-agent / CI vectors are out of scope for this skill. Vector numbers are stable identifiers, so gaps in the numbering are intentional — never renumber or reuse a gap.

## Load-when (markers) column — advisory gating

Every row carries a **Load when (markers)** cell: the grep/prescan markers that make the vector *worth loading* for a given codebase. This is a token-efficiency layer, **not** a scope gate — the completeness guarantee (OUTPUT-RULES Rule 0: every in-scope vector gets a verdict) is unchanged.

- **Feature markers** (e.g. `pyth`·`switchboard`, `token_2022`·`transfer_hook`, `invoke`·`CpiContext`) mean the vector is feature-specific. When *every* marker is provably absent — an empty prescan array (see `references/orchestration/pre-scan.md`) or zero grep hits across the in-scope tree — the vector is skip-deferred and renders `[N/A — feature absent: <marker>]`. This is an **evidence-backed verdict**, and it **reopens on demand**: the instant a manual read surfaces the feature, load the vector and evaluate it.
- **`always (<phase>)`** means the vector is universally applicable within that phase/domain and is **NEVER** skipped (private-key leak, secrets, supply-chain, access control, and other baseline vectors). A marker cell must never make a vector unreachable — when in doubt a vector is tagged to its phase (always-load for that scope), not a narrow feature.

## How to Contribute

1. Create a new file: `NNN-short-name.md` using the next number above 140 (numbers up to 140 are reserved, including the gaps; never reuse one)
2. Follow the existing format: YAML frontmatter + `### N — Title` + severity + real-world example + verification procedure with numbered steps
3. Add your entry to this index under the matching section (include the **Load when (markers)** cell — default to `always (<phase>)` unless the vector is provably feature-specific)
4. Update the totals at the bottom of this file, then submit a PR

### Crypto / On-Chain (1-30)

| # | Vector | Severity | Load when (markers) |
|---|--------|----------|---------------------|
| 1 | [Private Key Leak](001-private-key-leak.md) | 10 | always (crypto) |
| 2 | [Flash Loan Price Manipulation](002-flash-loan-price-manipulation.md) | 10 | `flash` · `flashloan` · oracle-priced deposit/withdraw · `pyth` · `switchboard` |
| 3 | [Reentrancy (CPI)](003-reentrancy-cpi.md) | 10 | `invoke` · `invoke_signed` · `CpiContext` |
| 4 | [Missing Access Control](004-missing-access-control.md) | 10 | always (crypto) |
| 5 | [Oracle Manipulation](005-oracle-manipulation.md) | 9 | `pyth` · `switchboard` · `oracle` · `PriceUpdate` · `get_price` |
| 6 | [First Depositor / Share Inflation](006-first-depositor-share-inflation.md) | 9 | `shares` · `mint_to` · `deposit` · `vault` · `total_supply` |
| 7 | [MEV Sandwich Attack](007-mev-sandwich-attack.md) | 7 | `swap` · `slippage` · `min_amount_out` · `route` |
| 8 | [Rug Pull / Admin Backdoor](008-rug-pull-admin-backdoor.md) | 10 | always (crypto) |
| 9 | [Unchecked CPI Target](009-unchecked-cpi-target.md) | 9 | `invoke` · `invoke_signed` · `CpiContext` · `program_id` |
| 10 | [PDA Confusion / Type Cosplay](010-pda-confusion-type-cosplay.md) | 8 | `seeds` · `find_program_address` · `AccountInfo` · `try_deserialize` |
| 11 | [Integer Overflow / Underflow](011-integer-overflow-underflow.md) | 9 | `arithmetic_sites` · `+` `-` `*` `/` · `checked_` |
| 12 | [Arithmetic Rounding Exploit](012-arithmetic-rounding-exploit.md) | 7 | `arithmetic_sites` · `/` · `div` · `mul_div` · `shares` |
| 13 | [Missing Signer Check](013-missing-signer-check.md) | 10 | always (crypto) |
| 14 | [Account Reinitialization](014-account-reinitialization.md) | 8 | `init` · `init_if_needed` · `is_initialized` |
| 15 | [Unchecked Account Owner](015-unchecked-account-owner.md) | 9 | always (crypto) |
| 16 | [Token Account Mismatch](016-token-account-mismatch.md) | 8 | `TokenAccount` · `token::mint` · `token::authority` · `spl_token` |
| 17 | [Vault Donation Attack](017-vault-donation-attack.md) | 7 | `vault` · `get_token_account_balance` · `.amount` · `shares` |
| 18 | [Fee-on-Transfer Token Exploit](018-fee-on-transfer-token-exploit.md) | 7 | `token_2022` · `TransferFee` · `transfer_hook` · `get_extension` |
| 19 | [Freeze Authority Griefing](019-freeze-authority-griefing.md) | 6 | `freeze_authority` · `FreezeAccount` · `mint` |
| 20 | [Program Upgrade Hijack](020-program-upgrade-hijack.md) | 10 | always (crypto) |
| 21 | [Governance Attack (Vote Buying)](021-governance-attack-vote-buying.md) | 8 | `realm` · `proposal` · `spl-governance` · `vote_record` · `voter_weight` |
| 22 | [Bridge Exploit (Fake Proof)](022-bridge-exploit-fake-proof.md) | 10 | `guardian` · `vaa` · `emitter` · `verify_signatures` · `attestation` |
| 23 | [Token-2022 Transfer Hook Attack](023-token-2022-transfer-hook-attack.md) | 7 | `token_2022` · `transfer_hook` · `TransferHook` · `get_extension` |
| 24 | [Stale/Missing Account Close](024-stale-missing-account-close.md) | 5 | `close` · `lamports` · `realloc` |
| 25 | [Compute Budget Exhaustion DoS](025-compute-budget-exhaustion-dos.md) | 6 | loops · `remaining_accounts` · `Vec` · `panic_sites` |
| 26 | [PDA Seed Collision](026-pda-seed-collision.md) | 8 | `seeds` · `find_program_address` · `create_program_address` |
| 27 | [Missing Discriminator Check](027-missing-discriminator-check.md) | 8 | `try_deserialize` · `AccountInfo` · `remaining_accounts` · discriminator |
| 28 | [Front-Running Transaction](028-front-running-transaction.md) | 6 | `swap` · `claim` · `commit` · `slippage` · price-sensitive ix |
| 29 | [Withdraw-Before-Update Race](029-withdraw-before-update-race.md) | 8 | `withdraw` · `invoke` · state-mutation-after-CPI · `reload` |
| 30 | [Infinite Mint / Uncapped Supply](030-infinite-mint-uncapped-supply.md) | 10 | `mint_to` · `supply` · `mint_authority` · `max_supply` |

### Program Deployment Ops (91)

| # | Vector | Severity | Load when (markers) |
|---|--------|----------|---------------------|
| 91 | [Upgrade Authority Not Secured](091-upgrade-authority-not-secured.md) | 10 | always (devops) |

### On-Chain — Modern Surface (101-109)

> Added in v4.4. Focus: sysvars, precompiles, lookup tables, PDA bump canonicalization, Token-2022 extensions, account revival, ATA assumptions, token decimals, and native/Pinocchio (p-token) programs.

| # | Vector | Severity | Load when (markers) |
|---|--------|----------|---------------------|
| 101 | [Sysvar Spoofing & Instructions-Sysvar Introspection](101-sysvar-spoofing-instructions-introspection.md) | 8 | `sysvar` · `instructions_sysvar` · `load_instruction_at` · `get_instruction_relative` |
| 102 | [Precompile Signature Verification Bypass (Ed25519/Secp256k1)](102-precompile-signature-verification-bypass.md) | 9 | `ed25519` · `secp256k1` · `precompile` · `instructions_sysvar` · signature-verify ix |
| 103 | [Address Lookup Table (ALT) Manipulation](103-address-lookup-table-manipulation.md) | 7 | `address_lookup_table` · `AddressLookupTable` · `lookup_table` · versioned tx |
| 104 | [Non-Canonical Bump / PDA Derivation Confusion](104-non-canonical-bump-pda-derivation-confusion.md) | 7 | `seeds` · `bump` · `create_program_address` · `find_program_address` |
| 105 | [Token-2022 Extension Abuse (permanent delegate / frozen-default / fee / confidential / mint-close)](105-token-2022-extension-abuse.md) | 8 | `token_2022` · `get_extension` · `PermanentDelegate` · `ConfidentialTransfer` · `TransferFee` |
| 106 | [Account Revival / Zombie After Close](106-account-revival-zombie-after-close.md) | 8 | `close` · `lamports` · `realloc` · `is_initialized` · reopen |
| 107 | [Fake / Non-Canonical Associated Token Account (ATA)](107-fake-non-canonical-associated-token-account.md) | 8 | `associated_token` · `get_associated_token_address` · `ATA` · `token::authority` |
| 108 | [Token Decimals & Cross-Mint Amount Confusion](108-token-decimals-cross-mint-amount-confusion.md) | 7 | `decimals` · `amount` · multi-mint · `transfer_checked` · `mint.decimals` |
| 109 | [Pinocchio / p-token — Missing Manual Validation in Zero-Copy Native Programs](109-pinocchio-ptoken-missing-manual-validation.md) | 8 | `pinocchio` · `p-token` · `no_std` · `AccountInfo` · manual-validation (native, no Anchor) |

### On-Chain DoS — SBF Stack Limits (111)

| # | Vector | Severity | Load when (markers) |
|---|--------|----------|---------------------|
| 111 | [BPF Stack Frame Overflow DoS](111-bpf-stack-frame-overflow-dos.md) | 6 | large stack arrays · `[u8; N]` · deep recursion · `panic_sites` (on-chain) |

### On-Chain — Governance & Randomness (118-120)

| # | Vector | Severity | Load when (markers) |
|---|--------|----------|---------------------|
| 118 | [Stake Account Authority Hijack](118-stake-account-authority-hijack.md) | 8 | `stake` · `StakeProgram` · `authorized` · `staker` · `withdrawer` |
| 119 | [Durable-Nonce Pre-Signed Governance Abuse](119-durable-nonce-pre-signed-governance-abuse.md) | 9 | `nonce` · `durable_nonce` · `advance_nonce` · `realm` · `proposal` · governance |
| 120 | [On-Chain Randomness Predictability & VRF Misbinding](120-onchain-randomness-predictability.md) | 7 | `random` · `vrf` · `switchboard` · `Clock` · `slot_hashes` · `blockhash` |

### Modern On-Chain, Custody & Off-Chain Consumers (121-123, 125-126)

| # | Vector | Severity | Load when (markers) |
|---|--------|----------|---------------------|
| 121 | [cNFT / Account-Compression Merkle Proof Abuse](121-cnft-account-compression-merkle-proof.md) | 7 | `spl-account-compression` · `bubblegum` · `merkle` · `cNFT` · `proof` |
| 122 | [Inner-Instruction / Event-Log Spoofing](122-inner-instruction-event-log-spoofing.md) | 7 | `emit_cpi` · `invoke` · inner-instruction · event parsing off-chain · `sol_log` |
| 123 | [Lamport-Donation Account Bricking (King-of-the-SOL)](123-lamport-donation-account-bricking.md) | 6 | `lamports` · rent-exempt check · `try_borrow_lamports` · balance-equality assumption |
| 125 | [Bonding-Curve Launchpad Graduation & Migration Abuse](125-bonding-curve-launchpad-graduation-abuse.md) | 7 | `bonding_curve` · `graduate` · `virtual_reserves` · `migrate` · `curve` |
| 126 | [Session Token as Custody](126-session-token-as-custody.md) | 7 | `session` · `session_token` · delegated-signing · `spending_limit` |

### DoS, Float Math, Keeper Lifecycle & CLMM Math (127-131)

| # | Vector | Severity | Load when (markers) |
|---|--------|----------|---------------------|
| 127 | [ATA / Account Pre-Creation DoS (Init Front-Running)](127-ata-account-precreation-dos.md) | 6 | `init` · `create_associated_token_account` · `init_if_needed` · pre-creation |
| 128 | [On-Chain Floating-Point Financial Math](128-onchain-floating-point-math.md) | 5 | `f32` · `f64` · `as f64` · `.sqrt()` · `.powi(` · float in value math |
| 129 | [Keeper Request→Execute Front-Running & Reordering](129-keeper-request-execute-frontrunning.md) | 7 | `keeper` · `request` · `execute` · two-step · `crank` · settlement |
| 130 | [CLMM/DLMM Tick-Boundary & Liquidity Math](130-clmm-tick-boundary-liquidity-math.md) | 7 | `tick` · `sqrt_price` · `liquidity_net` · `bin_array` · `fee_growth` |
| 131 | [Write-Lock Account Contention DoS (Hot Shared Writable)](131-write-lock-account-contention-dos.md) | 6 | shared writable account · global `mut` state · single hot PDA · `#[account(mut)]` global |

### Permissioned Tokens (134)

| # | Vector | Severity | Load when (markers) |
|---|--------|----------|---------------------|
| 134 | [Token ACL (SRFC-37) Gate-Program Bypass & Permissionless-Freeze Griefing](134-token-acl-gate-program-bypass.md) | 7 | `token_acl` · `TACLkU6` · `MINT_CFG` · `gating_program` · `thaw_permissionless` · `can_thaw_permissionless` · `DefaultAccountState` + delegated freeze authority |

### Transaction Format & Runtime-Upgrade Readiness (135)

| # | Vector | Severity | Load when (markers) |
|---|--------|----------|---------------------|
| 135 | [Transaction v1 Fee-Sponsor Cap Bypass & Disabled ComputeBudget Gates](135-transaction-v1-fee-sponsor-cap-bypass.md) | 8 | `feePayer` / `fee_payer` as a service · `sponsor` · `paymaster` · `gasless` · `relayer` · `partialSign` · `ComputeBudgetProgram` scan · `load_instruction_at` + `compute_budget` |

### Vendored Programs & White-Label Fleets (137)

| # | Vector | Severity | Load when (markers) |
|---|--------|----------|---------------------|
| 137 | [White-Label / Vendored On-Chain Program Version Drift & Inherited Admin Surface](137-vendored-program-version-drift.md) | 8 | always (crypto) |

### Runtime Timing: 200 ms Slots & the Alpenglow Clock (138)

| # | Vector | Severity | Load when (markers) |
|---|--------|----------|---------------------|
| 138 | [Slot-Denominated Time After SIMD-0525 (Slot Used as a Clock)](138-slot-denominated-time-assumptions.md) | 7 | `clock.slot` · `Clock::get()?.slot` · `SLOTS_PER_YEAR` · `DEFAULT_TICKS_PER_SLOT` · `DEFAULT_MS_PER_SLOT` · `*_slot` duration / deadline fields · epoch-denominated lockups · `warp_to_slot` · `216_000` / `432_000` |

---

## Known Duplicates & Consolidation Map

The kept set contains one near-duplicate pair (same root cause catalogued under two categories). Both
files are retained so the "Crypto" and "Program Deployment Ops" reading paths stay complete, but an
auditor should **evaluate the pair once and cross-reference the verdict** — do not double-count it as
independent coverage. Severity is aligned to the higher of the pair.

| Canonical | Duplicate of | Topic | Aligned Severity |
|-----------|--------------|-------|------------------|
| 020 | 091 | Program upgrade authority compromise | 10 |

Every other overlap (e.g. 023 ↔ 105 Token-2022 hooks/extensions, 014 ↔ 106 reinitialization vs revival,
010 / 026 / 104 PDA derivation) is a distinct concept: each gets its own verdict, with the shared root
cause cited in the cross-ref notes inside the vector files.

**Distinct concepts:** 57 (58 files − 1 duplicate pair).

---

**Total vector files:** 58 (on-chain and program-ops subset of the upstream catalog; numbering preserved)
**Distinct concepts:** 57 (after consolidating 1 duplicate pair)
**Categories (frontmatter `category`):** 4 (crypto, devops, dos, backend — the two `backend` vectors, 126 and 135, are kept for their on-chain custody / fee-payer surface)
**Severity range:** 5-10
