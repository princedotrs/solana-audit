# 02 — Access Control Checklist

> Domain: On-chain Solana Program  
> Severity if missed: CRITICAL to HIGH  
> References: Sealevel "Missing Signer Check", QEDGen AC properties, Anchor Signer type

Every item below is a single verification step. Mark each `[PASS]`, `[FAIL-{severity}]`, `[PARTIAL]`, or `[N/A]`.

---

## 2.1 — Signer Verification

- [ ] **AC-001**: Every instruction that moves tokens, SOL, or lamports has at least one `Signer<'info>` in its accounts struct
- [ ] **AC-002**: Every instruction that modifies on-chain state has at least one `Signer<'info>` — no permissionless state mutation
- [ ] **AC-003**: The signer's pubkey is linked to a state field via `has_one` (e.g., `has_one = manager` on Fund account)
- [ ] **AC-004**: No instruction relies solely on passing an account as `AccountInfo` and checking `is_signer` manually (prefer Anchor `Signer<'info>`)
- [ ] **AC-005**: If manual `is_signer` check is used, it's a hard `require!(account.is_signer, Error)`, not an if-else that silently skips
- [ ] **AC-006**: Admin/manager instructions: `manager: Signer<'info>` AND `fund: Account<'info, Fund>` with `has_one = manager`
- [ ] **AC-007**: Investor instructions: `investor: Signer<'info>` AND position/withdrawal with `has_one = investor`
- [ ] **AC-008**: Delegate instructions: delegate signer is validated against `token_account.delegate == Some(delegate.key())`
- [ ] **AC-009**: No instruction allows a third party to act on behalf of a signer without explicit delegation mechanism
- [ ] **AC-010**: There is no instruction callable by anyone (permissionless) that can move value — if one exists, document why

## 2.2 — Role-Based Access Control

- [ ] **AC-011**: List all roles in the program (manager, investor, delegate, admin, anyone) and map each instruction to exactly one role
- [ ] **AC-012**: No instruction has ambiguous role — "manager OR investor" must be explicitly documented and justified
- [ ] **AC-013**: Role escalation: can a non-manager call a manager instruction by spoofing accounts? Verify each manager instruction
- [ ] **AC-014**: Role escalation: can a non-investor call an investor instruction by spoofing position accounts?
- [ ] **AC-015**: Admin role (if exists): how is admin defined? Hardcoded pubkey? Program authority? Multisig?
- [ ] **AC-016**: If admin role exists, what can admin do? Can admin drain funds? Can admin pause/unpause?
- [ ] **AC-017**: Is there a "superadmin" or "god mode" that bypasses all checks? Document and flag
- [ ] **AC-018**: Fund manager cannot impersonate an investor (manager key ≠ investor key check if needed)
- [ ] **AC-019**: Investor cannot impersonate the manager (investor key ≠ manager key for manager-only operations)

## 2.3 — Permission Boundaries

- [ ] **AC-020**: Manager can only operate on their own fund (not another manager's fund)
- [ ] **AC-021**: Investor can only operate on their own position (not another investor's position)
- [ ] **AC-022**: Manager cannot directly withdraw investor funds (only through fee mechanism)
- [ ] **AC-023**: Manager fee percentage has a maximum cap enforced on-chain
- [ ] **AC-024**: Manager cannot change fee after fund creation (or changes are time-locked)
- [ ] **AC-025**: Treasury address is validated on every fee transfer — cannot be changed to attacker-controlled address
- [ ] **AC-026**: Treasury address is hardcoded or stored in an immutable configuration — not a mutable field
- [ ] **AC-027**: Platform fee minimum is enforced (`admin_fee >= minimum`) — manager cannot set it to zero
- [ ] **AC-028**: No instruction allows transferring fund PDA ownership from one manager to another without governance
- [ ] **AC-029**: Whitelist management (if exists) — only authorized role can add/remove programs

## 2.4 — Freeze & Pause Mechanisms

- [ ] **AC-030**: Is there a pause mechanism? (`fund.paused` flag or similar)
- [ ] **AC-031**: If pause exists, who can trigger it? (Should be restricted to manager/admin)
- [ ] **AC-032**: If pause exists, does it actually prevent all value-moving operations?
- [ ] **AC-033**: If pause exists, can manager still withdraw their own fees while paused? (Should they?)
- [ ] **AC-034**: If pause exists, can investors still withdraw while paused? (Should they — emergency exit?)
- [ ] **AC-035**: If NO pause mechanism exists — flag as LOW/MEDIUM finding (no emergency stop)
- [ ] **AC-036**: Can the program be frozen by Solana (freeze authority on mint)? Is freeze authority set?
- [ ] **AC-037**: Shares mint — who is the mint authority? Is it the fund PDA? Can anyone else mint shares?
- [ ] **AC-038**: Shares mint — is there a freeze authority? If yes, who controls it?

## 2.5 — Anti-Griefing on Access Control

- [ ] **AC-039**: Can an attacker front-run an account creation to claim the PDA first? (Seed collision with attacker-controlled data)
- [ ] **AC-040**: Can an attacker create a position in a fund that doesn't accept their wallet?
- [ ] **AC-041**: Can an attacker block withdrawals by manipulating shared state?
- [ ] **AC-042**: Can an attacker force-close another user's accounts?
- [ ] **AC-043**: Can an attacker trigger instructions on behalf of other users by replaying old transactions? (Solana inherently prevents this via recent_blockhash, but check off-chain replay)
- [ ] **AC-044**: Rate limiting: are there any on-chain rate limits (cooldown periods, minimum intervals)?
- [ ] **AC-045**: Can an attacker spam `init` instructions to fill up PDA space or exhaust payer's SOL?

## 2.6 — Cross-Instruction Authority

- [ ] **AC-046**: In multi-instruction transactions, can instruction N's authority context be exploited by instruction N+1?
- [ ] **AC-047**: After an account is closed in instruction N, can instruction N+1 in the same transaction access the closed account's stale data?
- [ ] **AC-048**: CPI called programs — can they callback into the calling program with elevated privileges?
- [ ] **AC-049**: Re-entrancy: does the program guard against re-entrant calls? (Solana's runtime prevents direct re-entrancy but CPI callbacks can simulate it)
- [ ] **AC-050**: If program uses `invoke_signed`, verify the seeds cannot be guessed/replicated by another program

## 2.7 — Off-Chain-Signed Authority Grants & Admin-Set Mutation

> Real-world: Rain white-label card contract, Aug 2026 — a crafted `AddCollateralAdmin` signature bundle against an outdated deployment granted the attacker admin over 1,100+ user collateral accounts (~$1.1M drained across Avici, Tria and other tenants). Cross-ref KV-137, KV-101/102.

- [ ] **AC-051**: Enumerate every instruction that grants, extends or transfers a privilege (add admin / operator / delegate / collateral-admin, set authority, grant role). Each one requires an existing **higher on-chain authority as `Signer`** — flag any privilege grant reachable with only an off-chain-signed message or "signature bundle"
- [ ] **AC-052**: Where signed-message authorization is used (ed25519/secp256k1 precompile + instructions-sysvar introspection), the signed payload binds ALL of: program ID, instruction discriminator, target account keys, an expiry, and a single-use nonce that is consumed on-chain — a signature missing any binding can be replayed or redirected to other accounts
- [ ] **AC-053**: Batch / bundle admin operations: every element of the bundle is individually validated against the signed payload — one valid signature must never authorize N unverified mutations appended to the same bundle
- [ ] **AC-054**: Membership of every admin/operator set is bounded, revocable, and every addition emits an event that feeds monitoring/alerting — an unexpected admin addition is detected in minutes, not at drain time
- [ ] **AC-055**: Blast-radius check: no single granted credential controls ALL user sub-accounts (collateral accounts, card balances, positions). Admin scopes are per-account, per-market or per-cohort, so one compromised grant bounds the loss

## 2.8 — Initialization, Anchoring & Privilege Hygiene

<!-- verified: anchor v0.29.0..v1.0.0 lang/src/accounts/program.rs (Program::programdata_address); agave v1.18.26 sdk/program/src/pubkey.rs and v2.1.0 sdk/pubkey/src/lib.rs (bytes_are_curve_point is unimplemented!() under target_os = "solana"); agave v2.1.0 curves/curve25519/src/edwards.rs (validate_edwards → sol_curve_validate_point); token-2022 main program/src/processor.rs (ImmutableOwner rejects AccountOwner change) -->

- [ ] **AC-056**: A singleton/global `initialize` (constant-only seeds such as `[b"config"]`) that stores the caller as admin, fee recipient or oracle authority is gated to the deployer. Either require `program_data.upgrade_authority_address == Some(signer.key())` with `program_data` pinned to **this** program's ProgramData (`seeds = [crate::ID.as_ref()], bump, seeds::program = bpf_loader_upgradeable::ID`, or `program.programdata_address()? == Some(program_data.key())` with `program: Program<'info, crate::program::MyProgram>`), or require a hard-coded admin key with `address =`. Loader-v4 programs keep the authority in the program-account header (no ProgramData). Deploy + init in the same transaction is not a mitigation: a newly deployed program can be invoked only from the next slot (KV-141).
- [ ] **AC-057**: For every privileged instruction that mutates a child account C, the authority chain is walked to a trusted root: `signer → P.authority`, `C.P == P.key()` (has_one or seeds containing `P.key()`), `P.G == G.key()` …, ending at a program-owned/PDA-derived root or a constant. Comparisons only among passed-in accounts prove internal consistency, not authority (KV-146).
- [ ] **AC-058**: Guard-coverage matrix: for every state field that moves value or grants authority, list every handler that writes it, with its signer, has_one, pause check, in-flight flag, slippage bound, oracle freshness and cooldown. The weakest writer is the attack surface. Any guard present on one writer and absent on another is either explained or reported (KV-170).
- [ ] **AC-059**: Authority is identified by role, not name. An unchecked account (`AccountInfo`/`UncheckedAccount`) whose key is compared against a stored authority/admin value, or against a hard-coded user/admin key (`pubkey!(..)`, `ADMIN`), to gate a privileged action is acting as an authority and must be `Signer`/`is_signer`. A key comparison that only pins *which account* receives or is read (stored treasury/fee destination, program ids, sysvar ids) does not imply authorization and needs no signature. An account forwarded into a CPI is exempt only if the callee requires it as a signer and the program does not sign for it via `invoke_signed`.
- [ ] **AC-060**: Every handler that signs with a protocol PDA over caller-chosen accounts does one of two things. It binds the user-side accounts to the transaction signer (`token::authority = signer`, `has_one`, seeds with `signer.key()`), or it is reachable only via self-CPI because it requires the program PDA itself as a `Signer`. Stack height alone proves that a CPI happened, not who made it (KV-149).
- [ ] **AC-061**: Every owner/authority rotation (positions, escrows, grants, obligations, manager roles, sub-accounts) resets every privilege derived from the old owner: delegates and delegated amounts, operators, session keys, close authority, pending claims/withdrawals, referrers. It also revokes SPL delegates on custody token accounts. Two-step transfers clear `pending_owner` on accept and overwrite it on re-propose. Token-2022 accounts with `ImmutableOwner` (including every Token-2022 ATA) reject an SPL owner change outright.
- [ ] **AC-062**: Every persisted pubkey (`authority`, `admin`, `fee_destination`, `treasury`, `creator_*`, signer/member lists) is validated before the write. It is not `Pubkey::default()`; it is a signer or canonical PDA where the role needs one; lists are deduplicated. Where a wallet signature will be required, it is on-curve: use the curve-validation syscall (`solana_curve25519::edwards::validate_edwards` → `sol_curve_validate_point`). `Pubkey::is_on_curve()` panics on-chain (`unimplemented!()` under `target_os = "solana"`, solana-program 1.x and 2.x). Legitimate PDA members that sign via `invoke_signed` are off-curve by design (KV-148).
- [ ] **AC-063**: `*_for(target)` / `delegate_to(target)` style instructions cannot target a protocol PDA or singleton (vault authority, treasury, fee PDA) in a way that imposes a lock, cooldown or position that bricks protocol operations.
- [ ] **AC-064**: Every semi-trusted role (keeper, crank, operator) is analysed in both directions, and a rotation/removal instruction exists for each role. Role→user abuse covers timing, parameters and **omission** (what degrades if the role stops, and how fast). User→role abuse covers griefing preconditions and front-running of predictable cranks.
- [ ] **AC-065**: No instruction's security rests on constraints anchored to an unchecked, caller-supplied key (AV-110, KV-145). "The CPI returned Ok" from an unpinned verifier/oracle program is not proof of verification.
- [ ] **AC-066**: Admin variants of user flows (`set_position_range`, `rebalance`, `unpause`, `set_fee`) that re-run a value-moving flow apply the user path's guards (slippage, oracle staleness, manipulation locks). A user must not be able to sandwich the admin transaction (bundles).

*Sources: sanbir/solana-auditor-skills B1 + access lens (MIT, Copyright (c) 2024 AI Skills Contributors); Ackee bootcamp #1 [paraphrased, cited] with corrections; Helius §1 [paraphrased, cited] with corrections; sannykim/solsec → Solend incident [paraphrased, cited]; qedgen/solana-skills P2 and store-without-validate pattern (MIT, Copyright (c) 2025 QEDGen) with is_on_curve correction; PlamenTSV/plamen §7/§9/§10 (MIT, Copyright (c) 2025-2026 Plamen Contributors); Sealevel Sentinel #3 (MIT, Copyright (c) 2026 Stan (stantheman0128)) with constant-key correction; SlowMist U1/U2 (Apache-2.0, attributed to SlowMist), paraphrased with Jet-fix correction; pashov/skills asymmetry step 5 (MIT, Copyright (c) 2024 AI Skills Contributors).*
