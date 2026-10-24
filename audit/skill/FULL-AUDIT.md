# Full Repository Audit — Master Execution Plan

> This document is the step-by-step execution plan for auditing the Solana on-chain programs in a repository (Rust: Anchor, native `solana-program`, Pinocchio).  
> The auditor agent reads this file and follows it from top to bottom, producing a complete report.
>
> **MANDATORY**: Read [OUTPUT-RULES.md](OUTPUT-RULES.md) FIRST — it defines the severity scale (1-10),
> the chunked execution protocol, the executive summary format, and the item-by-item output requirement.
> Every rule in OUTPUT-RULES.md overrides anything in this document if there's a conflict.

---

## PRE-FLIGHT

Before starting any phase:
0. Intake: if no `audit_<n>/intake.md` exists for this engagement, run the `intake` playbook ([commands/intake.md](commands/intake.md); `--auto` with no human present). It creates `audit_<n>/` per Rule 11d and records scope, in-scope paths (Q39/Q44) and the execution mode (Q46) that later steps read. If intake is skipped, ask Q46 at the first step that executes target code (Rule 11a)
1. Read [OUTPUT-RULES.md](OUTPUT-RULES.md) — the output format is non-negotiable
2. Run discovery, detect languages and frameworks (Rule 7 in OUTPUT-RULES.md), and declare the audit SCOPE from them (Rule 0) — do NOT bulk-read the corpus
3. Load only the in-scope checklists/vectors, on demand as each phase reaches them
4. Record the detected languages and frameworks in the report header (Rule 7)
5. Create the checkpoint file `audit-checkpoint.md` to track progress across chunks (Rule 3 in OUTPUT-RULES.md gives its location and format)
6. Remember: **walk the code file by file — never one-shot** (Rule 3)
7. Apply **Operating Safety** ([OUTPUT-RULES.md Rule 11](OUTPUT-RULES.md#rule-11-operating-safety)) before anything runs: take the execution mode recorded at intake (11a — isolated recommended, native allowed with a report caveat), list every outside service a tool contacts (11b), treat a `.git/` you did not clone yourself as untrusted (11c), and make `.gitignore` containing `*` the first file in `audit_<n>/` (11d)
8. Resolve every bundled path in this file (`tools/`, `templates/`, `scripts/`, `discovery/`, the corpus) from `<skill-root>` — the directory containing this skill's SKILL.md, never the audited repo, which is the working directory ([Rule 11e](OUTPUT-RULES.md#11e--bundled-paths)). Nothing is filled in here, so it is written `<skill-root>` below; substitute the absolute path. The executables this plan runs: `"<skill-root>/tools/auditor-tools/target/release/audit-scan"` and `"<skill-root>/tools/auditor-tools/target/release/audit-mem"`. Trail of Bits tooling is optional: if the Trail of Bits skills (https://github.com/trailofbits/skills, CC-BY-SA-4.0) are installed separately, delegate SAST / fuzzing / coverage harnesses per [references/orchestration/boundary-map.md](references/orchestration/boundary-map.md); otherwise use the native grep checks in [discovery/grep-commands.md](discovery/grep-commands.md) and note the tooling gap in the report's Coverage & Limitations

---

## PHASE -1: SCOPE DECLARATION

Declare scope per OUTPUT-RULES Rule 0 + SKILL Scope-Gated Loading; record the Scope Coverage table below (per checklist/vector group: in-scope yes/no + trigger).

| Checklist / vector group | In scope? | Trigger |
|--------------------------|-----------|---------|
| 01–07 on-chain (Rust / Anchor / native / Pinocchio) | yes/no | `.rs` program crate / `Anchor.toml` / `solana-program` or `pinocchio` dependency |
| 21 Anchor-specific | yes/no | `anchor-lang` in any `Cargo.toml` |
| 22 Token-2022 | yes/no | `token_2022` · `spl_token_2022` · `TokenInterface` · `InterfaceAccount` · `transfer_hook` markers, or a transfer-hook program |
| 23 Rust `unsafe` & panics | yes (every Rust program) | §23.1/§23.3/§23.4 gated on `unsafe` · `pinocchio` · `bytemuck` · `zero_copy` · `transmute` markers |
| 11, 12, 16 always-on | yes | any repo |
| on-chain known vectors | yes/no | per `known-vectors/INDEX.md` markers (Step 4.3) |

Off-chain code (TypeScript/JavaScript, Python, Go and other languages, off-chain Rust services, backends, frontends) is out of scope for this skill — record it once as `[N/A — out of scope: off-chain]`. Repo-wide supply-chain (11), secrets (12) and testing (16) checks still cover the whole tree.

---

## PHASE 0: SETUP

### 0.1 — Identify the Repository

```
ACTION: Read the following files to establish context:
  - Anchor.toml (program ID, cluster, provider)
  - Cargo.toml (workspace members, Anchor version, Solana version)
  - package.json (root, all workspaces — dependencies, scripts; supply-chain input for checklist 11)
  - .gitignore (verify secrets excluded)
  - README.md (project description, architecture)

RECORD:
  - Program ID: ___
  - Anchor version: ___
  - Solana SDK version: ___
  - Node.js dependencies count: ___
  - Git branch: ___
  - Git commit hash: ___
```

**0.1b — Runtime-context sheet (record before any runtime-dependent verdict).** Write `audit_<n>/runtime-context.md` with:
1. Cluster and slot of the observation (`solana -u m slot`). Also record the activation status, on that cluster, of every feature gate a finding may depend on (`solana -u <cluster> feature status <id>`; with no id the command lists every gate, with its description). The gates that matter most for program semantics, named as in agave `feature-set/src/lib.rs`:
   - `raise_cpi_nesting_limit_to_8` (SIMD-0268, CPI nesting 4 → 8), `6TkHkRmP7JZy1fdM6fg5uXn76wChQBWGokHBJzrLB3mj`
   - `enable_sbpf_v3_deployment_and_execution` (SIMD-0178/0189/0377), `5cC3foj77CWun58pC51ebHFUWavHWKarWyR5UUik7dnC`
   - `disable_sbpf_v0_v1_v2_deployment` (SIMD-0500), `B8JJXCy5amZyWG9r7EnUYLwzXSXTxG7GZ1qZ1qggo83g`
   - `account_data_direct_mapping`, `CR3dVN2Yoo95Y96kLSTaziWDAQT2MNEpiWh5cqVq2pNE`
   - `enable_tx_v1` (SIMD-0385), `txv1aq4pp281K9um3tnPgkfX8UqtFT6wcVW3hNezGLL`
   - rent: `deprecate_rent_exemption_threshold` (SIMD-0194), `rent6iVy6PDoViPBeJ6k5EJQrkj62h7DPyLbWGHwjrC`, plus the SIMD-0437 `set_lamports_per_byte_to_*` series
   - for programs that read validator commission (stake pools, LSTs): `commission_updates_only_allowed_in_first_half_of_epoch`, `noRuG2kzACwgaY7TVmLRnUNPLKNVQE1fb7X55YWBehp`

   A gate that exists in the validator source may still be inactive on a given cluster. Only the `feature status` output for that cluster counts as evidence.
2. Loader of each deployed program (`solana program show <id>`): loader-v3 `BPFLoaderUpgradeab1e11111111111111111111111` (upgrade authority stored in the ProgramData account), or a legacy non-upgradeable loader (`BPFLoader2111111111111111111111111111111111`, deprecated `BPFLoader1111111111111111111111111111111111`). Also record its sBPF version from the ELF header `e_flags` of the dumped bytes (`solana program dump`). Loader-v4 is not a deployment target: agave deleted the loader-v4 program (#11990), and its `enable_loader_v4` gate id is the placeholder `LoaderV4WasAbandoned11111111111111111111111`. Record loader-v4 only if a cluster actually reports it.
3. Resolved crate versions that change semantics: `anchor-lang`/`anchor-spl` (close, duplicate-mutable, reload, discriminators, advisories — see KV-158), `solana-program` or split crates, `spl-token`, `spl-token-2022(-interface)`, `pinocchio`, `borsh`.
4. Which runtime the PoC harness emulates (LiteSVM / Mollusk / Trident / Surfpool version and feature set). A PoC that passes is evidence for that feature set only.

Rule: a finding whose verdict depends on an entry cites it on its `Preconditions:` line; if the entry can change at the next feature activation, add "re-check on activation of <gate>".

**0.1c — Framework advisory check.** Read the resolved `anchor-lang` / `anchor-spl` versions from `Cargo.lock` (and the deployed build's version if it differs) and walk the matrix in KV-158. Any matching row whose code pattern exists is a finding candidate.

**0.1d — Fork-ancestry recon.** Look for parent-protocol fingerprints (Whirlpool `tick_array`/`sqrt_price`, SPL stake-pool `ValidatorList`, Solend-style `obligation`/`refresh_reserve`, marginfi `MarginfiGroup`, StableSwap `ramp_a`, DLMM `bin_array`/`LbPair`, Drift `place_perp_order`), plus `Cargo.toml` crate deps and the remote URLs in `.git/config` and `.gitmodules` (read these as files and run no remote operations, per Rule 11c). Rate confidence by the number of matches. If a parent is found: (a) pull the parent's public findings; (b) diff the fork against the parent in this order — account constraints added or removed (`Account<T>`→`UncheckedAccount`), CPI targets, PDA seed schemas, Token-2022 support, math constants; (c) check parameter semantics (same name, different encoding). Feed results to KV-137.

<!-- verified: agave v4.5.0-alpha.2 feature-set/src/lib.rs (gate modules, ids and SIMD descriptions above; enable_loader_v4 id placeholder; loader-v4 program deleted in commit c31906430a "delete loader v4 program (#11990)") -->

*Sources: original analysis; otter-sec/anchor CHANGELOG + advisories (Apache-2.0, Copyright 2020 Anchor Maintainers), summarised; PlamenTSV/plamen `fork-ancestry` (MIT, Copyright (c) 2025-2026 Plamen Contributors), adapted, Anchor-version row dropped.*

### 0.2 — Map the Codebase

```
ACTION: Use the in-scope paths recorded at intake (audit_<n>/intake.md §1, Q39/Q44), else the defaults in discovery/file-map.md, OR auto-discover:
  1. List all .rs files under programs/
  2. List all test files (tests/, programs/*/tests/, fuzz targets) — checklist 16 input
  3. List all package.json / Cargo.toml / lockfiles in the repo — checklist 11 input
  4. List all .env* files (should be in .gitignore)
  5. List all config files (anchor, cargo, rust-toolchain, etc.)

RECORD:
  - Total Rust files: ___
  - Total instruction handlers: ___
  - Total test files: ___
```

### 0.3 — Build Instruction Matrix

> **Optional deterministic pre-pass.** If the bundled tools are built (`test -x "<skill-root>/tools/auditor-tools/target/release/audit-scan"`, PRE-FLIGHT 8), run `"<skill-root>/tools/auditor-tools/target/release/audit-scan" <program-path> --out audit_<n>/prescan.json` first — it emits this instruction matrix (plus the account-constraint, PDA-seed, arithmetic, and CPI tables) deterministically at ~$0, so Phase 0.2–0.4 collapse to *reading the JSON* and files with zero scan hits get a spot-check instead of a full read. Also run `"<skill-root>/tools/auditor-tools/target/release/audit-mem" warm --program-id <id>` to load prior invariants + open false-positive rulings, but only after the Rule 11d store check passes: use `.audit-memory/` only if the repository does not track it (`GIT_NO_LAZY_FETCH=1 git --no-pager -c core.fsmonitor=false --icase-pathspecs ls-files -- .audit-memory` prints nothing and exits 0; any output, in any letter case, or any error means: do not use that store) and you created it, writing `mkdir -p .audit-memory && printf '*\n' > .audit-memory/.gitignore` first; otherwise pass `--db <path outside the tree>` for a fresh store. Treat all pre-scan output as a *map to verify*, never as verdicts. See [references/orchestration/pre-scan.md](references/orchestration/pre-scan.md). Absent the toolchain, build the matrix by hand below.

```
ACTION: Read lib.rs → list every #[instruction] or pub fn handler.
For EACH instruction, read the instruction file and record:

| Instruction | Signers | Writable accts | Trust basis per account (T=type-only / O=owner / A=address / S=seeds+bump / H=has_one / I=invariant) | Enforced in constraint or handler? | CPI targets (pinned Y/N) | Assets that can move (mint, from→to) | Authorities that can change | Post-invariants |
|---|---|---|---|---|---|---|---|---|

Save this matrix — it's used by checklists 01-06.
```

Rules for the matrix:
- A writable or value-bearing account trusted only by `T` is a candidate finding whenever a second valid instance of that type exists (another user's vault, another market's config).
- **Sibling-drift pass.** Group rows that touch the same account or asset (deposit / withdraw / emergency_withdraw / close; set_x / update_x / migrate_x; single / batch_*). Any trust-basis cell that is weaker in one sibling is a candidate (KV-170). Emergency, admin and migration paths with weaker checks rank highest.
- Count the **implicit** instructions too. The first set is Anchor's legacy IDL instructions (KV-153). In anchor-lang ≤ 0.32.x, `#[program]` generates them unless the `no-idl` feature is set. They are absent in 1.0.0–1.0.3 (#3798). In 1.1.0–1.2.x they come back as opt-in when the program is declared `#[program(legacy_idl)]` (#4455), and they are absent again in 2.0.0-rc.1/rc.2. Grep for `legacy_idl` before you mark them N/A on 1.x. The second is the `event-cpi` self-CPI handler. Dispatch includes it whenever the `event-cpi` feature is enabled on anchor-lang, usually because `#[event_cpi]` is used, but Cargo feature unification can also turn it on. That handler accepts only the program's own `__event_authority` PDA as a signer.

<!-- verified: anchor v0.32.1 lang/syn/src/codegen/program/dispatch.rs (IDL_IX_TAG_LE dispatch under `#[cfg(not(feature = "no-idl"))]`; event handler chosen by `#[cfg(feature = "event-cpi")]` only); anchor v1.0.0 CHANGELOG "Remove legacy IDL instructions … (#3798)", no IDL_IX_TAG in v1.0.0/v1.0.3 dispatch.rs; v1.1.0 commit 93a33158 "re-added legacy idl support … (#4455)", v1.1.0–v1.2.1 dispatch.rs `Some(args) if args.legacy_idl => generate_legacy_idl_dispatch()`; v2.0.0-rc.2 dispatch.rs has no legacy_idl/IDL_IX_TAG; anchor v0.32.1 lang/syn/src/codegen/program/handlers.rs `__event_dispatch` (signer + find_program_address check) -->

*Sources: franpersanchez/solana-audits-skill instruction matrix (MIT, Copyright (c) 2026 Fran Pérez), adapted.*

### 0.4 — Build State Model

```
ACTION: Read every file in state/ directory. For each account struct, record:

| Account | Seeds | Size | Key fields | Mutable by |
|---------|-------|------|------------|------------|
| ...     | ...   | ...  | ...        | ...        |

Map relationships: which accounts reference which.
Identify all enums and their variants.
```

---

## PHASE 0.5: CONTEXT RECONSTRUCTION (before any verdict)

Build understanding before judgment. No checklist item may be marked `[FAIL-N≥6]` against a function that has not first been reconstructed here. *(Pattern credit: Trail of Bits `audit-context-building`.)*

For every non-trivial function (any instruction handler, any value-moving or state-mutating fn, any fn with a CPI or arithmetic), fill `templates/context-worksheet.md`:

- **Purpose** — what the function is supposed to do, from the code (not the docs).
- **Signature** — inputs (args), accounts (+ constraints), state written, each `@ L#`.
- **Block-by-block** — what each block does, what it reads / writes, why it is there.
- **Invariants** it must preserve, each with the paths that hold it and the paths that break it.
- **Assumptions** about inputs, accounts and caller. Each gets an `established_by:` value: `L# (this fn)`, `callee fn@file:L#` (name each callee return path that sets it up), or `nothing found`. "The code relies on X and nothing enforces X" is the highest-value hand-off to hunting.
- **External-interaction risks** (CPIs, sysvars, `remaining_accounts`, oracle reads, return data). An empty section is written `none: <reason>` so that *none* and *not checked* stay distinct. There are no minimum counts.
- **Cross-function dependencies** — shared state, ordering assumptions.

Anti-hallucination rules (mandatory):

- Every claim cites a line (`L#`).
- The words "probably", "might", "seems", "should" are banned. If you cannot state it from the code, write `UNKNOWN — needs manual review`.
- Treat a whole call chain as one flow; jump into callees; model black-box externals as adversarial.
- **Trace each exit of a helper you depend on** (`check_authority`, `load_and_validate`, `get_price`, `try_from`, custom `AccountDeserialize`). A guarantee that some exits provide and others skip is not a guarantee. The exit that skips it is where to dig. Typical shapes: early `return Ok(())` when `amount == 0` or `remaining_accounts.is_empty()`; a legacy-version `match` arm that skips the owner check; `if cfg.paused { return Ok(()) }` before validation; a fallback oracle branch with no staleness check.
- **Names prove nothing.** `validate_*`, `assert_*`, `is_valid_*`, `safe_*` are claims. Cite the line that performs the check.
- **Black-box callee = adversarial.** For a CPI to code outside scope, record which accounts go writable or signer, whether a PDA signer is extended, and which post-CPI reads assume the callee behaved.
- **Record disagreements, do not reconcile them.** If two worksheets disagree (one says `vault.authority` is set only in `init`, another finds a setter), keep both statements. The conflict itself is a lead to resolve against the source.
- `UNKNOWN` is kept only for open questions ("cannot tell yet"), never for "relies on X and nothing enforces X".

*Sources: Trail of Bits `audit-context-building` method [paraphrased, CC-BY-SA-4.0, https://github.com/trailofbits/skills]. Three phrases that were close to the source wording have been rewritten.*

Output worksheets to `audit_<n>/worksheets/context/{fn}.md`. These feed the Rule 5b validation gate.

---

## PHASE 1: ON-CHAIN PROGRAM AUDIT (Checklists 01-06, 21-23)

### Execution Strategy

The on-chain audit proceeds **instruction-by-instruction**. For each instruction file:

1. Open the file
2. Run items from checklists 01 (account validation), 02 (access control), 03 (arithmetic), 04 (CPI/PDA) that apply, plus the in-scope framework checklists: 21 (Anchor, record the resolved `anchor-lang` version first), 22 (Token-2022 integrator / transfer-hook author) and 23 (panics and error propagation on every program; memory-safety sections when `unsafe` / zero-copy markers are present)
3. Record findings inline

After all instructions are reviewed individually, run the **cross-cutting** checks:
- Checklist 05 (state machine) — requires full lifecycle view
- Checklist 06 (economic/logic) — requires understanding of all instructions together

### Step 1.1 — Per-Instruction Deep Review

```
FOR EACH instruction file in programs/*/src/instructions/
(native / Pinocchio: each `process_instruction` dispatch arm and the processor fn it calls):

  READ the full file (accounts struct + handler function)

  CHECK (from 01-account-validation):
    - Every account type (AccountInfo vs UncheckedAccount vs Account<T>)
    - Every /// CHECK: comment has real validation
    - has_one constraints present and correct
    - seeds + bump for PDA accounts
    - remaining_accounts validation (if used)

  CHECK (from 02-access-control):
    - Signer present for value-moving operations
    - Signer linked to state via has_one
    - Role appropriate (manager/investor/delegate/permissionless)

  CHECK (from 03-arithmetic):
    - Every +, -, *, / operator — is it checked_*?
    - u128 intermediate for multiply-then-divide
    - Division by zero guards
    - Truncation safety (u128 → u64, u64 → u32)

  CHECK (from 04-cpi-pda):
    - CpiContext first arg is Pubkey (Anchor 1.0)
    - CPI targets validated (program ID)
    - from/to/authority/amount correct in each CPI
    - invoke_signed uses correct seeds
    - State mutations BEFORE CPI (checks-effects-interactions)

  RECORD: findings per instruction file
```

### Step 1.2 — Cross-Cutting State Machine Review (Checklist 05)

```
AFTER all individual instructions reviewed:

  (The items below use a share-vault protocol as the example; substitute the
   target's own lifecycles, roles and invariants.)

  1. Draw the withdrawal/redeem lifecycle from code (not docs)
     - Which instruction sets each status variant? (adapt to your status enum name)
     - Are all transitions present? Any dead variants?
     - Can withdrawals get stuck?

  2. Draw the overall protocol lifecycle
     - Creation → deposits → operations → withdrawals → (closure?)
     - Can every created account reach a terminal state?

  3. Verify invariants
     - total_shares == shares_mint.supply
     - total_shares == Σ(investor_position.shares)
     - Event emission for every financial operation

  RECORD: lifecycle diagrams + findings
```

### Step 1.3 — Economic & Logic Attack Review (Checklist 06)

```
AFTER understanding all instructions:

  1. Flash loan attack paths
  2. Sandwich/MEV attack paths
  3. First depositor attack scenario
  4. NAV manipulation scenarios
  5. Fee exploitation vectors
  6. Manager rug pull analysis
  7. Token-specific exploits
  8. DoS attack vectors

  RECORD: attack scenario descriptions + findings
```

### Step 1.4 — Attacker-Lens Sweep (optional on small programs; default on > 500 SLOC)

Run the lenses in [references/orchestration/attacker-lenses.md](references/orchestration/attacker-lenses.md) over the in-scope bundle, in parallel where the host supports it. Each lens emits FINDING / LEAD blocks (OUTPUT-RULES Rule 4b). Every FINDING then goes through Rule 5b like any checklist `[FAIL-N]`. Lens hunters are read-only inside the target repo: no PoC files there, even temporarily.

### Step 1.5 — Cross-Cutting Review Passes (run on every audit)

Each pass catches a class that a per-checklist walk misses on a cold read. Record each pass as `PASS-Pn: done / N/A (reason)` in the coverage section.
- **P1 Safe-utility coverage.** List every protective helper (`fn (verify|check|assert|validate|ensure|require)_*`, `*_in_place`, `safe_*`) and the primitive it guards. Any handler touching the same primitive without calling the helper is a candidate ("fixed here, not there").
- **P2 Per-role identity anchoring.** For every named principal (`<role>_token_account`, `<role>_destination`, `<role>_authority`, `<role>_vault`) confirm it is anchored by a stored field on a program-owned account, a signer check on the role itself, or a canonical PDA with the role in its seeds. A role that is only a label is a forgeable parameter (KV-147). **Root-anchor rule:** a chain of comparisons between passed-in accounts proves only internal consistency; at least one link must compare against a trusted program-owned account field or a hard-coded constant (KV-146).
- **P3 Store-without-validate.** For every `state.<pubkey_field> = <arg | accounts[i].key>`, name the predicate that constrained the value before the write (KV-148).
- **P4 Dead guards / declared intent.** Unread constants, write-only fields, unbranched mode flags, error variants with no raise site (KV-177).
- **P5 Comparison direction.** For every guard on a limit, balance, threshold, quorum, expiry or fee accumulator, first write one sentence with the intended direction from the field's role ("reject when `spent + amount > limit`"), then read the operator, operand order and accumulation sign. If flipping `<`/`>` or swapping operands would still compile and look plausible, derive the input that satisfies the wrong direction.
- **P6 Lifecycle-transition soundness.** Premature `Draft→Active` / `Building→Sealed` transitions before all parts exist (rate as cross-actor grief when a non-creator can trigger it); a permissionless System `create_account` at a derivable address, which fails with `AccountAlreadyInUse` once anyone pre-funds that address with 1 lamport. The fix is to transfer only the rent deficit, then `allocate` and `assign`, signed with the PDA seeds. Anchor `init` already does this. `CreateAccountAllowPrefund` (SIMD-0312, gate `create_account_allow_prefund`) is an alternative where that gate is active on the cluster.<!-- verified: anchor v0.29.0 lang/syn/src/codegen/accounts/constraints.rs (lamports > 0 branch: transfer + allocate + assign with signer seeds), same in v1.2.1 `generate_create_account_or_fund_allocate_assign`; agave v4.5.0-alpha.2 programs/system/src/system_processor.rs create_account `to.get_lamports() > 0` → AccountAlreadyInUse; feature-set/src/lib.rs `create_account_allow_prefund` "SIMD-0312" -->
- **P7 Sentinel asymmetry.** For each field with a behavioural sentinel (`0` = never/unlimited, `u64::MAX` = no cap, empty list = any, `Pubkey::default()` = none), list every reader and whether it rejects, special-cases or treats the sentinel literally. Divergence is the finding. Also flag one-sided windows (an expiry with no matching start).
- **P8 Trust-surface dependency walk** (only when the program trusts the result of `sign`/`verify`/`prove`/`commit`/`recover`/`aggregate` from a small or niche crate, or a niche zero-copy collection for fund-moving state): see [references/methodologies/trust-surface-deps.md](references/methodologies/trust-surface-deps.md). Exempt: `solana-program` and split crates, `spl-*`, `anchor-lang`, `pinocchio`.
- **P9 Semantic-inconsistency matrix.** Build instruction × {accounts read, accounts written, token ops, counters updated}. Find column pairs that co-occur in N−1 of N instructions and report the one instruction that breaks the pairing (e.g. "every instruction touching `reserve_stake` also mints or burns pool tokens" — except `initialize`).
- **P10 Sibling propagation.** After each confirmed finding, grep the root-cause pattern (by name and by code shape) across every other handler and module before closing it. Check both the Rust fn name and the Anchor instruction name; for native programs walk every `process_instruction` arm.

### Step 1.6 — Exploit-Chaining Pass (before severities are final)

1. List every LOW/INFO/"not exploitable alone" item as a primitive with a precondition and an effect ("can zero an account's data while it keeps lamports", "can choose the destination account", "can make `amount` stale for one instruction").
2. Try to compose primitives inside one transaction (precondition of B = effect of A), including attacker-program CPI wrappers, flash-loan bracketing, close/re-init cycles and Jito bundles across transactions.
3. Include effects that external programs (token programs, Metaplex, integrated AMMs) let an attacker produce.
4. A chain that reaches fund loss is reported as one finding at the chain's severity, listing every component; the components stay linked. Use [references/compose-cookbook.md](references/compose-cookbook.md) as prompts, not as automatic severity. Expect 0–2 chains per audit.

*Sources: qedgen/solana-skills Part P (MIT, Copyright (c) 2025 QEDGen), adapted; sannykim/solsec index → Sec3 "semantic inconsistency" stake-pool post and Solens "Royal Flush" [paraphrased, cited: https://www.sec3.dev/blog/solana-stake-pool-a-semantic-inconsistency-vulnerability-discovered-by-x-ray ; https://medium.com/@solens_io/schrodingers-nft-an-incinerator-spl-token-program-and-the-royal-flush-attack-58e4ce4e63dc]; sanbir/solana-auditor-skills shared rules (MIT, Copyright (c) 2024 AI Skills Contributors), adapted.*

---

## PHASE 2: OFF-CHAIN CODE — OUT OF SCOPE

Off-chain code (TypeScript, backends, frontends, other languages) is not audited by this skill. Record `[N/A — out of scope: off-chain]` in the Scope Coverage table and continue with Phase 3. The phase number is kept so cross-references stay stable.

---

## PHASE 3: OPSEC, SUPPLY CHAIN & SECRETS AUDIT (Checklists 07, 11, 12)

### Step 3.1 — OpSec & Governance (Checklist 07)

```
ACTIONS (some require terminal):

  # Check upgrade authority
  solana program show <PROGRAM_ID> --url $SOLANA_RPC_URL

  # Check for backdoors
  grep -rn "unsafe" --include="*.rs" programs/
  grep -rn "invoke(" --include="*.rs" programs/ | grep -v "invoke_signed"

  # Check IDL matches binary
  # Verify declare_id matches Anchor.toml

  # Timelock analysis — document all time-locked operations

RECORD: governance configuration + findings
```

### Step 3.2 — Supply Chain Audit (Checklist 11)

```
ACTIONS:

  # Check for compromised packages (SC-001, SC-002)
  grep -rn '"axios"' --exclude-dir=node_modules --include='package.json' --include='package-lock.json' .
  # → verify NOT 1.14.1 or 0.30.4
  W3='web3\.js@(npm:)?1\.95\.(6|7)([^0-9]|$)|/web3\.js/-/web3\.js-1\.95\.(6|7)\.tgz|"@solana/web3\.js"[[:space:]]*:[[:space:]]*"=?1\.95\.(6|7)"'
  grep -rnE "$W3" --exclude-dir=node_modules --include='package.json' --include='package-lock.json' \
    --include='pnpm-lock.yaml' --include='yarn.lock' --include='bun.lock' .
  # history too; --text because a committed .gitattributes can mark lockfiles binary,
  # which hides them from -G
  GIT_NO_LAZY_FETCH=1 git --no-pager -c core.fsmonitor=false -c log.showSignature=false -c core.bigFileThreshold=512m \
    log --all --oneline --text --no-textconv --no-ext-diff -G"$W3" -- '*lock*' '*package.json'
  # → hijacked @solana/web3.js releases (SC-005). A hit now is CRITICAL;
  #   a hit in history means rotate every key a build from that window loaded; a `fatal:` /
  #   `lazy fetching disabled` line means a partial clone: the history part is INCONCLUSIVE

  # Audits, registry queries and any cargo / rustc command (even --version) run from
  # a scratch dir OUTSIDE the target tree, on copies of the manifest + lockfile, with
  # the toolchain pinned, so the target's .npmrc / .cargo/config* / rust-toolchain*
  # cannot steer them — cargo and rustup read those from every parent directory, so
  # audit_<n>/ inside the tree is not far enough (Rule 11a)
  SCRATCH=$(mktemp -d)   # outside the target tree
  TC=$(cd "$SCRATCH" && rustup default | cut -d' ' -f1)   # your own toolchain, never the target's
  mkdir -p "$SCRATCH/rust" "$SCRATCH/js"
  cp Cargo.lock "$SCRATCH/rust/"

  # Run npm audit + check version pinning for every JS workspace with a lockfile
  # (e.g. the Anchor test harness, an in-repo client SDK)
  find . -name package-lock.json -not -path '*/node_modules/*' | while IFS= read -r lock; do
    d=$(dirname "$lock"); dst="$SCRATCH/js/${d#./}"; mkdir -p "$dst"
    cp "$d/package.json" "$lock" "$dst/"
    (cd "$dst" && npm audit)
    grep -E '[\^~]' "$d/package.json"   # should be minimal
  done

  # Cargo audit (SC-004), stderr kept. It exits 1 both for advisories and for an advisory
  # database it cannot fetch or load (offline, or github.com outside an isolated run's
  # egress), so the output decides:
  #   OUTCOME: vulnerabilities found   → findings, SC-004 FAIL
  #   OUTCOME: advisory DB unavailable → say so in Coverage & Limitations ("advisory DB
  #                                      unavailable"), or rerun with --no-fetch against
  #                                      a local DB if one exists
  #   OUTCOME: not installed           → SC-004 N/A, and Coverage & Limitations says so
  #   no OUTCOME line and no "error:"  → SC-004 PASS
  if (cd "$SCRATCH/rust" && RUSTUP_TOOLCHAIN="$TC" cargo audit --version) >/dev/null 2>&1; then
    (cd "$SCRATCH/rust" && RUSTUP_TOOLCHAIN="$TC" cargo audit --color never) 2>&1 | tee "$SCRATCH/cargo-audit.txt"
    grep -qE '^error: [0-9]+ vulnerabilit(y|ies) found' "$SCRATCH/cargo-audit.txt" && echo "OUTCOME: vulnerabilities found"
    grep -qE '^error: .*advisory database' "$SCRATCH/cargo-audit.txt" && echo "OUTCOME: advisory DB unavailable"
  else
    echo "OUTCOME: not installed"
  fi

  # Check quarantine (14-day rule) for newest deps
  (cd "$SCRATCH" && npm info @anchor-lang/core time | tail -5)

  # Dependency changes since the baseline (last audited ref; first audit: last
  # release tag) → checklist 11 §11.11: review the published artifacts' code delta
  GIT_NO_LAZY_FETCH=1 git --no-pager -c core.fsmonitor=false -c log.showSignature=false -c core.bigFileThreshold=512m \
    diff --text --no-textconv --no-ext-diff --stat <baseline>..HEAD \
    -- '*.lock' '*-lock.json' '*-lock.yaml' '*Cargo.toml' '*package.json'   # Rule 11c flags

RECORD: dependency audit results
```

### Step 3.3 — Secrets Audit (Checklist 12)

```
ACTIONS:

  # Hardcoded secrets scan
  grep -rn "secret\|private.*key\|mnemonic\|password" --include="*.ts" --include="*.json" --include="*.rs" . \
    | grep -v node_modules | grep -v target | grep -v ".env.example"

  # Keypair files in repo
  find . -name "*keypair*.json" -o -name "*delegate*.json" -o -name "id.json" | grep -v node_modules

  # .env files committed (Rule 11c flags)
  GIT_NO_LAZY_FETCH=1 git --no-pager -c core.fsmonitor=false -c log.showSignature=false ls-files | grep -i ".env"

  # Git history check (Rule 11c flags)
  GIT_NO_LAZY_FETCH=1 git --no-pager -c core.fsmonitor=false -c log.showSignature=false \
    log --all --no-textconv --diff-filter=A --name-only -- "*.env" "*.pem" "*secret*"

  # NEXT_PUBLIC_ audit (SEC-014) — only when the repo also ships a web client
  grep -rn "NEXT_PUBLIC_" --exclude-dir=node_modules --exclude-dir=target . 2>/dev/null

RECORD: any secret exposure
```

### Step 3.4 — Build & Test Verification (Checklists 07, 16)

```
ACTIONS:

  # Both commands below run target-controlled code (build.rs, proc-macros, and
  # Anchor.toml [scripts], which `anchor test` executes). Run them in the execution
  # mode recorded at intake — OUTPUT-RULES Rule 11a (isolated recommended; native
  # allowed, with the report caveat). If they cannot run in that mode, keep the
  # source-level verdicts and add a Rule 10 confidence note.

  # Verify build
  anchor build 2>&1 | tail -20
  # Check for warnings, errors

  # Verify tests pass
  anchor test --skip-local-validator 2>&1 | tail -30

  # Verify .gitignore completeness (SEC-018)
  cat .gitignore | grep -E "\.env|node_modules|target|keypair"

RECORD: build/test results + findings
```

---

## PHASE 4: VERIFICATION & KNOWN-VECTOR AUDIT (Checklist 16 + known vectors)

### Step 4.1 — Formal Verification & Testing Quality (Checklist 16)

```
ACTIONS:

  # Check for static analysis in CI
  grep -rn "clippy\|eslint\|semgrep\|slither\|cargo-audit\|npm audit" .github/ Makefile* scripts/ --include="*.yml" --include="*.yaml" --include="*.sh" --include="*.mjs"

  # Check test coverage setup
  grep -rn "coverage\|lcov\|istanbul\|tarpaulin" . --include="*.yml" --include="*.yaml" --include="*.json" --include="*.toml" | grep -v node_modules | grep -v target

  # Check for fuzz testing
  find . -name "*fuzz*" -o -name "*proptest*" | grep -v node_modules | grep -v target

  # Look for property-based tests
  grep -rn "proptest\|quickcheck\|fc\.\|fast-check" . --include="*.rs" --include="*.ts" | grep -v node_modules

  # Check for documented invariants
  grep -rn "invariant\|INVARIANT\|property.*test\|conservation" . --include="*.rs" --include="*.ts" --include="*.md" | grep -v node_modules | grep -v target

  # Error handling quality
  grep -rn "\.unwrap()" --include="*.rs" programs/

RECORD: verification & testing quality findings
```

### Step 4.2 — On-Chain Events & Emergency Controls (Checklists 05 §5.6, 07)

```
ACTIONS:

  # Event emissions in on-chain program (SM-047..049)
  grep -rn "emit!\|msg!\|emit_cpi" --include="*.rs" programs/
  # → compare against state-changing instructions: every instruction should emit

  # Emergency pause mechanism (OPS-045)
  grep -rn "pause\|freeze\|emergency\|circuit.breaker" --include="*.rs" programs/

  # Incident runbooks (off-chain context; record as a team answer, not scored in Phase 4.5)
  find . -name "INCIDENT*" -o -name "RUNBOOK*" -o -name "*incident*" -o -name "*recovery*" | grep -v node_modules

RECORD: event coverage + emergency-control findings
```

### Step 4.3 — Known Attack Vectors (every in-scope vector in known-vectors/INDEX.md)

Do NOT bulk-read every vector file — that nullifies the scope gate. Load each in-scope vector **only when its `known-vectors/INDEX.md` trigger fires** (phase + language + the vector's feature markers), driven by the prescan advisory manifest.

```
ACTIONS:

  1. Read known-vectors/INDEX.md — use its "Load when (markers)" column as the trigger table.
  2. For EACH in-scope vector (per Phase -1 scope):
       a. If the vector's markers are `always (<phase>)` → OPEN the vector file and evaluate it.
       b. Else check its feature markers against evidence:
            - the audit-scan prescan array (references/orchestration/pre-scan.md), and
            - a grep over the in-scope tree.
          If EVERY marker is PROVABLY ABSENT (empty prescan array OR zero grep hits) →
            record  [N/A — feature absent: <marker>]  from the gate (an evidence-backed verdict).
          Otherwise → OPEN the vector file and evaluate it.
  3. For each opened vector, record one verdict:
       [PASS] / [FAIL-{1-10}] / [PARTIAL] / [N/A]
  4. Add evidence line(s): file:line, prescan field, or command output reference.

RECORD format:
  - KV-001: [PASS] ...                             (always-load, evaluated)
  - KV-005: [N/A — feature absent: pyth/switchboard/oracle]   (skip-deferred from gate)
  ...
  - KV-129: [FAIL-7] ...

HARD RULE (completeness — OUTPUT-RULES Rule 0):
  Every in-scope KV item still has a verdict. A skip-deferred `[N/A — feature absent]` is an
  evidence-backed verdict, NOT a silent skip — and it REOPENS on demand: because the prescan
  under-reports (macros / trait dispatch, per its honesty rule), the instant a manual file read
  surfaces the missing feature (e.g. a `CpiContext` the scan missed), OPEN and evaluate that
  vector. No bug becomes unreachable. Out-of-scope vectors render
  [N/A — out of scope: <reason>] from the scope gate.

See: known-vectors/INDEX.md (Load-when trigger column) · references/orchestration/pre-scan.md
     (Evidence-driven load gating manifest).
```

The corpus covers the 100 vectors listed in `known-vectors/INDEX.md` (numbered between KV-001 and KV-182, with gaps). The vector-scan agent must open its output with a classification block, and the total must equal the in-scope vector count:

    Skip: KV-…        (construct and concept both absent)
    Drop: KV-…        (guard unambiguously blocks all paths, cited)
    Investigate: KV-…
    Total: N classified

*Sources: sanbir/solana-auditor-skills vector-scan protocol (MIT, Copyright (c) 2024 AI Skills Contributors), adapted.*

---

## PHASE 4.5: MATURITY ASSESSMENT

Orthogonal to the risk score: the risk score is the *deploy gate*; this scorecard is the *engineering-quality gate*. Rate each category WEAK / MODERATE / SATISFACTORY / STRONG with **gated tiers**: any WEAK criterion met → WEAK; MODERATE needs every WEAK criterion cleared and all MODERATE criteria met; SATISFACTORY needs all MODERATE criteria plus its own; STRONG is SATISFACTORY plus exceptional practice. Every rating cites `file:line` or a recorded team answer; a category that could not be evaluated is reported "not assessed: <reason>" and never gets a default score. Ask the team about what code cannot show (key custody, upgrade process, monitoring) instead of guessing. *(Pattern credit: Trail of Bits `code-maturity-assessor`.)*

| # | Category | Scored on |
|---|----------|-----------|
| 1 | Access Controls | signer/authority coverage, role separation, admin-key custody |
| 2 | Arithmetic | checked math, u128 intermediates, rounding discipline |
| 3 | Account & Type Safety | typed accounts, discriminator/owner checks, PDA canonicalization |
| 4 | Input Validation | bounds, allowlists, `remaining_accounts` validation |
| 5 | Testing | unit/integration coverage, LiteSVM/Mollusk, edge cases |
| 6 | Fuzzing & Property Tests | cargo-fuzz/proptest presence, documented invariants |
| 7 | Error Handling & DoS Resilience | no `unwrap()`/panic on user input, compute/stack bounds |
| 8 | Upgradeability & Governance | upgrade authority, timelock, multisig, emergency pause |
| 9 | Event emission & emergency controls | event emission coverage, emergency pause/freeze controls |
| 10 | Documentation | stated invariants, actors and privileges, account diagram |
| 11 | Complexity | handler nesting, duplicated validation, testability in isolation |

Emit the scorecard as a dedicated report section (see `templates/report-template.md`). Categories rated WEAK are prioritized in the Remediation Roadmap regardless of individual finding severity.

Gating criteria per category. Rubric rows map onto the scorecard as follows: Access control → 1, Arithmetic → 2, Low-level → 3 and 7, Transaction ordering → 4, Testing → 5 and 6, Upgrades → 8, Monitoring → 9, Documentation → 10, Complexity → 11.

| Category | WEAK if any of | MODERATE needs | SATISFACTORY needs |
|---|---|---|---|
| Arithmetic | `overflow-checks` not set in the workspace-root release profile (Cargo ignores `[profile]` in member crates) and no checked math; undocumented `wrapping_*` / narrowing `as`; no rounding policy | checked math (or overflow-checks + no panic on value paths); rounding direction stated per formula in the protocol's favour; parameter ranges stated; property tests on math | precision loss measured against a high-precision reference; every panic site listed; each documented formula maps to exactly one code site |
| Access control | an authority is a single hot key; a privileged instruction without `Signer` + `has_one`/`address`; no role split | least privilege; revocable roles; two-step authority transfer; tests per privileged instruction | authorities are multisig/governance PDAs; key-compromise blast radius documented |
| Upgrades / decentralisation | single-key upgrade authority with no timelock; admin can move user funds | risks documented; user exit works while paused; upgrade authority is a multisig | timelocked upgrades or immutable core; reproducible verified build published |
| Low-level | `unsafe` / Pinocchio `*_unchecked` without a `// SAFETY:` invariant; hand-rolled serialisation | each unsafe block justified; zero-copy layouts `#[repr(C)]`, padding explicit | differential tests against a safe reference |
| Testing | happy path only; tests do not run from a clean checkout | negative tests per account constraint; LiteSVM/Mollusk tests against the compiled `.so` | stateful fuzz invariants; mutation testing; every handler covered |
| Transaction ordering | no slippage/deadline on swaps, deposits, liquidations | `min_out` + expiry on user value operations; oracle staleness and confidence checks | MEV/keeper ordering risks documented and tested (incl. bundles) |
| Monitoring | no events on authority or parameter changes | `emit!`/`emit_cpi!` (or `sol_log_data`) for every privileged change and value move | emergency pause/freeze instructions exist, are access-controlled, leave user exit working, and are covered by tests |
| Documentation | no statement of invariants or actors | actors/privileges list, account diagram | invariants written and mapped to tests |
| Complexity | deeply nested handlers or duplicated validation | shared validation in constraints/helpers | each handler testable in isolation |

*Sources: Trail of Bits `code-maturity-assessor` gating method [paraphrased, CC-BY-SA-4.0, https://github.com/trailofbits/skills]; Solana criteria are our own.*

---

## PHASE 5: REPORT GENERATION

### Step 5.0 — Reconciliation (multi-agent runs)

1. Group all FINDING/LEAD blocks by `group_key = program | instruction | bug-class`. Exact matches first, then synonymous bug classes within the same (program, instruction). Keep the best-written body, annotate `[agents: N]`.
2. Apply the dedup and assembly gates in [references/report-format.md](references/report-format.md) § Dedup & Assembly Gates.
3. Composite chains: if A's effect meets B's precondition and the combined impact is strictly worse, emit `Chain: [F-A] + [F-B]` at severity ≥ max, confidence = min (Step 1.6).
4. Fix verification for confidence ≥ 75: re-trace the attack with the fix applied, confirm the fix adds no new DoS or CPI failure, and list every location where the pattern repeats.

*Sources: sanbir/solana-auditor-skills (MIT, Copyright (c) 2024 AI Skills Contributors); pashov/skills dedup-and-assembly (MIT, Copyright (c) 2024 AI Skills Contributors); beriktassuly/solana-audit-skill (MIT, Copyright (c) 2026 Berektassuly); all adapted.*

### Step 5.1 — Aggregate Findings

```
Collect ALL findings from Phases 1, 3 and 4.
Classify each by severity: CRITICAL / HIGH / MEDIUM / LOW / INFO
De-duplicate (same root cause appearing in multiple checklists)
```

### Step 5.2 — Generate Report

```
Use the template in templates/report-template.md
Fill in:
  - Corpus coverage section (every in-scope checklist and vector file)
  - Executive summary with counts
  - Each finding with: ID, severity, location, description, exploit scenario, fix recommendation
  - Checklist summary table
  - Detailed per-item results
  - Known vector results (every vector in known-vectors/INDEX.md, each in-scope one with verdict)

Save report to: audit_{N}/REPORT.md (where N is the next audit number)
```

### Step 5.3 — Generate Roadmap

```
Create a prioritized remediation roadmap:
  1. CRITICAL findings — fix immediately, block deploy
  2. HIGH findings — fix before next release
  3. MEDIUM findings — fix within 2 weeks
  4. LOW findings — address in next sprint
  5. INFO — track in backlog

Save to: audit_{N}/roadmap.md
```

### Step 5.4 — Optional deliverables

- Release gate (Mode 7): [templates/release-gate.md](templates/release-gate.md).
- Pre-sign review of a specific transaction or multisig proposal: [templates/tx-presign-review.md](templates/tx-presign-review.md).

---

## EXECUTION NOTES

### Walk The Code — Never One-Shot

Chunking (on-chain chunk size: 1 instruction file) + checkpoint format → OUTPUT-RULES.md Rule 3. Save a checkpoint after each chunk; if context is lost, resume from the checkpoint's `Next Action`.

### Parallelization
- Steps 3.1, 3.2, 3.3, 3.4 are independent — can run commands in parallel
- Steps 4.1, 4.2 are independent
- Phase 1 must be sequential (instruction review builds context)

**Multi-pass "new ground" loop.** Default is one attacker-lens pass; offer three on larger programs. Before pass K+1, render the known findings grouped by `program.instruction` with their bug-class labels (from `audit-mem` and this run) and append them to every lens prompt under "Known findings — ground already walked", with two rules: (a) spend effort on instructions and flows the list does not name; (b) report every bug found in full, listed or not, and reuse the listed label for the same class in the same instruction. Status line per pass: `Pass 2/3 — 17 findings (3 new) · 6 leads (2 new)`; append `· no new ground` when both new-counts are zero — that is the stop signal.

**Bundling.** Do not paste source into sub-agent prompts. Build one `source.md` (one `### path` header + fenced block per in-scope `.rs` file; exclude `tests/`, `target/`, `migrations/`, `*_test.rs`, `mod.rs` without handlers) in the session scratchpad (never `/tmp` in the target), then `agent-N-bundle.md = source.md + lens prompt + shared rules`. The spawn prompt names the bundle path and line count and tells the agent to read it fully in chunks. Vector-scan bundles include only the in-scope `known-vectors/*` selected in Phase -1.

*Sources: pashov/skills (MIT, Copyright (c) 2024 AI Skills Contributors); sanbir/solana-auditor-skills (same copyright); adapted. The source's remote VERSION check is deliberately not imported (conflicts with Rule 11b).*

### Scope Control
- `FULL`: Checklists 01-07, 11, 12, 16, 23 (+ 21 / 22 when their markers are present) + in-scope known vectors, all program files
- `PROGRAM`: Checklists 01-07, 16, 23 (+ 21 / 22 when their markers are present) (on-chain + opsec + verification)
- `OPSEC`: Checklists 07, 11, 12, 16 (governance + supply chain + secrets + verification)
- Off-chain code (backends, frontends, TS/Python/Go, off-chain Rust services) is out of scope for every mode
- With no `--scope` given, the scope is `FULL`. Checklists a narrower scope drops render `[N/A — out of scope: --scope <value>]` in the Scope Coverage table, so the Rule 0 completeness check still holds

### Language Auto-Detection
Language → checklist mapping is authoritative in [SKILL.md](SKILL.md) → Scope-Gated Loading, Step 2 (scope table); see also OUTPUT-RULES.md Rule 7. The auditor scans file extensions/markers (`Anchor.toml`, `solana-program` / `pinocchio` dependencies, program crates) and applies the correct checklists.
