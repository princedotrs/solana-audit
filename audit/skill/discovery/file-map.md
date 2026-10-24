# File Discovery Patterns

> Maps each audit checklist to the exact files/globs that must be scanned.  
> These are defaults. A target with another layout records its in-scope paths at intake (`QUESTIONS.md` Q39, exclusions under Q44, written to `audit_<n>/intake.md` §1) instead of editing this file, which a shared install overwrites on update.  
> Scope: Solana on-chain programs (Anchor / native `solana-program` / Pinocchio). Off-chain code — TypeScript / Python / Go clients, backends, frontends, off-chain Rust services — is out of scope for this skill; list it as excluded in Scope Coverage (see [Out of Scope](#out-of-scope--off-chain-code)). Deploy / admin scripts and CI jobs that hold program, upgrade-authority or admin keys stay in scope for checklists 07, 11 and 12.

---

## Repository Layout Assumptions

```
{root}/
├── programs/{program_name}/src/    # Solana program (Anchor)
│   ├── lib.rs                      # Entry point
│   ├── errors.rs                   # Error definitions
│   ├── instructions/               # One file per instruction
│   │   ├── mod.rs
│   │   └── *.rs
│   └── state/                      # Account state structs
│       ├── mod.rs
│       └── *.rs
├── apps/ clients/ services/        # Off-chain code (out of scope — list as excluded)
├── scripts/ migrations/            # Deploy / admin tooling (keys: checklists 11, 12)
├── tests/                          # Program tests / fuzz harnesses (checklist 16)
├── target/                         # Build output (gitignored)
│   ├── deploy/                     # Program .so + program keypair (<program>-keypair.json)
│   └── idl/                        # Generated IDL
├── Anchor.toml                     # Anchor config ([provider] wallet path)
├── Cargo.toml / Cargo.lock         # Rust workspace + lock file
├── .github/workflows/              # CI (in scope where it deploys or holds keys)
└── .env*                           # Environment (gitignored)
```

---

## Checklist → File Mapping

### 01 — Account Validation
```
PRIMARY:
  programs/*/src/instructions/*.rs     # Every instruction's accounts struct
  programs/*/src/state/*.rs            # State definitions (discriminators, sizes)

GREP PATTERNS:
  "AccountInfo"          → Flag deprecated usage (should be UncheckedAccount)
  "/// CHECK:"           → Verify each has real validation
  "UncheckedAccount"     → Verify CHECK comment exists
  "init_if_needed"       → Flag reinitialization risk
  "remaining_accounts"   → Verify validation before use
  "#[account(init"       → Verify space, payer, seeds
  "#[account(close"      → Verify destination constrained
  "#[account(mut, dup)]" → Document intentional duplicates
```

### 02 — Access Control
```
PRIMARY:
  programs/*/src/instructions/*.rs     # Signer checks per instruction
  programs/*/src/lib.rs                # Instruction dispatch (who can call what)
  programs/*/src/state/*.rs            # State structs (look for authority/owner/role fields)

GREP PATTERNS:
  "Signer<'info>"       → Map which instructions have signers
  "has_one ="            → Map account linking
  "require_keys_eq!"    → Map runtime key checks
  "is_signer"           → Manual signer checks (should use Anchor Signer type)
  "pub fn "             → Every handler needs a signer analysis
```

### 03 — Arithmetic Safety
```
PRIMARY:
  programs/*/src/instructions/*.rs     # All instruction logic
  programs/*/src/state/*.rs            # Helper methods on state structs (calculate_*)

GREP PATTERNS:
  " + "                  → Bare addition (flag if on state/user values)
  " - "                  → Bare subtraction
  " * "                  → Bare multiplication
  " / "                  → Bare division
  "checked_add"          → Correct usage
  "checked_sub"          → Correct usage
  "checked_mul"          → Correct usage
  "checked_div"          → Correct usage
  "saturating_"          → Flag on financial paths
  "as u64"               → Truncation risk
  "as u32"               → Truncation risk
  "as u128"              → Widening (correct pattern)
  "MathOverflow"         → Error usage
```

### 04 — CPI & PDA Safety
```
PRIMARY:
  programs/*/src/instructions/*.rs     # All CPI calls
  programs/*/src/state/*.rs            # PDA seed definitions

GREP PATTERNS:
  "CpiContext::new("              → Program id from a typed Program/Interface account or a constant (Anchor ≥ 1.0 takes a Pubkey, 0.x an AccountInfo)
  "CpiContext::new_with_signer("  → Same, plus signer seeds match the PDA authority
  "invoke_signed"                 → Check seeds correct
  "invoke("                       → Flag bare invoke (should be invoke_signed for PDA)
  "token::transfer"               → Check from/to/authority
  "token::mint_to"                → Check mint/to/authority
  "token::burn"                   → Check from/authority
  "token::close_account"          → Check destination constrained
  "seeds ="                       → Map all PDA derivations
  "bump ="                        → Verify stored bump reuse
```

### 05 — State Machine
```
PRIMARY:
  programs/*/src/state/*.rs            # State enums (status fields, lifecycle variants)
  programs/*/src/instructions/*.rs     # All instructions (trace state transitions)

GREP PATTERNS:
  "status ="              → State transitions
  "Status::"              → All status enum references (adapt to your enum name)
  "emit!\|emit_cpi\|msg!" → Event emission
  "#[event]"              → Event definitions
  "close ="               → Account closure (terminal state)
```

### 06 — Economic & Logic
```
PRIMARY:
  ALL programs/*/src/instructions/*.rs  (full instruction understanding required)
  programs/*/src/state/*.rs            # State structs (share/value calculation helpers)

GREP PATTERNS:
  "min_.*_out"           → Slippage protection (adapt field name to your protocol)
  "total_shares\|total_supply\|lp_supply" → Claim-token supply invariants (e.g. vault shares, LP tokens, LST supply)
  "total_assets\|reserve\|total_borrow\|total_lamports" → Asset tracking fields (e.g. vault assets, AMM reserves, lending borrows, stake-pool lamports)
  "fee_bps\|protocol_fee\|admin_fee" → Fee configuration fields
  "TREASURY\|treasury"         → Treasury address constants
  "whitelist\|allowlist"       → CPI target allowlist
```

### 07 — OpSec & Governance
```
PRIMARY:
  Anchor.toml                          # Program ID, provider, cluster
  Cargo.toml                           # Dependencies, versions
  programs/*/src/lib.rs                # declare_id!
  .gitignore                           # Secrets exclusion
  .github/workflows/*.yml              # CI that deploys / upgrades (OPS-064, OPS-067, OPS-074)

TERMINAL COMMANDS:
  solana program show <PROGRAM_ID>     # Upgrade authority
  anchor verify <PROGRAM_ID>           # Binary verification (rebuilds the target: Rule 11a mode only)

GREP PATTERNS:
  "declare_id!"          → Program ID
  "unsafe"               → Unsafe Rust (flag all)
  "*const\|*mut"         → Raw pointers (should not exist)
  "Pubkey::new_from_array"  → Hardcoded keys (potential backdoor)
  "pause\|freeze\|emergency\|circuit.?breaker" → Emergency mechanisms
```

### 11 — Supply Chain
```
PRIMARY:
  Cargo.toml / programs/*/Cargo.toml   # Rust workspace + program crates
  Cargo.lock                           # Rust lock file
  deny.toml                            # cargo-deny policy (SC-067), if present
  tests/fixtures/*.so, *.so dumps      # Vendored program binaries (SC-066)
  package.json + lockfile              # Only for deploy / admin tooling that loads keypairs (SC-005, SC-011)

TERMINAL COMMANDS (from a scratch dir OUTSIDE the target tree, on copies of the manifest +
lockfile, toolchain pinned — OUTPUT-RULES Rule 11a, FULL-AUDIT Step 3.2):
  cargo audit                          # Rust vulnerabilities (SC-004)
  cargo deny check advisories bans sources  # Yanked / duplicate / git sources (SC-063, SC-067)
  cargo outdated                       # Outdated crates (SC-018)
```

### 12 — Secrets & Key Management
```
PRIMARY:
  .gitignore                           # Must exclude secrets
  .env*                                # Should not exist in repo
  Anchor.toml                          # [provider] wallet path, cluster
  scripts/ / migrations/               # Deploy / admin scripts loading keypairs
  target/deploy/                       # Program keypairs — must not be committed (SEC-019)
  .github/workflows/*.yml              # CI that deploys or signs admin txs (SEC-045, SEC-046)

SCAN TARGETS (entire repo):
  **/*.rs
  **/*.ts
  **/*.json
  **/*.toml
  **/*.env*
  **/*.pem
  **/*keypair*
  **/*delegate*

TERMINAL COMMANDS (git with the OUTPUT-RULES Rule 11c prefix):
  GIT_NO_LAZY_FETCH=1 git --no-pager -c core.fsmonitor=false -c log.showSignature=false \
    ls-files | grep -i ".env"          # Committed env files
  GIT_NO_LAZY_FETCH=1 git --no-pager -c core.fsmonitor=false -c log.showSignature=false \
    log --all --no-textconv --no-ext-diff -S "private" --oneline   # Secrets in git history
  find . -name "*keypair*.json"        # Key files in repo
  GIT_NO_LAZY_FETCH=1 git --no-pager -c core.fsmonitor=false -c log.showSignature=false \
    ls-files -- 'target/deploy/*'      # Committed program keypairs
```

### 16 — Formal Verification & Testing Quality
```
PRIMARY (CI/CD & Testing):
  .github/workflows/*.yml              # CI pipelines (static analysis, tests)
  Makefile* / scripts/*.sh             # Build/test scripts
  tests/ / **/*test* / **/*spec*       # Test files
  **/*.fuzz.* / **/fuzz_targets/       # Fuzz targets

PROJECT CONFIG:
  .clippy.toml / clippy.toml           # Rust linter config
  codecov.yml                          # Coverage config
  trident-tests/ / Trident.toml        # Trident fuzzing (FV-071)

GREP PATTERNS:
  "proptest\|quickcheck\|fast-check\|hypothesis" → Property-based testing
  "fuzz\|fuzzing\|fuzzer"             → Fuzz testing
  "coverage\|lcov\|tarpaulin\|llvm-cov" → Coverage measurement
  "clippy\|semgrep\|cargo-audit\|cargo-deny" → Static analysis
  "INVARIANT\|invariant\|conservation" → Documented invariants
  "trident\|mollusk\|litesvm\|kani\|certora" → Solana verification tooling (FV-071)
  ".unwrap()"                          → Panic-prone code in Rust
  "#\[allow(clippy"                    → Suppressed lints in program code
```

---

## Out of Scope — Off-Chain Code

```
LOCATE (to list as excluded in Scope Coverage, never to audit):
  **/*.rs  EXCLUDING programs/** and target/**   # Off-chain Rust: geyser plugins, indexers, keepers, signer services
  apps/** / clients/** / services/**              # TS / Python / Go clients, backends, frontends
  .github/workflows/*.yml                         # Non-deploy CI jobs (read only for checklist 16 test / analysis coverage)

TERMINAL COMMANDS:
  find . -name "*.rs" -not -path "./programs/*" -not -path "./target/*"  # Enumerate off-chain Rust

STILL IN SCOPE THERE:
  Program / upgrade-authority / admin keys (checklist 12), deploy / admin tooling that loads them
  (checklist 11 SC-005, SC-045, SC-062), CI jobs that deploy or sign admin txs (checklists 07, 12)
```

---

## Porting to New Repository

When auditing a different repository:

1. **Record** the target's layout at intake (`QUESTIONS.md` Q39 scope, Q44 exclusions → `audit_<n>/intake.md` §1) instead of editing this file
2. **Adapt** the glob patterns above if directories differ (e.g. a native or Pinocchio program with `entrypoint.rs` / `processor.rs` instead of `instructions/`)
3. Checklists 01-07 and 23 are **generic** — they work for any Solana program (Anchor, native `solana-program`, Pinocchio); 21 adds Anchor-specific checks and 22 Token-2022 checks when their markers are present
4. Checklists 11, 12 and 16 are **always-on** — apply to every program repository regardless of framework
5. Off-chain code is out of scope for this skill — list it as excluded (see [Out of Scope](#out-of-scope--off-chain-code))
