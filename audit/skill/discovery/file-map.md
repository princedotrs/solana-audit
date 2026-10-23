# File Discovery Patterns

> Maps each audit checklist to the exact files/globs that must be scanned.  
> These are defaults. A target with another layout records its in-scope paths at intake (`QUESTIONS.md` Q39, exclusions under Q44, written to `audit_<n>/intake.md` §1) instead of editing this file, which a shared install overwrites on update.  
> Scope: Solana on-chain programs (Anchor / native `solana-program` / Pinocchio). Off-chain code — TypeScript / Python / Go clients, backends, frontends, CI workflows, off-chain Rust services — is out of scope for this skill; list it as excluded in Scope Coverage (see [Out of Scope](#out-of-scope--off-chain-code)).

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
├── packages/                       # Shared packages
├── tests/                          # Program tests / fuzz harnesses (checklist 16)
├── target/                         # Build output (gitignored)
│   ├── idl/                        # Generated IDL
│   └── types/                      # Generated TS types
├── Anchor.toml                     # Anchor config
├── Cargo.toml                      # Rust workspace
├── package.json                    # Root package.json
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
  "CpiContext::new("              → Check first arg is Pubkey
  "CpiContext::new_with_signer("  → Check first arg is Pubkey
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
  "total_shares\|total_supply" → Share math invariants (adapt to your token/share field names)
  "total_assets\|total_value"  → Asset tracking field (adapt to your protocol)
  "admin_fee\|mgmt_fee"        → Fee configuration fields
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
  package.json                         # Root (test / deploy tooling)
  apps/*/package.json                  # Client manifests sharing the workspace lockfile
  packages/*/package.json              # Shared
  package-lock.json                    # Lock file
  Cargo.toml                           # Rust workspace
  Cargo.lock                           # Rust lock file

TERMINAL COMMANDS (from a scratch dir OUTSIDE the target tree, on copies of the manifest +
lockfile, toolchain pinned — OUTPUT-RULES Rule 11a, FULL-AUDIT Step 3.2):
  npm audit                            # Known vulnerabilities
  cargo audit                          # Rust vulnerabilities
  npm info <pkg> time                  # Publish date check
  npm outdated                         # Outdated packages
```

### 12 — Secrets & Key Management
```
PRIMARY:
  .gitignore                           # Must exclude secrets
  .env*                                # Should not exist in repo
  Anchor.toml                          # [provider] wallet path, cluster
  scripts/ / migrations/               # Deploy / admin scripts loading keypairs
  apps/**                              # Client code: scanned for secrets only (SEC-014..015, SEC-026..028)

SCAN TARGETS (entire repo):
  **/*.ts
  **/*.tsx
  **/*.json
  **/*.rs
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
```

### 16 — Formal Verification & Testing Quality
```
PRIMARY (CI/CD & Testing):
  .github/workflows/*.yml              # CI pipelines (static analysis, tests)
  Makefile* / scripts/*.sh             # Build/test scripts
  tests/ / **/*test* / **/*spec*       # Test files
  **/*.fuzz.* / **/fuzz_targets/       # Fuzz targets

PROJECT CONFIG:
  .clippy.toml                         # Rust linter config
  .eslintrc* / eslint.config.*         # Linter config for TS test harnesses
  .prettierrc*                         # Formatter config
  codecov.yml / .coveragerc            # Coverage config
  trident-tests/ / Trident.toml        # Trident fuzzing (FV-071)

GREP PATTERNS:
  "proptest\|quickcheck\|fast-check\|hypothesis" → Property-based testing
  "fuzz\|fuzzing\|fuzzer"             → Fuzz testing
  "coverage\|lcov\|tarpaulin\|istanbul" → Coverage measurement
  "clippy\|eslint\|semgrep\|slither"  → Static analysis
  "INVARIANT\|invariant\|conservation" → Documented invariants
  "trident\|mollusk\|litesvm\|kani\|certora" → Solana verification tooling (FV-071)
  ".unwrap()"                          → Panic-prone code in Rust
  "catch {}\|catch(e) {}"             → Swallowed errors
  "@ts-ignore\|@ts-nocheck"           → Suppressed type checks
```

---

## Out of Scope — Off-Chain Code

```
LOCATE (to list as excluded in Scope Coverage, never to audit):
  **/*.rs  EXCLUDING programs/** and target/**   # Off-chain Rust: geyser plugins, indexers, keepers, signer services
  apps/** / clients/** / services/**              # TS / Python / Go clients, backends, frontends
  .github/workflows/*.yml                         # CI pipeline security (read only for checklist 16 test / analysis coverage)

TERMINAL COMMANDS:
  find . -name "*.rs" -not -path "./programs/*" -not -path "./target/*"  # Enumerate off-chain Rust

STILL IN SCOPE THERE:
  Secrets and keypairs (checklist 12), manifests and lockfiles (checklist 11)
```

---

## Porting to New Repository

When auditing a different repository:

1. **Record** the target's layout at intake (`QUESTIONS.md` Q39 scope, Q44 exclusions → `audit_<n>/intake.md` §1) instead of editing this file
2. **Adapt** the glob patterns above if directories differ (e.g. a native or Pinocchio program with `entrypoint.rs` / `processor.rs` instead of `instructions/`)
3. Checklists 01-07 are **generic** — they work for any Solana program (Anchor, native `solana-program`, Pinocchio)
4. Checklists 11, 12 and 16 are **always-on** — apply to every program repository regardless of framework
5. Off-chain code is out of scope for this skill — list it as excluded (see [Out of Scope](#out-of-scope--off-chain-code))
