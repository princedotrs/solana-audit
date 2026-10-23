# Grep & Terminal Commands Reference

> Consolidated command library for this skill (Solana on-chain programs: Anchor / native `solana-program` / Pinocchio).  
> Commands are written as `grep_search` (code search) and `run_in_terminal` (shell) calls — map them to whatever search and terminal tools the agent has.  
> Commands are grouped by **what they detect**.  
> Off-chain code (TypeScript / Python / Go clients, backends, frontends, CI workflows, off-chain Rust services) is out of scope for this skill — locate it only to list it as excluded in Scope Coverage (see [Scope Boundary](#scope-boundary--off-chain-code)).

---

## Quick Reference — Command Categories

| Category | Detects |
|---|---|
| [Account Safety](#account-safety-rust) | `AccountInfo`, missing CHECK, init_if_needed |
| [Arithmetic Safety](#arithmetic-safety-rust) | Bare operators, truncation, missing checked_* |
| [CPI & PDA](#cpi--pda-rust) | CPI targets, invoke vs invoke_signed, seeds |
| [Access Control](#access-control-rust) | Signer mapping, has_one, key checks |
| [State Machine](#state-machine-rust) | Status transitions, events, account closures |
| [Secrets & Keys](#secrets--keys) | Hardcoded keys, env leaks, committed secrets |
| [Supply Chain](#supply-chain) | Compromised packages, audit, publish dates |
| [Infrastructure](#infrastructure) | Build, deploy, upgrade authority, emergency controls |
| [Formal Verification & Testing](#formal-verification--testing-checklist-16) | Fuzz testing, coverage, static analysis, invariants |
| [Token, Sysvar & Modern On-Chain](#token-sysvar--modern-on-chain-kv-101109-kv-135) | Token-2022, ATA, decimals, sysvars, precompiles, ALTs, bumps, revival, Pinocchio, transaction v1 |
| [Scope Boundary](#scope-boundary--off-chain-code) | Off-chain code to list as out of scope |

---

## Account Safety (Rust)

### Deprecated AccountInfo
```
grep_search: "AccountInfo<"   includePattern: "programs/**/*.rs"
```

### CHECK comments (must exist for every UncheckedAccount)
```
grep_search: "UncheckedAccount"   includePattern: "programs/**/*.rs"
grep_search: "/// CHECK:"         includePattern: "programs/**/*.rs"
```
> Cross-reference: every UncheckedAccount MUST have a CHECK comment on the preceding line.

### Reinitialization risk
```
grep_search: "init_if_needed"   includePattern: "programs/**/*.rs"
```

### remaining_accounts usage
```
grep_search: "remaining_accounts"   includePattern: "programs/**/*.rs"
```

### Account close targets
```
grep_search: "close ="   includePattern: "programs/**/*.rs"
```

### init with space calculation
```
grep_search: "#[account(init"   includePattern: "programs/**/*.rs"
```

---

## Arithmetic Safety (Rust)

### Bare operators on financial values
```bash
# Terminal: Find bare +, -, *, / in instruction files (manual review needed)
grep -n '[^_]+ [0-9]\|[0-9] +[^_]' programs/*/src/instructions/*.rs
grep -n '\* [0-9]\|[0-9] \*' programs/*/src/instructions/*.rs
grep -n '/ [0-9]\|[0-9] /' programs/*/src/instructions/*.rs
grep -n '- [0-9]\|[0-9] -' programs/*/src/instructions/*.rs
```

### Verify checked_* usage
```
grep_search: "checked_add|checked_sub|checked_mul|checked_div"   isRegexp: true   includePattern: "programs/**/*.rs"
```

### Dangerous saturating on financial paths
```
grep_search: "saturating_"   includePattern: "programs/**/*.rs"
```

### Truncation casts
```
grep_search: "as u64|as u32|as u16|as u8"   isRegexp: true   includePattern: "programs/**/*.rs"
```

### MathOverflow error usage
```
grep_search: "MathOverflow"   includePattern: "programs/**/*.rs"
```

### Division before multiplication
```bash
# Terminal: Find potential div-before-mul patterns (manual review)
grep -n '\.checked_div.*\.checked_mul\|/ .*\*' programs/*/src/instructions/*.rs
```

---

## CPI & PDA (Rust)

### All CPI calls
```
grep_search: "CpiContext::new"   includePattern: "programs/**/*.rs"
```

### invoke vs invoke_signed
```
grep_search: "invoke("           includePattern: "programs/**/*.rs"
grep_search: "invoke_signed("    includePattern: "programs/**/*.rs"
```
> Any `invoke(` from a PDA authority is a bug — should be `invoke_signed`.

### Token operations
```
grep_search: "token::transfer|token::mint_to|token::burn|token::close_account"   isRegexp: true   includePattern: "programs/**/*.rs"
```

### PDA seeds
```
grep_search: "seeds ="   includePattern: "programs/**/*.rs"
```

### Bump storage
```
grep_search: "bump ="   includePattern: "programs/**/*.rs"
grep_search: "bump"     includePattern: "programs/*/src/state/*.rs"
```

---

## Access Control (Rust)

### Signer mapping
```
grep_search: "Signer<'info>"   includePattern: "programs/**/*.rs"
```

### has_one constraints
```
grep_search: "has_one ="   includePattern: "programs/**/*.rs"
```

### Runtime key checks
```
grep_search: "require_keys_eq!"   includePattern: "programs/**/*.rs"
```

### Hardcoded pubkeys (backdoor risk)
```
grep_search: "Pubkey::new_from_array"   includePattern: "programs/**/*.rs"
```

---

## State Machine (Rust)

### Status enums and transitions
```
# Adapt the enum names below to match your program's actual status types
grep_search: "Status::"             includePattern: "programs/**/*.rs"
grep_search: "status ="             includePattern: "programs/**/*.rs"
```

### Events
```
grep_search: "#[event]"   includePattern: "programs/**/*.rs"
grep_search: "emit!"      includePattern: "programs/**/*.rs"
grep_search: "emit_cpi"   includePattern: "programs/**/*.rs"
grep_search: "msg!"       includePattern: "programs/**/*.rs"
```

### Account closure
```
grep_search: "close ="   includePattern: "programs/**/*.rs"
```

---

## Secrets & Keys

> Checklist 12 is always-on: secrets in deploy scripts, test harnesses and config files that ship with the program repo are in scope even where the surrounding language is not.

### Hardcoded secrets in code
```
grep_search: "private_key|secret_key|mnemonic|seed_phrase"   isRegexp: true   includePattern: "**/*.rs"
grep_search: "private_key|secret_key|mnemonic|seed_phrase"   isRegexp: true   includePattern: "**/*.ts"
grep_search: "-----BEGIN"   includePattern: "**/*"
```

### API keys in code
```
grep_search: "api_key|apiKey|api-key"   isRegexp: true   includePattern: "**/*.ts"
```

### Env var usage
```
grep_search: "process.env"   includePattern: "**/*.ts"
```

### NEXT_PUBLIC_ exposure (SEC-014 / SEC-015)
```
grep_search: "NEXT_PUBLIC_"   includePattern: "apps/web/**/*.ts"
grep_search: "NEXT_PUBLIC_"   includePattern: "apps/web/**/*.tsx"
```

### Committed env/key files
```bash
# Terminal (OUTPUT-RULES Rule 11c flags):
GIT_NO_LAZY_FETCH=1 git --no-pager -c core.fsmonitor=false -c log.showSignature=false \
  ls-files | grep -iE "\.env|keypair|delegate\.json|\.pem|\.key"
find . -name "*.env*" -not -path "./node_modules/*" -not -path "./.git/*"
find . -name "*keypair*" -not -path "./node_modules/*" -not -path "./.git/*"
```

### Git history secrets
```bash
# Terminal (OUTPUT-RULES Rule 11c flags; a pickaxe search runs the repo's textconv drivers unless
# --no-textconv is given). -S also matches files a committed .gitattributes marks -diff or binary;
# -G and patch output (-p) skip their content unless --text is given:
GIT_NO_LAZY_FETCH=1 git --no-pager -c core.fsmonitor=false -c log.showSignature=false \
  log --all --no-textconv --no-ext-diff -S "private" --oneline | head -20
GIT_NO_LAZY_FETCH=1 git --no-pager -c core.fsmonitor=false -c log.showSignature=false \
  log --all --no-textconv --no-ext-diff -S "secret" --oneline | head -20
GIT_NO_LAZY_FETCH=1 git --no-pager -c core.fsmonitor=false -c log.showSignature=false \
  log --all --no-textconv --no-ext-diff -S "BEGIN RSA" --oneline | head -20
```

---

## Supply Chain

> Every package-manager or cargo command in this section reads the target's `.npmrc`, `.cargo/config*` and `rust-toolchain*` when started inside its tree. Run them from a scratch dir OUTSIDE the target tree, on copies of the manifest + lockfile with the toolchain pinned (OUTPUT-RULES Rule 11a; FULL-AUDIT Step 3.2).

### Check for compromised packages
```bash
# Terminal:
grep -E "axios.*1\.14\.1|axios.*0\.30\.4" package-lock.json
# from a scratch dir OUTSIDE the target tree holding copies of package.json + the lockfile (OUTPUT-RULES Rule 11a)
npm audit
```

### Hijacked `@solana/web3.js` releases (SC-005)
```bash
# Terminal: exact pins and resolved versions in package-lock / pnpm / yarn v1 + berry / bun;
# ranges such as "^1.95.7" do not match on their own:
W3='web3\.js@(npm:)?1\.95\.(6|7)([^0-9]|$)|/web3\.js/-/web3\.js-1\.95\.(6|7)\.tgz|"@solana/web3\.js"[[:space:]]*:[[:space:]]*"=?1\.95\.(6|7)"'
grep -rnE "$W3" --exclude-dir=node_modules --include='package.json' --include='package-lock.json' \
  --include='pnpm-lock.yaml' --include='yarn.lock' --include='bun.lock' .
# ...and anywhere in history (OUTPUT-RULES Rule 11c flags; --text because a committed .gitattributes can mark
# lockfiles binary, which hides them from -G):
GIT_NO_LAZY_FETCH=1 git --no-pager -c core.fsmonitor=false -c log.showSignature=false -c core.bigFileThreshold=512m \
  log --all --oneline --text --no-textconv --no-ext-diff -G"$W3" -- '*lock*' '*package.json'
```
> PASS: zero matches in the tree, and either zero matches in history or evidence that every key a build from that window loaded was rotated. FAIL: compromised version in the tree — CRITICAL; or a 1.95.6 / 1.95.7 hit in history with no evidence of rotation — every key a build containing it loaded is exposed. A `fatal:` or `lazy fetching disabled` line means a partial clone (OUTPUT-RULES Rule 11c): the history search did not run, so it is never a PASS.

### Package publish dates (14-day quarantine)
```bash
# Terminal: Check publish date for critical packages
npm info @anchor-lang/core time --json | tail -5
```

### Outdated packages
```bash
# Terminal:
npm outdated
cargo outdated  # if cargo-outdated installed
```

### License check
```bash
# Terminal:
npx license-checker --summary
```

---

## Infrastructure

### Program upgrade authority
```bash
# Terminal:
solana program show <PROGRAM_ID> --url mainnet-beta
```

### Anchor build verification
```bash
# Terminal — builds the target (build.rs, proc-macros): only in the OUTPUT-RULES Rule 11a mode recorded at intake
anchor build 2>&1 | tail -20
```

### Test suite
```bash
# Terminal — runs the target's tests and Anchor.toml [scripts]: only in the OUTPUT-RULES Rule 11a mode recorded at intake
anchor test --validator legacy 2>&1 | tail -30
```

### Binary hash verification
```bash
# Terminal — rebuilds the target from source: only in the OUTPUT-RULES Rule 11a mode recorded at intake
anchor verify <PROGRAM_ID> --provider-url mainnet-beta
```

### Emergency / pause mechanisms (checklist 07)
```
grep_search: "pause|freeze|emergency|circuit.?breaker"   isRegexp: true   includePattern: "programs/**/*.rs"
```

---

## Using These Commands

### From SKILL.md / Agent Invocation
The auditor agent should use `grep_search` tool calls with these patterns.  
For terminal commands, use `run_in_terminal`.

### Manual Execution
Copy-paste terminal commands into a system terminal.

### Batch Execution
When running a FULL audit (see FULL-AUDIT.md), execute commands per phase:
- Phase 1 (On-chain): Account Safety + Arithmetic + CPI/PDA + Access Control + State Machine + Token, Sysvar & Modern On-Chain
- Phase 2 (DevOps): Secrets + Supply Chain + Infrastructure
- Phase 3 (Verification): Formal Verification & Testing
- Scope Boundary: run once at intake to list excluded off-chain code

---

## Formal Verification & Testing (Checklist 16)

### Property-based / Fuzz testing
```
grep_search: "proptest|quickcheck|fast-check|hypothesis|fuzzing|fuzz_target"   isRegexp: true   includePattern: "**/*"
```

### Static analysis config
```
grep_search: "clippy|eslint|semgrep|slither|mythril"   isRegexp: true   includePattern: "**/*"
```

### Coverage tooling
```
grep_search: "coverage|lcov|tarpaulin|istanbul|c8|nyc"   isRegexp: true   includePattern: "**/*"
```

### Test quality indicators
```
grep_search: "describe\(|it\(|test\(|#\[test\]|#\[tokio::test\]"   isRegexp: true   includePattern: "**/*test*"
```

### Panic-prone code (Rust)
```
grep_search: ".unwrap()"   includePattern: "programs/**/*.rs"
grep_search: ".expect("    includePattern: "programs/**/*.rs"
```

### Suppressed type checking
```
grep_search: "@ts-ignore|@ts-nocheck|#\\[allow\\(clippy"   isRegexp: true   includePattern: "**/*"
```

### Swallowed errors
```
grep_search: "catch {}|catch(e) {}|catch (_) {}"   isRegexp: true   includePattern: "**/*.ts"
```

### Documented invariants
```
grep_search: "INVARIANT|invariant|conservation|SAFETY:"   isRegexp: true   includePattern: "**/*"
```

---

## Token, Sysvar & Modern On-Chain (KV-101..109, KV-135)

### SPL Token & Token-2022 extensions (KV-105, KV-107, KV-108)
```
grep_search: "token_2022|spl_token_2022|token_interface|TokenInterface|InterfaceAccount"   isRegexp: true   includePattern: "programs/**/*.rs"
grep_search: "permanent_delegate|default_account_state|transfer_fee|confidential|interest_bearing|close_authority|get_extension"   isRegexp: true   includePattern: "programs/**/*.rs"
grep_search: "transfer_checked|mint_to_checked|burn_checked"   isRegexp: true   includePattern: "programs/**/*.rs"
```
> Flag plain `token::transfer` where `transfer_checked` should bind decimals/mint. Flag arbitrary-mint acceptance without extension inspection.

### Associated Token Account assumptions (KV-107)
```
grep_search: "associated_token|get_associated_token_address|getAssociatedTokenAddress"   isRegexp: true   includePattern: "programs/**/*.rs"
```
> Verify `associated_token::mint`/`authority`/`token_program` constraints — not a bare `Account<TokenAccount>` where the canonical ATA is assumed.

### Token decimals / cross-mint amount confusion (KV-108)
```
grep_search: "decimals|10u64\\.pow|10\\.pow|1_000_000|1e6|1e9"   isRegexp: true   includePattern: "programs/**/*.rs"
```
> Flag hardcoded decimals constants and raw cross-mint amount math.

### Sysvar spoofing (KV-101)
```
grep_search: "Clock::get|Rent::get"   isRegexp: true   includePattern: "programs/**/*.rs"
grep_search: "UncheckedAccount.*[Cc]lock|AccountInfo.*[Cc]lock|Sysvar<'info,"   isRegexp: true   includePattern: "programs/**/*.rs"
```
> Time/rent must come from syscalls or `Sysvar<'info, T>` — never an unchecked passed account.

### Precompile signature introspection (KV-102)
```
grep_search: "load_instruction_at|get_instruction_relative|instructions_sysvar|ed25519_program|secp256k1_program|load_current_index"   isRegexp: true   includePattern: "programs/**/*.rs"
```
> Verify program-ID check + message/pubkey/offset binding + replay protection.

### Address Lookup Table & positional trust (KV-103)
```
grep_search: "remaining_accounts|accounts\\[[0-9]+\\]"   isRegexp: true   includePattern: "programs/**/*.rs"
```

### PDA bump canonicalization (KV-104)
```
grep_search: "create_program_address|find_program_address"   isRegexp: true   includePattern: "programs/**/*.rs"
```
> Any user-supplied bump fed to `create_program_address` is a finding. Bumps must be canonical, stored, and reused.

### Account revival after close (KV-106)
```
grep_search: "close = |CLOSED_ACCOUNT_DISCRIMINATOR|try_borrow_mut_lamports|\\*\\*lamports|init_if_needed"   isRegexp: true   includePattern: "programs/**/*.rs"
```
> Manual closes must zero the discriminator AND drain all lamports; guard `init_if_needed` against revival with stale state.

### Native / Pinocchio / p-token (KV-109)
```
grep_search: "pinocchio|p-token|p_token|no_std"   isRegexp: true   includePattern: "**/Cargo.toml"
grep_search: "entrypoint!|program_entrypoint!|fn process_instruction"   isRegexp: true   includePattern: "programs/**/*.rs"
grep_search: "is_signer|is_writable|\\.owner\\(\\)|owner =="   isRegexp: true   includePattern: "programs/**/*.rs"
grep_search: "unsafe|get_unchecked|from_raw_parts|\\.add\\(|unsafe-account-resize"   isRegexp: true   includePattern: "programs/**/*.rs"
```
> No Anchor safety net: every owner/signer/mut/length/discriminator check is manual. Bounds-check zero-copy reads; validate `unsafe-account-resize` size; for p-token, diff against canonical `spl-token` edge cases.

---

### Transaction v1 readiness (KV-135)
```
grep_search: "load_instruction_at|get_instruction_relative"   isRegexp: true   includePattern: "programs/**/*.rs"
grep_search: "ComputeBudget|SetComputeUnitPrice|computeUnitPrice|micro.?lamports"   isRegexp: true   includePattern: "**/*.{ts,rs,py,go}"
grep_search: "feePayer|fee_payer|sponsor|paymaster|gasless|partialSign"   isRegexp: true   includePattern: "apps/**/*.{ts,rs,py}"
```
> Every program introspection must not gate on ComputeBudget instructions; every ComputeBudget scan must have a v1 `transactionConfig` branch; every fee-payer service must detect version on the raw bytes (`0x81`) before its cap. See `references/vuln-classes/transaction-v1.md`.

---

## Scope Boundary — Off-Chain Code

```bash
# Terminal: locate off-chain Rust (geyser plugins, indexers, keeper/liquidator bots, signer services)
find . -name "*.rs" -not -path "./programs/*" -not -path "./target/*" -not -path "*/node_modules/*"
grep -rnE "geyser|GeyserPlugin|yellowstone|carbon|substreams|indexer|keeper|liquidator|crank|bot" --include="*.rs" -l . | grep -v "/programs/"
```
> Any `.rs` outside `programs/` (and any TypeScript / Python / Go client, backend, frontend or CI workflow) is off-chain code with a different threat model (network input, RPC trust, long-lived keys) and is out of scope for this skill. List it as excluded in Scope Coverage; do not route it through the on-chain checklists. Secrets it holds are still in scope for checklist 12, and its manifests and lockfiles for checklist 11.
