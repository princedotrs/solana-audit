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
1. Read [OUTPUT-RULES.md](OUTPUT-RULES.md) — the output format is non-negotiable
2. Run discovery and declare the audit SCOPE (Rule 0 in OUTPUT-RULES.md) — do NOT bulk-read the corpus
3. Load only the in-scope checklists/vectors, on demand as each phase reaches them
4. Detect languages in the repo (Rule 7 in OUTPUT-RULES.md) — this determines which checklists to apply
5. Create a session checkpoint file to track progress across chunks (Rule 3 in OUTPUT-RULES.md)
6. Remember: **walk the code file by file — never one-shot** (Rule 3)
7. Apply **Operating Safety** ([OUTPUT-RULES.md Rule 11](OUTPUT-RULES.md#rule-11-operating-safety)) before anything runs: take the execution mode recorded at intake (11a — isolated recommended, native allowed with a report caveat), list every outside service a tool contacts (11b), treat a `.git/` you did not clone yourself as untrusted (11c), and make `.gitignore` containing `*` the first file in `audit_<n>/` (11d)
8. Resolve every bundled path in this file (`tools/`, `templates/`, `scripts/`, `discovery/`, the corpus) from `<skill-root>` — the directory containing this skill's SKILL.md, never the audited repo, which is the working directory ([Rule 11e](OUTPUT-RULES.md#11e--bundled-paths)). Nothing is filled in here, so it is written `<skill-root>` below; substitute the absolute path. The executables this plan runs: `"<skill-root>/tools/auditor-tools/target/release/audit-scan"` and `"<skill-root>/tools/auditor-tools/target/release/audit-mem"`. Trail of Bits tooling is optional: if the Trail of Bits skills (https://github.com/trailofbits/skills, CC-BY-SA-4.0) are installed separately, delegate SAST / fuzzing / coverage harnesses per [references/orchestration/boundary-map.md](references/orchestration/boundary-map.md); otherwise use the native grep checks in [discovery/grep-commands.md](discovery/grep-commands.md) and note the tooling gap in the report's Coverage & Limitations

---

## PHASE -1: SCOPE DECLARATION

Declare scope per OUTPUT-RULES Rule 0 + SKILL Scope-Gated Loading; record the Scope Coverage table below (per checklist/vector group: in-scope yes/no + trigger).

| Checklist / vector group | In scope? | Trigger |
|--------------------------|-----------|---------|
| 01–07 on-chain (Rust / Anchor / native / Pinocchio) | yes/no | `.rs` program crate / `Anchor.toml` / `solana-program` or `pinocchio` dependency |
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

| Instruction | Signer | has_one constraints | CPIs | Arithmetic ops | State mutations |
|-------------|--------|-------------------|------|----------------|-----------------|
| ...         | ...    | ...               | ...  | ...            | ...             |

Save this matrix — it's used by checklists 01-06.
```

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
- **≥ 3 invariants** it must preserve · **≥ 5 assumptions** about inputs / accounts / caller · **≥ 3 external-interaction risks** (CPIs, sysvars, `remaining_accounts`, oracle reads).
- **Cross-function dependencies** — shared state, ordering assumptions.

Anti-hallucination rules (mandatory):

- Every claim cites a line (`L#`).
- The words "probably", "might", "seems", "should" are banned. If you cannot state it from the code, write `UNKNOWN — needs manual review`.
- Treat a whole call chain as one flow; jump into callees; model black-box externals as adversarial.

Output worksheets to `audit_<n>/worksheets/context/{fn}.md`. These feed the Rule 5b validation gate.

---

## PHASE 1: ON-CHAIN PROGRAM AUDIT (Checklists 01-06)

### Execution Strategy

The on-chain audit proceeds **instruction-by-instruction**. For each instruction file:

1. Open the file
2. Run items from checklists 01 (account validation), 02 (access control), 03 (arithmetic), 04 (CPI/PDA) that apply
3. Record findings inline

After all instructions are reviewed individually, run the **cross-cutting** checks:
- Checklist 05 (state machine) — requires full lifecycle view
- Checklist 06 (economic/logic) — requires understanding of all instructions together

### Step 1.1 — Per-Instruction Deep Review

```
FOR EACH instruction file in programs/*/src/instructions/:

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

  # Incident runbooks (input to Phase 4.5 category 9)
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

---

## PHASE 4.5: MATURITY ASSESSMENT

Orthogonal to the risk score: the risk score is the *deploy gate*; this scorecard is the *engineering-quality gate*. Rate each category 0-4 (0 absent · 1 ad-hoc · 2 partial · 3 good · 4 strong), weakest-link. *(Pattern credit: Trail of Bits `code-maturity-assessor`.)*

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
| 9 | Monitoring & Incident Response | event emission coverage, runbooks, alerting |

Emit the scorecard as a dedicated report section (see `templates/report-template.md`). Categories scoring ≤ 1 are prioritized in the Remediation Roadmap regardless of individual finding severity.

---

## PHASE 5: REPORT GENERATION

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

---

## EXECUTION NOTES

### Walk The Code — Never One-Shot

Chunking (on-chain chunk size: 1 instruction file) + checkpoint format → OUTPUT-RULES.md Rule 3. Save a checkpoint after each chunk; if context is lost, resume from the checkpoint's `Next Action`.

### Parallelization
- Steps 3.1, 3.2, 3.3, 3.4 are independent — can run commands in parallel
- Steps 4.1, 4.2 are independent
- Phase 1 must be sequential (instruction review builds context)

### Scope Control
- `FULL`: Checklists 01-07, 11, 12, 16 + in-scope known vectors, all program files
- `PROGRAM`: Checklists 01-07, 16 (on-chain + opsec + verification)
- `OPSEC`: Checklists 07, 11, 12, 16 (governance + supply chain + secrets + verification)
- Off-chain code (backends, frontends, TS/Python/Go, off-chain Rust services) is out of scope for every mode

### Language Auto-Detection
Language → checklist mapping is authoritative in [SKILL.md](SKILL.md) → Scope-Gated Loading, Step 2 (scope table); see also OUTPUT-RULES.md Rule 7. The auditor scans file extensions/markers (`Anchor.toml`, `solana-program` / `pinocchio` dependencies, program crates) and applies the correct checklists.
