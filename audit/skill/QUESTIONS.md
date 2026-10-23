# Pre-Audit Questionnaire

> These questions must be answered before running a full audit.
> The auditor agent uses these answers to contextualize findings, skip N/A sections, and calibrate severity.
> Most are multiple-choice or yes/no. Some require short text answers.
>
> **Scope of this skill:** Solana on-chain programs only — Rust with Anchor, native `solana-program`, or Pinocchio. Off-chain code (TypeScript / Python / Go clients, backends, frontends, infrastructure) is out of scope; questions about it are recorded only so the report can list it as out of scope. Question numbers are kept stable (retired questions keep their number) so intake references stay aligned.
>
> **For automated pipelines:** parse this as YAML or collect via form UI.
> **For manual use:** copy this file, fill in your answers, and include it when invoking the audit.

---

## Section 1: Project Overview

### Q1. Project type
What kind of project is this?
- [ ] DeFi protocol (DEX, lending, staking, yield)
- [ ] NFT / digital collectibles
- [ ] DAO / governance
- [ ] Payment / wallet infrastructure
- [ ] Gaming / metaverse
- [ ] Social / identity
- [ ] Infrastructure / tooling
- [ ] Other: _______________

### Q2. Blockchain
Which blockchain(s) does this project target?
- [ ] Solana
- [ ] Solana + other chains (cross-chain / bridge) — only the Solana programs are in scope
- [ ] Not Solana — out of scope for this skill
- [ ] Other: _______________

### Q3. On-chain program framework
What framework do the Solana programs use?
- [ ] Anchor
- [ ] Native Solana (`solana-program`, no framework)
- [ ] Pinocchio
- [ ] Mixed (list per program): _______________
- [ ] Other: _______________

### Q4. Off-chain components in the repository (out of scope)
Recorded so the report can list them under out of scope; they are not reviewed.
- [ ] TypeScript / JavaScript client or SDK
- [ ] Backend / API service
- [ ] Frontend / dApp UI
- [ ] Keeper / crank / bot
- [ ] Scripts / tooling (Python, Go, shell, …)
- [ ] None
- [ ] Other: _______________

### Q5. Programs in scope
List each on-chain program (crate path and program ID if deployed):
```
_______________
_______________
```

### Q6. Toolchain versions
- Anchor version (if used): _______________
- `solana-program` / Agave crate version: _______________
- Pinocchio version (if used): _______________
- Rust toolchain pinned (`rust-toolchain.toml`)? [ ] Yes [ ] No

### Q7. Monorepo structure?
- [ ] Yes — monorepo (Turborepo, Nx, Lerna, or workspace)
- [ ] No — single package
- [ ] Multiple repos (list them): _______________

---

## Section 2: Deployment & Environment

### Q8. Current deployment status
- [ ] Not yet deployed (pre-launch)
- [ ] Deployed on testnet/devnet only
- [ ] Deployed on mainnet (live with real funds)
- [ ] Deprecated / no longer maintained

### Q9. Deployed program IDs
Which cluster(s), and which program ID per program?
```
Cluster (mainnet-beta / devnet / testnet / localnet only): _______________
Program ID(s): _______________
```

### Q10. Total Value Locked (TVL) or funds at risk
How much value does the protocol currently manage?
- [ ] $0 (not launched)
- [ ] <$10K
- [ ] $10K–$100K
- [ ] $100K–$1M
- [ ] $1M–$10M
- [ ] >$10M
- [ ] Unknown

> **Why this matters:** Severity calibration. A missing signer check is Severity 10 for a $10M protocol but may be Severity 7 for a $1K testnet deployment.

### Q11. Is the smart contract upgradeable?
- [ ] Yes — upgrade authority is a single wallet
- [ ] Yes — upgrade authority is a multisig
- [ ] Yes — upgrade authority is a DAO/governance
- [ ] No — program is frozen/immutable
- [ ] Not applicable

### Q12. Is the source code public?
- [ ] Yes — fully open source
- [ ] Partially — programs public, off-chain code private
- [ ] No — fully private
- [ ] Planning to open source

---

## Section 3: Authentication & Access Control

### Q13. How do the programs authorize callers?
- [ ] Transaction signer (`Signer` / `is_signer`) on the user's wallet
- [ ] PDA-signed delegation (another program signs via `invoke_signed`)
- [ ] Session keys / delegated signers
- [ ] Multisig signer (e.g. Squads vault)
- [ ] Signature verified on-chain via the Ed25519 / secp256k1 precompile (off-chain signed message)
- [ ] No authorization (permissionless instructions only)
- [ ] Multiple: _______________

### Q14. Are there different user roles?
- [ ] Yes — admin/manager and regular users
- [ ] Yes — multiple tiers (admin, manager, investor, viewer, etc.)
- [ ] No — all users have equal access
- [ ] Describe roles: _______________

### Q15. Do the programs have admin instructions?
- [ ] Yes — on-chain admin / authority instructions (set params, pause, withdraw fees, …)
- [ ] Yes — driven from an off-chain admin UI or API (the UI/API itself is out of scope; the on-chain instructions it calls are in scope)
- [ ] No admin functionality

### Q16. How are admin instructions protected on-chain?
- [ ] Single-key authority signer (same key as upgrade authority)
- [ ] Single-key authority signer (separate key)
- [ ] Multisig authority
- [ ] Timelock + multisig
- [ ] DAO / governance program
- [ ] Not protected (❌ this is a finding)
- [ ] Not applicable

---

## Section 4: Financial Operations

### Q17. Does the protocol handle user funds?
- [ ] Yes — users deposit tokens/SOL into protocol-controlled accounts
- [ ] Yes — users approve spending but funds stay in their wallet
- [ ] No — no financial operations

### Q18. What tokens are supported?
- [ ] SOL / WSOL only
- [ ] SOL + specific SPL tokens (list): _______________
- [ ] Any SPL token
- [ ] Token-2022 (token extensions) supported
- [ ] Not applicable

### Q19. Does the protocol integrate with DEXes?
- [ ] Yes — Jupiter (Solana)
- [ ] Yes — Raydium
- [ ] Yes — Orca
- [ ] No DEX integration
- [ ] Other: _______________

### Q20. Does the protocol charge fees?
- [ ] Yes — management fee (% of AUM)
- [ ] Yes — performance fee (% of profits)
- [ ] Yes — transaction/swap fee
- [ ] Yes — withdrawal fee
- [ ] No fees
- [ ] Describe fee structure: _______________

### Q21. Is there a withdrawal process?
- [ ] Instant withdrawal
- [ ] Multi-step withdrawal (initiate → wait → finalize)
- [ ] Time-locked withdrawal (cooldown period)
- [ ] Admin-approved withdrawal
- [ ] No withdrawals (one-way deposit)
- [ ] Describe: _______________

---

## Section 5: External Integrations

### Q22. Which external data or transaction flows do the programs depend on?
Off-chain services themselves are out of scope; this records what the on-chain code trusts.
- [ ] Jupiter (swap routes / quotes passed into the program)
- [ ] Off-chain price source (Birdeye, CoinGecko, …) pushed on-chain by a keeper
- [ ] Geyser / Yellowstone gRPC stream or a transaction / block indexer (reads `getTransaction` / `getBlock` / `blockSubscribe`)
- [ ] Fee sponsorship / paymaster / co-signing — the project signs as fee payer or second signer for user-built transactions, or a program introspects the transaction (instructions sysvar)
- [ ] Chainlink / Pyth (oracles)
- [ ] None
- [ ] Other: _______________

### Q23. Does the protocol use oracles for pricing?
- [ ] Yes — Pyth Network
- [ ] Yes — Switchboard
- [ ] Yes — Chainlink
- [ ] Yes — custom oracle / API-based pricing
- [ ] No — prices from DEX quotes only
- [ ] No — no price feeds needed

### Q24. Does the protocol use cross-program invocations (CPI)?
- [ ] Yes — Token Program (SPL transfers)
- [ ] Yes — Associated Token Program
- [ ] Yes — DEX program (Jupiter, Raydium, etc.)
- [ ] Yes — Staking program
- [ ] Yes — Other: _______________
- [ ] No CPI

---

## Section 6: Security History

### Q25. Has this code been audited before?
- [ ] Yes — by a professional audit firm (name): _______________
- [ ] Yes — internal review only
- [ ] Yes — automated tools only (name): _______________
- [ ] No — first audit

### Q26. Has the protocol experienced any security incidents?
- [ ] Yes — fund loss (amount): _______________
- [ ] Yes — exploit attempt (blocked successfully)
- [ ] Yes — key compromise
- [ ] No known incidents
- [ ] Prefer not to disclose

### Q27. Is there a bug bounty program?
- [ ] Yes — public (platform): _______________
- [ ] Yes — private/invite-only
- [ ] No — planning to create one
- [ ] No

### Q28. Do you have incident response procedures?
- [ ] Yes — documented and tested
- [ ] Yes — documented but untested
- [ ] Informal / ad-hoc
- [ ] No

---

## Section 7: Development Practices

### Q29. How many developers have access to the repository?
- [ ] 1 (solo developer)
- [ ] 2-5
- [ ] 6-20
- [ ] 20+

### Q30. Do you use branch protection?
- [ ] Yes — PRs required, reviews required
- [ ] Yes — PRs required, no mandatory reviews
- [ ] No — anyone can push to main
- [ ] Not applicable (solo dev)

### Q31. Do you have CI/CD?
- [ ] Yes — GitHub Actions
- [ ] Yes — GitLab CI
- [ ] Yes — Other: _______________
- [ ] No CI/CD

### Q32. Do you run automated tests?
- [ ] Yes — unit tests
- [ ] Yes — integration tests
- [ ] Yes — end-to-end tests
- [ ] Yes — Anchor program tests
- [ ] Yes — LiteSVM / Mollusk tests
- [ ] Yes — fuzzing (e.g. Trident)
- [ ] No automated tests

### Q33. Do you use a secret scanner?
- [ ] Yes — GitHub secret scanning
- [ ] Yes — gitleaks / trufflehog / detect-secrets
- [ ] Yes — pre-commit hooks with secret detection
- [ ] No secret scanning

### Q34. What's your dependency update strategy?
- [ ] Dependabot / Renovate (automated PRs)
- [ ] Manual periodic updates
- [ ] Pin exact versions and update carefully
- [ ] No strategy — install once and forget
- [ ] 14-day quarantine rule (never install packages <14 days old)

---

## Section 8: Compliance & Legal (Retired)

Compliance, privacy and server-location review is out of scope for this skill. Q35–Q38 are retired; their numbers are kept so references to later questions stay aligned. Skip this section.

---

## Section 9: Scope & Priorities

### Q39. What should this audit focus on?
Select all that apply, or choose "Full":
- [ ] **Full audit** (every in-scope program, checklists 01-07 plus always-on 11, 12, 16)
- [ ] On-chain program logic only (checklists 01-07)
- [ ] Specific programs / instructions: _______________
- [ ] Secrets & key management only
- [ ] Supply chain / dependencies only
- [ ] Specific files/modules: _______________

### Q40. What are your top security concerns?
Rank your top 3:
- [ ] Fund theft / drain
- [ ] Private key compromise
- [ ] Denial of service / compute exhaustion / account bricking
- [ ] Privilege escalation / admin takeover
- [ ] Upgrade authority / governance capture
- [ ] Supply chain attack
- [ ] Insider threat
- [ ] Operational security
- [ ] Other: _______________

### Q41. Desired audit depth
- [ ] **Quick scan** — grep-based pattern matching, known vector check (~30 min, lowest cost)
- [ ] **Standard** — full checklist + known vectors, file-by-file review (~1-2 hours)
- [ ] **Deep** — standard + economic attack scenarios, cross-file analysis, formal property verification (~2-4 hours)
- [ ] **Maximum** — deep + manual verification steps, deployment & governance review (checklist 07) (~4-8 hours)

### Q42. Report delivery preference
- [ ] Markdown file in repo
- [ ] JSON (machine-parseable)
- [ ] Both markdown and JSON
- [ ] PDF (formatted)

---

## Section 10: Repository Access

### Q43. How will the auditor access the code?

**Option A: Open-source repo (recommended for public projects)**
```
Repository URL: _______________
Branch to audit: _______________
Commit hash (optional): _______________
```

**Option B: Local checkout in the auditor's workspace (recommended for private repos)**
```
Install this skill outside your repository (at a user-level skills path of your
AI coding agent; OUTPUT-RULES.md Rule 11e), then invoke the audit from that agent
in the repository.
```

**Option C: Upload files (for web-based service)**
```
Upload a ZIP/tar of your repository (without node_modules, .git, build artifacts).
Max size: ___ MB
```

### Q44. Any files or directories to EXCLUDE from audit?
```
Exclude patterns (one per line):
_______________
_______________
_______________
```

### Q45. Any additional context the auditor should know?
```
Free text — known issues, recent changes, areas of concern, etc.:
_______________
```

---

## Section 11: Audit Execution

### Q46. Where may the auditor run the project's own code?
Building, testing or installing the project runs code the project controls — build scripts, proc-macros, test suites, `Anchor.toml` scripts, package install hooks. Asked once per audit; see `OUTPUT-RULES.md` Rule 11a.
- [ ] **Isolated** (recommended) — a container, VM, or agent sandbox, with no keys or credentials mounted
- [ ] **Native** — on the auditor's own machine (the report says so)
- [ ] No preference — recorded as **native** (also the default when automated runs leave Q46 unanswered), and the report carries that caveat

> Tools that send code, dependency names or addresses to outside services (an RPC provider, a second-opinion LLM, package registries) are not gated by this answer; the report lists each one (Rule 11b).

---

## How Answers Affect the Audit

| Answer | Effect |
|--------|--------|
| Q1 = DeFi | Enables economic attack scenarios (checklists 06, known vectors 1-30) |
| Q2 = Solana | Enables the on-chain program checklists (01-07); always-on 11, 12, 16 run regardless. Q2 = Not Solana → stop: out of scope for this skill |
| Q3 = Anchor / Native / Pinocchio | Loads the matching `references/framework-idioms/{anchor,native,pinocchio}.md` |
| Q4 = any off-chain component | Listed as out of scope in the report; not reviewed |
| Q8 = Mainnet live | Increases all severity scores by 1 for fund-related findings |
| Q10 > $1M | Doubles the weight of critical findings in risk score |
| Q11 = Single wallet | Auto-flags as Severity 8+ finding |
| Q17 = Yes | Requires full economic review (checklist 06) |
| Q18 = Token-2022 | Loads `references/methodologies/token-2022.md` + KV-018 / KV-023 / KV-105 / KV-134 (fee-on-transfer, transfer hook, extension abuse, Token ACL gate) + checklist 01 §1.8 |
| Q22 = Geyser stream / indexer or fee sponsorship / introspection | Loads `references/vuln-classes/transaction-v1.md` + KV-135 (transaction v1: fee-sponsor cap bypass, program introspection) |
| Q25 = First audit | Triggers more thorough analysis, no assumptions about prior fixes |
| Q32 = No tests | Auto-flags testing gaps, enables checklist 16 recommendations |
| Q39 = Specific scope | Skips irrelevant checklists, reduces cost/time |
| Q41 = Quick scan | Uses grep + known vectors only, skips semantic analysis |
| Q46 = Isolated | Builds, tests, installs and every PoC build run in a container / VM / sandbox (`OUTPUT-RULES.md` Rule 11a); a step that cannot run there keeps its source-level verdict, and a PoC records `[PoC-ATTEMPTED]` |
| Q46 = Native, or unanswered | Target-controlled code runs on the auditor's machine; the report's Coverage & Limitations states it |
