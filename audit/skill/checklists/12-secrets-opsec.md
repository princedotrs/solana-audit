# 12 — Secrets & Key Management Checklist

> Domain: Program keypairs, upgrade / admin / deploy keys, and the scripts, config and CI that load them  
> Severity if missed: CRITICAL (exposed program, upgrade-authority or admin key) to MEDIUM (exposed devnet-only or low-privilege key)  
> References: Solana CLI keypair conventions (`~/.config/solana/id.json`, `target/deploy/<program>-keypair.json`), OWASP secrets management
>
> Scope: keys that deploy, upgrade, administer or hold a role in the program. Off-chain application secrets (frontend RPC / API keys, database and server credentials, container images) are out of scope.

Every item below is a single verification step. Mark each `[PASS]`, `[FAIL-{severity}]`, `[PARTIAL]`, or `[N/A]`.

---

## 12.1 — No Hardcoded Secrets

- [ ] **SEC-001**: `grep -rnE "private_?key|secret_?key" --include="*.rs" --include="*.ts" --include="*.json" --include="*.toml" .` — no private keys in program code, tests, deploy / migration / admin scripts or config
- [ ] **SEC-002**: `grep -rn "secret" --include="*.rs" --include="*.ts" --include="*.json" --include="*.toml" --include="*.env*" .` — check all matches
- [ ] **SEC-003**: `grep -rnE "mnemonic|seed phrase|seed_phrase" --include="*.rs" --include="*.ts" --include="*.json" --include="*.toml" .` — zero results
- [ ] **SEC-005**: No base58-encoded private keys in any file: a 64-byte Solana keypair encodes to 86–88 base58 characters (almost always 87–88) (`grep -rnE '[1-9A-HJ-NP-Za-km-z]{86,88}'`); 32–44-character strings are public keys
- [ ] **SEC-006**: No JSON keypair files committed (`.json` files with 64-element integer arrays)
- [ ] **SEC-007**: No Solana keypair files in repo (check for `id.json`, `*-keypair.json`, `*-delegate.json`)
- [ ] **SEC-008**: No `.env` files committed to git — check `GIT_NO_LAZY_FETCH=1 git --no-pager -c core.fsmonitor=false -c log.showSignature=false log --all --no-textconv --name-only | grep -i ".env"` (OUTPUT-RULES Rule 11c flags)

## 12.2 — Cluster Separation

- [ ] **SEC-017**: Localnet/devnet and mainnet use different keypairs and wallet paths — `Anchor.toml` `[provider] wallet`, deploy-script defaults and CI variables never point a devnet flow at a mainnet authority key, or the reverse

## 12.3 — Git Hygiene

- [ ] **SEC-018**: `.gitignore` includes: `.env`, `.env.*`, `*.pem`, `*-keypair.json`, `*-delegate.json`, `id.json`
- [ ] **SEC-019**: `.gitignore` includes `target/` (it holds the program keypair `target/deploy/<program>-keypair.json`), `.anchor/` and `test-ledger/`; a committed program keypair lets anyone claim that program ID on every cluster where it is not yet deployed
- [ ] **SEC-020**: Run `GIT_NO_LAZY_FETCH=1 git --no-pager -c core.fsmonitor=false -c log.showSignature=false log --all --no-textconv --diff-filter=A --name-only` (OUTPUT-RULES Rule 11c flags) — check if secrets were EVER committed (even if now deleted)
- [ ] **SEC-021**: If any secret was ever committed — it MUST be rotated (deleting from git history is not sufficient)
- [ ] **SEC-022**: Pre-commit hooks: is there a secret detection hook? (gitleaks, detect-secrets, etc.)
- [ ] **SEC-023**: No `.env` in any branch (check all branches, not just current)
- [ ] **SEC-024**: Commit messages don't contain private keys, seed phrases or keypair bytes

## 12.5 — Wallet & Program Key Safety

- [ ] **SEC-033**: Program deploy keypair — NOT stored on dev machine for mainnet
- [ ] **SEC-034**: Program deploy keypair — on hardware wallet (Ledger) or multisig for mainnet
- [ ] **SEC-035**: Program authority keypair — separate from deploy keypair (defense-in-depth)
- [ ] **SEC-036**: Keeper / crank / relayer wallet that holds an on-chain role — holds minimum SOL (fees and rent only), no other tokens
- [ ] **SEC-037**: Keeper / crank / relayer wallet — key loaded from a secrets manager, KMS or HSM, not a keypair file committed to the repo or baked into a build artifact
- [ ] **SEC-038**: Privileged-role wallets (e.g. admin, operator, pool/market authority, oracle or price-update signer) — hardware wallet or multisig for production
- [ ] **SEC-039**: Treasury wallet — multisig or hardware wallet
- [ ] **SEC-040**: Test wallets — separate from production, devnet only

## 12.6 — CI That Holds Deploy or Authority Keys

- [ ] **SEC-045**: A CI job that deploys, upgrades or sends admin transactions reads its key from the CI secret store, a secrets manager or KMS/HSM (or only creates a multisig proposal), scoped to a protected branch or environment and not exposed to fork PRs
- [ ] **SEC-046**: No keys in CI/CD logs — build and deploy steps don't echo the keypair, its path contents or the env var holding it

## 12.7 — Key Rotation & Incident

- [ ] **SEC-048**: Process exists for emergency key rotation
- [ ] **SEC-049**: If a key is suspected compromised — documented steps for rotation
- [ ] **SEC-050**: After rotating an on-chain authority (upgrade authority, admin, oracle signer) — the on-chain `set_authority` / config change and every signer's tooling are updated together, so no flow keeps signing with, or trusting, the old key
- [ ] **SEC-051**: Revoked/rotated keys are actually deactivated (not just removed from source but still valid)
- [ ] **SEC-052**: Authority rotation uses a staged handoff (two-step propose/accept, or a multisig member swap) that cannot leave the program with no valid authority

## 12.8 — Signing-Key Generation & Signing-Service Integrity

- [ ] **SEC-053**: Signing keys are generated with a CSPRNG (never predictable or derived from transaction material / timestamps / counters); any custom signing service is reviewed for ECDSA/EdDSA nonce reuse and side-channels, or replaced with a vetted HSM/MPC signer (Upbit $36.8M — private key back-calculated from on-chain signature material)
