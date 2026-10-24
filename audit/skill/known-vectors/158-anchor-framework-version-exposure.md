---
id: 158
title: "Anchor Framework-Version Security-Fix Exposure"
severity: 7
category: crypto
---

### 158 — Anchor Framework-Version Security-Fix Exposure

**Severity: 7 (per row: follow the advisory unless context lowers it)** | **Real: otter-sec/anchor GHSA advisories and CHANGELOG security fixes**

KV-137 covers vendored *program* forks. This vector covers the *framework crate*: a program built against an `anchor-lang`/`anchor-spl` version inside an affected range that uses the affected pattern inherits the bug. Some fixes do not show up in a CHANGELOG scan; the 1.0.2 entry, for example, does not mention its advisory. <!-- verified: anchor CHANGELOG [1.0.2] lists no Program/System fix -->

#### Verification Procedure

**Step 1: Resolved versions (and the deployed build's, if different)**
```
rg -n -A1 '^name = "anchor-(lang|spl)"$' Cargo.lock
rg -n 'anchor-(lang|spl)\s*=\s*\{?[^}]*(git|branch|rev|tag)' programs/*/Cargo.toml Cargo.toml   # git deps (anchor-next)
```

**Step 2: Walk the matrix.** Every row whose range contains the version **and** whose pattern exists in the code is a finding candidate. "1.2.2" below is the release prepared on the `release-bump/1.2.2` branch (CHANGELOG dated 2026-10-22, untagged on 2026-10-24); confirm the published version.

| Affected anchor-lang | Fixed in | Issue | Pattern | Source |
|---|---|---|---|---|
| 1.0.0 (incl. RCs with #3878) – 1.0.1 | 1.0.2 | `Program<'info, System>` accepts any executable | hand-built System `Instruction` from the account key, or forwarding the account (KV-154); not `init`/`realloc` | GHSA-c6rc-8jpp-2fgc / CVE-2026-45137 |
| 1.0.0-rc.1 | 1.0.0-rc.2 | `InterfaceAccount` discriminator check disabled, allowing substitution between discriminator-bearing types (SPL `Mint`/`TokenAccount` are unaffected because they never had one) | `InterfaceAccount<'info, MyType>` with several owners | GHSA-429q-fhh4-r6hj (#3837 → #4139) |
| 0.31.0 – 1.1.2 (`lazy-account`) | 1.2.0 | `LazyAccount::unload()` does not re-check owner/discriminator after a CPI | `LazyAccount` + a CPI that receives it writable + `unload()` + a security-relevant read | GHSA-6px8-6mw3-4hx4 (#4784) |
| ≤ 1.2.1 | 1.2.2 | constraint codegen shadowing | fields or expressions named `my_key`/`my_owner`/`actual`, or `associated_token::authority = my_owner` (KV-155) | #5105 |
| ≤ 1.2.1 | 1.2.2 | `init_if_needed` reusing an existing mint skips the declared Token-2022 `extensions::*` constraints. The base `mint::authority`/`freeze_authority`/`decimals`/token-program checks did run. A caller-supplied mint that names the expected authorities can therefore carry a different hook program, permanent delegate, close authority or pointer than declared | `init_if_needed` + `extensions::*` constraints with no handler re-check | #4845 |
| ≤ 1.2.1 | 1.2.2 | the `init_if_needed` mint-reuse freeze-authority check binds a closure parameter `fa`, so `mint::freeze_authority = fa` accepts any mint that has a freeze authority | `init_if_needed` mint whose freeze-authority account is named `fa` (KV-155) | #5209 |
| ≤ 1.2.1 | master, Unreleased (not in 1.2.2) | a `zero` field declared before an `init` field (or across nested account structs) can bind the same freshly created account, giving two writable typed wrappers over one buffer | `zero` + `init` in one struct or across composites | #4871 |
| 0.31.0 – 1.1.2 | 1.2.0 | all-zero or empty custom account discriminator accepted by anchor-lang (the IDL build already rejected it) | `discriminator = [0, …]` (KV-156) | #4645 |
| < 1.1.1 | 1.1.1 | `cpi::Return<T>::get()` does not verify the program id, and return data is not snapshotted | Anchor CPI return values (KV-152) | #4411, #4624 |
| all 0.x | 1.0.0 | duplicate mutable accounts not rejected (1.0.x scopes the check to serialize-on-exit types and includes `init_if_needed`) | two `mut` fields of one type (FP-6) | #3946, #4202, #4239 |
| < 1.0.0 | 1.0.0 | `Account::reload()` does not re-check the owner | `.reload()` after a CPI that can reassign or re-create the account | #3837 |
| < 1.2.0 | 1.2.0 | undersized zero-copy data panics; `AccountLoader::exit` could rewrite the discriminator over a truncated buffer | `AccountLoader` + realloc shrink | #4555, #4633 |
| 1.0.0 – 1.1.0 | 1.1.1 | `Migration::exit` returned `Ok` without persisting when `To::owner() != program_id` | `Migration<'info, From, To>` | #4706 |
| ≤ 1.2.1 | 1.2.2 | manual `close()` into the account itself not rejected; exit re-serialized data into an account whose owner the handler had changed | manual `close()` calls with a caller-chosen destination; handlers that `assign` a typed account | #5202, #5011 |
| < 1.2.0: wrong owner key (#4322); all versions: unusable | deprecated in 1.2.0 (#4465) | `anchor-spl` `cpi_guard_enable/disable` can never succeed on-chain: Token-2022 rejects CPI Guard toggles made via CPI (`CpiGuardSettingsLocked`) | code that relies on `cpi_guard_enable/disable` to set a guard | CHANGELOG 1.2.0 |
| `branch = "anchor-next"` git dep / 2.0.0-rc.* | — | v2 alpha, documented as not audited, with APIs that may break between commits (the doc says it is not on crates.io, but crates.io `anchor-lang` 2.0.0-rc.1/rc.2 is this v2 crate; a git dependency on the v2.0.0-rc tags can instead resolve the legacy `anchor-lang-v1` crate, to which the 1.x rows above apply — confirm which one `Cargo.lock` resolves); unpinned git deps are non-reproducible | git dependency or a 2.0.0-rc version | Anchor v2 `alpha-limitations.mdx` |

<!-- verified: anchor CHANGELOG sections [1.0.0] #3837 #3878 #3946 #4139 #4202 #4239, [1.1.1] #4411 #4624 #4706, [1.2.0] #4322 #4465 #4555 #4633 #4645 #4784; origin/release-bump/1.2.2 CHANGELOG [1.2.2] #4845 #5011 #5105 #5202 + commit a8a2cd6c (#5209); master 035797c6 (#4871) absent from release-bump/1.2.2; v1.2.1 constraints.rs init_if_needed mint path checks mint_authority/freeze_authority/decimals/token program only; 549729ba (#4706) replaces `return Ok(())`; v0.30.1 has no lazy_account.rs, v0.31.0 does; v1.0.0 adds migration.rs; token-2022 program/src/extension/cpi_guard/processor.rs `if in_cpi() { CpiGuardSettingsLocked }`; v1.2.1 spl/src/token_2022_extensions/cpi_guard.rs #[deprecated] -->

- ✅ PASS: no affected row matches, or each match is fixed in code
- ❌ FAIL: an affected version with the pattern present

Triage note from Anchor SECURITY.md, [verbatim, Apache-2.0, Copyright 2020 Anchor Maintainers]: "Not every safety check performed by Anchor is a security boundary. Some checks are defense-in-depth or anti-footgun measures ..." Do not report "Anchor would have caught this" as a framework guarantee unless the check is one of the advisory-class checks above.

**Overall verdict:**
- ✅: the version is outside every affected range, or the patterns are absent or mitigated
- ❌: any row matches

*Sources: otter-sec/anchor CHANGELOG (master and the 1.2.2 release branch), SECURITY.md, docs-v2 `alpha-limitations.mdx`, GHSA-c6rc-8jpp-2fgc, GHSA-429q-fhh4-r6hj, GHSA-6px8-6mw3-4hx4 (Apache-2.0, Copyright 2020 Anchor Maintainers). Rows were corrected: no `init`/`realloc` in the System row; rc.1 impact limited; the security-metadata deploy warning is Unreleased #5124 and mainnet-only, so it is not listed. Rows were then re-verified against source: #4845 covers extension constraints only, #4871 is not in 1.2.2, #4706 is a silent no-persist, and the CPI Guard helpers are unusable in every version.*
