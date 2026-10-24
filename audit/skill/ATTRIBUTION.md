# Attribution & Credits

## Superteam Brazil — auditor-skill (MIT)

Source: https://github.com/solanabr/auditor-skill
(imported at commit `b1e7a8f20baf2ea8081c89c629caf4a4161c8f96`).
Copyright (c) 2026 solanabr; licensed under the MIT License. The full license text is kept in
[LICENSE-solanabr-auditor-skill](LICENSE-solanabr-auditor-skill) and must accompany any copy of this skill.

This skill incorporates material from auditor-skill — its operating rules, audit workflow, agents,
playbooks, on-chain checklists (01–07, 11, 12, 16), Solana known vectors, discovery commands, templates,
references, the `audit-scan` / `audit-mem` tooling and the helper scripts — narrowed to Solana on-chain
programs (Rust / Anchor / native solana-program / Pinocchio). Off-chain checklists and vectors, the
post-incident detection & response track and the vendored Trail of Bits submodule were not carried over.

The third-party credits from "Trail of Bits — audit skills" through "Knowledge sources" are
auditor-skill's own, kept for the material that remains in this skill; that material draws on external
security methodology by *reference* and copies no third-party text.

Most of this skill is original. The extension described under
[Extension sources](#extension-sources--licence-policy-and-register) also contains short passages copied
under permissive licences (MIT, Apache-2.0, CC0), each marked inline as `[verbatim, <licence>, <copyright>]`.
Content from CC-BY-SA, AGPL, unlicensed repositories and "all rights reserved" articles is never copied:
it is re-expressed in our own words and the source URL is cited inline as `[paraphrased, …]`.

## Trail of Bits — audit skills (CC-BY-SA 4.0)

Source: https://github.com/trailofbits/skills

Not bundled with this skill. If the Trail of Bits skills are installed separately, the audit delegates
tool **execution** to them (static analysis, fuzzing, coverage, mutation, IR-level analysis); otherwise it
uses the native grep checks in `discovery/grep-commands.md` and notes the tooling gap. Nothing from that
repository is copied here, so no CC-BY-SA ShareAlike obligation attaches to this skill's MIT-licensed corpus.

Several Trail of Bits *methodology patterns* are additionally re-implemented
natively, in our own words (not copied), and credited inline where used:

| Trail of Bits skill | Implementation in this skill |
|---------------------|------------------------------|
| `fp-check` / `second-opinion` | `OUTPUT-RULES.md` Rule 5b — Validation Gate |
| `audit-context-building` | `FULL-AUDIT.md` Phase 0.5 — Context Reconstruction |
| `code-maturity-assessor` | `FULL-AUDIT.md` Phase 4.5 — Maturity Assessment |
| `differential-review` | Mode 4 — Differential Audit |
| `spec-to-code-compliance` | Mode 5 — Spec Compliance |

## safe-solana-builder (MIT)

Source: https://github.com/frankcastleauditor/safe-solana-builder

Solana-specific secure-coding guidance was **adapted** — re-framed from build-time
to audit-time and re-expressed in our own words — into native content:

| safe-solana-builder reference | Implementation in this skill |
|-------------------------------|------------------------------|
| `shared-base.md §21` (reward accounting) | `checklists/06` §6.10 |
| `§23` + `anchor.md §4.1` (Token-2022) | `known-vectors/105` + `checklists/04` |
| `anchor.md` / `native-rust.md` / `pinocchio.md` idioms | `references/framework-idioms/*` |
| `litesvm.md` (test patterns) | `checklists/16` (test-suite verification) |
| `shared-base.md §25` (BPF stack frame) | `known-vectors/111` |
| `shared-base.md §5.3–5.5` (CPI trust boundary) | `checklists/04` RE-006/007 + `references/framework-idioms/anchor.md` |

## defending-code-reference-harness (Apache-2.0)

Source: https://github.com/anthropics/defending-code-reference-harness (commit d3bea6b, 2026-08-06; the upstream README states the repository is not maintained).
Copyright 2026 Anthropic PBC, under the Apache License 2.0; upstream ships no NOTICE file.
Ported as method and re-expressed in our own words — no upstream text is copied.

| Upstream | Implementation in this skill |
|----------|------------------------------|
| `threat-model` skill (bootstrap and bootstrap-then-interview modes, the team-availability routing step, prior-vulnerability inputs, evidence that ranks goals without becoming them, seeded interview) | `commands/threat-model.md` `--bootstrap`, `references/audit-lifecycle/threat-model-bootstrap.md`, `scripts/threat-model/collect.sh`, `templates/threat-model.md` §4–§6 |

Modifications:

- Threat-model bootstrap: re-expressed in our own words (nothing quoted) and re-targeted to Solana programs — one hardened read-only collector instead of a research swarm, pickaxe mining of removed / quietly added account guards, fork-point and parent-guard hints, `security_txt!` / `declare_id!` provenance, an allowlisted INCIDENTS.json reader. Not ported: the swarm, STRIDE gap-fill, likelihood × impact scoring, checkpoint state.

## Cloudflare — security-audit skill (MIT)

Source: https://github.com/cloudflare/security-audit-skill

Audit-method principles, re-expressed natively in our own words (no text copied):

| Cloudflare idea | Implementation in this skill |
|-----------------|------------------------------|
| Code the audited repository controls runs only inside a sandbox that holds no credentials — otherwise it does not run | `OUTPUT-RULES.md` Rule 11a (our isolated mode; native allowed with a caveat) |
| Keep audit output out of version control and public CI | `OUTPUT-RULES.md` Rule 11d — Output hygiene |

## Assessed, not vendored

External security skill packs reviewed for anything to absorb. Re-check when the trigger fires.

| Source | Licence | Assessed commit | Verdict | What we took → where | Re-check trigger |
|--------|---------|-----------------|---------|----------------------|------------------|
| [anza-xyz/claude-skills](https://github.com/anza-xyz/claude-skills) (2★ at assessment) | none (all rights reserved) | `0ec828e` (tag v1.1.0; 3 commits: 2 on main + PR head `5e9b2be`) | Watch; idea re-implemented independently, no text used | Review of a dependency bump's published code delta → `checklists/11` §11.11, the `diff-audit` playbook's dependency lane (`commands/diff-audit.md`); findings kept out of public CI → Rule 11d | It gains a LICENSE, or adds skill/command content |
| [cloudflare/security-audit-skill](https://github.com/cloudflare/security-audit-skill) | MIT | `c1c8a8c` | Absorb principles only; not vendored | Execution isolation → `OUTPUT-RULES.md` Rule 11a (our isolated mode; native allowed with a caveat); output hygiene → Rule 11d (see the Cloudflare section above) | Each release |

## Knowledge sources

Taxonomy structure, exploit→vector mappings, and severity calibration were
informed by public post-mortems and publicly disclosed audit reports, and
re-expressed in our own words. No proprietary or trade-secret material is
included in this repository.

## Extension sources — licence policy and register

The extension adds known vectors KV-141 … KV-182, checklists 21–23, new checklist items in the kept
checklists, false-positive entries FP-7 … FP-22, and new references and templates. Every source whose
text or ideas it uses is listed below with its URL, licence, copyright line and reuse mode.

### Licence policy

- **Copy-with-attribution** (verbatim allowed, marked inline `[verbatim, <licence>, <copyright>]`): MIT,
  Apache-2.0, CC0. Every verbatim passage carries its licence and copyright line where it appears.
- **Paraphrase-and-cite** (no verbatim text, own words only, URL cited inline): CC-BY-SA-4.0 (Trail of
  Bits skills), AGPL-3.0 (crytic/building-secure-contracts), repositories with no licence, and
  "all rights reserved" articles. No ShareAlike or AGPL obligation attaches, because no expression from
  those sources is reproduced.
- **Cite-only**: CC0 directories and the post-mortems, audit reports and blog posts linked inline.
- **Apache-2.0 change notice:** text quoted from otter-sec/anchor (`footguns.mdx`, `SECURITY.md`,
  `account-constraints.mdx`) is reproduced unmodified inside quotation marks; all surrounding text is newly
  written, so the files that contain those quotations are modified works. SlowMist content is paraphrased only.
- **Scope:** only on-chain program content was kept. Upgrade and account-migration items aimed at a
  deployment-infrastructure checklist that this skill does not ship were retargeted to
  `checklists/07` §7.14 (OPS-098 … OPS-103); off-chain material was dropped.

<!-- verified: every source LICENSE file (MIT copyright lines exact; otter-sec/anchor LICENSE appendix "Copyright 2020 Anchor Maintainers", no NOTICE; SlowMist LICENSE appendix left as "Copyright [yyyy] [name of copyright owner]"; crytic/building-secure-contracts README "licensed and distributed under the AGPLv3 license"; awesome-solana-ai README CC0 badge, no LICENSE file; solsec README "Feel free to do whatever you want with this material"). Article copyright lines are as recorded from each article's page footer. -->

### MIT-licensed sources (copy-with-attribution)

Each source below is used under the MIT License. For each, the copyright notice is reproduced and the
following permission notice applies:

> Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
> associated documentation files (the "Software"), to deal in the Software without restriction, including
> without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
> copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the
> following conditions: The above copyright notice and this permission notice shall be included in all
> copies or substantial portions of the Software. THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY
> KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
> PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
> CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF
> OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

| Source | Copyright notice | Reuse mode | Used in |
|---|---|---|---|
| sanbir/solana-auditor-skills — https://github.com/sanbir/solana-auditor-skills | Copyright (c) 2024 AI Skills Contributors | copy-with-attribution | Orchestration lenses, FINDING/LEAD format, judging gates, attack vectors V24/V25/V34/V64/V81/V85/V87/V100/V103 (corrected where noted), session keys. Files: `QUICK-AUDIT.md`, `OUTPUT-RULES.md`, `FULL-AUDIT.md`, `checklists/02`, `checklists/04`, `checklists/05`, `checklists/06`, `agents/audit-reporter.md`, `agents/peer-reviewer.md`, `agents/vuln-hunter.md`, `references/false-positives.md`, `references/methodologies/lending.md`, `references/methodologies/perps.md`, `references/methodologies/token-2022.md`, `references/methodologies/wallets-multisig-custody.md`, `references/orchestration/attacker-lenses.md`, KV-141/150/170/171/173/174/175 |
| pashov/skills — https://github.com/pashov/skills | Copyright (c) 2024 AI Skills Contributors | copy-with-attribution | Senior-auditor SOP, attacker lenses, dedup & assembly gates, report language, round-trip invariants. Files: `QUICK-AUDIT.md`, `OUTPUT-RULES.md`, `FULL-AUDIT.md`, `checklists/02`, `checklists/03`, `checklists/04`, `checklists/05`, `checklists/06`, `checklists/16`, `agents/audit-reporter.md`, `agents/peer-reviewer.md`, `agents/vuln-hunter.md`, `references/false-positives.md`, `references/invariant-catalog.md`, `references/orchestration/senior-auditor-sop.md`, `references/report-format.md`, `references/report-language.md`, KV-152/165/170/171/172/173 |
| PlamenTSV/plamen — https://github.com/PlamenTSV/plamen | Copyright (c) 2025-2026 Plamen Contributors | copy-with-attribution | Introspection, return-data, IDL, migration, zero-state, staleness and parity sweeps; evidence tags and HALT list; fork recon; checklist items. Files: `SKILL.md`, `OUTPUT-RULES.md`, `FULL-AUDIT.md`, `checklists/01`, `checklists/02`, `checklists/03`, `checklists/04`, `checklists/05`, `checklists/06`, `checklists/07`, `agents/audit-reporter.md`, `agents/peer-reviewer.md`, `agents/vuln-hunter.md`, `references/invariant-catalog.md`, `references/methodologies/lending.md`, `references/methodologies/oracles.md`, `references/methodologies/upgrades-and-migrations.md`, KV-003/151/152/153/160/161/170/172 |
| solana-foundation/solana-dev-skill — https://github.com/solana-foundation/solana-dev-skill | Copyright (c) 2026 (no holder named; attributed to the Solana Foundation solana-dev-skill contributors) | copy-with-attribution; its version and tooling facts are marked "per source, unverified" | Reentrancy model, introspection flash loans, optional accounts, Anchor 1.x deltas, hook-author checks, Token-2022 fee/close/memo mechanics, Pinocchio API notes, tooling notes. Files: `security.md`, `OUTPUT-RULES.md`, `checklists/01`, `checklists/03`, `checklists/04`, `checklists/05`, `checklists/07`, `checklists/21`, `checklists/22`, `references/false-positives.md`, `references/framework-idioms/anchor.md`, `references/framework-idioms/build-and-tooling.md`, `references/framework-idioms/native.md`, `references/framework-idioms/pinocchio.md`, `references/methodologies/lending.md`, `references/methodologies/token-2022.md`, `references/methodologies/wallets-multisig-custody.md`, `references/orchestration/poc-harness.md`, KV-003/148/151/153/154/156/157/167/168/169. `security.md` is derived from its `skills/solana-dev/references/security.md` (vulnerability categories 1–9, program checklist and review questions kept largely verbatim; client-side, Token-2022 and agent-safety sections removed; categories 10–12, the numbering, some examples and the class index are this skill's own) |
| beriktassuly/solana-audit-skill — https://github.com/beriktassuly/solana-audit-skill | Copyright (c) 2026 Berektassuly | copy-with-attribution | Release gate, claim discipline, pre-sign review, design questions, extension policy table, dust/close DoS, durable-nonce custody, migration items OPS-098 … OPS-103. Files: `SKILL.md`, `OUTPUT-RULES.md`, `FULL-AUDIT.md`, `checklists/05`, `checklists/07`, `checklists/22`, `references/audit-lifecycle/threat-model-bootstrap.md`, `references/methodologies/token-2022.md`, `references/methodologies/upgrades-and-migrations.md`, `references/methodologies/wallets-multisig-custody.md`, `references/report-format.md`, `templates/release-gate.md`, KV-119/160/168/169 |
| franpersanchez/solana-audits-skill — https://github.com/franpersanchez/solana-audits-skill | Copyright (c) 2026 Fran Pérez | copy-with-attribution | Instruction matrix, conditional-risk templates, "do not discard solely because", mixed frameworks, runtime size limits, payout bricking, keeper fallback. Files: `OUTPUT-RULES.md`, `FULL-AUDIT.md`, `checklists/01`, `checklists/04`, `checklists/05`, `references/false-positives.md`, `references/framework-idioms/build-and-tooling.md`, `references/framework-idioms/pinocchio.md`, KV-169/170 |
| Sealevel Sentinel — https://github.com/stantheman0128/sealevel-sentinel | Copyright (c) 2026 Stan (stantheman0128) | copy-with-attribution | Grounding gate, eval labels method, class-to-check mapping (`security.md` class index), role-based authority heuristic, detector-derived grep additions. Files: `security.md`, `OUTPUT-RULES.md`, `checklists/02`, `checklists/04`, `discovery/grep-commands.md`, `references/false-positives.md`, KV-101/104/106/143 |
| CDSecurity/cdsecurity-skills — https://github.com/CDSecurity/cdsecurity-skills | Copyright (c) 2026 CD Security | copy-with-attribution | Readiness mode, output contract, handler-to-test mapping, dependency hygiene, feature-flag and lint-suppression checks. Files: `SKILL.md`, `OUTPUT-RULES.md`, `checklists/07`, `checklists/11`, `checklists/16`, `discovery/grep-commands.md`, `references/framework-idioms/build-and-tooling.md`, `references/orchestration/readiness-agents.md`, KV-104 |
| qedgen/solana-skills — https://github.com/qedgen/solana-skills | Copyright (c) 2025 QEDGen | copy-with-attribution | Cross-cutting review passes, evidence discipline, composition cookbook, trust-surface deps, domain dossier, known non-findings, category-catalog patterns, Kani harness shape. Files: `QUICK-AUDIT.md`, `SKILL.md`, `OUTPUT-RULES.md`, `FULL-AUDIT.md`, `checklists/01`, `checklists/02`, `checklists/03`, `checklists/04`, `checklists/05`, `checklists/06`, `checklists/07`, `checklists/16`, `references/audit-lifecycle/threat-model-bootstrap.md`, `references/compose-cookbook.md`, `references/false-positives.md`, `references/framework-idioms/pinocchio.md`, `references/invariant-catalog.md`, `references/methodologies/lending.md`, `references/methodologies/token-2022.md`, `references/methodologies/trust-surface-deps.md`, `references/orchestration/poc-harness.md`, `references/report-format.md`, `templates/kani/conservation.rs`, KV-003/106/146/147/148/172/175/176/177/181/182 |
| workersio/skills — https://github.com/workersio/skills | Copyright (c) 2026 workers.io | copy-with-attribution; nothing taken from `plugins/fuzzer/**` (a CC-BY-SA copy of third-party material) | Kani soundness checks, harness patterns, `assert_ok!`/`assert_err!` macros, Kani setup recipes, confidence scoring; files live in the `refs/pull/9/head` tree (`plugins/solana-audit/`, `plugins/kani-proof/`). Files: `OUTPUT-RULES.md`, `checklists/16`, `references/framework-idioms/build-and-tooling.md`, `references/invariant-catalog.md`, `references/tooling.md`, `templates/kani/frame-isolation.rs`, `templates/kani/infrastructure.rs`, KV-009/106 |
| Ackee-Blockchain/trident — https://github.com/Ackee-Blockchain/trident | Copyright (c) 2021 Ackee Blockchain | copy-with-attribution | Trident engine notes, flow skeleton (renamed struct), harness soundness checks, templates. Files: `OUTPUT-RULES.md`, `checklists/16`, `references/false-positives.md`, `references/invariant-catalog.md`, `references/orchestration/poc-harness.md`, `references/tooling.md`, `templates/fuzz-trident/README.md`, `templates/patch/VERIFICATION.md` |

### Apache-2.0-licensed sources

Licence text: [LICENSE-Apache-2.0](LICENSE-Apache-2.0) (also at http://www.apache.org/licenses/LICENSE-2.0).
That copy must accompany any redistribution of the files that contain the quotations below.

| Source | Copyright / NOTICE | Reuse mode | Use, changes and files used in |
|---|---|---|---|
| Anchor framework — https://github.com/otter-sec/anchor (docs, `SECURITY.md`, CHANGELOG, GHSA advisories) | Copyright 2020 Anchor Maintainers; no NOTICE file | copy-with-attribution (quotations unmodified) | Short quotations from `footguns.mdx`, `SECURITY.md` and `account-constraints.mdx` reproduced unmodified; version facts summarised; all other text newly written (modified work). Files: `FULL-AUDIT.md`, `checklists/01`, `checklists/04`, `checklists/07`, `checklists/21`, `discovery/grep-commands.md`, `references/exploit-history.md`, `references/false-positives.md`, `references/framework-idioms/anchor-v2.md`, `references/framework-idioms/anchor.md`, `references/framework-idioms/build-and-tooling.md`, KV-106/152/154/155/156/158 |
| SlowMist — https://github.com/slowmist/solana-smart-contract-security-best-practices | LICENSE has no copyright holder filled in; attributed to SlowMist; no NOTICE file | paraphrased only | Jet v1 case, owner-rotation reset, swallowed errors, rounding helpers, legacy Pyth status gate (sections of its `README.md`). Files: `checklists/02`, `checklists/03`, `checklists/04`, `references/exploit-history.md`, `references/invariant-catalog.md`, `references/methodologies/lending.md`, `references/methodologies/oracles.md`, KV-012/149/150 |

### CC0 sources

| Source | Licence | Copyright | Reuse mode | Use and files used in |
|---|---|---|---|---|
| solana-foundation/awesome-solana-ai — https://github.com/solana-foundation/awesome-solana-ai | CC0-1.0 public-domain dedication (README badge; no LICENSE file) | none (public-domain dedication) | cite-only | Discovery feed for the tool landscape table. Files: `OUTPUT-RULES.md`, `references/false-positives.md`, `references/tooling.md` |

### Paraphrased and cited (no text copied)

| Source | Licence / copyright | Reuse mode | Topics and files used in |
|---|---|---|---|
| Trail of Bits skills — https://github.com/trailofbits/skills | CC-BY-SA-4.0 ("This work is licensed under a Creative Commons Attribution-ShareAlike 4.0 International License. Made by Trail of Bits.") | paraphrase-and-cite | Context reconstruction, maturity gating, arithmetic panic edge cases, discarded results (`rust-review` result-discarded finder), arbitrary-CPI false positive, dimensional analysis method, scanner rationalizations. Files: `SKILL.md`, `OUTPUT-RULES.md`, `FULL-AUDIT.md`, `checklists/03`, `checklists/04`, `agents/context-builder.md`, `references/false-positives.md`, `references/framework-idioms/build-and-tooling.md`, `references/methodologies/dimensional-analysis.md`, `references/report-format.md`, `templates/context-worksheet.md`, KV-009/150 |
| Trail of Bits (Not So) Smart Contracts: Solana — https://github.com/crytic/building-secure-contracts/tree/master/not-so-smart-contracts/solana | AGPL-3.0 (README: "licensed and distributed under the AGPLv3 license"; "These examples are developed and maintained by Trail of Bits.") | paraphrase-and-cite | Introspection many-to-one, deprecated sysvar helpers, arbitrary-CPI builder false positive, Wormhole patch-gap lesson. Files: `security.md`, `checklists/01`, `checklists/04`, `discovery/grep-commands.md`, `references/methodologies/bridges.md`, KV-101/151 |
| crytic/solana-lints — https://github.com/crytic/solana-lints | no licence; copyright reserved by its authors | paraphrase-and-cite | Lint scopes and limits, Borsh enum cosplay layouts, owner-check correctness. Files: `OUTPUT-RULES.md`, `checklists/01`, `checklists/04`, `checklists/16`, `discovery/grep-commands.md`, `references/false-positives.md`, `references/framework-idioms/anchor.md`, `references/framework-idioms/native.md`, `references/tooling.md`, KV-009/015/101/104/106/142/159 |
| coral-xyz/sealevel-attacks — https://github.com/coral-xyz/sealevel-attacks | no licence; copyright reserved by its authors | paraphrase-and-cite (directory names only, in eval labels; the `security.md` class index uses the class list) | The 11 classes, PDA sharing, init polarity, close semantics. Files: `SKILL.md`, `security.md`, `checklists/01`, `checklists/04`, `checklists/16`, `references/false-positives.md`, `references/framework-idioms/anchor.md`, `references/framework-idioms/native.md`, `references/tooling.md`, `templates/evals/sealevel-attacks-labels.json`, KV-009/014/106/142/143/159 |
| Ackee Solana-Auditors-Bootcamp — https://github.com/Ackee-Blockchain/Solana-Auditors-Bootcamp | no licence; copyright reserved by its authors | paraphrase-and-cite | Singleton init, self-referential seeds, tautological constraints, vesting off-by-one, on-chain secrets, fuzz-harness patterns. Files: `checklists/01`, `checklists/02`, `checklists/04`, `checklists/06`, `checklists/16`, `references/framework-idioms/anchor.md`, KV-141/142/143/144/145/164/176/179 |
| Solana Foundation Program Security course — https://github.com/solana-foundation/developer-content/tree/main/content/courses/program-security | no licence; copyright reserved by its authors | paraphrase-and-cite | Close timeline, SPL builder false positive, clone-program cosplay, `seeds::program`, negative tests, PoC recipes. Files: `security.md`, `checklists/01`, `checklists/04`, `checklists/16`, `references/false-positives.md`, `references/framework-idioms/anchor.md`, KV-009/015/104/106/143/145/156 |
| sannykim/solsec — https://github.com/sannykim/solsec | no licence (informal grant in README: "Feel free to do whatever you want with this material"; linked articles keep their authors' copyright) | paraphrase-and-cite | Exploit history, COPE roulette, Candy Machine, Solend market, stake-pool init, Royal Flush, rounding disclosure, LP oracle pricing. Files: `FULL-AUDIT.md`, `checklists/01`, `checklists/02`, `checklists/03`, `checklists/06`, `checklists/07`, `references/compose-cookbook.md`, `references/exploit-history.md`, `references/false-positives.md`, `references/methodologies/lending.md`, `references/methodologies/liquid-staking.md`, `references/methodologies/oracles.md`, KV-012/014/142/146/162/178 |
| 0xMacro/awesome-solana-security — https://github.com/0xMacro/awesome-solana-security | no licence; copyright reserved by its authors | paraphrase-and-cite | Anchor IDL instruction surface (via Accretion), audit-readiness guide (via Exo Technologies), tools. Files: `QUESTIONS.md`, `checklists/07`, KV-153 |
| Neodyme — https://neodyme.io/en/blog/solana_common_pitfalls ; https://neodyme.io/en/blog/token-2022 ; Token-2022 audit for Anza (2024) https://www.neodyme.io/reports/Token%202022%20-%202024.pdf | "Common Pitfalls": © 2026 Neodyme AG. All rights reserved. Token-2022 article and report: © Neodyme AG, all rights reserved (no explicit line on the page) | paraphrase-and-cite | Type confusion overlays, guard overflow, layout drift, Token-2022 CPI Guard / resurrection / hooks / fees / confidential transfers; the SPL token-lending rounding disclosure is cited via solsec. Files: `SKILL.md`, `checklists/01`, `checklists/03`, `checklists/04`, `checklists/11`, `checklists/22`, `references/exploit-history.md`, `references/false-positives.md`, `references/framework-idioms/native.md`, `references/methodologies/lending.md`, `references/methodologies/token-2022.md`, KV-009/010/012/015/159/160/166/167/168 |
| Helius — https://www.helius.dev/blog/a-hitchhikers-guide-to-solana-program-security | © 2026 Helius. All rights reserved. | paraphrase-and-cite | Singleton init ("Insecure Initialization"), round-to-nearest ("Rounding Errors"), taker-side bounds ("Frontrunning"). Files: `checklists/02`, `checklists/03`, `checklists/06`, `references/methodologies/lending.md`, `references/methodologies/nft-marketplaces.md`, KV-028/141 |
| Zellic — https://www.zellic.io/blog/the-vulnerabilities-youll-write-with-anchor | Zellic © 2026, all rights reserved | paraphrase-and-cite | Seed-concatenation collisions. Files: `references/framework-idioms/anchor.md`, KV-026 |
| OtterSec — https://osec.io/blog/solana-security-intro ; https://osec.io/blog/2023-12-11-jumping-around-in-the-vm | © Otter Audits LLC 2026, all rights reserved | paraphrase-and-cite | Memory-corruption escalation, sBPF memory map, unchecked-CPI gadget, System transfer rule, binary review. Files: `OUTPUT-RULES.md`, `checklists/04`, `references/framework-idioms/native.md`, `references/framework-idioms/pinocchio.md`, KV-180/182 |

### Other linked references (cite-only)

Post-mortems, audit reports, blog posts and exploit write-ups linked inline (for example in
`references/exploit-history.md` and the known vectors) are cited as references only; no text is copied
from them and each keeps its authors' copyright.

### Primary sources consulted for verification

Version-specific statements were checked against the published source of the frameworks and programs
they describe, all under Apache-2.0: Anchor (https://github.com/solana-foundation/anchor, Copyright 2020
Anchor Maintainers), SPL Token (https://github.com/solana-program/token), Token-2022
(https://github.com/solana-program/token-2022), Associated Token Account
(https://github.com/solana-program/associated-token-account), Pinocchio
(https://github.com/anza-xyz/pinocchio) and Agave (https://github.com/anza-xyz/agave). Their code is
referenced by tag, path and identifier; no source text is copied beyond API names and short signatures
needed to describe behaviour.

### Listed as tools only

Sealevel Guard (https://github.com/NewmanXBT/sealevel-guard, MIT, Copyright (c) 2026 Sealevel Guard
contributors), sendaifun/skills (https://github.com/sendaifun/skills, Apache-2.0) and tenequm/skills
(https://github.com/tenequm/skills, MIT, Copyright (c) 2025 Mykhaylo Kolesnik) appear by name in
`references/tooling.md`; no content from any of them is used.
