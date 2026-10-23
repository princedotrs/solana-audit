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

The third-party credits below are auditor-skill's own, kept for the material that remains in this skill.
Where it draws on external security methodology it does so by *reference* — no third-party text is
copied — and credits the source here.

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
