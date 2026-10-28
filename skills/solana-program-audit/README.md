# solana-program-audit

A security-audit skill for coding agents that review **Solana on-chain programs written in Rust**: Anchor, native `solana-program` and Pinocchio. It gives the agent a method (scope gate, context reconstruction, per-instruction review, validation gate, report), a corpus to check against (909 checklist items in 13 checklists and 100 known attack vectors), and fixed output formats from a one-file quick audit to a client-style report.

## Credits

This skill is based on **Superteam Brazil's [`solanabr/auditor-skill`](https://github.com/solanabr/auditor-skill)** (MIT), narrowed to on-chain programs and extended. The extension draws on the vetted public sources listed in [ATTRIBUTION.md](ATTRIBUTION.md), among them solana-foundation/solana-dev-skill, sanbir/solana-auditor-skills, pashov/skills, PlamenTSV/plamen, qedgen/solana-skills, CDSecurity/cdsecurity-skills, beriktassuly/solana-audit-skill, franpersanchez/solana-audits-skill, Sealevel Sentinel, workersio/skills and Ackee Trident. Content from those sources is copied only under MIT, Apache-2.0 or CC0 and is marked inline; CC-BY-SA, AGPL, unlicensed and all-rights-reserved material (Trail of Bits, crytic, coral-xyz/sealevel-attacks, Neodyme, OtterSec, Helius, Zellic and others) is paraphrased and cited, never copied. Version-specific statements were checked against the published source of Anchor, SPL Token, Token-2022, the Associated Token Account program, Pinocchio and Agave. The licence texts that must travel with the folder are [LICENSE-solanabr-auditor-skill](LICENSE-solanabr-auditor-skill) and [LICENSE-Apache-2.0](LICENSE-Apache-2.0).

## Layout

| Path | What it holds |
|---|---|
| [SKILL.md](SKILL.md) | Entry point: how to pick a mode, what to read first, severity scale, loading rules |
| [security.md](security.md) | Quick reference: the core Solana vulnerability classes with prevention snippets, a short program checklist and the Security Review Questions |
| [OUTPUT-RULES.md](OUTPUT-RULES.md) | Mandatory output rules: scope coverage, severity (Rule 1), verdict format, validation gate (Rule 5b), honesty, operating safety (Rule 11) |
| [QUICK-AUDIT.md](QUICK-AUDIT.md) | The quick audit's steps and a digest of the output rules that bind it (read in place of OUTPUT-RULES in quick mode) |
| [FULL-AUDIT.md](FULL-AUDIT.md) | Phase-by-phase plan for a full repository audit |
| [checklists/](checklists/) | 13 scope-gated checklists (01–07 on-chain, 11 supply chain, 12 secrets, 16 verification and testing, 21 Anchor, 22 Token-2022, 23 Rust `unsafe` and panics) |
| [known-vectors/](known-vectors/) | 100 known attack vectors, each with a verification procedure; [INDEX.md](known-vectors/INDEX.md) groups them by domain and load trigger |
| [references/](references/) | Framework idioms, protocol methodologies (AMM, lending, perps, oracles, bridges, Token-2022, …), false positives, exploit history, tooling, orchestration and report guidance |
| [templates/](templates/) | Report, worksheet, intake, threat-model, release-gate, PoC, patch, Kani and Trident templates, plus eval labels |
| [commands/](commands/) | Playbooks: `audit`, `quick-scan`, `diff-audit`, `spec-audit`, `deep-review`, `re-audit`, `audit-cycle`, `audit-assist`, `poc`, `patch`, `triage`, `threat-model`, `intake`, `economic-sim`, `audit-report` |
| [agents/](agents/) and [AGENTS.md](AGENTS.md) | Role prompts for multi-agent runs (context builder, threat modeler, vuln hunter, economic analyst, peer reviewer, PoC and patch engineers, reporter) |
| [discovery/](discovery/) | Grep commands and the default file map |
| [QUESTIONS.md](QUESTIONS.md) | Intake questionnaire |
| [scripts/](scripts/) | Report-to-PDF converter, the offline threat-model history collector, and `check-eval-isolation.sh` (a maintainer lint that keeps eval labels off every audit path) |
| [tools/auditor-tools/](tools/auditor-tools/) | Optional Rust pre-scanner (`audit-scan`) and cross-audit findings store (`audit-mem`) |
| [ATTRIBUTION.md](ATTRIBUTION.md) | Source and licence register |

## Installation

The folder is self-contained. Install it as an agent skill by copying the **whole folder** into your agent's skills directory, keeping the folder name and leaving `SKILL.md` at its top level:

```bash
# example: a user-level skills directory; use the path your agent reads skills from
mkdir -p ~/<agent-config-dir>/skills
cp -R skills/solana-program-audit ~/<agent-config-dir>/skills/
```

Install it **outside** the repository you are auditing. Every bundled path (`checklists/`, `templates/`, `scripts/`, `tools/`, …) resolves from the skill folder, never from the audited repo ([OUTPUT-RULES.md](OUTPUT-RULES.md) Rule 11e). Agents without a skills mechanism can be pointed at `SKILL.md` directly. To update, replace the folder; record per-target layout at intake rather than editing `discovery/file-map.md`.

## Usage

The skill triggers on requests to audit or review Solana program code, or on code that uses `anchor_lang`, `solana_program`, `pinocchio`, `#[program]`, `#[derive(Accounts)]` or `entrypoint!`.

**Quick audit** — a triage pass that answers the Security Review Questions for every instruction, checks the highest-severity vectors and writes `audit.md` in a short format:

```
Audit the Solana program in programs/<your_program>/ and write the findings to audit.md
```

**Full audit** — the full engagement: every in-scope checklist item and vector gets a verdict, high-severity findings pass a validation gate, and the report lands in `audit_<n>/REPORT.md`:

```
Audit the entire repository using the solana-program-audit skill with FULL scope
Audit programs/<your_program>/ using the solana-program-audit skill with PROGRAM scope
```

**Targeted modes**:

```
Run solana-program-audit checklist 03 (Arithmetic Safety) on programs/<your_program>/
Review the withdraw instruction in programs/<your_program>/src/instructions/withdraw.rs with solana-program-audit
Audit the changes in main..feature-branch with solana-program-audit (diff audit)
Re-audit the fixes against audit_1/REPORT.md with solana-program-audit
```

Other modes (spec compliance, audit readiness, release gate, PoC and patch generation, threat model) are listed in [SKILL.md](SKILL.md) → How to Run an Audit. Agents that support slash commands can expose the playbooks in [commands/](commands/) directly.

Severity uses a 1–10 scale: Critical 10–9, High 8–7, Medium 6–5, Low 4–3, Info 2–1 ([OUTPUT-RULES.md](OUTPUT-RULES.md) Rule 1).

## Optional tooling

None of these is required; without them the skill falls back to its grep-based walk and notes the gap in the report. Anything that compiles the audited program runs in the execution mode recorded at intake (OUTPUT-RULES Rule 11a / 11f).

- **Pre-scanner (bundled source).** `tools/auditor-tools` builds two binaries, `audit-scan` (instruction, constraint, PDA and arithmetic map as JSON) and `audit-mem` (local SQLite store for dedup, regressions and false-positive rulings). Requires a Rust toolchain:
  ```bash
  cd <skill-folder>/tools/auditor-tools && cargo build --release
  # binaries: target/release/audit-scan, target/release/audit-mem
  ```
  See [references/orchestration/pre-scan.md](references/orchestration/pre-scan.md).
- **Trail of Bits skills** ([trailofbits/skills](https://github.com/trailofbits/skills), CC-BY-SA-4.0), installed separately: static analysis, fuzzing, coverage, mutation and second-opinion tasks are delegated to them as described in [references/orchestration/boundary-map.md](references/orchestration/boundary-map.md). Not bundled; nothing from them is copied here.
- **Trident** ([Ackee-Blockchain/trident](https://github.com/Ackee-Blockchain/trident)): stateful fuzzing of Anchor programs. Templates and recipes in [templates/fuzz-trident/](templates/fuzz-trident/); notes in [references/tooling.md](references/tooling.md).
- **Kani** ([model-checking/kani](https://github.com/model-checking/kani)): bounded model checking of arithmetic and state invariants. Harness templates in [templates/kani/](templates/kani/); soundness checks in checklist 16 §16.8.
- **pandoc**: optional PDF export of reports via `scripts/report-to-pdf.sh`.

## Limitations

- **Not a substitute for a human audit.** The output is a rigorous first pass. It does not replace an independent review of business logic, economic design, key management and legal compliance, and it never issues a "safe to deploy" guarantee.
- **Coverage is bounded by the corpus and the code read.** Novel bug classes, cross-program interactions with code outside the repository, and deployment state (authorities, accounts on chain) can be missed.
- **Findings need confirmation.** High-severity findings must pass a validation gate, and PoCs are optional; treat unproven findings as leads.
- **On-chain Rust only.** Off-chain clients, backends, frontends, keepers and non-Solana contracts are out of scope.
- **Version-specific facts age.** Framework behaviour is pinned to the versions named in the corpus (Anchor, Pinocchio, Token-2022, Agave); re-check against the resolved versions in the target's `Cargo.lock`.
- **No formal proof.** The skill flags missing proofs and harnesses and can drive Kani or Trident, but its own verdicts are not machine-checked.

## Licence

MIT for the skill's own corpus and the material taken from `solanabr/auditor-skill` (see [LICENSE-solanabr-auditor-skill](LICENSE-solanabr-auditor-skill)); quotations from Apache-2.0 sources are covered by [LICENSE-Apache-2.0](LICENSE-Apache-2.0). Per-source terms: [ATTRIBUTION.md](ATTRIBUTION.md).
