# agent-skills

Skills for coding agents. Each skill is a self-contained folder with a `SKILL.md` entry point that an agent loads on demand.

## Skills

| Skill | Folder | What it does |
|---|---|---|
| `solana-program-audit` | [audit/skill/](audit/skill/) | Security audit of Solana on-chain programs in Rust (Anchor, native `solana-program`, Pinocchio): 909 checklist items in 13 checklists, 100 known attack vectors, framework and protocol references, PoC / patch / fuzz / formal-verification templates, and report formats from a one-file `audit.md` to a full client report |

## solana-program-audit

Built on Superteam Brazil's open-source [`solanabr/auditor-skill`](https://github.com/solanabr/auditor-skill) (MIT), narrowed to on-chain programs and extended with vetted public Solana security sources. Version-specific claims are checked against the published source of Anchor, SPL Token, Token-2022, the Associated Token Account program, Pinocchio and Agave. Every source and its licence is listed in [audit/skill/ATTRIBUTION.md](audit/skill/ATTRIBUTION.md).

**Modes:**

| Mode | What you get |
|---|---|
| Quick audit | Security Review Questions answered for every instruction, the core checklists, the highest-severity vectors, and an `audit.md` report |
| Full audit | A verdict on every in-scope checklist item and vector, a validation gate for high-severity findings, and `audit_<n>/REPORT.md` |
| Targeted | Single checklist, single instruction, PR or diff, spec compliance, re-audit of fixes, audit readiness, release gate, PoC and patch |

**Install:** copy the whole `audit/skill/` folder into your agent's skills directory, outside the repository you are auditing:

```bash
cp -R audit/skill <your-agent-skills-dir>/solana-program-audit
```

**Use:**

```
Audit the Solana program in programs/<your_program>/ and write the findings to audit.md
Audit the entire repository using the solana-program-audit skill with FULL scope
```

Full layout, all modes, optional tooling (bundled Rust pre-scanner, Trident, Kani, Trail of Bits skills) and limitations: [audit/skill/README.md](audit/skill/README.md). Start-of-audit instructions for the agent: [audit/skill/SKILL.md](audit/skill/SKILL.md).

> The skill's output is a rigorous first pass, not a substitute for an independent human audit.

## Repository layout

```
audit/
  skill/
    SKILL.md          entry point
    security.md       quick reference: core vulnerability classes + review questions
    QUICK-AUDIT.md    quick-audit contract
    OUTPUT-RULES.md   output, severity and validation rules
    FULL-AUDIT.md     full-audit phases
    checklists/       13 scope-gated checklists
    known-vectors/    100 attack vectors + INDEX.md
    references/       framework idioms, protocol methodologies, false positives, tooling, exploit history
    templates/        report, worksheet, PoC, patch, Kani and Trident templates
    commands/         playbooks
    agents/           role prompts for multi-agent runs
    tools/            optional Rust pre-scanner
```

## Licence

Each skill carries its own licence terms. `solana-program-audit` is MIT, including the material from `solanabr/auditor-skill` ([licence](audit/skill/LICENSE-solanabr-auditor-skill)); quotations from Apache-2.0 sources are covered by [LICENSE-Apache-2.0](audit/skill/LICENSE-Apache-2.0). Per-source terms: [ATTRIBUTION.md](audit/skill/ATTRIBUTION.md).
