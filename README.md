# agent-skills

Skills for coding agents. Each skill is a self-contained folder with a `SKILL.md` entry point that an agent loads on demand.

## Skills

| Skill | Folder | What it does |
|---|---|---|
| `solana-program-audit` | [skills/solana-program-audit/](skills/solana-program-audit/) | Security audit of Solana on-chain programs in Rust (Anchor, native `solana-program`, Pinocchio): 909 checklist items in 13 checklists, 100 known attack vectors, framework and protocol references, PoC / patch / fuzz / formal-verification templates, and report formats from a one-file `audit.md` to a full client report |

## solana-program-audit

Built on Superteam Brazil's open-source [`solanabr/auditor-skill`](https://github.com/solanabr/auditor-skill) (MIT), narrowed to on-chain programs and extended with vetted public Solana security sources. Version-specific claims are checked against the published source of Anchor, SPL Token, Token-2022, the Associated Token Account program, Pinocchio and Agave. Every source and its licence is listed in [skills/solana-program-audit/ATTRIBUTION.md](skills/solana-program-audit/ATTRIBUTION.md).

**Modes:**

| Mode | What you get |
|---|---|
| Quick audit | Security Review Questions answered for every instruction, the core checklists, the highest-severity vectors, and an `audit.md` report |
| Full audit | A verdict on every in-scope checklist item and vector, a validation gate for high-severity findings, and `audit_<n>/REPORT.md` |
| Targeted | Single checklist, single instruction, PR or diff, spec compliance, re-audit of fixes, audit readiness, release gate, PoC and patch |

**Install** (any one of these). The skill installs at user level, outside the repository you are auditing.

Any agent (Claude Code, Codex, Cursor, Gemini CLI, Copilot, OpenCode, …) via the [`skills`](https://skills.sh) CLI:

```bash
npx skills add princedotrs/solana-audit -g
```

Claude Code plugin, updated with `/plugin update`:

```
/plugin install solana-program-audit --marketplace princedotrs/solana-audit
```

On Claude Code before 2.1.275, run `/plugin marketplace add princedotrs/solana-audit` and then `/plugin install solana-program-audit@solana-audit`.

No Node: a shell script that installs into `~/.claude/skills`, `~/.agents/skills` and the skills folder of every other agent it finds (`SKILLS_DIR=<dir>` to pick one):

```bash
curl -fsSL https://raw.githubusercontent.com/princedotrs/solana-audit/main/install.sh | bash
```

Ask your agent. Paste this into any coding agent that can run shell commands:

```
Install the solana-program-audit skill from https://github.com/princedotrs/solana-audit:
copy its skills/solana-program-audit/ folder into your user-level skills directory as solana-program-audit
(not inside this repository), then read its SKILL.md.
```

Chat apps: download `solana-program-audit.zip` from [Releases](https://github.com/princedotrs/solana-audit/releases) and upload it as a skill (on claude.ai: Settings → Capabilities → Skills).

Manual: `cp -R skills/solana-program-audit <your-agent-skills-dir>/`

### After installing

1. **Restart your agent** (or open a new session) so it picks up the new skill.
2. **Open your Solana program's repository** in the agent, at the root, next to `Cargo.toml` / `Anchor.toml`. Commit or stash your work first, so you can see exactly what the audit writes.
3. **Ask for an audit in plain English.** The skill loads by itself when you ask to audit or review Solana program code. To be sure it's used, name it: `...using the solana-program-audit skill`. In Claude Code you can also call it directly with `/solana-program-audit` (plugin install: `/solana-program-audit:solana-program-audit`).

Start with a quick audit:

```
Audit the Solana program in programs/<your_program>/ and write the findings to audit.md
```

Then go deeper:

```
# full audit: every checklist item and vector gets a verdict, report in audit_<n>/REPORT.md
Audit the entire repository using the solana-program-audit skill with FULL scope

# one instruction, one checklist, or a PR
Review the withdraw instruction in programs/<your_program>/src/instructions/withdraw.rs with solana-program-audit
Run solana-program-audit checklist 03 (Arithmetic Safety) on programs/<your_program>/
Audit the changes in main..feature-branch with solana-program-audit

# after fixing
Write a PoC exploit test for finding F-001 using solana-program-audit
Re-audit the fixes against audit_1/REPORT.md with solana-program-audit
```

**What you get:** each finding has a severity (Critical / High / Medium / Low / Info, scored 1–10), the affected file and line, an exploit scenario and a suggested fix. Quick audits write `audit.md`; full audits write `audit_<n>/REPORT.md`.

**Tips:**
- Use your agent's strongest model and give it time. A full audit of a large program is a long, multi-step run.
- Keep `Cargo.lock` in the repo. The skill reads exact Anchor / SPL / Pinocchio versions from it to rule version-specific bugs in or out.
- Treat findings as leads to verify, not final verdicts. Ask for a PoC on anything High or Critical.

Full layout, all modes, optional tooling (bundled Rust pre-scanner, Trident, Kani, Trail of Bits skills) and limitations: [skills/solana-program-audit/README.md](skills/solana-program-audit/README.md). Start-of-audit instructions for the agent: [skills/solana-program-audit/SKILL.md](skills/solana-program-audit/SKILL.md).

> The skill's output is a rigorous first pass, not a substitute for an independent human audit.

## Repository layout

```
.claude-plugin/
  marketplace.json    Claude Code plugin marketplace
install.sh            curl installer
skills/
  solana-program-audit/
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

Each skill carries its own licence terms. `solana-program-audit` is MIT, including the material from `solanabr/auditor-skill` ([licence](skills/solana-program-audit/LICENSE-solanabr-auditor-skill)); quotations from Apache-2.0 sources are covered by [LICENSE-Apache-2.0](skills/solana-program-audit/LICENSE-Apache-2.0). Per-source terms: [ATTRIBUTION.md](skills/solana-program-audit/ATTRIBUTION.md).
