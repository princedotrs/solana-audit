# Orchestration Boundary — Solana Program Audit × Trail of Bits

This skill's native corpus is the **knowledge** layer (checklists, vectors, severity, gates).
Trail of Bits is the **execution** layer — real tools that this skill's prose + grep cannot run.
It is **not bundled**: if the Trail of Bits skills (https://github.com/trailofbits/skills,
CC-BY-SA-4.0) are installed separately, subagents delegate to them per the map below; otherwise
they use the native grep checks in `discovery/grep-commands.md` and note the tooling gap in the
report.

Two rules from `OUTPUT-RULES.md` Rule 11 apply to the rows below. A row that builds or runs target code
follows the execution mode recorded at intake (Rule 11a). A row that sends code or dependency data to an
outside service is listed in the report — tool, service, what was sent (Rule 11b).

## Detection

Before delegating, confirm the Trail of Bits skills are installed, and use them from that installation.
`<tob-root>` is the absolute directory where they were installed separately (the one holding their
`plugins/` tree), never the working directory, which is usually the audited repo; `<skill-root>` is the
directory containing this skill's `SKILL.md`, never the audited repo (`OUTPUT-RULES.md` Rule 11e):

```
test -d "<tob-root>/plugins" && echo present
```

**Paths inside a Trail of Bits skill.** A Trail of Bits skill read from its installed tree has nothing
that defines its `{baseDir}` placeholder or anchors its relative paths (`scripts/…`, `references/…`,
`workflows/…`, `tools/…`) — the semgrep skill, for one, runs `{baseDir}/scripts/run-scans.sh`. Both
point into that plugin's own directory, `<tob-root>/plugins/<plugin>/`:
for a skill file, normally `skills/<skill>/`; some plugins keep a tool at the plugin root (e.g.
`constant-time-analysis/ct_analyzer/`). In a plugin-level agent (`agents/*.md`), a path written
`{baseDir}/skills/<skill>/…` counts from the plugin root (`sharp-edges`, `differential-review`), but
`zeroize-audit` hands its agents the skill directory, `skills/zeroize-audit/`, as `baseDir`. A Markdown
link counts from the directory of the file that contains it. Substitute the resolved absolute directory
before running or reading anything, and never resolve such a path against the working directory
(`OUTPUT-RULES.md` Rule 11e).

If absent (not installed), run the native fallback and note in the report:
"Trail of Bits tooling not installed — deeper tool execution is available by installing
https://github.com/trailofbits/skills (CC-BY-SA-4.0) separately; native grep checks were used instead".

## Capability → plugin map

| Capability | ToB plugin (`<tob-root>/plugins/…`, when installed) | This skill's use | Native fallback |
|------------|---------------------------------------------|-------------|-----------------|
| Interprocedural SAST (taint) | `static-analysis`, `semgrep-rule-creator`, `variant-analysis` | `vuln-hunter` runs SAST over the in-scope program crates; fold SARIF into verdicts. A CodeQL database build compiles the target (Rule 11a) | `discovery/grep-commands.md` scanners |
| Property / fuzz harnesses | `testing-handbook-skills`, `property-based-testing` | generate + run a harness for any ≥High arithmetic/economic finding (the Rule 5b PoC); the `poc` playbook (`commands/poc.md`) orchestrates this. Harnesses on target code follow Rule 11a | checklist 16 "does the suite exist" prose checks |
| Coverage & mutation | `testing-handbook-skills`, `mutation-testing` | evidence-back FV coverage items; an uncaught mutant downgrades the corresponding checklist PASS; the `patch` playbook (`commands/patch.md`) with `--verify-with-mutation` uses a caught mutant on the patched line as fix evidence. Mutation runs follow Rule 11a | FV items marked `[PARTIAL — not machine-verified]` |
| Secret zeroization (IR-level) | `zeroize-audit` | verify zeroization of secret-bearing types (key / seed material, checklist 12) at the IR level when in-scope Rust holds them; it compiles the target (Rule 11a) | grep `zeroize`/`Zeroizing` on secret-bearing types |
| Constant-time (custom crypto) | `constant-time-analysis` | check secret-dependent branches when custom crypto is present; it compiles the code it checks (Rule 11a) | note "manual constant-time review needed" |
| Entry-point enumeration | `entry-point-analyzer` | seed the Phase 0 instruction matrix (has native Solana support); on Solidity it runs `slither .` when Slither is installed, which compiles the target (Rule 11a) | manual `#[instruction]` enumeration |
| Supply-chain metadata | `supply-chain-risk-auditor` | enrich checklist 11 (SC-044..046). Covers npm / PyPI / Go only (e.g. the program repo's JS test / tooling manifests), not Cargo. Its collector sends the project's dependency names to 8 outside services — OSV, the npm registry and downloads API, PyPI, the Go module proxy, deps.dev, the GitHub API (with your `gh` token when logged in) and OpenSSF Scorecard — so the report records it (Rule 11b). `--offline` only replays cached responses; it is not a privacy control | `npm audit` / `cargo audit` + grep |
| Dimensional / unit analysis | `dimensional-analysis` (its roles run as `dimensional-analysis:*` agents, so it needs the ToB plugin installed; without them it reports BLOCKED) | annotate + propagate units through DeFi value paths (checklist 03/06) — catches mixed-decimals / wrong-scale bugs. It writes unit comments into the files it is given and `DIMENSIONAL_SCOPE.json` / `DIMENSIONAL_UNITS.md` at the project root, and adopts a `DIMENSIONAL_UNITS.md` it finds there, so run it on a scratch copy of the tree without the target's `DIMENSIONAL_*` files | manual per-quantity unit tracking |
| Insecure-default trace | `insecure-defaults` (a Trail of Bits command + workflow that runs only with the ToB plugin installed; without it, read its `references/*.md` category files from the installed tree) | fail-open vs fail-secure path trace for suspected weak defaults (checklist 12) | grep fallback-secret patterns |
| API misuse / footguns | `sharp-edges` | misuse-resistance review of a program's own public/CPI interface + config schema | `references/framework-idioms/*` footgun catalog |
| Exploitability verify | `fp-check` (local; an executable PoC it builds follows Rule 11a); `second-opinion` sends the selected code to an external LLM CLI — OpenAI Codex or Google Antigravity / Gemini — so the report records it (Rule 11b) | `peer-reviewer` + `poc-engineer` confirm a finding is real, not a harness artifact | manual re-derivation |
| Fix blast-radius | `differential-review` | the `patch` playbook (`commands/patch.md`) step 4 + `patch-engineer`: confirm the fix closes the exploit path and leaves every other path unchanged | the `re-audit` playbook (`commands/re-audit.md`) step 4b differential execution (Rule 11a) plus a manual review of the patched function's callers and sibling instructions |

## FV / harness delegation gates

Before delegating an FV/fuzz harness (the `property-based-testing` / `testing-handbook-skills` /
`mutation-testing` rows above), apply the ladder in `references/audit-lifecycle/methodology.md` §6:

- **Trident stateful sequences first.** The default harness for any non-trivial program is
  **multi-instruction stateful** fuzzing (Trident / SVM-level), because most real Solana logic bugs
  live in cross-instruction state (ordering, accumulation, stale-state, multi-user interleaving), not
  in a single pure function. Delegate proptest-on-pure-functions as the cheap first probe, but treat
  the stateful Trident sequence as the **primary bug-finder** — do **not** escalate to deductive FV
  (Certora/Kani) for a property a stateful fuzzer would surface in minutes. Reserve Certora/Kani for
  the 3–10 invariants whose single counterexample is catastrophic.
- **Skip FV if the target is CPI-dominated.** Deductive/BMC proof reasons only about code you have.
  When an instruction's outcome is decided mainly by a **cross-program invocation into
  untrusted/foreign code** (aggregator swap, arbitrary callee, external program whose post-state
  cannot be modeled), FV cannot conclude anything useful — **do not spend the FV budget on it**.
  Fall back to Trident sequences that mock the CPI boundary adversarially plus manual CPI-trust review
  (`references/framework-idioms/anchor.md` per-CPI checklist). Note this abstention explicitly in the
  report's Assumptions & Simplifications section.

## Rule

Delegation **augments**, never replaces, the native verdict. Every finding still carries a
native verdict from this skill and (if N ≥ 6) a filled Rule 5b gate. Tool output is *evidence*, not a verdict.
