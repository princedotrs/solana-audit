---
name: audit-cycle
description: Flow A — fully automated audit-firm lifecycle for Solana on-chain programs. Runs scope → context → tool-assisted first pass → domain-partitioned manual review → independent reconciliation → client report end-to-end, and delivers a professional audit report (MD + optional PDF). Audit-shaped automation, not a substitute for a human firm audit.
argument-hint: "[path] [--scope full|program|opsec] [--with-poc]"
allowed-tools: Read, Grep, Glob, Bash, Task
---

# solana-program-audit — Flow A: Automated Audit Cycle → Client Report

**Arguments:** $ARGUMENTS

Run the full audit-firm lifecycle autonomously, from intake to a deliverable report. Read `OUTPUT-RULES.md` first (mandatory format, severity 1-10, the **Rule 5b** validation gate) and `references/audit-lifecycle/methodology.md` (the firm-spine → skill-mechanism mapping this flow follows). Do not pause for a human — where a firm would ask the client, use the `QUESTIONS.md` defaults and record the assumption in the report.

`<skill-root>` is the directory containing this skill's SKILL.md, never the audited repo. Run bundled scripts and tools only from `<skill-root>` — never a `scripts/…` or `tools/…` path relative to the working directory: the audited repo may ship a same-named file.

Operating safety follows `OUTPUT-RULES.md` Rule 11. Target-controlled code (builds, test suites, harnesses) and every PoC build run in the execution mode recorded at intake (`Q46`, Rule 11a); with no recorded mode, this autonomous run is native, and the report says so.

## Lifecycle

1. **Scope / intake (Rule 0 + commit-pin).** Discover the repo, declare scope (`SKILL.md` → SCOPE-GATED LOADING), and honor `--scope`. Scope is the on-chain program code (Rust / Anchor / native `solana-program` / Pinocchio); off-chain code (TS / Python / Go clients, backends, frontends) is out of scope for this skill and is listed as such. Pin the audited commit (`git rev-parse HEAD`) so the report names exactly what was reviewed. If no human is present to answer intake, apply `QUESTIONS.md` defaults and list every assumed answer under "Scope & Assumptions". Persist the intake as `audit_<n>/intake.md` (the `intake` playbook's artifact, `commands/intake.md`) so every later phase and the report read one source of truth.

2. **Context reconstruction (Phase 0.5).** Spawn `context-builder`. It produces the instruction matrix, state model, and per-function worksheets in `audit_<n>/worksheets/context/`. No verdicts yet — understanding only. These worksheets are the shared substrate every later phase reuses (avoids re-reconstruction cost).

2b. **Threat model.** Spawn `threat-modeler` → `audit_<n>/threat-model.md`: asset inventory, an actor×capability table (what each actor must NOT be able to do), and the trust boundaries, built from the context worksheets + `intake.md`. This seeds report §4.4/§4.6/§4.7 and hands the reviewers concrete attacker goals to test — not verdicts.
   - **Bootstrap triggers.** Before spawning, check them: T2 is a prior audit or incident recorded in intake §7. For T3/T4 run `bash "<skill-root>/scripts/threat-model/collect.sh" --repo <target> --out audit_<n>/bootstrap --pin <sha> --detect`.
   - **Offline collection.** If any trigger fires, run the same command with `--offline` instead of `--detect` and pass `audit_<n>/bootstrap/` to the agent (`references/audit-lifecycle/threat-model-bootstrap.md`). This flow never clones or fetches.

3. **Tool-assisted first pass (tools up-front).** If the Trail of Bits skills (https://github.com/trailofbits/skills, CC-BY-SA-4.0) are installed separately, delegate SAST to ToB `static-analysis` over the in-scope program crates and fold the SARIF **as evidence that clears the mechanical surface and directs manual attention** — not as verdicts (`references/orchestration/boundary-map.md`). This follows Trail of Bits' precedent of running the toolset (Clippy pedantic, `cargo-audit`, `cargo-outdated`) at engagement start so linter/advisory noise is dispatched before the deep human read. Otherwise use the native grep checks in `discovery/grep-commands.md` and note the tooling gap. Load in-scope `references/methodologies/*` per their protocol markers (`SKILL.md` reference table) so domain review has the right playbook.

4. **Domain-partitioned manual review (NOT N identical clones).** Partition the surface by domain and run reviewers **in parallel over disjoint surfaces** — naive N-way fan-out of the same prompt produces ~87% false positives, so each reviewer owns a distinct partition:
   - `vuln-hunter` — in-scope checklists + phase-triggered known-vectors over the program surface.
   - `economic-analyst` — checklist 06 + economic known-vectors + the loaded `references/methodologies/*` over the value-flow surface.

   Each reviewer first reads `audit_<n>/threat-model.md` §4 — the goals mapped to its partition, their Evidence, and the Leads — and tests those before the rest of its walk.
   
   **Anti-false-positive gate at the leaf.** Each reviewer triages every candidate finding through **Rule 5b** + `references/false-positives.md` **before emitting it**. A finding that cannot complete the Rule 5b Reachability + Math/State-Bounds block (Attacker-Model for N≥7) is downgraded to `[PARTIAL]` / `[UNCONFIRMED]` — no bare high-severity claims cross the boundary.

4b. **Triage.** Run the `triage` playbook (`commands/triage.md`) over the candidate set before reconciliation: dedup by root-cause (when `"<skill-root>/tools/auditor-tools/target/release/audit-mem"` is built, its `check` auto-suppresses prior-ruled false positives and flags regressions), re-apply the Rule 5b gate (downgrade to `[UNCONFIRMED]`/`[UNDETERMINED]` with a quantified barrier per `references/false-positives.md`), and split real findings (severity 1–10) from the **Notes & Nitpicks** list (Rule 1). Emit a suppression appendix — what was withheld and why.

5. **Independent reconciliation.** Spawn `peer-reviewer` on the **top-severity survivors**: every confirmed finding at **N≥8**, plus any **N≥7** the primary could not PoC. It re-derives each finding **from the code** (reusing `audit_<n>/worksheets/context/*`), not from the primary's write-up. Reconcile: a `DISPUTE` forces the finding back through Rule 5b or to `[UNCONFIRMED]`; a `DOWNGRADE` re-rates it; disagreement forces re-examination before anything ships.

6. **Synthesis.** Spawn `audit-reporter`: deduplicate findings **by root-cause**, classify by severity (1-10), order by **severity / business importance**, and fill the **client-facing** audit report — `templates/audit-report.md` (maturity narrative + trust-model caveats + disclaimers, **no deploy guarantee**). The internal `templates/report-template.md` retains the numeric Repository Risk Score for the team's own gating; the client document never presents a risk score as a "safe to deploy" verdict (`references/audit-lifecycle/methodology.md` §1).

   **Assumptions & Simplifications section (mandatory).** The report includes a named **Assumptions & Simplifications** section, built from `context-builder`'s per-function assumptions / external-risks (Phase 0.5 worksheets) plus every intake default applied in step 1 — what the review took as given (trusted admins, honest oracles, upgrade-authority custody, out-of-scope programs) and anything the analysis abstracted away. This mirrors Certora's "General Assumptions and Simplifications" section: a reader must know the envelope the findings hold within, so "no finding here" reads against the stated assumption rather than as a blanket clearance.

7. **Deliver.** Emit `audit_<n>/REPORT.md` (the deliverable). Then best-effort PDF: if `pandoc` is available, run `"<skill-root>/scripts/report-to-pdf.sh" audit_<n>/REPORT.md` to render `audit_<n>/REPORT.pdf`; if pandoc (or the script) is absent, skip silently — **Markdown is the deliverable**, the PDF is a convenience.

   **Harnesses as a named deliverable.** If fuzz / FV harnesses were generated during the run (ToB property/fuzz harnesses via `references/orchestration/boundary-map.md`, when the Trail of Bits skills are installed separately, or Trident / cargo-fuzz targets from the `poc` playbook's `--fuzz` path), save them to **`audit_<n>/harnesses/`** as a first-class output — not scaffolding to discard. Accompany them with a short **coverage-gaps note**: which properties/invariants are asserted, which inputs are exercised, and what is explicitly **not yet covered**, so the client can rerun and extend the harness. This follows the Ackee/ToB convention of treating the harness itself as a reusable deliverable. If no harnesses were produced, omit the directory (nothing to ship).

   **Executable PoCs & patches (opt-in: `--with-poc`).** With `--with-poc`, after reconciliation the flow spawns `poc-engineer` on every confirmed **N≥7** finding, with the execution mode recorded at intake (native when none was recorded, and the report says so; `OUTPUT-RULES.md` Rule 11a) to pass to `run.sh` as `AUDITOR_EXEC_MODE`, to emit `audit_<n>/poc/F-xxx/` (see [references/orchestration/poc-harness.md](../references/orchestration/poc-harness.md)) and records the `[PoC-*]` tier on each; `patch-engineer` then drafts `audit_<n>/patches/F-xxx.patch` + `VERIFICATION.md` and records the `[FIX-*]` tier. Toolchain-gated — absent `cargo build-sbf` / surfpool it degrades to `[PoC-ATTEMPTED]` + prose and never blocks the report. Without the flag, PoCs are produced only on demand via the `poc` / `patch` playbooks (`commands/poc.md`, `commands/patch.md`), so the default run cost is unchanged.

## Honesty clause (state this in the report)

This is **audit-shaped automation — a rigorous, reproducible first pass**, not a substitute for a human audit firm. It does not replace human business-logic, economic-model, and legal-compliance review. Recommend pairing with a human audit before mainnet (`SKILL.md` → When NOT to Use).
