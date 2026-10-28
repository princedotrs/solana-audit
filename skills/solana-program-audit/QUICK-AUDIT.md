# Quick Audit: procedure and rules digest

> **Load when:** quick-audit mode ("quick audit", "first look", "triage", a request that names `audit.md`) or the `quick-scan` playbook.
> **What it replaces:** a quick audit reads this page *instead of* the whole of [OUTPUT-RULES.md](OUTPUT-RULES.md). It restates the parts of OUTPUT-RULES that bind a quick audit. If this page and OUTPUT-RULES ever disagree, OUTPUT-RULES wins; open the named rule when a case is not covered here.
> **Output:** `audit.md` in the format of [SKILL.md](SKILL.md) → Quick Reference.

---

## 1. Steps, in order

0. **Discover the target (before reading anything else).**
   - Check that the path exists and holds on-chain Rust: `Cargo.toml` with `anchor-lang`, `solana-program` or `pinocchio`, `Anchor.toml`, `programs/`, `#[program]`, `entrypoint!`. If the path is missing or empty, or holds no on-chain program, stop here and write the short form in §6.
   - List every in-scope `.rs` file with its line count.
   - Read the resolved versions of `anchor-lang`, `anchor-spl`, `solana-program`, `spl-token`, `spl-token-2022` and `pinocchio` from `Cargo.lock` as text. Run no `cargo` command inside the tree (Rule 11a).
   - Note the markers present (Token-2022, `unsafe`, `remaining_accounts`, `invoke`, sysvars, oracles) for the vector filter in step 5.
1. **Read** [security.md](security.md) (the classes and the 14 Security Review Questions), then this page, then the **Triage fast pass** at the end of [references/false-positives.md](references/false-positives.md). Open a full FP entry only when a candidate matches it. [references/orchestration/senior-auditor-sop.md](references/orchestration/senior-auditor-sop.md) is 11 lines; read it too.
2. **Walk the code.** Read every in-scope file completely, and read the callee whenever a handler calls into another file (Rule 3). Files under about 150 lines may be read in batches of up to about 600 lines. For each instruction, answer every Security Review Question. Use the checklist sections in §2 to look up what an answer must prove. You do not need to read whole checklists or give a verdict per item.
3. **Cheap cross-cutting checks** (from FULL-AUDIT Step 1.5), only on the handlers you flagged and their siblings:
   - P4, dead guards: a check that can never reject (inverted polarity, tautology, the wrong account) is a finding at the ceiling of the path it fails to protect.
   - P5, comparison direction: write down which way each limit check should go, then read the operator.
   - P10, sibling propagation: grep each confirmed root cause across every other handler.
4. **Triage every candidate** against the fast pass, then score it (§3). Any candidate at 6 or more must pass the gate in §4.
5. **Known vectors.** Evaluate the rows of [known-vectors/INDEX.md](known-vectors/INDEX.md) that satisfy both conditions:
   - the row's Severity column is **7 or higher** (this is what "CRITICAL / HIGH" means for vectors);
   - the row is triggered: its Load-when cell is `always (crypto)`, or at least one of its markers occurs in the in-scope tree.

   The one-line row is enough unless the code has the row's pattern. Then open the vector file and follow its procedure. On Anchor, also walk the KV-158 version matrix for the resolved version (checklist 21 AN-001). INDEX's "every vector gets a verdict" is the completeness rule of a full audit (Rule 0) and does not bind a quick audit. A quick audit lists which vectors it evaluated and says that the rest were not evaluated.
6. **Chain check.** With two or more findings or leads, spend one paragraph on whether one finding's effect meets another's precondition (FULL-AUDIT Step 1.6). A chain is scored at the chain's severity.
7. **Write `audit.md`** where the user asked for it. If the user named no place, write it in a new `audit_<n>/` whose first file is a `.gitignore` containing `*` (Rule 11d).

**Not run in a quick audit; name them under Coverage as not run:** the Rule 0 Scope Coverage table, per-item verdicts (Rule 4), the attacker-lens sweep (FULL-AUDIT Step 1.4), Step 1.5 passes other than P4, P5 and P10, checklists 05–07, 11, 12, 16 and 23, builds, tests, PoCs and fuzzing. The grep checks in [discovery/grep-commands.md](discovery/grep-commands.md) are optional on small targets. On a target over about 2,000 in-scope lines, run the Account Safety, Access Control and CPI & PDA groups first to decide which files to read first. You still read every file.

**Checkpoint (Rule 3).** It is optional when the target has 15 or fewer in-scope files and 2,000 or fewer lines and you finish in one session. Otherwise write `audit-checkpoint.md` every few files: in the host's session scratchpad, or else next to `audit.md` (never elsewhere in the target tree).

## 2. Which checklist sections answer which question

| Security Review Question (security.md) | Look up |
|---|---|
| 1 Fake account passes validation | 01 §1.1, §1.2, §1.3, §1.6; §1.10 (native / Pinocchio) |
| 2 Missing authorization | 02 §2.1–2.3, §2.6, §2.8 |
| 3 Malicious CPI target | 04 §4.1, §4.5 |
| 4 Reinitialization | 01 §1.7, §1.13 |
| 5 Shared PDAs | 04 §4.3, §4.4 |
| 6 Same account in two slots | 01 §1.3 (AV-031), §1.13 (AV-108) |
| 7 Closed-account revival | 01 §1.7 (AV-056), FP-2 |
| 8 Stored vs provided data mismatch | 01 §1.3, §1.6; 02 §2.8 |
| 9 Rounding | 03 §3.3–3.5, §3.10 |
| 10 `remaining_accounts` | 01 §1.4 |
| 11 Sysvar spoofing, introspection | 01 §1.9 |
| 12 CPI return data | 04 §4.2 (CPI-033) |
| 13 Token-2022 extensions | 01 §1.8; checklist 22 when its markers are present |
| 14 Init front-running, pre-created or pre-funded accounts | 01 §1.12, §1.13; 02 §2.8 |
| any Anchor-specific behaviour | checklist 21 (version-dependent semantics) |
| overflow, casts, division | 03 §3.1–3.3, §3.8 |

## 3. Severity (Rule 1, digest)

| Score | Label | Meaning |
|---|---|---|
| 10–9 | Critical | fund drain or loss with minimal preconditions (10 unbounded and permissionless, 9 bounded or minimal precondition) |
| 8–7 | High | fund loss with preconditions, partial drain, privilege escalation |
| 6–5 | Medium | state corruption, DoS, griefing, limited economic manipulation, logic bugs |
| 4–3 | Low | minor leak; a security gap with no stated exploit path |
| 2–1 | Info | hardening with a concrete benefit; an undocumented trust assumption |
| — | Notes | no security impact; unscored |

Decision guide: theft without preconditions → 10 (9 if the amount is bounded). Theft with preconditions → 8 (7 if small or bounded). State corruption, DoS or economic manipulation → 6 (5 if limited). A gap without a clear exploit path → 4 if data is exposed, else 3. Hardening only → 2 or 1.

The first four rules below are stated in full in OUTPUT-RULES Rule 1 → "Scoring basis and precedence".

- **Basis.** Assume preconditions the deployment can have (an account state the program's own instructions can create, a configuration, a token mint the program accepts). Never assume impact that the code does not have. "Theoretical → 3" is for a gap with no exploit path at all.
- **Precedence.** A dead guard inherits the ceiling of the path it fails to protect, and that ceiling replaces "logic bug → 5". A finding that composes into a worse chain takes the chain's score. Levers apply last.
- **Levers.** Moving down needs a named lever with its worked justification (self-sacrifice, economic infeasibility with numbers, recoverable, bounded blast radius, redundant guard, privilege required). One lever moves at most 2 points, two independent levers at most 4.
- **Checklist and vector bands are ceilings.** A severity written in a checklist item, a checklist header or the INDEX Severity column is the class's ceiling when its impact is realised. Rule 1 and the gate set the score.
- **Teaching code, fixtures and fragments.** Use one basis for every finding and name it in the status line. *As written* is the default for example, test or fixture code. *Lifecycle assumed* applies when the code is a fragment of a real program. Details: OUTPUT-RULES Rule 1 → "Teaching code, fixtures and fragments".
- **Admin-only paths** are capped at Low or Info centralisation notes unless an unprivileged amplifier exists, or the power is undisclosed (Rule 5b admin-action rule).

## 4. The gate for N ≥ 6 (Rule 5b, digest)

Run the cheap rejections first, in order:

| Gate | Reject when | Demote when |
|---|---|---|
| 0 Refutation | a concrete guard, cited, blocks the exact step | a smell remains although refuted |
| 1 Runtime / framework | the runtime or framework blocks it on the resolved version (FP catalogue) | blocked only on some versions in use |
| 2 Reachability | the vulnerable state is structurally impossible (apply the §3 basis the same way to every finding) | it needs privileged actions outside normal operation |
| 3 Trigger | cost exceeds extractable value **and** there is no griefing, lock-up or DoS impact | only trusted roles can trigger it |
| 4 Impact | self-harm only | dust, non-compounding |

Then fill the **Validation** field of the finding (one line per item, each cited `file:line`):
- **Reachability** (N ≥ 6): entry point; signer required; preconditions; why the guards do not block it; REACHABLE / GUARDED / UNREACHABLE.
- **Math / State-Bounds** (N ≥ 6): the expression or transition; the input domain; the boundary that breaks; a worked case; the net effect.
- **Attacker-Model** (N ≥ 7): capability; setup cost; profit or damage; atomicity; profitable, griefing-only or requires-privilege.

If a block cannot be filled with cited evidence, the finding becomes `[UNCONFIRMED]` (unreachable or unbounded as written) or `[UNDETERMINED]` (reachable, impact not quantified, reported at its likely band and flagged). Put the token after the severity in the heading.

**Evidence.** Tag what you rely on: `[CODE]`, `[EXT-UNV]` (an external crate or program you could not read at the resolved version), `[DOC]`. You may not *reject* a finding on `[EXT-UNV]` or `[DOC]` evidence; mark it `[UNCONFIRMED]` instead. You *may* apply the downgrade an FP entry prescribes when the entry states the version range it holds for and the `Cargo.lock` version is inside it. To read a dependency at its exact version without running anything, follow Rule 11a → "Reading a dependency's source".

## 5. Honesty and safety (Rules 10 and 11, digest)

- **Status line.** Open `audit.md` with the triage disclaimer and the run status. The run status is one of `completed`, `build-blocked`, `tooling-blocked`, `policy-interfered`, `target-absent` or `no-in-scope-code`. Add a status for each lane: source review, compilation, PoC (`passed | partial | blocked | failed | skipped`, with a reason).
- **No "clean".** Say what was examined and what was not. A quick audit that found nothing still lists what it covered.
- **Never** claim a check you did not read. Use `*confidence: medium` (or low) where a verdict rests on an unread callee or a macro you did not expand.
- **No target code runs** in a quick audit unless the user asks for a build or an analyzer you run needs one; then the execution mode of Rule 11a applies. Any `cargo`, `rustc` or `anchor` command started inside the tree counts as running target code (Rule 11a).
- **Name every outside service** a tool contacted, for example crates.io for a dependency fetch (Rule 11b).
- **Git.** In a checkout you did not create, use only the safe read forms of Rule 11c.
- **Bundled paths.** Every bundled path resolves from `<skill-root>`, never from the audited repo (Rule 11e).

## 6. When there is nothing to audit

If the target is missing or empty (`target-absent`), or holds no on-chain program (`no-in-scope-code`), write only the status line, a Program Summary that names the path and what was looked for, no Findings section, and this sentence: "No code was audited; this is not a statement that anything is safe." Add how to resume ("re-run the quick audit on <path> once it exists"). Never write findings from a description of the code.

*Sources: a digest of this skill's OUTPUT-RULES.md (Rules 1, 3, 5b, 10, 11), SKILL.md and FULL-AUDIT.md. The gate table restates Rule 5b's, adapted from sanbir/solana-auditor-skills `solana-auditor/references/judging.md` and pashov/skills `solidity-auditor/references/judging.md` (MIT, Copyright (c) 2024 AI Skills Contributors). The P4, P5 and P10 passes restate FULL-AUDIT Step 1.5, adapted from qedgen/solana-skills `skills/qedgen-auditor/references/manual-review-passes.md` (MIT, Copyright (c) 2025 QEDGen). The rest is original.*
