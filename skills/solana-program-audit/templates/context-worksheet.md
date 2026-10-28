# Context Worksheet — {function_name}

File: {path} | Lines: {start}-{end} | Access tier: {permissionless | user | manager | admin}

> Phase 0.5 artifact. Understanding only — no verdicts here. Every claim cites a line (`L#`).
> Banned words: "probably", "might", "seems", "should". If unknown, write `UNKNOWN — needs manual review`.

## Purpose (from code, not docs)
{1-2 sentences}

## Signature
- Inputs (args): {name: type — meaning} @ L#
- Accounts: {name: type/constraint — role} @ L#
- Outputs / state written: {account.field <- what} @ L#

## Block-by-Block Walkthrough
| L# | Code intent | Reads | Writes | Notes |
|----|-------------|-------|--------|-------|
|    |             |       |        |       |

## Assumptions
| # | Assumption | Source trust (signer / PDA / user data / external program) | established_by (L# · callee fn@file:L# on all paths · `nothing found`) |
|---|---|---|---|

## Invariants
| # | Invariant | Holds on paths | Broken on paths |
|---|---|---|---|

## External-Interaction Risks
| # | Interaction (CPI / sysvar / remaining_accounts / oracle / return data) @ L# | Accounts passed writable / signer | PDA signer extended? | Post-CPI reads that assume good behaviour |
|---|---|---|---|---|
(write `none: <reason>` if empty)

## Cross-Function Dependencies
- Shares state with: {fn} via {account / field}
- Must run before / after: {fn} — ordering assumption: {...}

## Unresolved — next place to look
- {question} — look at {file / fn / account}

*Sources: Trail of Bits `plugins/audit-context-building/skills/audit-context-building/SKILL.md` [paraphrased, CC-BY-SA-4.0, https://github.com/trailofbits/skills].*
