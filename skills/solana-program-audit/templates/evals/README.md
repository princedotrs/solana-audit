# Evals: measuring the skill itself (maintainers only)

**Never read this folder during an audit, in any mode.** It holds labels for public teaching corpora. An auditor who has read the labels is no longer blind, and the run measures nothing. No audit path links here; `scripts/check-eval-isolation.sh` fails when one does.

## What is here

`sealevel-attacks-labels.json` labels the `coral-xyz/sealevel-attacks` variants (labels only, no code copied):

- **Recall gate.** Report the class on every vulnerable variant.
- **Precision gate.** Report nothing on safe variants except declared, reasoned cross-class entries, which must keep appearing on every run. Score Informational output (severity ≤ 2) and unscored Notes separately from the gate, because Rule 1 allows them on safe code (an undocumented trust assumption is severity 1).

Fixture-specific facts (pinned versions, which `secure` variant is in fact broken, why a variant is not exploitable) live in the label file's `note` and `_verified` fields, never in `security.md`, the checklists, the known vectors or the references.

## How to run an eval honestly

1. Give the auditor the target path and the mode only. Do not mention the corpus name if you can avoid it.
2. Run `scripts/check-eval-isolation.sh` first. A failure means a fixture verdict leaked into an audit path; fix that before you trust any score.
3. Falsify the harness before you trust a green run: turn one checklist item into a no-op and recall must drop; make the auditor fire on everything and precision must fail.
4. Public judged contests (Code4rena, Sherlock, Cantina, CodeHawks First Flights) work as calibration. Missed Highs point to checklist gaps, and invalidated reports point to false-positive gaps. Re-check judged counts before relying on them.
