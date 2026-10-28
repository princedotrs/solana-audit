# Audit-Readiness Report — {repo} @ {commit}

> This is a readiness score, **not** a security verdict. It says nothing about exploitability.

| Phase | Score /100 | Weight | Weighted |
|---|---|---|---|
| 1 Test coverage | | 20 | |
| 2 Documentation | | 15 | |
| 3 Code hygiene | | 20 | |
| 4 Dependencies | | 10 | |
| 5 Best practices | | 35 | |
| **Total** | | | **/100 — {Audit Ready | Almost Ready | Needs Work | Not Ready}** |

Bands: 90–100 Audit Ready · 75–89 Almost Ready · 50–74 Needs Work · < 50 Not Ready. Our added rule: if Phase 1 scores below 90, the verdict is capped at "Almost Ready (coverage below 90%)".

## Handler-to-test map
| Handler | Value-moving? | Tested? (measured / estimated) | Test file |
|---|---|---|---|

## Findings by phase
(paste each agent's PHASE block verbatim — references/orchestration/readiness-agents.md)

## Quick wins (top 5 FAIL items)
| # | Check | Location | Fix |
|---|---|---|---|

## Coverage & limitations
State the coverage tool's scope (host or SBF), any phase an agent did not report, and which tools were not run and why.
