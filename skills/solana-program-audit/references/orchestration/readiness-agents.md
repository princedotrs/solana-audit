# Audit-readiness pass (Mode 6) — agents, phases, scoring

Not a bug hunt. Never produces a security verdict (OUTPUT-RULES Rule 10).

| Phase | Agent | Focus |
|---|---|---|
| 1 Test coverage | Testing | handler-to-test map (FV-096), measured coverage if available (scope per FV-106) |
| 2 Documentation | Testing | `///` on `#[program]` handlers, state structs, math fns, error enums |
| 3 Code hygiene | Source | US-018 leftovers, US-006 lint suppressions, US-005 SAFETY comments, OPS-089 feature-gated checks |
| 4 Dependencies | Infra | SC-063..067 + SC-004/011/033/037 |
| 5 Best practices | Source | checklist 01/03/04 grep heuristics only (no deep analysis) |

Agent output contract, [verbatim, MIT, (c) 2026 CD Security — CDSecurity/cdsecurity-skills `rust-audit-prep/references/shared-rules.md`]:
```
PHASE <N> | <Name> | SCORE: <X>/100

FAIL | <check> | <-N> | <file:line or n/a>
desc: <one factual sentence — what is wrong>
fix: <one sentence — specific action to fix it>

PASS | <check>
note: <brief evidence>

END PHASE <N>
```
Validation: a missing `PHASE N` marker scores 0 "(not reported by agent)"; a missing `SCORE:` is recomputed as 100 minus deductions. Weights (one set only): Best practices 35 · Hygiene 20 · Tests 20 · Docs 15 · Dependencies 10. Bands: 90–100 Audit Ready, 75–89 Almost Ready, 50–74 Needs Work, < 50 Not Ready. End with a "Quick Wins" table: top 5 FAIL items with locations.
