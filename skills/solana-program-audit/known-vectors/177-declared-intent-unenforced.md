---
id: 177
title: "Declared Intent the Code Never Enforces"
severity: 5
category: crypto
---

### 177 — Declared Intent the Code Never Enforces

**Severity: inherits the ceiling of the path the dead guard fails to protect (e.g. HIGH for an unwired authority check on a privileged CPI); 5 by default** | **Real: qedgen benchmark corpus (repeatedly missed on cold reads)**

The author named an invariant but nothing enforces it, so there is no guard to find a gap in: (1) a constant defined but never read (`MIN_PAYOUT_LAMPORTS`); (2) a config field written at init and never read; (3) a mode/enum parameter persisted but never branched on ("quote-only" behaves like "both"); (4) an `#[error_code]` variant with zero raise sites; (5) a `match` arm treating variants identically when the docs say one is partial.

> Cross-ref: FULL-AUDIT Step 1.5 P4, SM-005, SM-077.

#### Verification Procedure
```
# unwired error variants
for v in $(rg -o '^\s+[A-Z][A-Za-z0-9]+' programs/*/src/error*.rs | awk '{print $NF}'); do
  n=$(rg -n "::$v\b|err!\(.*$v|error!\(.*$v" programs/ --type rust | rg -v 'error.rs' | wc -l)
  [ "$n" = 0 ] && echo "UNWIRED $v"; done
# error enums in errors.rs / error/mod.rs / lib.rs: adjust the path; `::$v` also catches custom enum names
```
Also run `cargo check` for dead-code warnings (Rule 11f). Note that rustc does not warn on unused `pub` items in a library crate (Anchor programs are `lib`/`cdylib`), so an unread `pub const` or error variant needs the grep, not the warning. Grep each config field for readers outside init. Search the README, doc comments and bounty text for `must|only|always|never|at most|within|per day`, and confirm each claim in the code.
- ✅ PASS: every declared constraint has an enforcement site, or is documented as not enforced
- ❌ FAIL: a security-relevant declared constraint is unenforced

**Overall verdict:** ✅ intent enforced · ❌ dead guard on a value or authority path

*Sources: qedgen/solana-skills `skills/qedgen-auditor/references/manual-review-passes.md` §3f dead-guard / intent-drift sweep and `skills/qedgen-auditor/references/category-catalog.md` `bounty_intent_drift` (MIT, Copyright (c) 2025 QEDGen).*
