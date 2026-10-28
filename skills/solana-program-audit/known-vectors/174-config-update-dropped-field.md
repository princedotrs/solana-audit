---
id: 174
title: "Config Update Silently Drops a Field"
severity: 5
category: crypto
---

### 174 — Config Update Silently Drops a Field

**Severity: 5 (higher when the dropped field is a safety lever: fee, cap, pause, oracle, migration allocation)** | **Real: Pump Science H-02 (contest)**

`update_settings(params)` copies most fields but forgets one. The admin believes a parameter changed; it never does, so a safety lever is dead. Also: `Option<T>` params where `None` is handled but `Some` is never written.

> Cross-ref: SM-079.

#### Verification Procedure
```
rg -n 'pub struct \w*(Params|Input|Args|Settings)' programs/
rg -n 'fn (update|set)_[a-z0-9_]+' programs/
```
Diff each params struct's fields against the assignments in its handler.
- ✅ PASS: every field written. Exhaustive destructuring `let S { a, b, c } = p;` with no `..` makes a field added to the struct later a compile error (E0027) until it is named, and a named field that is never assigned shows up as an unused-variable warning
- ❌ FAIL: any field never written

```rust
// VULNERABLE
cfg.fee_bps = p.fee_bps; cfg.admin = p.admin; /* p.max_cap never written */ cfg.whitelist = p.whitelist;
// FIXED
let SettingsInput { fee_bps, admin, max_cap, whitelist } = p;
cfg.fee_bps = fee_bps; cfg.admin = admin; cfg.max_cap = max_cap; cfg.whitelist = whitelist;
```

**Overall verdict:** ✅ every field applied · ❌ any field silently dropped

*Sources: sanbir/solana-auditor-skills `solana-auditor/references/attack-vectors/attack-vectors-1.md` V25 (MIT, Copyright (c) 2024 AI Skills Contributors).*
