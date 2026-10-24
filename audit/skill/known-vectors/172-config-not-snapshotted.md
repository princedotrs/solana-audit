---
id: 172
title: "Live Config Read at Execute / Release Instead of a Snapshot"
severity: 6
category: crypto
---

### 172 — Live Config Read at Execute / Release Instead of a Snapshot

**Severity: 6 (4–7; HIGH when an admin change can strand or seize committed funds; higher when a permissionless actor moves the parameter or can front-run the admin change)** | **Real: Zellic Pye — "fee can be front-run on deposit/withdraw" (High)**

Two-step flows (request → keeper execute, unstake → claim, commit → reveal, order → fill) and custody flows (deposit/lock/stake → release) store the user's own parameters (KV-129 covers those) but read protocol terms — `fee_bps`, `max_slippage`, `oracle`, `haircut`, `exchange_rate`, `lock_duration`, `exit_fee`, hook, allowlist, pause — from live `Config` at execute/release. An admin or permissionless update between the steps applies terms the user never agreed to: a longer lock or a flipped allowlist strands funds; an exit fee raised toward 100 % seizes them. This generalises ECON-027 (retroactive fee), ECON-070 (settle before rate change) and the `update_curve_params` rule in `references/methodologies/launchpads.md` to every term.

> Cross-ref: SM-080, OPS-094, KV-129, Rule 5b admin amplifier (race / retroactive).

#### Verification Procedure
```
rg -n 'struct\s+\w*(Request|Ticket|Pending|Order|Receipt|Lock)\b' programs/
rg -n 'config\.(fee|slippage|oracle|rate|haircut|ltv|bonus|lock_duration|exit_fee|hook|allowlist)' programs/ | rg -i 'execute|withdraw|unlock|claim|redeem|release|fill'
```
For each request/receipt type, list fields stored at step 1 and `config.*` reads at step N.
- ✅ PASS: user-protective terms snapshotted at request/deposit (`fee_bps_at_request`, `unlock_at`, `terms_hash`, or `config_version` with `require!(config.version == request.config_version)` and penalty-free cancel); newly lowered safety limits deliberately re-read; setters monotonic in the user's favour or timelocked
- ❌ FAIL: terms that decide whether/when/how much can leave are read live, and an admin setter has no bound or delay

```rust
// VULNERABLE
require!(now >= receipt.deposited_at + config.lock_duration, ErrorCode::Locked); // live read
// FIXED
receipt.unlock_at = now.checked_add(config.lock_duration).ok_or(ErrorCode::Math)?; // at deposit
require!(now >= receipt.unlock_at, ErrorCode::Locked);                              // at withdraw
```

**Overall verdict:**
- ✅: committed users cannot be re-termed retroactively
- ⚠️: re-termable, but the power is documented as a trust assumption and timelocked
- ❌: retroactive re-terming possible

*Sources: pashov/skills in-flight config pattern (MIT, Copyright (c) 2024 AI Skills Contributors); qedgen/solana-skills live-config custody pattern (MIT, Copyright (c) 2025 QEDGen) cross-linked as a generalisation; PlamenTSV/plamen §5 (MIT, Copyright (c) 2025-2026 Plamen Contributors); Zellic Pye [cited: https://reports.zellic.io/publications/pye/sections/fee-can-be-front-run-on-depositwithdraw-fee-frontrunning].*
