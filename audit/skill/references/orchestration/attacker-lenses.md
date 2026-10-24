# Attacker lenses (FULL-AUDIT Step 1.4)

Each lens hunts the same bundle with a different mindset and is told "other lenses cover X; you only do Y". Output: OUTPUT-RULES Rule 4b blocks. All findings go through Rule 5b. Lenses are read-only in the target repo. An empty result is a valid answer.

**Shared rules for every lens.** When you find a bug in one handler, search every other handler and module for the same pattern by name **and** by code shape (check Rust fn names and Anchor instruction names; for native programs walk every dispatch arm). Escalate each finding to its worst exploitable variant (a DoS may hide theft), then revisit the function and attack its other branches.

> Verbatim shared rule, [verbatim, MIT, (c) 2024 AI Skills Contributors — sanbir/solana-auditor-skills `shared-rules.md`]: "When you find a bug in one instruction handler, **weaponize that pattern across every other handler and module in the bundle.** Search by function name AND by code pattern. Finding missing signer validation in `deposit()` means you check every other handler's account validation — missing a repeat instance is an audit failure."

| # | Lens | Focus (Solana) | Extra required fields |
|---|---|---|---|
| 1 | Vector scan | grind `known-vectors/*` in scope; extract each root cause and hunt every manifestation under any name; reach guarded states via sibling handlers, CPI paths, `remaining_accounts`, attacker-controlled seeds; open with the Skip/Drop/Investigate/Total block | — |
| 2 | Math precision | every fixed-point domain (bps, decimals, oracle expo, accumulators) and every division on value paths; narrowing `as` and sign flips; `saturating_*` hiding errors; overflow-checks profile; lamport vs token; 6 vs 9 decimals; worked numbers required | worked numbers |
| 3 | Access control | permission map first (authorities, `has_one`, `Signer`, seeds, constraints, `require!`, PDA gates); **weakest-writer rule** (a field written by ≥ 2 handlers is as safe as its weakest guard); `Pubkey::default()` as new authority (lock-out); escalation chains; init front-running; upgrade authority | `guard_gap` |
| 4 | Economic security | unlimited capital, any instruction composition in one transaction or bundle; break external dependencies (stale oracle freezing liquidations); starve shared caps; turn protocol mechanisms against it; profit/cost numbers | profit/cost |
| 5 | Execution trace | entry → final state within and across transactions; parameter divergence (instruction-data mint vs the token account's mint; `amount` arg vs measured delta); sentinel bypass (`Pubkey::default()`, `0`, `u64::MAX`, empty `Vec`); wrong-state execution (withdraw before init, close while locked); request→execute interleaving; durable-nonce freshness. Stale reads after CPI → pointer to RE-002/003 | `input`, `assumption` |
| 6 | Invariant | map conservation laws and couplings (`vault.tracked == token.amount`, mint supply vs internal shares, round-trip ≤ input, commutativity, cap-skipping paths: fee accrual, admin, emergency); break; build the exploit | `invariant`, `violation_path` |
| 7 | Periphery | start with the smallest modules (`math.rs`, `utils.rs`, seed and validation helpers, custom pack/unpack): helpers trusted to validate that do not; hidden lamport moves or CPIs; CPI wrappers that do not pin program ids; loops whose worst case exceeds the caller's CU budget | — |
| 8 | First principles | no pattern names allowed; per handler extract value (fresh), ordering (init before deposit), identity (this pubkey is who we think), arithmetic (fits, non-zero) and state (PDA exists; no concurrent change by another instruction in the tx) assumptions and break each; report only unnamed classes | `assumption`, `violation` |
| 9 | Asymmetry | checklist 05 §5.12 (pairs, branches, field lifecycle, admin variants, bad symmetry) | — |
| 10 | Boundary | checklist 04 §4.7 (enumerate every boundary, ask the fixed questions) | `boundary`, `assumption`, `actual` |
| 11 | Numerical gap | only bugs that need precision × invariant × boundary at once (invariant-catalog §9) | `seam:` + numbers |
| 12 | Trust gap | only access × economics × asymmetry seams (ECON-108) | `seam:` |
| 13 | Flow gap | only execution × periphery × first-principles seams (ECON-109) | `seam:` |
| 14 | Protocol (deep) | classify the protocol type and run the matching `references/methodologies/*` | — |

Gap hunters (11–13) drop anything a single lens could express.

**Bundling and passes:** FULL-AUDIT Execution Notes (bundle files in the session scratchpad, never inline source; multi-pass "new ground" loop).
