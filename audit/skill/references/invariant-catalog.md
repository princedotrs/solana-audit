# Invariant Catalog — Harness-Ready Invariant Menus per Protocol Class

> **Load when:** `context-builder` or `economic-analyst` needs a starting invariant set for a
> detected protocol class — i.e. when reconstructing per-function invariants (Phase 0.5), when
> scoping an FV/fuzz harness (`references/audit-lifecycle/methodology.md` → FV ladder), or when
> writing the report's invariant-property table. Instantiate the relevant menu(s); a protocol is
> usually a **blend**, so pull from several.

---

## How to use this file

Each entry is a **candidate invariant** stated in three parts, so it can go straight into a harness:

- **Statement** — one line, declarative ("what must always be true"), independent of any code line.
- **Ranges over** — the state the invariant quantifies across (which accounts / values / op sequences it must hold for). This is what a harness enumerates.
- **Assert** — how to check it in a harness: a `proptest`/`quickcheck` property on a pure function, or a **Trident** stateful post-condition asserted after every instruction (or after a random multi-instruction sequence). Where relevant, note the `assume` (precondition) the harness needs.

These are a **menu, not a spec** — pick the invariants whose violation is a real finding for *this* target, drop the ones that don't apply, and add protocol-specific ones from `context-builder`'s per-function work. An invariant is only worth a full proof (Certora/Kani) when a single counterexample is catastrophic; the rest are fuzz/proptest targets. Cross-ref the per-class methodologies (`references/methodologies/*`) for the domain-specific failure modes each invariant guards.

---

## 1. Token / Vault

Conservation of value is the whole game: shares and underlying must reconcile, and no path may create or destroy value without a matching, accounted counter-move.

- **Supply conservation.**
  - *Statement:* Σ of all token-account balances for a mint == the mint's recorded `supply` (no tokens exist outside the accounted set).
  - *Ranges over:* every token account of the mint, across any sequence of mint / burn / transfer / deposit / withdraw instructions.
  - *Assert:* Trident post-condition after each instruction — sum the tracked token accounts and `assert_eq!(sum, mint.supply)`. Seed the harness with all holders as tracked accounts.

- **No mint without a matching debit.**
  - *Statement:* every increase in circulating supply (or vault shares) is backed by a corresponding recorded inflow — shares minted ⇒ underlying deposited; underlying withdrawn ⇒ shares burned. `Δshares` and `Δunderlying` never move in a value-creating direction.
  - *Ranges over:* the (shares_supply, vault_underlying) pair across deposit/withdraw/mint/burn sequences.
  - *Assert:* Trident — snapshot both before/after each op; `assert!` that `shares_out` was matched by `underlying_in` (round-trip `deposit(x); withdraw_all()` returns ≤ x). This is the ECON share-inflation guard as a property.

- **Rent-exemption preserved.**
  - *Statement:* no instruction leaves a still-live program-owned account below its rent-exempt minimum (an account is either rent-exempt or fully closed, never a partially-drained zombie).
  - *Ranges over:* every account the program debits lamports from (vault, fee, state) across all ops, including partial withdraws and fee sweeps.
  - *Assert:* Trident post-condition — for each live account, `assert!(account.lamports() >= Rent::minimum_balance(account.data_len()))`. Cross-ref KV-123 (lamport-donation bricking) for the dual (donation) direction.

---

## 2. AMM / CLMM

The pool must never pay out more than the curve allows, and rounding must always leave the pool at least whole. For concentrated liquidity, boundary math is where these break (cross-ref `references/methodologies/amm-clmm.md`).

- **Constant-product floor (`k = x · y` non-decreasing).**
  - *Statement:* after any swap (fees included), `reserve_x · reserve_y ≥ k_before` — the invariant product never decreases across a swap.
  - *Ranges over:* the two reserve balances across an arbitrary sequence of swaps in both directions, at arbitrary sizes.
  - *Assert:* Trident — record `k = x*y` (as u128) before each swap, `assert!(x_after * y_after >= k_before)` after. For CLMM, the analogue is per-tick: active `liquidity` reconstructs correctly after crossing sequences.

- **Rounding favors the pool.**
  - *Statement:* every conversion (amount-in, amount-out, sqrt-price step) rounds so the pool is never short — amount-in rounds up, amount-out rounds down; a round-trip cannot extract value.
  - *Ranges over:* single swap-step math (pure function), then repeated-crossing sequences.
  - *Assert:* `proptest` on the pure `compute_swap_step` / `get_amount_delta` function — assert output direction against exact rational arithmetic; plus a Trident sequence asserting `swap(a→b); swap(b→a)` returns ≤ starting amount (dust-per-crossing leak, the CLMM boundary class).

- **Fee never exceeds input.**
  - *Statement:* the fee charged on a swap is ≤ the input amount (and ≤ its configured bps), and fee accounting credits exactly what was withheld — no double-count, no negative net.
  - *Ranges over:* fee computation per swap across all sizes and both directions.
  - *Assert:* `proptest` on the fee function — `assert!(fee <= amount_in && fee <= amount_in * fee_bps / DENOM + 1)`; Trident to confirm `fee_growth_global` is monotonic and matches summed withholdings.

---

## 3. Lending / Borrowing

Solvency and health must hold *continuously* — including mid-CPI and at oracle bounds. (Deep failure modes: `references/methodologies/lending.md`; this is the harness distillation.)

- **Solvent positions stay above the liquidation line.**
  - *Statement:* every obligation that the protocol treats as non-liquidatable satisfies `collateral_value / debt_value ≥ liquidation_threshold`; conversely, any obligation with health < 1 is liquidatable.
  - *Ranges over:* every open obligation across deposit / borrow / repay / withdraw / accrue / liquidate sequences, under conservative pricing.
  - *Assert:* Trident post-condition after each op — for each tracked obligation, `assert!(!marked_healthy || health(o) >= threshold)`; feed prices at their staleness/confidence bounds via the harness `assume`. Compute health only from refreshed state.

- **Interest index is monotonic per slot.**
  - *Statement:* the borrow/liquidity index never decreases — `new_index ≥ old_index` at every accrual point (no negative interest, no reset).
  - *Ranges over:* the index value across every accrual / refresh call at arbitrary slot deltas.
  - *Assert:* `proptest` on the accrual function — `assert!(accrue(index, rate, dt) >= index)` for all `dt ≥ 0`; Trident to confirm no instruction path resets or rounds it down.

- **Aggregate borrows bounded by collateralized deposits.**
  - *Statement:* Σ borrows ≤ Σ deposits × collateral-factor across the reserve (system-wide solvency), so the pool can always cover withdrawable liquidity minus reserves.
  - *Ranges over:* the (total_borrowed, total_supplied) reserve aggregates across any op sequence.
  - *Assert:* Trident global invariant — `assert!(total_borrowed <= total_supplied.saturating_mul(collateral_factor) / DENOM)` after each op; the standalone `total_supplied >= total_borrowed + reserves_taken` solvency check is a property-test target over random sequences.

---

## 4. Multisig / Governance

Authorization and single-execution are the invariants; the subtle one is that a membership/threshold change must not leave stale approvals live (cross-ref `references/methodologies/governance.md`).

- **Execution implies sufficient approvals.**
  - *Statement:* a proposal/transaction can only reach `Executed` if its recorded approvals ≥ the threshold that was in force for it.
  - *Ranges over:* every proposal across propose / approve / revoke / execute sequences with arbitrary signer subsets.
  - *Assert:* Trident post-condition — on any transition to `Executed`, `assert!(approval_count >= threshold)`; drive random approve/revoke orderings.

- **No double-execution.**
  - *Statement:* a proposal executes at most once — a second execute of the same proposal is rejected (idempotence via a consumed/executed flag or nonce).
  - *Ranges over:* the executed-state of each proposal across repeated execute attempts (including reentrant / duplicate-instruction attempts).
  - *Assert:* Trident — attempt `execute` twice in a sequence; `assert!` the second fails and state/effects are unchanged. Model the executed marker as the state it ranges over.

- **Member-set / threshold change invalidates stale approvals.**
  - *Statement:* changing the member set or threshold invalidates approvals collected under the old configuration — a proposal cannot execute on signatures from removed members or against a superseded threshold.
  - *Ranges over:* the (approvals, member_set, threshold) triple across a change-config op interleaved with pending proposals.
  - *Assert:* Trident sequence — collect approvals, mutate the member set/threshold, then attempt execute; `assert!` it either fails or requires re-approval under the new config (this is the classic stale-approval finding).

---

## 5. Vesting / Staking

Claimed can never exceed earned, and every reward accounting change must reconcile its bookkeeping so no double-claim survives a stake change.

- **Cumulative claimed ≤ vested.**
  - *Statement:* the total amount ever claimed by a beneficiary is ≤ the amount vested at the current time per the schedule (never claim ahead of the curve).
  - *Ranges over:* the per-beneficiary `total_claimed` against `vested_at(now)` across claim calls at arbitrary timestamps (including clock edge cases at start/cliff/end).
  - *Assert:* Trident post-condition after each claim — `assert!(total_claimed <= vested_amount(schedule, clock.unix_timestamp))`; `proptest` the pure `vested_amount` for monotonicity and clamping to the total grant.

- **`reward_debt` reconciles on every stake change.**
  - *Statement:* the accumulator-based reward bookkeeping (`pending = user_stake * acc_per_share - reward_debt`) is reset consistently on **every** deposit/withdraw so a stake change can never mint unearned rewards or strand earned ones.
  - *Ranges over:* the (user_stake, reward_debt, acc_per_share) tuple across interleaved stake/unstake/claim sequences for multiple users.
  - *Assert:* Trident — after each stake-changing op, `assert!` computed `pending` is non-negative and that summed distributed rewards ≤ total rewards funded; drive random multi-user stake churn (this is where MasterChef-style double-claim bugs surface).

---

## 6. Oracle-Consuming

Any protocol that reads a price must refuse to act on data that is stale or too uncertain — the invariant is on the *gate*, not the price value (cross-ref `references/methodologies/oracles.md`).

- **Staleness bound enforced.**
  - *Statement:* no state-changing decision uses a price whose publish slot is older than `MAX_STALENESS` — a stale read rejects the whole instruction, never silently falls back.
  - *Ranges over:* every price-consuming instruction across arbitrary `clock.slot` vs `price.publish_slot` gaps.
  - *Assert:* Trident with a mocked price account — set publish_slot to exceed the bound via `assume`, `assert!` the instruction reverts; `proptest` the pure `is_fresh(slot, publish_slot)` gate at the boundary (`= MAX` vs `> MAX`).

- **Confidence checked.**
  - *Statement:* a price is used only when its confidence interval (Pyth `conf/price`, or Switchboard variance) is within a configured bps cap — a too-wide band rejects.
  - *Ranges over:* the (price, conf) pair across the consuming instructions at varying confidence widths.
  - *Assert:* Trident — feed a wide-confidence price, `assert!` reject; `proptest` the `conf_bps = conf * 10_000 / price` gate for overflow-safety and the reject boundary.

---

## 7. Token-Registry / Listing Consumer

A registry (token list, canonical-asset mapping, risk score) is an off-chain identity oracle. The invariants below are for the *consumer* — the on-chain program whose allowlist / listing / collateral decision the registry feeds, and the off-chain component that feeds it. Off-chain code (backends, frontends, the registry operator's ranking / scoring) is out of scope for this skill: assert the on-chain half in the harness, and record the off-chain half as an assumption in the report's Assumptions & Simplifications section.

- **Value paths are mint-pinned.**
  - *Statement:* for every swap / transfer / payment / collateral path, the mint the transaction touches equals a mint present in the pinned config or on-chain allowlist at the time the path was entered — never a mint freshly resolved from a symbol, name or registry `assetId`.
  - *Ranges over:* every value-moving instruction / endpoint, across any registry response (including a hostile "primary variant" for the same symbol).
  - *Assert:* property test — fuzz the registry stub to return arbitrary mints for the same symbol / assetId and `assert!(tx.mint ∈ pinned_set)`; Trident post-condition on an on-chain allowlist program: an accepted mint set changes only through the admin / governance instruction.

- **Score never authorizes.**
  - *Statement:* the set of mints a listing / collateral / routing path accepts is invariant under the registry risk score, grade, tier or `verified` flag — flipping the score for a mint never changes acceptance without the on-chain checks (mint / freeze authority, permanent delegate, extension set, metadata mutability) also passing.
  - *Ranges over:* every acceptance decision, across all score values including `unavailable` / `insufficient data`.
  - *Assert:* differential test — same mint, score ∈ {A, C, unavailable, error}; `assert_eq!(accepted(mint, score_i), accepted(mint, score_j))` for every pair when on-chain facts are held constant; and `assert!(!accepted)` for a mint with a live freeze authority regardless of score.

- **Registry outage fails closed.**
  - *Statement:* when the registry / risk provider is unreachable, stale beyond the bound, or returns an unknown mint, no path yields a *verified* / *safe* / *listed* outcome.
  - *Ranges over:* every consumer path, across provider states {timeout, 5xx, 429, malformed, stale, unknown mint}.
  - *Assert:* stub each provider state and assert every outcome is in `{unverified, unavailable, rejected}` (an off-chain path: assert it only when that feeder code is supplied as context; otherwise record it as an assumption).

---

## 8. Round-trip & cycle invariants (complements §1, which already has `deposit(x); withdraw_all() <= x`)

- **Reverse then forward gives no free shares (measured in shares):** redeem `s` shares for assets `a`, then deposit `a`; the shares received are ≤ `s`.
- **Repeated-cycle dust extraction (mandatory for vaults and pools):** N cycles of `deposit(X) → withdraw(all)` never increase the actor's balance. Test X ∈ {1, 2, 10^decimals − 1, u64::MAX / 2}, and repeat with a donated (inflated) exchange rate.
- **Commutativity:** `A.ix → B.ix` and `B.ix → A.ix` by different users give each user the same value up to a stated rounding bound. Order dependence a party controls (bundles) is extractable value.
- **View/execute equivalence:** every `quote_*` / `simulate_*` / `get_*` instruction, return-data helper and official SDK math returns exactly what the matching execute instruction applies (penalties, fees and accrual terms are the usual omission).
- *Assert:* proptest on the pure math (seeded vault, shares and assets rounded down), LiteSVM/Mollusk or Trident for the full transaction path.

---

## 9. Seam invariants (properties that need two lenses at once)

- *precision × invariant:* `Σ position.shares == pool.total_shares` holds per deposit, but per-deposit floor rounding with full-amount crediting drifts until the last withdrawer cannot exit.
- *boundary × precision:* `fee = amount * bps / 10_000` is 0 below `10_000 / bps`; splitting an operation into many instructions (bounded by the 1232-byte transaction and the compute budget, and repeatable across transactions) avoids the fee entirely.
- *boundary × invariant:* `repay(0)` / `claim()` with nothing pending returns before `last_accrual` updates (or updates without accruing) — interest for the period disappears.
- *three-way:* a liquidation bonus that rounds to 0 for dust positions leaves them unliquidated; bad debt grows.
- **Σf(segment) ≠ f(Σ):** compounding per crank segment differs from one accrual over the span; splitting cranks changes debt.

---

## 10. Mechanical invariants (checkable from state diffs alone, no spec)

After every instruction a harness can assert: (1) no fuzzer-controlled account gains lamports unexpectedly; (2) total lamports across touched accounts are conserved; (3) no account's owner changes unexpectedly; (4) no account's discriminator/type changes; (5) a closed account is fully scrubbed (lamports 0, owner System, data empty); (6) no live account drops below rent exemption; (7) a realloc never exposes non-zero tail bytes; (8) SPL token balances are conserved across the instruction except for explicit mint/burn, whose delta must equal the mint's supply change; for Token-2022 mints with `TransferFee`, count the `withheld_amount` in token accounts and in the mint as part of the total (a fee-bearing transfer credits the destination `amount − fee`, and `WithdrawWithheldTokens*` raises an `amount` with no mint), and leave confidential-transfer balances out of the sum (they are encrypted), handling `Deposit`/`Withdraw` as explicit moves. (2) and (6) are also enforced by the runtime: lamport imbalance fails the instruction, and a transition into a rent-paying state fails the transaction. If (6) fails in the harness post-state, the harness (e.g. an instruction-level run) skipped the transaction-level rent check. On a real cluster that same input makes the transaction fail. Re-run it through a transaction-level harness and judge it as a possible liveness/DoS finding (e.g. a payout path that always leaves a PDA below rent exemption can never succeed), not as harness noise. Program faults (`require!`, overflow, `unwrap`) appear as failed transactions that this suite cannot see — they need reproducers.

---

## 11. Additional per-domain invariants

- **Return to zero (Token/Vault):** when share supply reaches 0, all residual value (accrued rewards, locked profit, fees, high-water marks, token-account dust) is either 0 or not claimable by the next minter (KV-161).
- **Payout ≤ principal (Vesting/Streaming):** Σ payouts ≤ recorded principal, checked at the boundary (`now ≥ end`, last period); `unlocked(start) == 0` unless a documented cliff/tranche; `unlocked(end) == total`; monotone in time (KV-176).
- **Owner rotation (all):** after an owner/authority change, no principal other than the new owner holds rights over the object (delegate, operator, session key, close authority, pending claim) (AC-061).
- **Upgrade readability (all):** every live account is readable by the deployed binary, or rejected cleanly and migratable (KV-160).
- **Liveness of distribution (all):** no recipient-controlled account state can revert a settlement, liquidation or distribution that pays others (KV-169).

---

## 12. Reaching the state

Each invariant needs a harness that can *reach* the violating state. Use the flow recipes in `templates/fuzz-trident/RECIPES.md` (account-pool mixing, state injection, time flows) and mark each invariant "fuzz/proptest" or "prove" (Kani shapes in `templates/kani/`).

*Sources: pashov/skills `fizz` round-trip analyst and gap lenses (MIT, Copyright (c) 2024 AI Skills Contributors), adapted and narrowed; qedgen/solana-skills X2 (MIT, Copyright (c) 2025 QEDGen); PlamenTSV/plamen `zero-state-return` (MIT, Copyright (c) 2025-2026 Plamen Contributors); SlowMist best practices (Apache-2.0, attributed to SlowMist), paraphrased; Ackee-Blockchain/trident (MIT, Copyright (c) 2021 Ackee Blockchain); workersio/skills (MIT, Copyright (c) 2026 workers.io).*

---

## Instantiation checklist (fast pass)

- [ ] Identify the protocol class(es) — pull the matching menu(s); a blend pulls from several (§1–§7); add the cross-class §8–§11 sets
- [ ] For each candidate invariant, keep only those whose violation is a real finding for *this* target; drop N/A
- [ ] Add target-specific invariants from `context-builder`'s per-function work (Phase 0.5)
- [ ] Mark each as **fuzz/proptest** (broad, no proof) vs **prove** (Certora/Kani — reserve for the 3–10 catastrophic ones)
- [ ] Wire the kept invariants into the harness (Trident stateful post-conditions + proptest on pure fns) and record them in the report's **invariant-property table** (property → asserted? → inputs exercised → not-yet-covered)
