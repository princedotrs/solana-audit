# 03 — Arithmetic Safety Checklist

> Domain: On-chain Solana Program  
> Severity if missed: CRITICAL to HIGH (financial programs), MEDIUM (non-financial)  
> References: Neodyme "Integer Overflow/Underflow", QEDGen ARITH properties, Rust checked math

Every item below is a single verification step. Mark each `[PASS]`, `[FAIL-{severity}]`, `[PARTIAL]`, or `[N/A]`.

---

## 3.1 — Overflow & Underflow Prevention

- [ ] **AR-001**: Every `+` operation on state-derived or user-supplied values uses `checked_add` with `.ok_or(Error)?`
- [ ] **AR-002**: Every `-` operation on state-derived or user-supplied values uses `checked_sub` with `.ok_or(Error)?`
- [ ] **AR-003**: Every `*` operation on state-derived or user-supplied values uses `checked_mul` with `.ok_or(Error)?`
- [ ] **AR-004**: Every `/` operation on state-derived or user-supplied values uses `checked_div` with `.ok_or(Error)?`
- [ ] **AR-005**: No bare arithmetic operators (`+`, `-`, `*`, `/`, `%`) are used on financial values (grep the entire program for these)
- [ ] **AR-006**: No `saturating_add`, `saturating_sub`, `saturating_mul` on financial paths — these silently cap instead of failing
- [ ] **AR-007**: No `wrapping_add`, `wrapping_sub`, `wrapping_mul` anywhere — these silently wrap
- [ ] **AR-008**: Constants-only arithmetic (e.g., `8 + 32 + 32`) is acceptable without checked_* — verify all operands are truly constant
- [ ] **AR-009**: Anchor's `space` calculation in `#[account(init, space = ...)]` — bare arithmetic is OK here since values are known at compile time

## 3.2 — Intermediate Precision (u128 Widening)

- [ ] **AR-010**: For `a * b / c` patterns, intermediate result `a * b` is computed in `u128` to prevent overflow
- [ ] **AR-011**: For share calculation `(deposit * total_shares) / total_assets` — uses u128 intermediate
- [ ] **AR-012**: For fee calculation `(amount * fee_bps) / 10000` — uses u128 intermediate if amount can be large
- [ ] **AR-013**: For proportion calculation `(amount * fraction) / total` — uses u128 intermediate
- [ ] **AR-014**: After u128 computation, downcast to u64 using `as u64` only after verifying the result fits (or use `u64::try_from()`)
- [ ] **AR-015**: No `as u64` truncation on u128 values without checking if value > u64::MAX
- [ ] **AR-016**: No `as u32` truncation on u64 values without bounds checking
- [ ] **AR-017**: No `as i64` cast on u64 values that could exceed i64::MAX (sign flip vulnerability)

## 3.3 — Division Safety

- [ ] **AR-018**: Every division operation checks that divisor is not zero (either via guard or checked_div)
- [ ] **AR-019**: For share pricing `price = total_assets / total_shares` — guard for `total_shares == 0` case
- [ ] **AR-020**: For withdrawal proportion `fraction = investor_shares / total_shares` — guard for `total_shares == 0`
- [ ] **AR-021**: Division that can truncate to 0 when it shouldn't — is there a minimum output requirement?
- [ ] **AR-022**: Integer division rounding direction — verify it rounds in favor of the protocol (not the user) for share minting
- [ ] **AR-023**: Share/collateral redemption rounds in favour of the **protocol**: assets out = `floor(shares × total_assets / total_shares)`; shares burned for a requested asset amount = `ceil(…)`. Any user-favourable rounding on either side of a deposit → redeem round trip is a FAIL (KV-012; Neodyme SPL token-lending disclosure).
- [ ] **AR-024**: Dust amount attacks: can an attacker exploit rounding by making many small deposits/withdrawals to accumulate rounding errors?
- [ ] **AR-025**: First depositor attack: if total_shares == 0, can first depositor manipulate initial share price?

## 3.4 — Share Math Specific

- [ ] **AR-026**: Share minting formula: `shares = deposit_amount * total_shares / total_assets` — verify correctness
- [ ] **AR-027**: Share minting when `total_shares == 0` OR `total_assets == 0` — uses 1:1 ratio (or documented alternative)
- [ ] **AR-028**: Share burning formula: `asset_return = burn_shares * total_assets / total_shares` — verify correctness
- [ ] **AR-029**: Slippage protection on mint: `require!(shares_minted >= min_shares_out)` — is this enforced?
- [ ] **AR-030**: Slippage protection on burn: `require!(assets_returned >= min_assets_out)` — is this enforced?
- [ ] **AR-031**: Inflation attack: can someone donate tokens to the vault to dilute share value for new depositors?
- [ ] **AR-032**: Deflation attack: can someone withdraw in a way that makes remaining shares worth less?
- [ ] **AR-033**: Total shares supply matches sum of all investor positions (invariant check)
- [ ] **AR-034**: Shares mint supply matches `fund.total_shares` (invariant check)

## 3.5 — Fee Calculation

- [ ] **AR-035**: Management fee formula is correct and uses checked math
- [ ] **AR-036**: Performance fee formula is correct and uses checked math
- [ ] **AR-037**: Platform fee (treasury) formula is correct and uses checked math
- [ ] **AR-038**: Fee split: `manager_fee + platform_fee + investor_return == total_amount` — no funds lost or created
- [ ] **AR-039**: Fee basis points: verify `fee_bps <= 10000` (100%) — no fee exceeding 100%
- [ ] **AR-040**: Fee basis points minimum: verify minimum platform fee is enforced
- [ ] **AR-041**: Fee calculation order: fees extracted before or after share calculation? Verify consistency
- [ ] **AR-042**: Compound fee attack: can fees be charged on fees? (fee on withdrawal that includes previous fees)
- [ ] **AR-043**: Zero-value edge case: what happens when fee calculation yields 0? Is 0-amount transfer safe?
- [ ] **AR-062**: When multiple fee/rate components apply to the same operation simultaneously (e.g., trade + platform + creator-share + referral), their **sum** is validated ≤ denominator / 100% at config-set time — not merely each component individually ≤ 100% (independently-valid components can still sum past the total and underflow the residual; see KV-128)

## 3.6 — NAV (Net Asset Value) Safety

- [ ] **AR-044**: NAV calculation includes all token positions held by the fund PDA
- [ ] **AR-045**: NAV calculation uses correct token decimals for each position
- [ ] **AR-046**: NAV calculation handles zero-balance positions correctly
- [ ] **AR-047**: NAV cannot be artificially inflated by the manager (attestation must be honest or verifiable)
- [ ] **AR-048**: NAV cannot be artificially deflated to steal from new depositors
- [ ] **AR-049**: NAV attestation PDA is validated (address re-derived, not just discriminator checked)
- [ ] **AR-050**: Stale NAV: is there a timeout after which NAV attestation is considered stale?

## 3.7 — Lamport & SOL Handling

- [ ] **AR-051**: All lamport values are treated as `u64` — no truncation to smaller types
- [ ] **AR-052**: Lamport transfers check that source has sufficient balance: `source.lamports() >= amount + rent_exempt_minimum`
- [ ] **AR-053**: After lamport manipulation, verify rent exemption is maintained for non-closeable accounts
- [ ] **AR-054**: No instruction can drain an account below rent-exempt minimum without closing it
- [ ] **AR-055**: WSOL handling: wrapping and unwrapping account for correct lamport ↔ token conversion

## 3.8 — Edge Cases

- [ ] **AR-056**: What happens with MAX u64 values as input? Does every path handle it?
- [ ] **AR-057**: What happens with 0 as amount input? Every deposit/withdraw/transfer/fee path
- [ ] **AR-058**: What happens with 1 lamport/token as input? Minimum viable amounts
- [ ] **AR-059**: What happens when fund has exactly 1 share remaining? Edge case in proportional math
- [ ] **AR-060**: What happens when fund has maximum number of investors all withdrawing simultaneously?
- [ ] **AR-061**: Timestamp arithmetic (if used): `Clock::get()?.unix_timestamp` is i64 — check for negative/overflow issues

## 3.9 — Floating-Point in On-Chain Financial Math

> Floating point has no place in on-chain value computation: rounding is non-deterministic across builds/targets, precision is silently lost at scale, `powf`/`sqrt` blow up CU, and `f64 → u64` casts truncate or saturate. Every value/price/fee/interest/exchange-rate path must use fixed-point + checked integer math instead.

- [ ] **AR-063**: No `f64`/`f32` (nor `powf`, `powi`, `sqrt`, `ln`, `exp`, or `as f64`/`as f32` casts) appears in any on-chain value, price, fee, interest, or exchange-rate computation — fixed-point representation with checked integer arithmetic is used instead; any `f64 ↔ u64` boundary cast in a value path is treated as a finding (see KV-128)

## 3.10 — Panic Edge Cases, Rounding Modes & Hidden Unchecked Math

- [ ] **AR-064**: Divisors are proven non-zero for every `wrapping_div/rem`, `overflowing_div/rem`, `saturating_div`, `div_euclid`/`rem_euclid` (and their wrapping/overflowing forms) call. Each one panics when the divisor is zero. Only the `checked_*` forms (`checked_div`, `checked_rem`, `checked_div_euclid`, `checked_rem_euclid`) return `None`. "We use saturating math" does not clear AR-018.
- [ ] **AR-065**: Signed `iN::MIN / -1` and `iN::MIN % -1` written with plain operators panic whatever `overflow-checks` is set to. Check signed PnL, funding and i64 timestamps for this input. (`checked_div` returns `None` and `wrapping_div` returns `iN::MIN` for the same input.)
- [ ] **AR-066**: `iN::MIN.abs()` panics under overflow-checks and stays negative without them. Use `checked_abs()`/`unsigned_abs()` and keep the sign where it carries meaning (AR-077).
- [ ] **AR-067**: `checked_shl`/`checked_shr` return `None` only when the shift amount ≥ bit width. Bits shifted out are lost silently. Q64.64 / sqrt-price code must not use `checked_shl(64)` as an overflow check. Use `x.checked_mul(1u128 << 64)` on a u128 value, or a U256 widening multiply.
- [ ] **AR-068**: `checked_*(..).unwrap()` / `.expect()` count as panic sites, not as hardened math. On liquidation, settlement, crank and withdrawal paths each one is a liveness risk.
- [ ] **AR-069**: Plain `<<`/`>>` with a shift count derived from user or account data is bounded. A count ≥ bit width panics under overflow-checks and is masked without them (`x << 64` on u64 == `x << 0`).
- [ ] **AR-070**: No limit, bounds or authorization guard computes unchecked arithmetic on a user-influenced operand inside the comparison (`used + requested <= cap`, `start + len <= buf.len()`, `ts + delay < now`). A wrapped guard is a bypass. Whether it drains funds depends on what follows: it matters most when the guard type is narrower than the guarded amount, or when the guarded value feeds internal accounting. Use a checked sum, or a checked subtraction on the trusted side.
- [ ] **AR-071**: No round-to-nearest/half-up mode (`try_round_u64`, `.round()`, `round_half`, `+ HALF_WAD`, spl-math `PreciseNumber::to_imprecise()`) on any value-conversion path. Choose the direction per call site from who receives value: floor what the protocol pays out, ceil what it receives. Size the attack as (rounding gains per instruction × instructions per transaction × transactions), not by one transaction's gain. <!-- verified: spl-math to_imprecise adds a half-unit rounding correction before dividing (round half up) -->
- [ ] **AR-072**: A safe wrapper does not hide unchecked inner math (`x.saturating_sub(a * b * c)` protects only the subtraction). Typed-quantity newtypes (`QuoteLots(u64)`) do not `impl Add/Mul/Sub` with raw operators on the inner field.
- [ ] **AR-073**: An `as u8/u16/u32` on a value derived from a const generic or `size_of::<T>()` is not guarded only by an associated-const assertion that nothing references. In a generic impl, `const OK: () = assert!(..)` is evaluated only when it is used. Use `u16::try_from(n)?` or force evaluation (`let () = Self::OK;`).
- [ ] **AR-074**: Inverse helper pairs (`to_shares`/`to_assets`, `normalize`/`denormalize` by decimals, `scale_up`/`scale_down`) are applied symmetrically. Every value scaled at entry is unscaled at the matching exit with the same parameters (the same mint's decimals, the same rounding policy) on every path.
- [ ] **AR-075**: No hard-coded rent constants (`2_039_280` = 165-byte token account, `1_461_600` = 82-byte mint, `890_880` = 0-byte account, `LAMPORTS_PER_BYTE`, `165`-byte assumptions). Use `Rent::get()?.minimum_balance(len)` and, for Token-2022, `ExtensionType::try_calculate_account_len::<Account>(&exts)`. User input never chooses `space` on keeper-paid accounts. (The `\b165\b` grep is noisy; use it for triage only.) <!-- verified: token-2022 interface/src/extension/mod.rs try_calculate_account_len<S: BaseState>(&[ExtensionType]); constants = (len+128)*3480*2 -->
- [ ] **AR-076**: Integer narrowing with `as` silently truncates (use `try_from`). Float→int `as` saturates (NaN → 0). A same-width signed↔unsigned `as` reinterprets the bits. A widening signed→unsigned `as` sign-extends (`-1i32 as u64 == u64::MAX`). Classify each `as` on a value path accordingly.
- [ ] **AR-077**: Signed quantities (funding rate, PnL, skew) keep their sign through abs/divide steps. Compute in i128 with `checked_abs`/`checked_div`, or carry the sign separately. An `unsigned_abs()` + unsigned divide "fix" that drops the direction is a logic bug.
- [ ] **AR-078**: Every add, subtract or compare on a value path uses one unit and scale (lamports vs token base units, `D(decimals)` per mint, oracle `{price}×10^expo`, bps vs ppm, slot vs seconds, shares vs tokens). Every multiply/divide is followed by an explicit rescale (references/methodologies/dimensional-analysis.md).

Grep (triage only; every hit still needs a manual read):

```bash
rg -n '\b(wrapping|saturating|overflowing)_(div|rem)\b|_euclid\(' programs/
rg -n '\.abs\(\)' programs/
rg -n 'checked_sh[lr]\(|<<\s*[a-z_]|>>\s*[a-z_]' programs/
rg -n 'checked_\w+\([^)]*\)\s*\.(unwrap|expect)\(' programs/
rg -n 'try_round_u(64|128)|\.round\(\)|round_half|to_imprecise\(' programs/
rg -n '\.(saturating|checked|wrapping)_(add|sub|mul|div)\([^)]*[a-z_)\]]\s*[*+-]\s*[a-z_(]' programs/
rg -n 'impl (std::ops::|core::ops::)?(Add|Sub|Mul|Div)(Assign)? for' programs/ -A6 | rg 'self\.0\s*[*+-]'
rg -n 'const [A-Z_]+: \(\) = assert!' programs/
rg -n '2_?039_?280|890_?880|1_?461_?600|LAMPORTS_PER_BYTE' programs/
```

*Sources: Trail of Bits `rust-review` arithmetic finders [paraphrased, CC-BY-SA-4.0; reworded, `saturating_rem` removed]; Neodyme "Common Pitfalls" U2 [paraphrased, cited] with corrected example scope; sannykim/solsec → Neodyme lending disclosure [paraphrased, cited]; SlowMist U4 (Apache-2.0, attributed to SlowMist), paraphrased; Helius §2 [paraphrased, cited]; qedgen/solana-skills hidden-unchecked-arithmetic and const-generic narrowing patterns (MIT, Copyright (c) 2025 QEDGen); PlamenTSV/plamen §8 (MIT, Copyright (c) 2025-2026 Plamen Contributors); solana-foundation/solana-dev-skill #9 (MIT, Copyright (c) 2026); pashov/skills `as` note corrected (MIT, Copyright (c) 2024 AI Skills Contributors).*
