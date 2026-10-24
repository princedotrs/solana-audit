# Dimensional (unit) analysis for Solana value paths — manual method

Use when the ToB `dimensional-analysis` plugin is unavailable (boundary-map fallback) and on every value-moving path in checklists 03/06.

**Notation.** `[scale]{unit}`: `{lamport}`, `D(mint.decimals){tok:USDC}`, `{price:SOL/USD}·10^expo`, `{bps}`, `{ppm}`, `Q64.64{sqrtP}`, `{slot}`, `{s}`, `{share}`, `{1}`.

| Quantity | Dimension | Common trap |
|---|---|---|
| SOL balance | `{lamport}` (1e9 per SOL) | mixing lamports with wSOL token `amount` while the rent reserve sits in the account (KV-163) |
| SPL amount | `D(decimals){tok:MINT}` | decimals from the wrong mint; adding two mints; Token-2022 gross `amount` vs net received |
| Pyth price | `{quote/base}·10^expo`, `expo` an i32 — usually negative, handle positive | ignoring `expo`; mixing `conf` at another scale; comparing to Switchboard at a different scale |
| Switchboard | decimal mantissa + scale | assuming Pyth's scale |
| Fees | `{bps}` (1e4) vs `{ppm}` (1e6) vs `D9`/`D18` rates | a bps constant applied to a ppm field |
| CLMM | `Q64.64{sqrt(tokB/tokA)}`, `{tick}` | squaring without u128/U256 widening; A/B orientation swapped |
| Time | `{slot}` vs `{s}` (`Clock.unix_timestamp`, i64) | slot deltas used as seconds (KV-138) |
| Vault | `{share}` vs `{tok}`; rate `{tok/share}` | returning shares on one branch and tokens on another |

**Algebra.** `+`, `−` and comparisons need the same unit **and** scale. `×` adds scales, `÷` subtracts them — a rescale must follow. A `{1}` constant must be justified.

**Bug patterns.** decimals where an amount is expected (or the reverse); cross-mint addition; oracle `expo` ignored or applied in the wrong direction; missing or redundant rescale after `price × amount`; return paths with different dimensions; a fee on the wrong quantity (shares vs tokens; gross vs net); slot/second confusion; hidden dimension inside a helper (`to_ui_amount()` returning a float, `normalize()` assuming 6 decimals).

**Procedure.** (1) Annotate every state field and handler argument with a unit comment. (2) Propagate units through every expression on value-moving paths. (3) Every cross-unit add/subtract/compare is a candidate; every multiply/divide must be followed by an explicit rescale. (4) Record each candidate under AR-078.
```bash
rg -n '\bdecimals\b|10u(64|128)\.(checked_)?pow|\.expo\b|exponent|_bps\b|BPS|PPM|PRECISION|SCALE|Q64|<<\s*64' programs/
rg -n 'unix_timestamp|\.slot\b' programs/
```
