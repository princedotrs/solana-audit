# Vesting & streaming

Invariants: `Σ claimed ≤ vested(now) ≤ total`; `vested` monotone in time; `vested(start) == 0` unless a documented cliff/immediate tranche; `vested(t ≥ end) == total` exactly (invariant-catalog §5/§11). Vector: KV-176. Checklist: ECON-110, SM-062/063.

1. **Schedule math at the boundaries.** Evaluate at `now < cliff`, `now == start`, mid-interval, last interval, `now ≥ end`. Interval schedules must not count the *current* interval as released (`+1`); clamp to `principal − already_paid` before transfer; use u128 intermediates and floor rounding in the protocol's favour.
2. **Creation validation.** `end > start`, `interval > 0`, `interval ≤ end − start`, amounts > 0, `start`/`end` types consistent with `Clock::unix_timestamp` (i64) — flag `as u64` casts of timestamps.
3. **Vault binding.** Each grant/escrow is bound to its own vault (`has_one = vault`, or seeds including the escrow key); a global PDA authority over all vaults plus an unbound vault is a cross-instance drain (KV-143).
4. **Recipient binding.** Withdraw/claim requires the recipient as signer or pays only to the recipient's anchored token account (KV-147).
5. **Revocation / clawback.** Revocable grants pay the vested part to the recipient and the rest to the grantor, atomically; terms (cliff, end, revocability) are snapshotted at creation (KV-172).
6. **Time control in tests.** Drive the Clock sysvar (`set_sysvar::<Clock>`, `warp_to_slot`, `forward_in_time`) and property-test `(A, start, end, interval, t)` for `unlocked(t) ≤ A`, monotonicity and exact end.
7. **Slot vs seconds.** Schedules in slots are subject to slot-time changes (KV-138).
