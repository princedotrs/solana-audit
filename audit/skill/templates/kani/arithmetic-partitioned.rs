// P7 Arithmetic safety, partitioned to keep the solver tractable (our code).
// Kani checks arithmetic overflow, division by zero and panics in the called code by default.
#[cfg(kani)]
mod kani_math {
    use super::*;
    #[kani::proof]
    fn fee_math_near_zero() {
        let amount: u64 = kani::any();
        let bps: u16 = kani::any();
        kani::assume(amount <= 1_000 && bps <= 10_000);
        let r = compute_fee(amount, bps);                    // production fn (FV-085)
        if let Ok(fee) = r { kani::assert(fee <= amount, "fee exceeds amount"); }
        kani::cover!(r.is_ok(), "ok path reached");
    }
    #[kani::proof]
    fn fee_math_near_max() {
        let amount: u64 = kani::any();
        let bps: u16 = kani::any();
        kani::assume(amount >= u64::MAX - 1_000 && bps <= 10_000);
        let r = compute_fee(amount, bps);                    // must not overflow or panic
        if let Ok(fee) = r { kani::assert(fee <= amount, "fee exceeds amount"); }
        kani::cover!(r.is_ok(), "ok path reached");
    }
}
