// P1 Conservation. Adapted from the qedgen/solana-skills `references/kani-examples.md` minimal pattern
// (MIT, Copyright (c) 2025 QEDGen). It is hardened per FV-074/FV-075: the minimal pattern's
// `if result.is_ok() { assert_eq!(..) }` passes vacuously when deposit always errors.
#[cfg(kani)]
mod kani_conservation {
    use super::*;

    #[kani::proof]
    fn deposit_preserves_total_assets() {
        let mut state: PoolState = kani::any();              // PoolState: cfg_attr(kani, derive(kani::Arbitrary))
        kani::assume(state.is_valid());                      // restrict to reachable states (FV-078)
        let amount: u64 = kani::any();

        kani::assume(amount > 0);
        kani::assume(state.total_assets <= u64::MAX - amount);
        // add every other precondition deposit legitimately checks (not paused, below cap, ...)

        let before = state.total_assets;
        assert_ok!(state.deposit(amount), "valid deposit must succeed");
        kani::assert(state.total_assets == before + amount, "total_assets delta != amount");
        kani::cover!(true, "deposit reached");                // must be SATISFIED (FV-075)
    }
}
