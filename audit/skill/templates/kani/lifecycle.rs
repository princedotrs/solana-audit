// P9 State machine + P12 sequence (our code). `Status` must be Copy + PartialEq.
#[cfg(kani)]
mod kani_lifecycle {
    use super::*;
    #[kani::proof]
    #[kani::unwind(4)]                                         // ≥ max iterations + 1 (3 steps here)
    fn transitions_are_valid_and_err_leaves_status_unchanged() {
        let mut s = populated_state();
        for _ in 0..3 {
            let before = s.status;
            let op: u8 = kani::any();
            let r = match op % 4 { 0 => s.activate(), 1 => s.pause(), 2 => s.resume(), _ => s.close() };
            match r {
                Ok(_) => kani::assert(is_valid_transition(before, s.status), "invalid transition"),
                // On-chain, a failed instruction reverts anyway; this checks the model never relies on that.
                Err(_) => kani::assert(s.status == before, "status changed on Err"),
            }
            kani::assert(check_invariants(&s), "invariant broken after step");
        }
        kani::cover!(s.status == Status::Closed, "closed reachable");
    }
}
