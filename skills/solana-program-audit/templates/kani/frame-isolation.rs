// P2 Frame / isolation for zero-copy multi-user accounts (our code, following workers.io P2).
// The user slot type must be Copy + PartialEq so the whole slot can be snapshotted and compared.
#[cfg(kani)]
mod kani_proofs {
    use super::*;
    #[kani::proof]
    fn settle_only_touches_target_slot() {
        let mut book = populated_book();                     // ≥ 2 active users, MAX_USERS = 4 under cfg(kani)
        let t: usize = kani::any();
        let b: usize = kani::any();
        kani::assume(t < MAX_USERS && b < MAX_USERS && t != b);
        let snap = book.users[b];                            // Copy: snapshot all fields
        let px: u64 = kani::any();
        kani::assume(px > 0);
        assert_ok!(book.settle(t, px), "settle must succeed");
        kani::assert(book.users[b] == snap, "bystander slot mutated");
        kani::cover!(true, "reached");
    }
}
