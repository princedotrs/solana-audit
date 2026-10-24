// Audit-grade Trident 0.12 sketch (our code). Adapt types to the generated types.rs.
use trident_fuzz::fuzzing::*;
use trident_fuzz::fuzzing::solana_sdk::instruction::InstructionError; // same crate as TransactionError
mod fuzz_accounts; mod types;
use fuzz_accounts::*; use types::*;

/// Per-flow allowlists: list the expected program codes AND the expected Anchor framework codes.
/// Constraint codes start at 2000 (2001 ConstraintHasOne, 2002 ConstraintSigner, 2003 ConstraintRaw,
/// 2006 ConstraintSeeds). Account codes start at 3000 (3002 AccountDiscriminatorMismatch,
/// 3007 AccountOwnedByWrongProgram, 3008 InvalidProgramId, 3010 AccountNotSigner,
/// 3012 AccountNotInitialized). Init flows may also hit System `Custom(0)` = AccountAlreadyInUse.
fn allowed_custom(flow: &str) -> &'static [u32] {
    match flow {
        "withdraw" => &[6000 /* InsufficientFunds */, 2001 /* ConstraintHasOne */],
        "attacker_substitution" => &[2001, 2003, 2006, 3002, 3007, 3008, 3010, 3012],
        _ => &[6000, 6001],
    }
}

#[derive(FuzzTestMethods)]
struct FuzzTest { trident: Trident, fuzz_accounts: AccountAddresses }

impl FuzzTest {
    /// Every transaction goes through here. On-chain panics are bugs, unexplained errors are bugs,
    /// and a failed transaction must leave the watched state unchanged. Callers in attacker flows
    /// must treat a `true` (unexpected success) as a finding (FV-099).
    fn exec(&mut self, ixs: &[Instruction], name: &str, watched: &[Pubkey], allowed_non_custom: &[InstructionError]) -> bool {
        let before: Vec<_> = watched.iter().map(|k| self.trident.get_account(k)).collect();
        let res = self.trident.process_transaction(ixs, Some(name));   // named tx: metrics can count panics
        if res.is_success() { return true; }
        match res.get_result() {                                        // &Result<(), TransactionError>
            // (a) For a deployed .so, the runtime maps a program panic (overflow under overflow-checks,
            //     unwrap on None, out-of-bounds index), an abort, most VM faults and VM-level compute
            //     exhaustion to ProgramFailedToComplete. Some of the same bugs surface as other variants:
            //     compute exhaustion inside a syscall is ComputationalBudgetExceeded, and with
            //     stricter_abi_and_runtime_constraints an out-of-bounds account access becomes
            //     InvalidRealloc / AccountDataTooSmall / ReadonlyDataModified-style errors. Never put those
            //     in allowed_non_custom without a reason. (With an entrypoint deployment the program runs
            //     natively and a panic is a host panic, caught by the flow executor.)
            Err(TransactionError::InstructionError(_, InstructionError::ProgramFailedToComplete)) =>
                panic!("{name}: program panic / abort / CU exhaustion\n{}", res.logs()),
            Err(TransactionError::InstructionError(_, InstructionError::Custom(c))) =>
                assert!(allowed_custom(name).contains(c), "{name}: unexpected error {c}\n{}", res.logs()),
            Err(TransactionError::InstructionError(_, e)) =>
                assert!(allowed_non_custom.contains(e), "{name}: unexpected failure {e:?}\n{}", res.logs()),
            other => panic!("{name}: unexpected result {other:?}"),
        }
        // (c) a failed tx leaves watched accounts byte-identical
        for (k, b) in watched.iter().zip(before) {
            assert_eq!(self.trident.get_account(k), b, "{name}: state changed on failed tx");
        }
        false
    }

    /// Global invariants (references/invariant-catalog.md), run after EVERY flow.
    /// Check the program's actual discriminator bytes and length, and assert missing/closed accounts
    /// explicitly: get_account_with_type does not compare the discriminator and returns None for
    /// missing or closed accounts (FV-094).
    fn check_globals(&mut self) {
        // e.g. vault.amount >= Σ user.claimable ; Σ shares == pool.total_shares ; rent-exempt ; owners unchanged
    }
}

#[flow_executor]
impl FuzzTest {
    fn new() -> Self { Self { trident: Trident::default(), fuzz_accounts: AccountAddresses::default() } }

    #[init]
    fn start(&mut self) {
        // An honest admin and honest users. Register ATTACKER keys in the SAME storages, so get() sometimes
        // returns a wrong-but-plausible account. Insert non-canonical-bump and cross-user PDAs by hand
        // (insert_with_address); address storage only yields canonical bumps.
    }

    #[flow] fn deposit(&mut self)  { /* amounts incl. 0, 1, 10^dec-1, u64::MAX; exec(); check_globals() */ }
    #[flow] fn withdraw(&mut self) { /* ... */ }
    #[flow] fn attacker_substitution(&mut self) {
        // The attacker signs only for attacker-held keys (TridentSVM does not verify signatures: any
        // is_signer meta counts as signed). Override the generated builder's metas, e.g.
        // ix.accounts.token_program = AccountMeta::new_readonly(fake, false), before .instruction().
    }
    #[flow] fn time_passes(&mut self) {
        let dt = self.trident.random_from_range(0..=7 * 86_400i64);
        self.trident.forward_in_time(dt);
    }
    #[flow] fn reinit_attempt(&mut self) { /* initialize is ALSO a flow, not only #[init] */ }

    #[end] fn end(&mut self) { self.check_globals(); }
}

fn main() { FuzzTest::fuzz(1_000, 200); }
// If one flow starves (> ~95% reverts), use #[flow(weight = N)] on every flow (the weights sum to 100).
