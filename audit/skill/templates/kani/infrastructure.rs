// Shared Kani helpers. assert_ok!/assert_err! are verbatim from workers.io `kani-proof`
// references/proof-patterns.md (MIT, Copyright (c) 2026 workers.io).
// Declare this file in lib.rs BEFORE the proof modules, so the macros are in scope there:
//     #[cfg(kani)] #[macro_use] mod kani_infra;
#![cfg(kani)]

/// Forces the Ok path — fails the proof if the operation returns Err.
macro_rules! assert_ok {
    ($result:expr, $msg:expr) => {
        match $result {
            Ok(v) => v,
            Err(_) => {
                kani::assert(false, $msg);
                unreachable!()
            }
        }
    };
}
/// Forces the Err path — fails the proof if the operation returns Ok.
macro_rules! assert_err {
    ($result:expr, $msg:expr) => {
        match $result {
            Err(e) => e,
            Ok(_) => {
                kani::assert(false, $msg);
                unreachable!()
            }
        }
    };
}

// Use the Pubkey type the program uses (anchor_lang::prelude::Pubkey, solana_pubkey::Pubkey, ...).
// It does not implement kani::Arbitrary, so build it from 32 symbolic bytes.
// (In pinocchio 0.9.x, `Pubkey` is a `[u8; 32]` alias and `kani::any()` works directly.)
use anchor_lang::prelude::Pubkey;
pub fn any_pubkey() -> Pubkey { Pubkey::new_from_array(kani::any()) }

// Shrink state only under Kani (keep ≥ 2 entities and full/empty boundaries reachable — FV-078/FV-081):
// #[cfg(kani)]      pub const MAX_ACCOUNTS: usize = 4;
// #[cfg(not(kani))] pub const MAX_ACCOUNTS: usize = 4096;

// CPI stub (FV-079): replace the exact function the code under test calls, with an identical
// signature (Anchor ≥ 0.32 re-exports solana_invoke::invoke_signed; Pinocchio has
// pinocchio::cpi::invoke_signed). Model both Ok and Err, and prove the stub fired.
// Attach it with #[kani::stub(<original path>, invoke_signed_stub)] and run with -Z stubbing.
// fn invoke_signed_stub(_ix: &Instruction, _a: &[AccountInfo], _s: &[&[&[u8]]]) -> ProgramResult {
//     kani::cover!(true, "stub fired");
//     if kani::any() { Ok(()) } else { Err(ProgramError::Custom(kani::any())) }
// }
