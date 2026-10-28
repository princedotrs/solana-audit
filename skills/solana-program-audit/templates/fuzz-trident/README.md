# Trident (≥ 0.12) harness template

Layout: `trident-tests/fuzz_N/{test_fuzz.rs, fuzz_accounts.rs, types.rs}` plus `trident-tests/{Trident.toml, Cargo.toml}`. `types.rs` is generated from the Anchor IDL; `trident fuzz refresh <fuzz_N>` regenerates it. Every `trident fuzz` subcommand needs an `Anchor.toml` workspace, so native and Pinocchio programs need a stub Anchor workspace. Building and running execute target code (Rule 11f).

The generated 0.12 skeleton is below, [verbatim, MIT, (c) 2021 Ackee Blockchain — Trident `crates/template/templates/test_fuzz.rs.tera`]. The docs page `fuzzing-flows.md` shows the same skeleton with the older `FuzzAccounts` name; the generator emits `AccountAddresses`.
```rust
use fuzz_accounts::*;
use trident_fuzz::fuzzing::*;
mod fuzz_accounts;
mod types;
use types::*;


#[derive(FuzzTestMethods)]
struct FuzzTest {
    /// Trident client for interacting with the Solana program
    trident: Trident,
    /// Storage for all account addresses used in fuzz testing
    fuzz_accounts: AccountAddresses,
}

#[flow_executor]
impl FuzzTest {
    fn new() -> Self {
        Self {
            trident: Trident::default(),
            fuzz_accounts: AccountAddresses::default(),
        }
    }

    #[init]
    fn start(&mut self){
        // Perform any initialization here, this method will be executed
        // at the start of each iteration
    }

    #[flow]
    fn flow1(&mut self){
        // Perform logic which is meant to be fuzzed
        // This flow is selected randomly from other flows
    }

    #[flow]
    fn flow2(&mut self){
        // Perform logic which is meant to be fuzzed
        // This flow is selected randomly from other flows
    }

    #[end]
    fn end(&mut self){
        // Perform any cleanup here, this method will be executed
        // at the end of each iteration
    }
}

fn main() {
    FuzzTest::fuzz(1000, 100);
}
```
`FuzzTest::fuzz(iterations, flows_per_iteration)`. Start from `test_fuzz.rs` (audit grade), not from the bare skeleton, and apply checklist 16 §16.9 before claiming "fuzzed, no findings".
