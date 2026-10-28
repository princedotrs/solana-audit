# Kani harness shapes for Solana state transitions

Kani checks host-compiled Rust. It does **not** cover SBF limits (4 KiB stack frames, compute, realloc, 128-bit alignment: `u128` is 16-byte aligned on x86_64 hosts since Rust 1.77 and on aarch64, but 8-byte aligned on SBF) or account validation. Pair every proof with a runtime test (checklist 16 §16.8, FV-087/FV-088). Building runs target code (Rule 11f).

Setup: save `infrastructure.rs` as `src/kani_infra.rs` (or add `#[path = "infrastructure.rs"]`) and declare it as `#[cfg(kani)] #[macro_use] mod kani_infra;` **before** the proof modules, so that `assert_ok!`/`assert_err!` are in scope. Derive `kani::Arbitrary` for state types under Kani only: `#[cfg_attr(kani, derive(kani::Arbitrary))]`. The derive needs every field to implement `kani::Arbitrary`; a `Pubkey` field (Anchor / solana-pubkey) does not, so write `impl kani::Arbitrary` by hand for such types and use `any_pubkey()` for those fields.

| Pattern | Use for | Property |
|---|---|---|
| P1 Conservation | vault/share supply, fee accrual | the equation holds after the op **and** the delta is exact (`after == before + amount`) — `conservation.rs` |
| P2 Frame / isolation | multi-user state in one account (order books, `[Position; N]`, zero-copy slabs) | an op on user `t` leaves every field of bystander `b != t` byte-identical — `frame-isolation.rs` |
| P3 Invariant preservation | any mutation | `inv(before) ⇒ inv(after)` |
| P4 Error path | helpers whose `Err` is caught inside the program (loops with `continue`, batched settlement) | the specific error variant **and** no partial mutation (a top-level `Err` reverts the whole transaction anyway) |
| P5 Monotonicity | nonces, `last_update_slot`, cumulative indexes | moves in one direction only |
| P6 Idempotency | `accrue`, `sync`, `crank`, `settle`, `refresh` | applying it twice in one slot == applying it once |
| P7 Arithmetic safety (partitioned) | fee/price/interest math on u128/i128 | no overflow, underflow or division by zero; separate `near_zero` and `near_max` harnesses — `arithmetic-partitioned.rs` |
| P8 Access control | admin setters as pure functions | an unauthorised key ⇒ `Err`, and the invariant still holds |
| P9 State machine | lifecycle enums | `Ok ⇒ valid_transition(before, after)`; `Err ⇒ status unchanged` — `lifecycle.rs` |
| P10 Inductive delta | core accounting on primitives | the equation is preserved for all symbolic pre-states; **calls the production fn** (FV-085) |
| P11 Concrete known-bad | regression for a confirmed finding | the exploit values now return `Err` |
| P12 Lifecycle sequence | deposit → trade → withdraw chains | the invariant holds after every step — `lifecycle.rs` |

Grep cues: `rg -n 'bytemuck|zero_copy|AccountLoader|\[.*; *MAX_' --type rust` (P2); `rg -n 'fn (accrue|sync|crank|settle|refresh)' --type rust` (P6).
