# Reaching each vulnerability class with Trident flows

Core idea: put correct and incorrect addresses in the same address storage, so handlers receive wrong-but-plausible accounts.

| Class | How the flow reaches it | Oracle |
|---|---|---|
| Owner check | `set_account_custom(&fake, ..)` with owner = an attacker program or System and data cloned from the real account; insert `fake` beside the real one | a tx that consumed `fake` must fail |
| Signer check | the authority storage holds the admin key and attacker keys; attacker flows mark only attacker keys as signers | if a privileged field changed, a signer meta equals the stored authority |
| Arbitrary CPI | override the generated builder's program meta with a mock or dumped program id; deploy a mock that records the invocation or returns success with no effect | a non-canonical program id ⇒ failure; the vault never drops without a real token-program transfer |
| Re-initialization | `initialize` is also a `#[flow]` | the second init fails; config/authority bytes unchanged |
| PDA sharing | put user A's PDAs/vaults into the storage that B's flows draw from | B never moves value out of A's PDA; Σ claims ≤ deposits per user |
| Type cosplay | `set_account_custom` with type X's bytes (including its discriminator) where Y is expected; also try 1-byte and no-discriminator layouts | failure; invariant reads check the discriminator |
| Duplicate mutable accounts | `get()` may return the same key twice for (from, to); use `get_except` only in honest flows | conservation holds when from == to |
| Revival / closing | a multi-instruction tx `[close(acc), system_transfer(attacker→acc, rent)]`, then a later flow uses `acc` | the closed account is unusable; discriminator, owner and lamports are asserted |
| Data matching | token accounts with mismatched mint/owner in the same storage (`initialize_token_account` / `initialize_token_account_2022`) | a mismatch ⇒ failure; vault mint == config mint after every flow |
| Rounding (both directions) | repeated deposit/withdraw with `random_from_range(1..=10)`, interleaved with large amounts; a first-depositor flow with a donation | round trip ≤ input; vault ≥ Σ redeemable; a non-zero deposit mints > 0 shares or reverts |
| Precision loss | amounts biased to `{0, 1, 10^dec − 1, u64::MAX/k}`; mixed decimals; `record_histogram("dust", ..)` | cumulative dust stays within n_ops × the per-op rounding bound of the formula, and always in the protocol's favour |
| Token-2022 extension matrix | a random **legal** subset of the mint extensions Trident supports, per iteration (respect the invalid combinations; deploy a hook program for hook mints). Trident has no confidential-transfer extensions | the program rejects the mint, or accounts with the received delta |
| Time-dependent logic | a `time_passes` flow with `forward_in_time`, and an occasional `warp_to_slot` / `warp_to_epoch` | vesting/index/timelock monotonicity; gates measured in seconds |

Is the client suite adversarial at all? Run `rg -n "set_account_custom|insert_with_address|get_except|create_program_address|forward_in_time" trident-tests/`. No hits ⇒ it probably exercises honest paths only (FV-093).
