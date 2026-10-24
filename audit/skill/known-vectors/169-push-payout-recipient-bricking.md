---
id: 169
title: "Push-Payout Bricking by Recipient-Controlled Account State"
severity: 6
category: crypto
---

### 169 — Push-Payout Bricking by Recipient-Controlled Account State

**Severity: 6 (Medium; higher when the blocked path is a liquidation or settlement that must advance protocol state)** | **Real: audit pattern (MemoTransfer / CPI Guard / frozen or closed destinations in batch payouts)**

When the callee of a CPI returns an error, the whole transaction aborts and the caller cannot catch it (only checks that fail inside the caller's own wrapper, before the invoke syscall, come back as a catchable `Err`), so any loop that pushes value to accounts **recipients control** is all-or-nothing. One recipient can block the distribution, settlement or liquidation containing its payout, or freeze a settlement in its own favour (refuse the refund leg so a liquidation cannot complete).

| Payout kind | Failure the recipient (or the issuer) controls |
|---|---|
| SPL / Token-2022 | destination closed by its owner; frozen by the issuer (`AccountFrozen`); `MemoTransfer` enabled on the destination (the previous processed sibling instruction at the same stack height must be a Memo program instruction, else `NoMemo` — so one memo CPI before *each* transfer in a loop); mint hook revert; `NonTransferable` or paused mint (issuer-side); non-confidential credits disabled on the destination (owner's `DisableNonConfidentialCredits` → `NonConfidentialTransfersDisabled`); for confidential payouts, confidential credits disabled (`ConfidentialTransferDepositsAndTransfersDisabled`) or the pending-balance credit counter at its maximum (`MaximumPendingBalanceCreditCounterExceeded`) |
| User-funded pull | user enabled **CPI Guard** on the source: a transfer signed by the owner and forwarded into a CPI fails (`CpiGuardTransferBlocked`); transfers signed by an approved delegate still work, but approving via CPI is also blocked (`CpiGuardApproveBlocked`) |
| SOL | an empty (e.g. just-closed) address credited below the rent-exempt minimum (fails the post-transaction rent check); a reserved address (sysvar, builtin program) or a program invoked in the same transaction, which the runtime demotes to read-only; any account passed read-only (`ReadonlyLamportChange`). Crediting an ordinary executable program account no longer fails: Agave removed the executable lamport-change check (feature `remove_accounts_executable_flag_checks`, cleaned up in v3.0.0) |
| Any | the destination is write-locked by contention near a deadline (KV-131) |

Token-account owners can enable `MemoTransfer`/CPI Guard on their own accounts at any time (first adding space with Token-2022 `Reallocate`, which the owner can also call) without the mint authority or the protocol. Deriving each recipient's ATA in the program instead of accepting any token account does **not** isolate the batch: the recipient still owns that ATA, controls its extensions and can close it while its balance is zero. <!-- verified: token-2022 program@v11.1.0 program/src/processor.rs (transfer: CpiGuard owner-authority check, AccountFrozen, memo_required → check_previous_sibling_instruction_is_memo, non_confidential_transfer_allowed), process_approve (CpiGuardApproveBlocked); interface/src/extension/confidential_transfer/mod.rs valid_as_destination; program/src/extension/memo_transfer/mod.rs; agave v4.3.2 transaction-context/src/instruction_accounts.rs set_lamports (no executable check), commit 3e1aa3befe first in v3.0.0 -->

> Cross-ref: ECON-103, TK-011/TK-012/TK-005, KV-019, KV-123, KV-105.

#### Verification Procedure
```
rg -n 'for .* in .*(remaining_accounts|winners|recipients|holders)' programs/ -A8 | rg 'transfer|invoke'
rg -n 'MemoTransfer|memo_transfer|build_memo|spl_memo|CpiGuard|cpi_guard' programs/
rg -n 'token_2022|spl_token_2022|TokenInterface|InterfaceAccount' programs/
```
- ✅ PASS (primary): pull-based — credit claimable balances in state; each recipient claims in its own transaction (and pays ATA creation for itself); user-funded flows pull as a delegate approved at top level
- ✅ PASS (alternative): the batch pre-checks every destination in the same instruction (exists, owned by the expected token program, right mint, not frozen, no blocking extension state) and moves any failing entry to a claimable balance instead of transferring; a hook mint whose hook can revert still fails this, because a hook revert cannot be pre-checked
- ⚠️ Partial only: a memo CPI before each transfer handles `MemoTransfer` but not closed, frozen or credit-disabled destinations or hook reverts; do not treat it as a PASS on its own
- ❌ FAIL: a batch push to N recipient-controlled accounts in one instruction with no isolation

```rust
// VULNERABLE: settlement pays every winner inline
for (i, w) in winners.iter().enumerate() {
    token_interface::transfer_checked(cpi_to(&ctx.remaining_accounts[i]), w.amount, decimals)?; // one bad ATA reverts all
}
state.settled = true;
// FIXED: record entitlements; recipients pull
for w in winners { claims.add(w.owner, w.amount)?; }
state.settled = true;
```

**Overall verdict:**
- ✅: no recipient can block another's payout or a protocol state transition
- ❌: one can

*Sources: solana-foundation/solana-dev-skill `skills/solana-dev/references/security.md` "Metadata Spoofing and Memo Requirements" (MIT, Copyright (c) 2026); franpersanchez/solana-audits-skill `skill/references/protocol-risk-map.md` "Token-2022 Integrations" (MIT, Copyright (c) 2026 Fran Pérez) with Reallocate/sibling caveat; beriktassuly/solana-audit-skill `skill/references/workflows/token-2022-policy-workflow.md` (MIT, Copyright (c) 2026 Berektassuly) with an added pull-first PASS; original analysis.*
