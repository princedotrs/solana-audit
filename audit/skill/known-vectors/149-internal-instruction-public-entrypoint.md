---
id: 149
title: "Internal-Only Instruction Reachable as a Public Entrypoint"
severity: 9
category: crypto
---

### 149 — Internal-Only Instruction Reachable as a Public Entrypoint

**Severity: 9** | **Real: Jet Protocol v1 `withdraw_tokens` (arbitrary-withdrawal case documented by SlowMist)**

Anyone can call any Anchor `#[program]` handler or native dispatch arm. Some designs split an action into an outer instruction that checks the user and an inner one, meant to be reached only by self-CPI, that moves funds. That split is broken if the inner instruction signs with a protocol PDA over caller-chosen accounts and requires only "some signer". In Jet v1 the inner `withdraw_tokens` used the `market_authority` PDA as both the Burn and the Transfer authority. It required an unconstrained `depositor` signer and did not bind `deposit_note_account` or `withdraw_account` to it, so anyone could burn another user's deposit notes and withdraw the underlying tokens. The fix documented by SlowMist made `depositor` the **Burn** authority (the vault Transfer still uses the PDA). The outer `Withdraw` passes `market_authority` as `depositor` in the self-CPI (the program signs for that PDA) and binds `deposit_account` with `seeds = [b"deposits", reserve, depositor]`. A direct caller can therefore burn only notes they control.

> Cross-ref: AC-060, RE-008.

#### Verification Procedure

**Step 1: Handlers that look internal**
```
rg -n 'pub fn [a-z0-9_]*(internal|inner|_cpi|do_|process_)[a-z0-9_]*\(' programs/
rg -n 'authority:\s*self\.[a-z_]*authority|authority:\s*ctx\.accounts\.[a-z_]*(authority|pool|vault|state)' programs/
rg -n "Program<'info, *crate::|#\[account\(address\s*=\s*crate::ID\)\]" programs/
rg -n 'get_stack_height|TRANSACTION_LEVEL_STACK_HEIGHT' programs/
```
(`process_` also matches every native processor function; triage by whether the handler signs with a PDA.)

**Step 2: Gate**
- ✅ PASS (option B, the documented fix): user-side accounts are bound to the signer (`token::authority = depositor`, seeds that include `depositor.key()`, `has_one`), and the user-owned asset is moved with the user or delegate as authority. Any PDA-signed leg that remains (Jet's vault Transfer) must pay out only an amount derived from what that bound signer gave up.
- ✅ PASS (option A, our alternative): the inner instruction requires the program PDA itself as a `Signer`. Only `invoke_signed` from this program can produce that signature. This moves the burden to every outer handler that produces the signature: each must bind the user-side accounts it forwards. An outer handler that forwards caller-chosen accounts, or executes caller-supplied instructions (RE-008), reopens the hole.
- ⚠️: `get_stack_height() > TRANSACTION_LEVEL_STACK_HEIGHT` plus Instructions-sysvar introspection showing that the current top-level instruction belongs to this program. This works only because indirect reentrancy (A→B→A) is rejected by the runtime, so every frame above is this program. Stack height alone proves a CPI, not who made it.
- ❌ FAIL: a public handler signs with a protocol PDA over caller-chosen accounts gated only by "someone signed"

```rust
// VULNERABLE: callable by anyone; PDA burns/transfers over caller-chosen accounts
#[derive(Accounts)]
pub struct WithdrawTokens<'info> {
    /// CHECK: PDA, signs via invoke_signed
    pub market_authority: UncheckedAccount<'info>,
    pub depositor: Signer<'info>,                                             // any signer
    #[account(mut)] pub deposit_note_account: Account<'info, TokenAccount>,   // not bound
    #[account(mut)] pub withdraw_account: Account<'info, TokenAccount>,       // attacker's
}
// FIXED (option B)
#[account(mut, token::authority = depositor)] pub deposit_note_account: Account<'info, TokenAccount>,
// … and the Burn CPI uses `authority: depositor`
// FIXED (option A, alternative)
#[account(seeds = [market.key().as_ref()], bump)] pub market_authority: Signer<'info>,
```

**Overall verdict:**
- ✅: every internal-looking handler is safe when called directly
- ❌: any is not

*Sources: SlowMist solana-smart-contract-security-best-practices (Apache-2.0, attributed to SlowMist), paraphrased and corrected.*
