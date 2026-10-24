# Composition cookbook (thinking prompts, not automatic severity)

Use in FULL-AUDIT Step 1.6. A chain is reported once at the chain's severity with every component linked. Do not compose with a primitive absent from this code.

| Primitive A | + Primitive B | = Chain ceiling |
|---|---|---|
| Missing signer | Arbitrary CPI | account takeover via forged CPI authority (CRIT) |
| Missing signer / permissionless | Unvalidated close destination | drain rent and state from any closable PDA (CRIT) |
| Type confusion | Missing owner check | forged-data trust (CRIT) |
| PDA seed collision | Missing signer | take over another user's PDA (CRIT) |
| Non-canonical bump | Signer-derived seeds | program signs for / accepts an alternate PDA for the same seeds — duplicate state / impersonation (HIGH) |
| Permissionless init | Unanchored stored authority/fee field (KV-148) | front-run init, capture every fee or withdrawal (CRIT) |
| Root-unanchored account chain (KV-146) | Typed-but-unanchored CPI authority | mint/withdraw under the real authority against fake collateral (CRIT) |
| Role token account unanchored (KV-147) | Authority-signed payout | authority redirects a passive role's funds (CRIT) |
| Payout > principal (KV-176) | Shared vault + permissionless claim | per-position leak becomes a pool drain (HIGH→CRIT) |
| Custody terms retroactive (KV-172) | Single-key admin, no timelock | instant strand/seize of deposits (HIGH→CRIT) |
| Privileged action with no delay | Durable-nonce pre-signed approval | months-old approval lands instantly, no revoke window (MED→CRIT) |
| Transfer hook (untrusted callee) | Caller invariant false across the transfer | hook acts on inconsistent state via third programs, not re-entry (HIGH→CRIT) |
| Lamport balance used as accounting | `withdrawable = lamports() − rent` | donate, withdraw a surplus never deposited (HIGH) |
| Payout to stored address | Address later executable or reserved | permanent DoS of the payout handler (MED→HIGH) |
| Parent full-delete close (KV-175) | Children not closed | stale children revive under the re-created parent |
| Saturating by design | Amount-shaped field + permissionless caller | silent value loss, no error path (MED→HIGH) |
| Closable account (revival) | Token-program quirk + missing post-condition | small issues chained into a drain (Solens "Royal Flush" shape) |
| Spec/docstring claims X, code does not enforce | Formal proof generated from that spec | green proof of broken behaviour (HIGH) |
