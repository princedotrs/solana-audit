# Pre-Sign Transaction Review — {tx / proposal id}

Scope: a privileged transaction or multisig/governance proposal that acts on the audited program, such as an upgrade, authority change, config/pause change, migration batch or treasury movement. Use it before signers approve.

Verdict labels (the strictest one that applies wins):
- `AUTONOMOUS_OK`: matches a pre-approved, bounded signing policy and has no value, authority, owner, delegate, close, upgrade or config effect beyond the approved fee cap. Never use it for anything in the hard-stop list (in practice, almost no privileged transaction qualifies).
- `CONFIRM_REQUIRED`: may be valid, but a human or quorum must approve the exact decoded effects.
- `NEVER_AUTO_SIGN`: must not be signed unattended, even if it simulates successfully.
- `NEEDS_MORE_INFO`: critical facts are missing. Do not guess a pass.

## Procedure
1. Decode every instruction: program, accounts with their signer/writable flags, and data. Resolve address-lookup-table entries.
2. Compare each instruction, program, writable account, ALT entry, mint and close destination with the stated intent.
3. Classify the role of each signer: user, multisig member, PDA (through the multisig program), delegate, session key.
4. Apply the hard stops listed below.
5. Simulate. Simulation is evidence, never approval: a transaction that simulates successfully but has unsafe deltas is still unsafe. Programs can behave differently in simulation and in execution (OPS-095).
6. Record any durable-nonce use (nonce account and nonce authority, OPS-091), plus the compute-budget and priority-fee instructions.

## Hard stops → `NEVER_AUTO_SIGN`
- Any change to the mint, freeze, close, owner, delegate, permanent-delegate, transfer-hook, metadata, fee or confidential authority.
- A program upgrade, buffer-authority change or upgrade-authority change.
- Governance execution, or an admin/pause/config mutation.
- Unlimited or unclear approvals, burns, freezes or close-account instructions.
- `Approve`/`ApproveChecked` where delegate == owner. Self-delegation bypassed CPI Guard on Token-2022 builds before the ND-ANZ-LO-01 fix.
- Unknown writable accounts or unexplained ALT entries.
- Value movement without exact mints, max-in/min-out, a fee cap and an expiry.
- Any mismatch between the stated intent, the wallet or multisig prompt, the decoded instructions and the simulated deltas.

## Output
| # | Instruction | Program | Writable / signer accounts | Matches intent? | Hard stop? | Note |
|---|---|---|---|---|---|---|
Verdict: … · Evidence: … · Required before signing: …
