# Senior-auditor reasoning SOP (load before Phase 1)

Checklists say **what** to check; this says **how to think** about code no checklist names. Refutation happens later (Rule 5b, peer reviewer) — do not argue yourself out of a bug while hunting.

1. **Feynman (always first, every handler).** Explain the handler in plain words, without framework jargon. "Validates accounts and transfers tokens" fails. "Moves the user's USDC from their token account into the pool vault and credits LP shares at the current price" passes. Where the explanation turns vague — "…into the pool vault": *which* vault, bound by `has_one`, by seeds, or not at all? — there is an unchecked assumption.
2. **Socratic (when a line is unclear).** For each constraint or `require!`: why is it here, what does it assume, where is that assumption enforced? Example: `if mint.key() != NATIVE_MINT { transfer_checked(..) }` — why the branch? SOL arrives as lamports. Where are the lamports checked to equal `amount` on the native branch? Often nowhere.
3. **Inversion (when a path looks too clean).** Read each check backwards: what value gets past it? Read each state write backwards: what state was the account in just before?
4. **Amplify (when you reach a bug).** Chain it, find more victims, lower the precondition cost.
5. **Weaponize across the program.** Same name and same code shape in every other handler (a missing `token_program` pin in `deposit` → check every handler that takes one).

Core rule, [verbatim, MIT, (c) 2024 AI Skills Contributors — pashov/skills `solidity-auditor/references/senior-auditor-sop.md`]: "A finding is not real until you've traced the attack with concrete values. You are an attacker, not a defender — when you find a bug, deepen the attack; never argue yourself out of one."
