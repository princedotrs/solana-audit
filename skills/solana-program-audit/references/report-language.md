# Report language (Simplified Technical English subset)

Applies to finding titles, descriptions and summaries — and to hunter output, so the first sentence written is report-ready.

**Rules.** Description: one sentence, ≤ 25 words. Title: ≤ 12 words, one clause, present tense. Active voice, actor first, simple present ("could potentially" banned). No `-ing` clauses; keep articles; at most three nouns in a row. One word per concept; no metaphor, idiom or slang. Say what happens, not how bad it is (no "catastrophic"/"critical" in prose). Positive statements, cause before effect.

**Replace:** "bricks" → "makes the instruction fail for every caller, forever"; "rug" → "the authority takes the user deposits"; "griefing" → "an attacker makes the instruction fail for other users"; "DoS" → "blocks every caller"; "arbitrary" → "any value the caller chooses"; "stale price" → "old price"; "atomically" → "in one transaction"; "edge case" → name the input.

**Never rewrite:** identifiers (`transfer_checked`, `ctx.accounts.vault`), diffs in fix blocks, bug-class labels (memory keys), fixed template strings.

**Example.** Before: "Missing owner check enables a malicious actor to leverage a spoofed config account, potentially draining the vault." After: "The instruction does not check the owner of `config`, so any caller can pass a fake config and withdraw all tokens from the vault."

**Self-check.** Does the sentence name who acts and what they get? One sentence, ≤ 25 words, no `-ing` clause? Identifiers, label and diff exactly as written?

*Sources: pashov/skills `solidity-auditor/references/report-language.md` (MIT, Copyright (c) 2024 AI Skills Contributors), adapted.*
