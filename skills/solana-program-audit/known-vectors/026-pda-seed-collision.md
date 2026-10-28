---
id: 26
title: "PDA Seed Collision"
severity: 8
category: crypto
---

### 26 — PDA Seed Collision
**Severity: 8** | **Real: Solana PDA confusion exploits**

Two different logical accounts derive to the same PDA because seeds overlap — attacker exploits the collision.

#### Verification Procedure

**Step 1: Catalog all PDA seed patterns**
```
grep -rn --include="*.rs" "seeds = \[" programs/*/src/instructions/
```
- Record: Every seed pattern with its account type

**Step 2: Seed-concatenation analysis (per program id)**
PDA derivation hashes `seed_0 ‖ seed_1 ‖ … ‖ bump ‖ program_id ‖ "ProgramDerivedAddress"` with **no separators or length prefixes**. Write each PDA type as segments: `L(bytes)` literal, `F(n)` fixed width (Pubkey `F(32)`, `u64.to_le_bytes()` `F(8)`), `V(0..=32)` variable/user-controlled. For every pair of types (A, B), including A with itself:
- aligned literal-vs-literal bytes must agree for a collision; aligned literal-vs-`F` bytes are satisfiable when that `F` value is attacker-chosen (an arbitrary non-signer pubkey, a `u64` argument);
- any `V` segment: can an attacker choose its bytes so the concatenations match? (A Borsh `String` must be valid UTF-8, so embedding a random victim pubkey is usually impossible; `Vec<u8>`/`[u8; N]` have no such limit.)
- self-collision: two adjacent `V` segments (`("ab","c")` vs `("a","bc")`) map two entities to one PDA.
```
rg -n -A1 'seeds\s*=\s*\[' programs/ | rg 'seeds|Account<|AccountLoader<|UncheckedAccount'
rg -n 'seeds\s*=\s*\[\s*[a-z_]+(\.|\s*,)' programs/                       # first seed not a literal
rg -n '#\[instruction\(.*(String|Vec<u8>|&\[u8\])' programs/
```
- ✅ PASS: each account type has its **own distinct** literal first seed, no literal is a byte-prefix of another, and every variable-length seed is last, length-delimited, or hashed to 32 bytes
- ❌ FAIL: a seeds list without a literal domain prefix, overlapping literals (`b"user"` vs `b"user_stats"` followed by a variable seed), or adjacent variable segments with no delimiter

**Step 3: Grade by attacker control of the overlapping bytes**
- Squatting only (attacker `init`s type A at the address a victim's type-B `init` needs): Low/Medium DoS.
- Same-type collision (two logical entities of one account type map to one PDA, e.g. the adjacent-`V` self-collision above): no discriminator or owner check can tell them apart, so grade by what the second entity can do with the first one's account (often High/Critical when it holds funds or authority).
- Cross-type collision: High/Critical only if a read path skips the discriminator/owner type check (KV-010/027) **and** the attacker controls the overlapping bytes. A structurally unsafe layout whose overlap needs a victim's key to be valid UTF-8 is "structurally unsafe", not exploitable.
- Not a finding: distinct literal + fixed-width keys (`[b"vault", pool.key()]`); PDAs of different program ids (the id is hashed).

*Sources: Zellic "The Vulnerabilities You'll Write With Anchor" [paraphrased, cited: https://www.zellic.io/blog/the-vulnerabilities-youll-write-with-anchor].*

**Step 4: Check bump seed handling**
```
grep -rn --include="*.rs" "bump" programs/*/src/instructions/
```
- ✅ PASS: Stored bump is reused via `bump = entity.bump` (consistent derivation)
- ⚠️ PARTIAL: Bump re-derived each time (wastes CU but not a security issue)
- ❌ FAIL: Bump not stored and `find_program_address` used in instruction (potential inconsistency)

**Overall verdict:**
- ✅: Unique prefixes, sufficient variable seeds, stored bumps
- ⚠️: Unique seeds but bumps re-derived
- ❌: Shared seed prefixes or insufficient seeds allowing collision
