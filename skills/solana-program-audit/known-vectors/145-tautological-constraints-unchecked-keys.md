---
id: 145
title: "Tautological Constraints Anchored on Unchecked Keys"
severity: 8
category: crypto
---

### 145 — Tautological Constraints Anchored on Unchecked Keys

**Severity: 8** | **Real: Ackee Solana Auditors Bootcamp CTF level-5 (fake verification program); Solana Foundation Program Security course `seeds::program` example**

Anchor constraints are only as strong as the key they compare against. When `seeds::program = verifier.key()`, `owner = verifier.key()`, `address = x.key()`, `token::authority = x`, or `seeds = [.., x.key().as_ref()]` take `x` from an `AccountInfo`/`UncheckedAccount` with no pin of its own, an attacker deploys their own "verifier", creates a PDA under it, and every constraint is satisfied. The struct looks heavily constrained, which is why review misses it. A CPI "verifier" or "oracle" passed as an unchecked account where the caller treats "the CPI returned Ok" as verification has the same shape (an attacker program always returns Ok). Native equivalents: `find_program_address(seeds, unpinned_id)` and `create_program_address(seeds, acct.owner)` (derives under whatever program owns the passed account, which the attacker chooses by passing an account their own program owns — circular).

> Cross-ref: AV-110, PDA-024, AC-065, KV-009 (first-order unchecked CPI target).

#### Verification Procedure

**Step 1: Collect unchecked accounts, then constraints that trust their keys**
```
rg -n -o "pub ([a-z_]+): (AccountInfo|UncheckedAccount)<'info>" programs/
# for each name N:
rg -n "(seeds::program|owner|address|token::authority|mint::authority|associated_token::authority)\s*=\s*N(\.key\(\))?" programs/
rg -n "seeds\s*=\s*\[[^]]*N\.key\(\)" programs/
rg -n "(find|create)_program_address\([^)]*,\s*(&?\*?[a-z_]+\.owner|[a-z_]+\.key)\)" programs/
rg -n -A1 "/// CHECK:.*(checked|verified|safe).*(program|later|below|CPI)" programs/
```

**Step 2: Pins**
- ✅ PASS: the right-hand side comes from `Program<'info, T>`, `address = KNOWN_ID`, or a canonical PDA/ProgramData check; every `/// CHECK:` that claims "checked elsewhere" points at a real check
- ❌ FAIL: any constraint's key comes from an unpinned account

```rust
// VULNERABLE: both checks are relative to an attacker-chosen program
/// CHECK: "checked in program" (it is not)
pub verifier: AccountInfo<'info>,
/// CHECK: validated by the verifier
#[account(seeds = [b"gs", user.key().as_ref()], bump, seeds::program = verifier.key(), owner = verifier.key())]
pub guardian_set: AccountInfo<'info>,

// FIXED: pin the program first; everything derived from it becomes meaningful
pub verifier: Program<'info, VerificationProgram>,        // or #[account(address = verification_program::ID)]
/// CHECK: address and owner pinned to the known program
#[account(seeds = [b"gs", user.key().as_ref()], bump,
          seeds::program = verification_program::ID, owner = verification_program::ID)]
pub guardian_set: AccountInfo<'info>,
```
Report wording: describe the whole chain (unchecked account → constraint inherits trust → value moved) so the finding is not dismissed as "it has `owner =` and `seeds::program`".

**Overall verdict:**
- ✅: every constraint key is pinned
- ❌: any constraint inherits trust from an unpinned key on a value-moving or privileged path

*Sources: Ackee-Blockchain Solana-Auditors-Bootcamp `Capture-the-Flag/level-5` [paraphrased, cited: https://github.com/Ackee-Blockchain/Solana-Auditors-Bootcamp/tree/master/Capture-the-Flag/level-5]; Solana Foundation Program Security course `arbitrary-cpi.md` (`seeds::program`) [paraphrased, no licence, https://github.com/solana-foundation/developer-content/tree/main/content/courses/program-security].*
