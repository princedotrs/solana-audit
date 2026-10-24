---
id: 179
title: "On-Chain Secrets & Low-Entropy Commitments"
severity: 7
category: crypto
---

### 179 — On-Chain Secrets & Low-Entropy Commitments

**Severity: 7** | **Real: Ackee Solana Auditors Bootcamp (`revival-attack`, `arbitrary-cpi`, `type-cosplay`, CTF levels 1, 2, 4)**

All account data, instruction arguments, `msg!` logs and historical transactions are public. Traps: (1) a "secret" stored in account data (readable with `getAccountInfo`; a "cleared" secret remains in history); (2) a plaintext argument checked on-chain (the first honest use reveals it, and anyone observing the transaction before it lands can reuse it); (3) a hash of low-entropy input (`hash(pin_u8 × 4)` is 2^32 tries — seconds on a GPU, minutes on one CPU core; a `hash(u64)` passcode is not low-entropy, but revealing it in instruction data is still fatal); (4) `msg!` of sensitive values or other accounts' data.

> Cross-ref: KV-120, KV-101/102.

#### Verification Procedure
```
rg -n -i '(pin|secret|password|passcode|passphrase|seed_phrase|private)[0-9_a-z]*\s*:' programs/*/src
rg -n 'hashv?\(.*(to_be_bytes|to_le_bytes|as_bytes)\(\)' programs/
rg -n 'msg!\(' programs/ | rg -i 'secret|pin|key|seed'
```
- ✅ PASS: authentication by signatures only (`Signer`, or the ed25519 precompile with introspection per KV-101/102); commit-reveal commits to `hash(value ‖ 32-byte random salt ‖ signer)` and binds the reveal to the committing signer
- ❌ FAIL: any shared secret gating value

**Overall verdict:** ✅ no secret-based gate · ❌ value gated on public or brute-forceable data

*Sources: Ackee bootcamp item 7 [paraphrased, cited], timing and level-5 example corrected.*
