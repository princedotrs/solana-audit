---
id: 27
title: "Missing Discriminator Check"
severity: 8
category: crypto
---

### 27 — Missing Discriminator Check
**Severity: 8** | **Real: Anchor type cosplay attacks, account substitution**

Account of wrong type passes validation because discriminator isn't checked — attacker provides Fund account where Position was expected.

#### Verification Procedure

**Step 1: Verify Anchor manages all state accounts**
```
grep -rn --include="*.rs" "#\[account\]" programs/*/src/state/
```
- ✅ PASS: All state structs use `#[account]` macro (8-byte discriminator auto-added)
- ❌ FAIL: Manual account structs without Anchor discriminator

**Step 2: Verify Account<> type is used in instruction contexts**
```
grep -rn --include="*.rs" "Account<'info," programs/*/src/instructions/
```
- ✅ PASS: All state accounts deserialized via `Account<'info, StateType>` (auto-checks discriminator)
- ❌ FAIL: Any account deserialized manually or via try_from_slice without discriminator check

**Step 3: Check for manual deserialization**
```
grep -rn --include="*.rs" "try_from_slice\|try_deserialize\|from_account_info\|AccountDeserialize" programs/
```
- If found: Does it include discriminator verification?
- ✅ PASS: All manual deserialization includes discriminator check
- ❌ FAIL: Manual deserialization without discriminator (type cosplay possible)

**Step 4: Short, custom, generic and cross-program discriminators**
- Custom discriminators (`#[account(discriminator = ..)]`, anchor-lang ≥ 0.31.0) are prefix-matched (`try_deserialize` compares only the first `DISCRIMINATOR.len()` bytes): when a short discriminator is a byte-prefix of another type's discriminator (custom or default 8-byte), an account of the longer-discriminator type passes as the short-discriminator type. An all-zero custom discriminator looks like a fresh account to `zero`, and an empty one (`[]`, `b""`) matches every account. A `zero` target with an N-byte custom discriminator also accepts a live account of the same program whose first N bytes are zero (another type's discriminator that starts with zero bytes). The `#[account]` macro rejects all-zero or empty discriminators only from 1.2.0 (#4645), and only when they are written as literals: a `const` or a function that returns zeros still compiles. The IDL build (0.31.0+, #3159/#3365) rejects empty, all-zero, prefix-colliding and `zero`-conflicting account discriminators, but only within one program and only when the IDL is actually generated. So do not dismiss these on version grounds; check the discriminator values in the code (KV-156). <!-- verified: anchor v0.31.1 lang/attribute/account/src/lib.rs try_deserialize; v1.2.0 commits e47eda0a (#4645, literal-only is_zeroed_discriminator) and 30708194, absent from v1.1.2; v0.31.0 idl/src/build.rs (empty, collision, all-zero and zero-conflict checks) -->
- Generic `#[account] S<T>` instantiations share one discriminator (KV-156).
- The discriminator is program-agnostic; owner must be checked first (KV-015 Step 6).
- Native programs: see KV-159 (Borsh enum tags).

**Overall verdict:**
- ✅: All accounts use Anchor #[account] + Account<> type (automatic discriminator)
- ⚠️: Manual deserialization present but with discriminator check
- ❌: Accounts without discriminator check
