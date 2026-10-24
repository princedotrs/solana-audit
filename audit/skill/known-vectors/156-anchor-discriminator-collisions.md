---
id: 156
title: "Anchor Discriminator Collisions (Generic, Custom, Short, All-Zero)"
severity: 8
category: crypto
---

### 156 — Anchor Discriminator Collisions (Generic, Custom, Short, All-Zero)

**Severity: 8 when the confused type carries authority or balance fields** | **Real: Anchor `footguns.mdx`; CHANGELOG #3157, #3159, #3166, #3365, #4645**

1. **Generic accounts.** The default discriminator is `sha256("account:<Name>")[..8]`. Generic arguments are not part of the name, so `State<u64>` and `State<u128>` share it. Borsh deserialization does not require all bytes to be consumed, so the longer layout reads as the shorter one with its trailing bytes ignored, and the shorter layout reads as the longer one whenever the account is large enough. Anchor's docs, [verbatim, Apache-2.0, Copyright 2020 Anchor Maintainers]: "Different instantiations of the same generic `#[account]` type share a default discriminator: generic arguments are not part of its derivation." and "Do not rely on generic arguments to prevent this type confusion. Use distinct account structs with distinct discriminators, or explicitly validate a stored type tag before using the account data." <!-- verified: otter-sec/anchor docs/content/docs/footguns.mdx (both sentences verbatim) -->
2. **Custom discriminators (≥ 0.31).** `#[account(discriminator = …)]` and `#[instruction(discriminator = …)]` can be any length and are **prefix**-matched. `[1]` accepts any account whose data starts with `0x01`: another custom type `[1, 2]`, or a default 8-byte discriminator that starts with `0x01`. In the other direction, a `[1]` type whose first field is caller-chosen can be written to start with `0x01 0x09` and then passes as a `[1, 9]` type, with every following byte under the caller's control. Ambiguity is checked only during the IDL build (#3157), so a build without `idl-build` can ship it. Instruction dispatch takes the first declared discriminator that prefixes the data, so instruction discriminators that prefix each other route to the wrong handler. <!-- verified: anchor v0.31.0 lang/attribute/account/src/lib.rs try_deserialize compares `&buf[..disc.len()]`; v0.31.0 lang/syn/src/codegen/program/dispatch.rs `data.starts_with(discriminator)` in declaration order -->
3. **All-zero / empty.** An all-zero discriminator looks like a freshly allocated account. It defeats the `zero` constraint and lets uninitialised data deserialize as `T`. The IDL build rejects all-zero (#3159), empty (#3166) and `zero`-conflicting (#3365) account discriminators from 0.31.0. anchor-lang itself rejects all-zero and empty account discriminators at compile time only from 1.2.0 (#4645). Events and instructions may still use all-zero values. A discriminator that only *starts* with zeros is also dangerous. If account type A's discriminator begins with at least as many zero bytes as type B's discriminator is long, an initialised A passes B's `zero` constraint and is re-initialised as B. Only the IDL build (#3365) rejects this case; anchor-lang 1.2.0 still accepts it. <!-- verified: anchor c4ce2d77 (#3365) idl/src/build.rs leading-zero count vs other discriminator length; v1.2.0 lang/attribute/account/src/lib.rs rejects only empty or all-zero --> <!-- verified: anchor v1.2.0 lang/attribute/account/src/lib.rs const panic "all-zero or empty discriminators are not supported"; CHANGELOG 0.31.0 #3159/#3166/#3365 -->
4. **Cross-program.** The discriminator does not depend on the program. A clone program's same-named struct produces identical bytes, so the owner check must come first (AV-001, AV-005).

> Cross-ref: AN-005/AN-006, KV-027, KV-010.

#### Verification Procedure
```
rg -n -A1 '#\[account(\(.*\))?\]' programs/ | rg 'pub struct \w+<'
rg -n "Account<'info, *\w+<[^>]+>>" programs/
rg -n '#\[(account|event|instruction)\([^)]*discriminator\s*=' programs/
rg -n 'discriminator\s*=\s*(\[\s*0(\s*,\s*0)*\s*\]|0\b)' programs/
rg -n 'discriminator\s*=\s*\[\s*0\s*,' programs/         # leading zero bytes: compare with the shortest account discriminator
```
- ✅ PASS: distinct non-generic structs (or a stored type tag checked by a constraint) for different trust roles; custom discriminators that are non-empty, non-zero, and equal-length or prefix-free within each namespace; no account discriminator's leading zero bytes are as long as another account type's discriminator; a unit test that deserializes every account type as every other type and expects an error
- ❌ FAIL: two instantiations of one generic account type in different trust roles; a prefix pair; an all-zero or empty account discriminator on anchor-lang < 1.2.0; a leading-zero account discriminator that satisfies another type's `zero` check (any version, unless the IDL build ran)

```rust
// VULNERABLE: the shorter discriminator's caller-chosen payload can impersonate the longer one
#[account(discriminator = [1, 9])] pub struct Config   { pub admin: Pubkey }
#[account(discriminator = [1])]    pub struct UserNote { pub body: [u8; 64] }  // body is user-written
// A UserNote whose body starts with 9 passes as Config, and body[1..33] becomes Config.admin.
// FIXED: keep the 8-byte defaults, or use equal-length, non-prefix custom values; never [0]
```

**Overall verdict:**
- ✅: no two account types can satisfy each other's discriminator check
- ❌: two can

*Sources: otter-sec/anchor footguns.mdx (two sentences verbatim, Apache-2.0; surrounding text rewritten), CHANGELOG (Apache-2.0, Copyright 2020 Anchor Maintainers); solana-foundation/solana-dev-skill #4e (MIT, Copyright (c) 2026); Solana Foundation course U3 [paraphrased, cited].*
