# Methodology — Token-2022 / Token-Extensions (Downstream-Integration Audit Checks)

> **Load when:** a protocol **accepts, holds, or moves Token-2022 mints** is detected — grep markers:
> `token_2022` · `TokenInterface` · `transfer_hook` · `TransferFee` · `PermanentDelegate` · `ConfidentialTransfer` · `get_extension` · `spl_token_2022`
> (also: `token_interface`, `InterfaceAccount`, `Interface<'info, TokenInterface>`, `transfer_checked`,
> `StateWithExtensions`, `ExtensionType`, `TransferHook`, `ExtraAccountMetaList`, `DefaultAccountState`,
> `InterestBearing`, `ScaledUiAmount`, `MintCloseAuthority`, `CpiGuard`; **Token ACL / SRFC-37:** `token_acl`,
> `TACLkU6`, `MINT_CFG`, `gating_program`, `thaw_permissionless`, `can_thaw_permissionless`).
>
> **Purpose:** protocol-specific checks for **downstream integrators** — a DeFi protocol, vault, AMM,
> lending market, perp, bridge, wallet, staking system, or indexer that handles tokens issued under the
> Token Extensions Program (`TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb`). **The scope is NOT the
> Token-2022 program itself** (that is reviewed across 15+ third-party engagements). The scope is the
> integration: which extensions a given mint has enabled, and whether *your* code behaves correctly. These
> sit **on top of** the language-agnostic checklists (`checklists/01`–`06`); where a generic check covers the
> base case the note says *"beyond `<ID>`, also verify…"*. The confidential-transfer / ZK surface overlaps
> `references/vuln-classes/zk-and-compression.md` — cross-linked, not duplicated.
>
> **How to use:** each section is an auditor check — *safe shape*, *failure mode*, *grep*. PASS = safe
> shape enforced *in code*; FAIL = failure mode reachable.
>
> **Why this surface is dense:** "we support Token-2022" is not one claim — it is a **per-extension** claim,
> and protocols routinely pass ten extensions and fail one. Token-2022 is a strict **superset** of SPL Token
> that stitches opt-in *extensions* onto mints and accounts, mutating what `transfer`, `mint_to`, `burn`, and
> **balance reads** mean. The single most-reported integration finding is **fee-blind accounting** (crediting
> the requested `amount` instead of the received delta on a TransferFee mint); the highest-severity is a
> **PermanentDelegate** mint accepted into a vault (a third party can seize custodied funds). The whitehat ZK
> ElGamal soundness disclosures (2025, Fiat-Shamir transcript gaps) are the reminder that confidential
> extensions ride on a proof program that is itself a trust root. Extension semantics are public program
> documentation.

---

## 0. Read the mint's extension set FIRST — every downstream check branches on it

Two layers of extensions exist: **mint extensions** (configured on the mint, affect every account of that
mint) and **account extensions** (configured on a token account — the integrator's own vault accounts are
the relevant ones). The first action against any accepted mint is to parse its extension set with the
**official accessor** and branch on the full tuple — never hand-roll TLV walking, never branch on one flag
in isolation.

```rust
use spl_token_2022::extension::{StateWithExtensions, ExtensionType, BaseStateWithExtensions};
use spl_token_2022::state::Mint;

let mint_data = mint_account.try_borrow_data()?;
let mint = StateWithExtensions::<Mint>::unpack(&mint_data)?;   // official parser; do NOT hand-roll TLV
let extensions = mint.get_extension_types()?;                  // branch on the FULL set, not one flag
```

```
grep -rn -E "token_2022|spl_token_2022|TokenInterface|token_interface|get_extension|StateWithExtensions" programs/
grep -rn -E "transfer_hook|TransferFee|PermanentDelegate|ConfidentialTransfer|DefaultAccountState|InterestBearing|ScaledUiAmount|MintCloseAuthority|CpiGuard" programs/
```

---

## 1. Per-extension bug / defense table

Each row: what the extension does → the bug it introduces downstream → the canonical defense. This is the
core of the methodology; the invariants (§2), coexistence rules (§3), and allowlist tiers (§4) operationalize it.

| Extension | What it does | Downstream bug | Canonical defense |
|---|---|---|---|
| **TransferFee** | withholds a bps fee on every transfer; receiver gets `amount − fee`, fee accrues on the destination | **fee-blind accounting** — vault credits the *sent* `amount`, double-counting the fee; fees-on-fees geometric decay through wrapper hops; withheld fees accrue on the destination and block CloseAccount (KV-168); the fee is epoch-dependent (older/newer fee; a newly set fee takes effect two epochs later); calculate_fee and the inverse-fee helpers are not interchangeable (§10) | **read post-transfer balance delta** on the destination (`after − before`); credit the delta, never the `amount` arg. `transfer_checked_with_fee` only as a sanity assert, not a replacement (T1) |
| **TransferHook** | invokes a protocol-defined program on every transfer, with `ExtraAccountMetaList`-resolved extra accounts, **inside the transfer CPI** | arbitrary CPI + **remaining-accounts injection**; the hook is **untrusted code inside the caller's critical section**. It cannot call back into the calling program or into Token-2022 itself (both are indirect reentrancy, which the runtime rejects, so a hook can never re-transfer any Token-2022 token). It receives source/mint/destination/authority read-only and non-signer. It still reads the caller's accounts as last written to the account data (an Anchor `Account<T>` is not written back until exit), can CPI third programs, and can always revert (griefing: the mint becomes untransferable). The hook `authority` can point the mint at a different hook program at any time (`TransferHook` `Update`) | **pin the hook program id against an allowlist** at mint registration; validate `ExtraAccountMetaList` derivation; treat the hook as **untrusted CPI**; flush caller state before the transfer; **re-check the hook program id against the allowlist on every transfer path**, not only at registration; assume the hook reads everything its extra accounts grant (T2) |
| **PermanentDelegate** | mint authority designates an account that can transfer/burn from **any** account of this mint with no holder signature | **third party can seize custodied tokens** — the delegate drains the vault; the protocol's own access control is bypassed entirely | **reject at custody time** — parse `permanent_delegate`; if non-default and not the protocol itself, refuse in the **allowlist**, not the deposit ix (T4) |
| **FreezeAuthority / DefaultAccountState** | new accounts open in a chosen state (usually `Frozen`); freeze authority can freeze any account any time | **freeze DoS** — the vault account itself is frozen mid-flight, halting deposits/withdrawals/liquidations; deposits fail until thaw | prefer null freeze authority on critical paths; else **surface the freeze error clearly** (never swallow-and-retry into a stuck loop); document the trust assumption (T5); if the mint is SRFC-37 / Token ACL-gated (freeze authority delegated to a gate program) apply §9 |
| **ConfidentialTransfer / ConfidentialMintBurn / ConfidentialBalances** | ElGamal-encrypted balances/amounts; transfers carry ZK proofs verified by the ZK ElGamal Proof Program | **opaque amounts break plaintext accounting**; **ZK soundness** is the trust root (Fiat-Shamir gaps were forgeable, 2025); a non-zero `auditor_pubkey` is a **decrypt backdoor** | treat the confidential balance as **opaque** (no plaintext shadow ledger); pin the **post-patch** ZK ElGamal Proof Program id; inspect + disclose `auditor_pubkey`, refuse non-zero unless explicitly accepted; escalate to ZK specialists (T8; cross-ref `references/vuln-classes/zk-and-compression.md`) |
| **InterestBearing / ScaledUiAmount** | UI/display amount = `raw × multiplier` (Scaled) or `raw × (1+r)^t` (Interest); **raw `amount` is unchanged**; multiplier/rate is **mutable** by an authority | **display-vs-raw drift** — protocol quotes/settles in UI units at one boundary and raw at another → double- or under-count; cached multiplier goes stale on update | pick **one accounting layer (raw, internally)**; convert to UI only at the display boundary via the official helpers; **never cache** the multiplier/rate; treat any update as state-invalidating (T9) |
| **MetadataPointer / MintCloseAuthority** | metadata pointer references a (possibly self / external) metadata account, authority can update it; close authority can close the mint account | **spoofing** — stale/attacker-controlled `(name, symbol, uri)`; embedded-metadata re-borrow hazard; **mint revival** — a closed mint account's address can be recreated, and code caching "mint X exists / decimals = d" is fooled; **mint resurrection**: existing token accounts keep their old account-level extensions and frozen state after the mint is re-created with a different extension set (KV-166) | resolve the pointer + validate its owner program at **use-time**; use `spl_token_metadata_interface` to bounds-check embedded metadata; treat a mint with a live close authority as unstable — re-read mint state, don't cache existence/decimals across the close boundary (T7) |
| **CpiGuard** | *Account* extension that only the **owner** can enable or disable, and only at top level (inside a CPI it fails with `CpiGuardSettingsLocked`). While it is on, inside a CPI: Transfer and Burn signed by the owner are rejected, including when the owner is also the delegate or the permanent delegate, so they must be signed by a delegate; Approve is rejected; CloseAccount must send the lamports to the owner; the close authority can only be unset. Changing the account owner is rejected even at top level (`CpiGuardOwnerChangeBlocked`). | **Integration DoS**: a program that forwards the *user's* own signature into a Token-2022 `transfer_checked` CPI fails for every user who enabled CPI Guard. A PDA owner can sign only through `invoke_signed`, which is always a CPI, so a **PDA-owned vault cannot enable or use CPI Guard**. Historical: before the fix for Neodyme ND-ANZ-LO-01 (solana-program-library PR #6724, May 2024; the report's fix commit `dc85c98…`), the guard was skipped when the owner had delegated to itself. PR #6863 (June 2024) then generalised the check to every owner-signed Transfer and Burn, which also covers an owner that is the permanent delegate. | Pull user funds as a **delegate**: the user signs a top-level `Approve`/`ApproveChecked` to a program PDA, then the program transfers as the delegate via `invoke_signed` and verifies the balance delta. The pull must bind the source token account to the transaction signer (`token::authority = user`, user signs); if one delegate PDA is shared across users, anyone can otherwise pull from any account that approved it (KV-143, KV-165). Do not treat the guard as a control on clusters or test validators that run a pre-fix Token-2022 build (KV-137). The `anchor-spl` `cpi_guard_enable`/`cpi_guard_disable` wrappers can never succeed on-chain; they carry `#[deprecated]` from anchor-spl 1.2.0. |
| **ImmutableOwner** | *account* extension: prevents `owner` change via `set_authority` | a brief window of misconfigured authority permanently reassigns vault ownership, locking out the protocol | **enable on every protocol-owned vault**; ATAs get it by default, manually-created vaults must opt in at init (T3) |
| **Pausable** | global mint-level pause; when paused, `Transfer`/`MintTo`/`Burn` all revert | **liveness** — a paused mint halts liquidations, oracle rebalances, keeper actions; a pause toggled between simulate and execute weaponizes the failure; an insider can sandwich state transitions | treat the pause authority with **freeze/mint-authority-level scrutiny** (diversified, time-locked, multisig); reject hostile/unknown pause authority; surface pause errors clearly (T5/T10) |
| **NonTransferable** | transfers always fail; only mint/burn/close work | **liveness** — code assuming "deposit ⇒ withdraw via transfer" breaks permanently; LP/share wrappers can't redeem | **reject at acceptance** from any flow requiring transfer-out; allow only where mint/burn/close semantics suffice (T5) |
| **GroupPointer / MemberPointer** | Token Group standard — a mint is a group or a member; group authority can add members at will | **identity confusion** — treating "same group" as "same trust domain" inherits the group authority's trust; a hostile mint can be added tomorrow | gate on the conjunction `(group_id, group_authority)`; **snapshot membership** at the decision point; never infer trust transitively from group identity (T10) |

---

## 2. Invariant catalog

For every protocol that integrates Token-2022, the following must hold. Evidence (test / review note) per item.

| # | Invariant | Failure = |
|---|-----------|-----------|
| **T1** | **Vault accounting tracks NET received, not GROSS sent** — a credited balance equals the destination's **post-transfer balance delta**, not the transfer's `amount` argument | Fee-on-transfer mint over-credits; share math inflated |
| **T2** | **Transfer hooks are treated as untrusted code in the critical section.** The hook program id is allowlisted and **re-checked on every transfer path**; extra accounts are validated; caller state is flushed before the transfer; no invariant may be false across the transfer. A hook cannot call back into the caller or into Token-2022 (indirect reentrancy is rejected), but it can act on third programs | Untrusted callee acting on inconsistent state via third programs, remaining-accounts injection, griefing |
| **T3** | **Protocol-owned Token-2022 vaults have `ImmutableOwner`** (Token-2022 ATAs get it automatically; keypair or PDA token accounts opt in with `InitializeImmutableOwner` before `InitializeAccount`). **CPI Guard is not a vault control** (a PDA owner cannot enable it). Instead, user-funded flows are CPI-Guard-compatible (delegate pull, verified delta) | Ownership hijack / deposit DoS for guarded users |
| **T4** | **PermanentDelegate-bearing mints are rejected at custody time** — inspected in the mint allowlist, refused if the delegate is not the protocol itself | Third party seizes custodied funds |
| **T5** | **Freeze/pause/non-transferable states are handled, not swallowed** — any mint with active freeze authority (incl. `DefaultAccountState=Frozen`, `Pausable`, post-hoc `freeze_account`) or `NonTransferable` produces a clean surfaced error, never a retry loop or a silent success | Freeze/pause DoS wedges the protocol |
| **T6** | **Token-program id is pinned** — `Interface<'info, TokenInterface>` + `token::token_program = token_program`; the program is not whichever was passed | Silent SPL Token vs Token-2022 confusion |
| **T7** | **Decimals read at deserialize; multiplier/rate resolved at use-time** — decimals come from the mint (0–18, never hard-coded `9`); ScaledUiAmount/InterestBearing conversions use the **current** multiplier/rate and are not cached | Amount mis-scaling; stale-conversion drift |
| **T8** | **Confidential balances are opaque; ZK proof program version validated** — no plaintext shadow ledger of encrypted balances; any call into the ZK ElGamal Proof Program targets the **post-patch** deployment; `auditor_pubkey` is inspected and disclosed | Broken accounting; forged proofs; undisclosed decrypt backdoor |
| **T9** | **A single accounting layer is chosen (raw internally)** — the protocol never quotes in UI units at one boundary and settles in raw at another | Double-count / under-count of interest/scaling |
| **T10** | **Authority diversity of every accepted mint is audited** — one key holding mint + freeze + pause + permanent-delegate authority is a total-control vector; group membership is gated on `(group_id, group_authority)` | Single-key total control; transitive-trust injection |
| **T11** | **Mint extension parsing uses the official accessor** — `StateWithExtensions` / `get_extension`, not hand-rolled TLV walking that can skip an unknown extension without honoring its length and mis-parse the rest | Extension mis-parse → wrong code path |
| **T12** | **Permissioned (Token ACL / SRFC-37) semantics are enforced by a verified gate, not assumed** — the gate `can_thaw` / `can_freeze` decisions key on the token account real owner and mint, verify the Token ACL flag context, validate extra-account PDAs, are exact inverses of each other, and protocol-owned accounts have a proven thaw path (§9) | Permissionless freeze griefing / unauthorized thaw / protocol vault DoS |

---

## 3. Coexistence / compatibility: what the runtime actually rejects

Mint initialisation rejects only these combinations (`check_for_invalid_mint_extension_combinations` in `spl-token-2022-interface`, Token-2022 `main`; older `spl-token-2022` releases check fewer rules, so re-check against the pinned version):
1. `ConfidentialTransferFeeConfig` without both `TransferFeeConfig` **and** `ConfidentialTransferMint`.
2. `TransferFeeConfig` + `ConfidentialTransferMint` **without** `ConfidentialTransferFeeConfig`.
3. `ConfidentialMintBurn` without `ConfidentialTransferMint`.
4. `ScaledUiAmount` + `InterestBearingConfig`.
5. `NonTransferable` + `ConfidentialTransferMint` **without** `ConfidentialMintBurn`.

Every other pair can be initialised, including **TransferHook + TransferFee** (common: fee-bearing hook mints), **TransferHook + Confidential**, and **NonTransferable + TransferFee** (redundant but legal). Integrators **must** handle fee + hook on the same transfer (T1 delta accounting *and* T2 hook rules).

Account extensions that Token-2022 creates with each token account (the source of mint resurrection, KV-166): `TransferFeeConfig` → `TransferFeeAmount`; `NonTransferable` → `NonTransferableAccount` + `ImmutableOwner`; `TransferHook` → `TransferHookAccount`; `Pausable` → `PausableAccount`.

**Downstream branching rule:** branch on the full extension tuple, not individual booleans. `Confidential* × TransferFee` remains one of the highest-bug-density surfaces: the fee is proven inside the ZK proof, not applied to a plaintext amount.

---

## 4. Mint-allowlist tier policy

No serious integrator accepts arbitrary Token-2022 mints. The allowlist is the primary policy lever and must
be **on-chain enforced** (a `mint_registry` / per-mint PDA), not merely documented.

- **Tier 0 — reject Token-2022 entirely.** SPL Token only. The simplest, most defensive posture; appropriate
  for legacy protocols not engineered for extension semantics.
- **Tier 1 — Token-2022 with no extensions.** Accept only mints whose extension set is **empty** (behaves
  identically to SPL Token). Verified at registration.
- **Tier 2 — curated extension allowlist.** Accept only extensions the protocol has explicitly engineered for.
  Typical **safe** set: `MetadataPointer`, `GroupPointer`/`MemberPointer` (gated on authority),
  `InterestBearing`/`ScaledUiAmount` (with raw-amount accounting), `ImmutableOwner` (holder side). Typical
  **refused** set: `PermanentDelegate`, `TransferHook` (unless hook is whitelisted), `NonTransferable`,
  `DefaultAccountState=Frozen`, and hostile/unknown `Pausable` or freeze authority.
- **Tier 3 — full Token-2022 support.** Accept all extensions with explicit per-extension handling —
  fee-aware accounting, hook validation, confidential-amount opacity, pause-tolerant flow, the works. Reserved
  for protocols whose business model **is** Token-2022 (wrapped-asset bridges, issuance platforms).

**Governance flow for adding a mint (Tier 2/3):** read the extension set on-chain and serialize it into the
proposal; enumerate every enabled extension with its risk acknowledgment; list every authority (mint, freeze,
pause, permanent-delegate, fee, withdraw, scale, metadata-pointer); approve at the same threshold as other
treasury-affecting actions; re-approve on any change to the mint's authorities or extension set (off-chain
monitor). Cross-ref `references/methodologies/governance.md`.

---

## 5. Detection recipes

Concrete on-chain reads an auditor (or a static pass) runs against every accepted mint.

**Refuse hostile combinations at integration time:**

```rust
for ext in &extensions {
    match ext {
        ExtensionType::PermanentDelegate  => return Err(ErrorCode::MintHasPermanentDelegate.into()), // T4
        ExtensionType::NonTransferable    => return Err(ErrorCode::MintIsNonTransferable.into()),     // T5
        ExtensionType::DefaultAccountState => { /* allow but flag for freeze-tolerant handling */ }   // T5
        ExtensionType::TransferHook => {
            let hook = mint.get_extension::<TransferHook>()?;                                          // T2
            if !ALLOWLISTED_HOOKS.contains(&hook.program_id) {
                return Err(ErrorCode::HookNotAllowlisted.into());
            }
        }
        ExtensionType::ConfidentialTransferMint
        | ExtensionType::ConfidentialTransferFeeConfig
        | ExtensionType::ConfidentialMintBurn => { /* inspect auditor_pubkey; refuse non-zero unless accepted */ } // T8
        ExtensionType::Pausable => { /* record pause authority for governance review */ }              // T10
        _ => {}
    }
}
```

**Fee-aware deposit — read the destination delta, credit the delta (T1):**

```rust
let before = token_interface::accessor::amount(&ctx.accounts.vault.to_account_info())?;
token_interface::transfer_checked(cpi_ctx, amount, decimals)?;
ctx.accounts.vault.reload()?;                                   // MUST reload after the transfer CPI
let credited = ctx.accounts.vault.amount
    .checked_sub(before)
    .ok_or(ErrorCode::Underflow)?;
// use `credited`, NOT `amount`, for every share / balance / debt calculation
```

**Scaled / interest-bearing quoting — convert at the boundary, never cache (T7/T9):**

```rust
let raw = vault.amount;                                          // protocol accounting stays in raw units
let ui  = spl_token_2022::amount_to_ui_amount(raw, mint.decimals); // helper consults the CURRENT multiplier/rate
// do NOT persist `ui` across instructions; a multiplier/rate update invalidates it
```

```
grep -rn -E "\.amount\b|credited|balance_before|balance_after|reload" programs/   # is credit = post-transfer delta?
grep -rn -E "amount_to_ui_amount|ui_amount_to_amount|multiplier|interest_rate"   programs/   # boundary conversion, no cache?
grep -rn -E "auditor|elgamal|ZkE1Gama1Proof|proof_program"                       programs/   # confidential trust root pinned?
```

---

## 6. High-density surfaces (fastest findings)

- **S1 — Fee-blind accounting (T1).** Vault credits `amount` sent instead of the destination balance delta.
  **The single most-reported Token-2022 integration finding**, across deposit/withdraw in every category.
  Beyond `AV-062` (credit from vault delta): confirm the delta is read **after** a `.reload()` and used for
  *all* downstream share/debt math.
- **S2 — Transfer-hook untrusted code + injection (T2).** The hook cannot call back into the caller or Token-2022 (indirect reentrancy is rejected), but it runs while the caller holds unflushed in-memory state and can act on third programs, read stale account data, burn CU or revert; or the hook's extra accounts overlap the caller's in an unexpected
  way. Beyond `CPI-009` (validate program id of pass-through CPIs) and `KV-105`: the hook is an **untrusted
  program inside your CPI chain** — allowlist it and flush state before the transfer.
- **S3 — PermanentDelegate accepted at integration (T4).** Deposit succeeds; the delegate drains the vault
  later. Beyond `AV-063`/`AV-064`: the decision must live in the **allowlist**, and must also catch a **rotation** of an existing permanent delegate (re-validate on deposit). A permanent delegate cannot be added to an already-initialised mint.
- **S4 — Confidential-transfer ZK soundness + auditor key (T8).** The ZK ElGamal Proof Program is the trust
  root; Fiat-Shamir gaps were forgeable in 2025; a non-zero `auditor_pubkey` silently grants a third party
  decrypt over every transfer on the mint. Cross-ref `references/vuln-classes/zk-and-compression.md`; escalate
  to ZK specialists — not catchable by black-box testing.
- **S5 — ScaledUiAmount / InterestBearing display-vs-raw (T7/T9).** Especially in **oracle adapters** that
  read an on-chain balance and treat it as price-relevant, and in any flow that quotes in UI units but settles
  in raw. Beyond `AV-061` (decimals from mint, normalize before compare): the multiplier/rate is **mutable** —
  resolve at use-time, never cache.
- **S6 — Extension parse skip (T11).** A hand-rolled TLV walker advances past an unknown extension without
  honoring its length and mis-parses everything after it. Use `StateWithExtensions`.
- **S7 — Wrap / unwrap boundary.** For wrapped-asset bridges, extension preservation, fee accounting on the
  wrapped side, and hook re-invocation through the wrapper are the recurring bug cluster — test transfer-fee
  mints specifically. Cross-ref `references/methodologies/bridges.md` (B8).
- **S8 — Mint-close / metadata spoofing (T7).** A live `MintCloseAuthority` makes cached "mint exists /
  decimals = d" unsafe (mint-revival); a mutable metadata pointer makes cached `(name, symbol, uri)` stale.
  Re-read at use-time; validate the pointed account's owner program.

---

## 7. Per-instruction review worksheets

Each worksheet lists the safe shape. FAIL if any line is missing on any reachable path.

### Vault deposit (accepting a Token-2022 mint)
- The mint passed the **allowlist tier** (§4); its extension set was parsed with the official accessor (T11)
  and re-validated for a `PermanentDelegate` rotation / authority change (T4).
- Balance read **pre** transfer; `transfer_checked` with current decimals; `.reload()`; balance read **post**;
  **credit = post − pre** (T1). Refuse if the delta is zero or negative.
- Token program pinned via `Interface<TokenInterface>` + `token::token_program` (T6).
- If the mint is hook-bearing, the hook program id is allowlisted and `ExtraAccountMetaList` accounts are
  resolved correctly; caller state is flushed before the CPI (T2).

### Vault withdraw / transfer-out
- Pause/freeze/non-transferable state checked and surfaced cleanly if hit — no retry loop (T5).
- Output computed on the **raw** amount; UI conversion (if ScaledUi/InterestBearing) happens only at display,
  using the current multiplier/rate (T7/T9).
- `transfer_checked` with the mint's actual decimals (T7); token program pinned (T6).

### `transfer_checked` / `transfer_checked_with_fee` (any transfer)
- The `_checked` variant is used (asserts mint + decimals) — never the legacy unchecked `transfer` (T6/T7).
- Fee-aware accounting on the destination (T1). Hook accounts resolved; hook treated as untrusted (T2).

### Confidential-transfer / mint / burn paths
- Proofs verified by the **post-patch** ZK ElGamal Proof Program id (T8). The confidential balance is treated
  as opaque — no plaintext shadow ledger (T8). Pending balance flushed before reading available balance.
  `auditor_pubkey` disclosed and, if non-zero, explicitly accepted per policy. Escalate to ZK specialists.

### Mint-acceptance / allowlist registration
- Extension set read on-chain; each enabled extension mapped to the tier policy (§4); hostile combinations
  refused; every authority (mint/freeze/pause/permanent-delegate/fee/withdraw/scale/metadata) enumerated and
  its diversity assessed (T10). Governance approval recorded; re-approval wired to an authority/extension-set
  change monitor.

### Protocol-owned vault initialization
- `ImmutableOwner` enabled (Token-2022 ATAs get it by default; other token accounts opt in before
  `InitializeAccount`). User-side CPI-Guard compatibility is tested; CPI Guard is never expected on a
  PDA-owned vault (T3).

---

## 8. Test / PoC strategy

A Token-2022 integration is **not tested** if the suite uses only the bare SPL Token program. Minimum bar:

- **Extension-combination fuzz (T11, §3).** Generate mints across every **legal** combination (§3);
  run deposit/swap/withdraw for each; assert correct accounting in every case. Branch on the full tuple.
- **Differential transfer-fee tests (T1) — MANDATORY.** For a deposit of `x` at `y` bps, assert the vault
  credit equals `x − fee(x, y)` — across fee configs including 0, 1, and a high cap, plus a deposit→immediate
  withdraw round trip (the user must not silently double-fee). This is the highest-value negative test.
- **Transfer-hook smoke (T2).** Deploy a **no-op**, a **logging**, a **reverting**, and a **recursive** hook.
  Assert the protocol is correct or reverts **cleanly** for each; the recursive hook must produce a clean error,
  not undefined behavior; the reverting hook must not wedge the protocol.
- **PermanentDelegate refusal (T4).** Register a mint with a permanent delegate → **refused**. On a tolerated permanent-delegate mint, rotate the delegate (`SetAuthority(PermanentDelegate)`) and deposit → **detected/refused** (adding one post-init is impossible).
- **Frozen / paused tolerance (T5).** Deposit into and withdraw from a frozen vault, transfer through a frozen
  intermediate, and pause the mint mid-transaction (validator-level) → each **surfaces cleanly** with the right
  error, never swallowed; resume → state consistent.
- **CPI-Guard compatibility (T3).** A user account with the guard on can still deposit through the
  delegate-pull path; an owner-signed CPI pull fails as expected (`CpiGuardTransferBlocked`).
- **Scaled / interest-bearing accounting (T7/T9).** Change the multiplier/rate after deposit, before withdraw →
  the protocol uses **raw** internally and the user-visible UI amount reflects the new multiplier **without**
  changing bookkeeping.
- **Wrap/unwrap parity (S7).** For wrapped-asset bridges, a wrap→unwrap round trip preserves balance, fee, and
  extension behavior — test transfer-fee mints specifically.
- **ZK escalation (T8).** For any ConfidentialTransfer/MintBurn/Balances integration, escalate the proof-program
  integration to formal verification / ZK-specialist review — the 2025 ElGamal soundness disclosures were **not**
  catchable by black-box testing. Cross-ref `references/vuln-classes/zk-and-compression.md`.

Prefer **LiteSVM** / **Mollusk** for fast deterministic per-extension unit tests; use **Surfpool** forked
mainnet to exercise **real** Token-2022 mints with their actual extension sets.

---

## 9. Permissioned tokens — Token ACL (SRFC-37) and gate programs

> **Load when (additional markers):** `token_acl` · `token-acl` · `TACLkU6CiCdkQN2MjoyDkVg2yAH9zkxiHDsiztQ52TP` ·
> `MINT_CFG` · `gating_program` · `thaw_permissionless` / `freeze_permissionless` (+ `_idempotent`) ·
> `can_thaw_permissionless` / `can_freeze_permissionless` · `thaw-extra-account-metas` · `srfc37` / `srfc-37`.

**What it is.** SRFC-37 (solana-foundation/token-acl, program `TACLkU6…`) makes a Token-2022 mint *permissioned*
without a transfer hook. The mint sets **`DefaultAccountState = Frozen`** (every new token account starts frozen)
and **delegates its freeze authority to the Token ACL program**. `create_config` writes a `MintConfig` PDA
(`[b"MINT_CFG", mint]`) holding `authority`, `gating_program`, `enable_permissionless_thaw`,
`enable_permissionless_freeze`. Anyone may then call `thaw_permissionless` / `freeze_permissionless` (and the
`_idempotent` variants): Token ACL CPIs into the configured **gate program** (`can_thaw_permissionless` /
`can_freeze_permissionless`, 8-byte discriminators derived from
`efficient-allow-block-list-standard:can-…-permissionless`) with
`[caller, token_account, mint, token_account_owner, flag_account, extra_account_metas]` plus the extra accounts
resolved from `[b"thaw-extra-account-metas", mint]` / `[b"freeze-extra-account-metas", mint]`. Gate **success ⇒**
Token ACL thaws / freezes with its delegated authority; gate **error ⇒** blocked. The issuer keeps authority-signed
`thaw` / `freeze`, `set_authority`, `set_gating_program`, `forfeit_freeze_authority`. A **flag account**
(0 lamports, data `[1]`, owned by Token ACL) is passed so the gate can prove it is being invoked *by Token ACL in
a permissionless context*, and Token ACL **de-escalates** the CPI (no signer / writable privilege of the caller
is forwarded) so a hostile gate cannot use the call for anything else.

**Why it matters downstream.** Composability changes shape: a transfer to any *fresh* token account fails until
that account is thawed, the gate — not the mint — decides *who may hold*, and whoever controls the gate (or
`set_gating_program`) holds the equivalent of the freeze authority. Three audit roles apply: the **gate author**,
the **issuer** who configures the mint, and the **downstream integrator** (vault / AMM / lending / wallet).

### 9.1 Gate program (author) — safe shape

| # | Check | Failure mode |
|---|-------|--------------|
| **G1** | The gate asserts `flag_account.owner == TOKEN_ACL_PROGRAM_ID`, `data == [1]` (and 0 lamports) before trusting the context. A gate with *any* side effect (one-time allowance consumed, counter, fee, event an indexer trusts) must only apply it under a verified flag. | Anyone calls `can_thaw_permissionless` directly with a forged flag and burns allowances / spoofs events |
| **G2** | Thaw and freeze semantics are **consistent and inverse**: allow-list ⇒ `can_thaw` passes only allowlisted owners **and** `can_freeze` passes only *non*-allowlisted; block-list ⇒ `can_thaw` fails blocklisted **and** `can_freeze` passes only blocklisted. | Inverted / missing freeze rule ⇒ **anyone freezes any legitimate holder permissionlessly** (griefing DoS) or a blocklisted owner keeps a thawed account |
| **G3** | Identity is **re-derived from the token account**: `token_account.owner == token_account_owner` and `token_account.mint == mint` are checked by the gate itself (unpack with `StateWithExtensions<Account>`), not trusted from the passed pubkey. | Attacker passes an allowlisted pubkey as `token_account_owner` for a token account they own ⇒ unauthorized thaw |
| **G4** | Extra accounts (allowlist / blocklist entry PDAs, config) are validated as **canonical PDAs** — seeds from `(mint, owner)` under the gate program, owner program checked, discriminator checked (cross-ref T2, KV-010, KV-026). The extra-account-metas PDA is populated by the author (SRFC-37 ships no interface instruction for it) and is itself authority-gated. | Forged "allowlist entry" account passed in `remaining_accounts` ⇒ thaw for anyone |
| **G5** | `can_*` handlers are **read-only / idempotent** and demand no signer or writable privilege from `caller` (Token ACL de-escalates; a gate that requires them fails for everyone). | Spam through Token ACL mutates gate state; or the gate is unusable |
| **G6** | Gate list-admin authority and gate **upgrade authority** are treated as freeze-authority-equivalent — multisig / timelocked, enumerated in the mint authority-diversity review (T10). | One key un-permissions or bricks the token |

### 9.2 Issuer configuration — safe shape

- **I1** The mint really is ACL-gated: `DefaultAccountState = Frozen` **and** the mint's freeze authority is the
  Token ACL PDA — an ACL `MintConfig` next to a freeze authority held elsewhere is decorative.
- **I2** `gating_program` is non-default and matches the audited gate; the tuple
  (`gating_program == default`, `enable_permissionless_thaw == true`) is understood — with no gate the token is
  effectively *permissionless* for thaw.
- **I3** `set_gating_program`, `set_authority`, `forfeit_freeze_authority` are governance-gated and **monitored**:
  swapping the gate to an `always-allow` implementation silently removes the permission layer; `forfeit`
  returns raw freeze authority to the issuer key.
- **I4** Enforcement liveness for block-lists: a thawed account stays thawed until someone calls
  `freeze_permissionless` — the issuer runs (or relies on a public) keeper that freezes newly blocklisted
  holders; otherwise the list is advisory.

### 9.3 Downstream integrator — safe shape

- **D1** Every **protocol-owned** account of an ACL mint (vault, escrow, fee, LP-side ATA) starts *frozen*. The
  initialization / first-deposit path thaws it (`thaw_permissionless_idempotent`) **or** the protocol PDA is on
  the issuer's allowlist — and that allowlist status is a tracked config item with a monitor. A protocol PDA the
  gate refuses is a permanent deposit failure (T5).
- **D2** Paths that create a **recipient** token account in the same transaction (swap output ATA, liquidation
  payout, claim, airdrop) include an idempotent thaw for it, and surface a clean error when the recipient is not
  permitted — a liquidator or claimant who cannot be thawed must not wedge the protocol (bad-debt liveness,
  cross-ref `lending.md`).
- **D3** **Re-freeze mid-flight is reachable by anyone** once the gate says an owner should be frozen — including
  the protocol's own vault if the protocol PDA is blocklisted. Handle as T5 (surface, never retry-loop) and
  treat the issuer's gate policy as a trust assumption in the mint allowlist (§4 tier decision).
- **D4** `MintConfig` changes (gate swap, authority change, forfeit) are **mint-authority-level events** for the
  integrator's monitor; the integrator never hardcodes assumptions about the gate's policy.
- **D5** When the integrator CPIs Token ACL, the program id is pinned (`TACLkU6…`) and `MintConfig` is derived
  `[b"MINT_CFG", mint]` under it (KV-009 / KV-010).

```
grep -rn -E "token_acl|token-acl|TACLkU6|MINT_CFG|gating_program|thaw_permissionless|freeze_permissionless|can_thaw_permissionless|can_freeze_permissionless|extra-account-metas" programs/ apps/ packages/
grep -rn -E "DefaultAccountState|default_account_state|AccountState::Frozen" programs/
```

### 9.4 Test strategy

- **Gate semantics.** Allow-list: non-allowlisted thaw → fails; allowlisted → succeeds; stranger freezes an
  allowlisted holder → **fails**; freeze after removal → succeeds. Block-list: the inverse. Both directions
  tested, not just thaw (G2).
- **Context spoof.** Call `can_thaw_permissionless` directly with a fake flag account → rejected / no side
  effect (G1). Pass an allowlisted pubkey with a token account owned by someone else → rejected (G3). Pass a
  forged allowlist-entry account → rejected (G4).
- **Integrator liveness.** First deposit into a fresh vault; swap that creates the output ATA; liquidation to a
  non-allowlisted liquidator — each either succeeds via idempotent thaw or surfaces a clean, non-wedging error
  (D1 / D2). Blocklist the protocol PDA on a fork and confirm the failure is surfaced, not looped (D3).
- **Governance drills.** `set_gating_program` → `always-allow` and `forfeit_freeze_authority` on a fork; the
  monitor alerts and the integrator's allowlist review re-opens (I3 / D4).

Use **Surfpool** with the mainnet Token ACL program and the reference `token-acl-gate` for realistic fixtures;
**LiteSVM / Mollusk** for gate unit tests with hand-built flag / extra-meta accounts.

---

<!-- verified: token-2022 main (program@v11.1.0 era) program/src/processor.rs (CPI Guard checks in transfer/burn/approve/set_authority/close; hook Execute call site), program/src/extension/cpi_guard/processor.rs (CpiGuardSettingsLocked under in_cpi), interface/src/extension/mod.rs (check_for_invalid_mint_extension_combinations, required_init_account_extensions, adjust_len_for_multisig), interface/src/extension/transfer_fee/mod.rs, program/src/extension/transfer_fee/processor.rs (newer fee = epoch + 2), program/src/extension/confidential_transfer_fee/processor.rs; spl-transfer-hook-interface 0.4.1 src/instruction.rs (Execute metas read-only, non-signer); anchor v1.2.0 spl/src/token_2022_extensions/cpi_guard.rs (#[deprecated], absent in v1.1.0); token-2022 git log 51275605 (#6724 self-delegate CPI Guard fix, = Neodyme report fix dc85c98) and d1281814 (#6863 all owner-signed paths); program/src/processor.rs SetAuthority(PermanentDelegate) validates the current delegate; interface/src/extension/confidential_transfer/mod.rs valid_as_destination (counter > maximum fails) -->

## 10. Fee helpers and epochs
- `calculate_fee(gross)` is the fee charged on an amount sent. For "the receiver must net `net`", use `calculate_pre_fee_amount(net)` (the gross to send) or `calculate_inverse_fee(net)` (the fee on that gross). Using `calculate_fee(net)` as the top-up shorts the receiver by `fee(net + fee(net)) − fee(net)`. That is second order in the rate and grows with the amount (1 % on 1,000,000 → short by 100). It differs from ±1 rounding, and it shrinks to zero once both fees hit `maximum_fee`. To pay exactly X net, use the inverse helper and pass the fee to `transfer_checked_with_fee`, which fails with `FeeMismatch` if the fee is wrong.
- `TransferFeeConfig` holds `older_transfer_fee` and `newer_transfer_fee`. `SetTransferFee` schedules the new fee for **current epoch + 2**. Compute fees at use time with `get_epoch_fee(Clock::get()?.epoch)` / `calculate_epoch_fee(epoch, amount)`. Never cache the bps across an epoch boundary, and pair fees with slippage bounds, because a scheduled fee change can take effect at an epoch boundary between quote and settle.

```
rg -n "newer_transfer_fee|older_transfer_fee|transfer_fee_basis_points|calculate_(inverse_|epoch_|inverse_epoch_)?fee|calculate_pre_fee_amount|get_epoch_fee" programs/
```

## 11. Authority inventory (post-allowlist powers)
| Authority | Power that matters downstream |
|---|---|
| `TransferHook.authority` | point the mint at another hook program (an always-reverting hook bricks transfers); re-check `program_id` on every transfer path |
| `freeze_authority` | freeze/thaw; update `DefaultAccountState` to `Frozen` later, so vaults created afterwards start frozen (T5) |
| `ConfidentialTransferMint.authority` | approve accounts, toggle auto-approve, change the auditor ElGamal key (re-check at use, T8) |
| `ConfidentialTransferFeeConfig.authority` | enable/disable harvesting confidential withheld fees to the mint |
| `TransferFeeConfig.withdraw_withheld_authority` | sweep withheld fees, both plaintext and confidential (the confidential path also checks the configured withdraw ElGamal key) |
| `transfer_fee_config_authority` | change the fee (effective two epochs later) |
| `MintCloseAuthority` | close the mint at zero supply → re-creation (KV-166) |
| `InterestBearingConfig.rate_authority` | change the rate (T7/T9) |
| `ScaledUiAmountConfig.authority` | change the UI multiplier (T7/T9) |
| `PausableConfig.authority` | pause/resume transfers, mints and burns (T5) |
| Group/member pointer, `TokenGroup`/`TokenMetadata` update authority | repoint, add members, rewrite name/symbol/uri |
| `mint_authority` | mint; also `WithdrawExcessLamports` from the mint account (explains lamport movements) |
| `PermanentDelegate.delegate` | transfer/burn from any account of the mint; the current delegate itself signs `SetAuthority(PermanentDelegate)` to rotate or clear it (once cleared it cannot be set again), so trust follows whoever controls the delegate key |

Note: a **PermanentDelegate cannot be added after `InitializeMint`** (its init instruction only accepts an uninitialised mint), but an existing one can be rotated or cleared by the current delegate. The mint authority *can* add `TokenMetadata`, `TokenGroup` and `TokenGroupMember` to an initialised mint (with the matching pointer). A registration fingerprint of the extension set must therefore leave out these variable-length extensions (or treat their addition as benign). It should hash `u16::from(ext)` values, since `ExtensionType` has no Borsh impl, and include the rotatable authority keys (hook program, permanent delegate, freeze authority). Protocols that *tolerate* a permanent-delegate mint (compliance clawback, RWA) must reconcile stored totals with actual balances. They must handle `vault.amount < recorded_total` and `== 0` without division by zero, without underflow, and without paying one user from another's funds.

## 12. Confidential-transfer liveness and privacy
- Each incoming confidential credit increments `pending_balance_credit_counter`. Once the counter reaches `maximum_pending_balance_credit_counter` (set at `ConfigureAccount`; no instruction updates it), further confidential credits *to* the account fail until the owner runs `ApplyPendingBalance`. An attacker can spam tiny credits to block time-critical incoming payments (liquidations, auctions, settlements).
- `ApplyPendingBalance` carries no ZK proof. It adds the pending ciphertexts homomorphically, then records the expected and actual counters plus a client-supplied decryptable balance. A credit that lands concurrently does not make it fail: the counter mismatch shows up and the owner recomputes. A larger maximum costs client-side decryption, not proof generation.
- A program-driven flow that applies and then withdraws right after a single incoming credit reveals the credited amount. Batch or delay, or document it in the privacy claims.
- Owners can disable confidential or non-confidential credits on their accounts; push paths must tolerate that (KV-169).

```
rg -n "ApplyPendingBalance|apply_pending_balance|maximum_pending_balance_credit_counter|pending_balance_credit_counter|(Enable|Disable)(Non)?ConfidentialCredits" programs/
```

## 13. Extension policy table (reporting discipline)
Every extension that can affect value, authority, liveness, display or close behaviour gets exactly one policy:

| Extension or behavior | Policy | Evidence required | Residual risk |
|---|---|---|---|
| Transfer fee | supported/rejected/residual risk | balance-delta tests, fee lifecycle review | over-credit, close failure |
| Transfer hook | supported/rejected/residual risk | hook program policy, extra-account validation | callback and liveness risk |

(Extend with every other extension in §1.) Every accepted extension needs one positive test and one negative test, and the negative test proves the rejection happens **before** any state mutation. Minimum negative tests: wrong token program variant; unsupported extension mix; fee mint where net received < requested; hook mint with an unapproved hook; memo-required destination without memo; default-frozen source/destination; permanent delegate present; close path with withheld fees present.

*Sources: Neodyme "SPL Token-2022: Don't shoot yourself in the foot with extensions" and Neodyme Token-2022 audit for Anza (ND-ANZ-LO-01, ND-ANZ-IN-01; fix history checked against token-2022 git log: #6724, #6863) [paraphrased, cited: https://neodyme.io/en/blog/token-2022 ; https://www.neodyme.io/reports/Token%202022%20-%202024.pdf]; sanbir/solana-auditor-skills `solana-auditor/references/attack-vectors/attack-vectors-4.md` V87 (MIT, Copyright (c) 2024 AI Skills Contributors), CPI Guard half corrected; solana-foundation/solana-dev-skill `skills/solana-dev/references/security.md` "Transfer Fee Accounting" and "calculate_fee vs calculate_inverse_fee Rounding" (MIT, Copyright (c) 2026), drift wording corrected; beriktassuly/solana-audit-skill `skill/references/workflows/token-2022-policy-workflow.md` extension policy table: the two table rows are [verbatim, MIT, (c) 2026 Berektassuly]; qedgen/solana-skills `skills/qedgen-auditor/references/known-non-findings.md` reentrancy entry (MIT, Copyright (c) 2025 QEDGen); original analysis. Behaviour checked against solana-program/token-2022 `main` and anchor v1.2.0.*

---

## Token-2022 integration checklist (fast pass)

- [ ] Extension set parsed with the official `StateWithExtensions` accessor; branching is on the full tuple, not one flag (T11)
- [ ] Vault credit = post-transfer destination delta (after `.reload()`), never the `amount` arg — fee-aware (T1)
- [ ] Transfer hooks allowlisted + treated as untrusted CPI; extra accounts validated; caller state flushed pre-transfer; hook revert/CU/third-program effects handled (re-entry is rejected by the runtime) (T2)
- [ ] Protocol-owned vaults have `ImmutableOwner`; user-funded pulls work for CPI-Guard-enabled user accounts (delegate pull) (T3)
- [ ] PermanentDelegate rejected at custody time in the allowlist; delegate rotation re-validated on deposit (T4)
- [ ] Freeze / pause / non-transferable states surfaced cleanly — no swallow, no retry loop (T5)
- [ ] Token program pinned via `Interface<TokenInterface>` + `token::token_program`; never assumed (T6)
- [ ] Decimals read from the mint; ScaledUi/InterestBearing multiplier/rate resolved at use-time, never cached (T7)
- [ ] Confidential balances opaque; post-patch ZK ElGamal Proof Program id validated; `auditor_pubkey` disclosed (T8)
- [ ] Single accounting layer (raw internally); never quote-UI-settle-raw (T9)
- [ ] Authority diversity audited per accepted mint; group membership gated on `(group_id, group_authority)` (T10)
- [ ] Mint-allowlist tier chosen (0 reject … 3 full) and on-chain enforced; governance approval + change-monitor wired (§4)
- [ ] Extension-combination fuzz + differential fee tests + hook smoke (no-op/logging/reverting/recursive) pass (§8)
- [ ] Token ACL (SRFC-37) mints: `DefaultAccountState=Frozen` + freeze authority held by the Token ACL PDA; `gating_program` non-default; `set_gating_program` / `set_authority` / `forfeit` governance-gated and monitored (§9 I1–I4)
- [ ] Gate program verifies the flag account, re-derives owner / mint from the token account, validates extra-account-meta PDAs, is side-effect-free, and implements thaw / freeze as exact inverses; protocol-owned accounts have a proven thaw path and swap / liquidation / claim paths thaw idempotently (§9 G1–G5, D1–D3, T12)

*Public incidents referenced: ZK ElGamal Proof Program soundness disclosures (2025, whitehat — Fiat-Shamir
transcripts omitting public values, enabling forged proofs on the confidential-transfer path). Token-2022
extension semantics, the coexistence rules, and the fee/hook/confidential mechanics are public program
documentation. Cross-refs: `AV-058`/`AV-060`/`AV-061` (token-program pinning, `_checked` variants, decimals
from mint), `AV-062` (credit from vault delta), `AV-063`/`AV-064`/`AV-066` (extension inspection, clawback/
freeze rejection, mint allowlist), `CPI-009` (validate pass-through CPI program id), `KV-105` (Token-2022
extension footguns), `references/vuln-classes/zk-and-compression.md` (confidential-transfer ZK soundness),
`references/methodologies/bridges.md` (B8 wrap/unwrap fee accounting), `references/methodologies/governance.md`
(mint-allowlist approval), `KV-134` (Token ACL gate bypass / permissionless-freeze griefing; SRFC-37 spec and
reference gates in solana-foundation/token-acl).*
