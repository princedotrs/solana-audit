# Release Gate — {program / release}

Status labels (exactly these), [verbatim, MIT, (c) 2026 Berektassuly — beriktassuly/solana-audit-skill `skill/references/workflows/release-gate-workflow.md`]:

> Use exactly these status labels:
>
> 1. `PASS`: direct evidence supports the check.
> 2. `FAIL`: the check exposes a release-blocking gap or unresolved high-risk assumption.
> 3. `SKIP`: the check is not applicable to this release, or the user explicitly scoped it out.
>
> Do not use `SKIP` for missing evidence when the release depends on that evidence. If a mainnet release needs the check and no proof is available, mark it `FAIL` and name the evidence required to clear it.
>
> ```text
> GATE: FAIL target=<program-or-release> blockers=2 warnings=1 skipped=1
> CHECK: authority status=FAIL severity=High evidence="<what was reviewed>" action="<required fix or proof>"
> CHECK: build status=PASS severity=Info evidence="<artifact or command result>" action="none"
> CHECK: compute status=SKIP severity=Info evidence="<why not applicable>" action="none"
> ```
>
> Every `FAIL` must map to a finding, remediation task, or explicit release blocker. Every `PASS` must name the artifact, command output, simulation, test, or review evidence that supports it.

## Checks
1. **Authority custody.** The upgrade authority is immutable or a documented multisig/governance key. FAIL if the deploy key is also the upgrade authority, if a claimed timelock is unproven, or if emergency powers go beyond the stated trust model. Include the IDL / Program Metadata authority (OPS-088) and every durable-nonce authority used for pre-signed privileged transactions (OPS-091).
2. **Build provenance.** Tie together the reviewed source, the local build, the deployed bytes and the release artifact: a verifiable build (`solana-verify` hash match) or a diff of the dumped program. Record the cargo features the build used (OPS-089). Building runs target code (Rule 11f).
3. **Compute and liveness headroom.** Measured CU with headroom on every value-moving, admin, migration, close, claim and emergency path. No exit path loops over an account set whose size an attacker controls.
4. **Account size, rent, realloc.** Program, buffer and migration rent is funded. Sizes stay within the runtime limits: an account can grow by at most 10,240 bytes per instruction (`MAX_PERMITTED_DATA_INCREASE`), so an account created through a CPI is capped at 10,240 bytes; 10 MiB is the maximum account size; total account-data growth is capped at 20 MiB per transaction. Grow, shrink and zeroing paths are tested.
5. **Upgrade and migration lifecycle.** checklists/07 §7.14 (OPS-098..OPS-103) and references/methodologies/upgrades-and-migrations.md.
6. **Release controls.** Record the exact commands, signers, approvals, artifacts and monitoring for deploy, pause, code rollback and remediation verification. Nothing may depend on someone remembering it.
7. **Deploy / upgrade transaction landing.** Applies to buffer writes, the deploy or upgrade transaction, migration batches and admin transactions. Distinguish forwarded from landed, and set an explicit finality target. On blockhash expiry (`lastValidBlockHeight`), stop, rebuild and re-sign instead of resending forever. Keep the simulation logs of failed transactions. Close leftover buffers from failed deploys, and record who holds their authority.

**Avoid:** treating a missing artifact as a PASS; calling authority risk "informational" when it contradicts the trust model; "the migration is safe because tests pass on fresh accounts"; treating code rollback as data rollback.
