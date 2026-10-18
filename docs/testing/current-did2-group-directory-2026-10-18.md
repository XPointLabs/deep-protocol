# Current DID2 group directory/consent source checkpoint

Owner: Mr. X. Date: 2026-10-18. This is **not CLI group E2E** or S11 acceptance.

Normative owner: [DR-0142](../../../docs/survival-program/decisions/DR-0142-current-did2-group-directory.md)
and CONTACT-AND-GROUP §13. This note records implementation and receipts only.

## Implemented boundary

- Non-forgeable current directory capability from actual verified DID2 freshness,
  stable ADC1 V2/DMD1/DRS1/device closure and rechecked protected monotonic time.
- Owner-only genesis, owner invitations, explicit accepting-device consent and
  the accepted-invite successor reducer. Invitations/acceptances do not themselves
  activate members. Other membership reducers remain unsupported/closed.
- Exact original lookup provenance survives independent current nonce proofs.
  Stable identity changes reject; raw GCP1 support is not current authority.
- Artifact-specific owned device signing, replacing the unused generic signing
  interface/empty old author. All signer keys come from verified current devices.
- Exact predecessor/proposal/support/member-table validation and consent time
  ordering. Existing permanent fork latch is exercised with two genuinely valid
  owner successors, exact replay and restored state.
- ADC/ADP refs accept version2 only. Other group headers/domains stay unchanged;
  unknown reference types/versions reject. No compatibility reader or Session path.

## Captured checks

All paths below are under this repository's `artifacts/cli-groups-20261018`:

| Receipt | Observed scope |
| --- | --- |
| `focused-09` | 24 passed, 0 failed/skipped, native0; current consent/custody/nonce/clock/fork/time-order and structural hostile cases |
| `graph-05` | Final normal Release + Debug builds, zero warnings/errors; exact-three actual assembly/resource/API graph native0 for each |
| `vectors-03` | Deterministic producer/check: 12 canonical records + 15 hostile records, native0 |
| `registry-03` | Final strict generated/source/anchor registry check, native0 |

CLI downstream `deep-cli/artifacts/cli-groups-20261018/downstream-03` passed
37 existing tests/native0 against current Shared/Protocol source. These tests
are **not group commands or network delivery**. No Windows/Android/production
deployment or account reset occurred. Existing contact/file profiles are retained.

Earlier `focused-01..04` compile failures, vector-generator hostile fixture
failures `vectors-01..02`, and pre-repin API failures `graph-01..02` are retained.
`registry-02` rejected a later normative-document digest change; `normative-03`
mechanically regenerated source/anchors, then fresh `registry-03` passed. The
failed original receipt was not rewritten or waived.
No required full/package/device qualification was performed in this slice.

## Still required before the requested two-CLI group PASS

Compose the current reducer inside the protected DID2 account owner: registered
group state, original invitation evidence, durable batch fanout, retry/recovery
and fork custody. Add owned group DMC2 authoring and authenticated native semantic
receive/materialization before ACK, then current control quorum. CLI commands
must delegate to that owner, not reopen the old Session-based group runtime or
carry group JSON inside text. Keep generic group DMC2 RuntimeActivation=false
until its composed path is qualified.

Then run two independent processes through create → invite → accept → owner
activation → messages both ways → cold reopen/dedup/refusal, retaining original
unknown intents. No local reducer/test result substitutes that evidence.
