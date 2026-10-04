# S02/S03 independent node ID and descriptor key — 2026-10-04

Owner: Mr. X. Source candidate, not production enrollment or release evidence.
Input Protocol: `afb09996313516b4e0467fc6d4b71169336c1f19`, plus this change.
Normative contract: [XPOINT-NETWORK §7.2](../../../docs/architecture/XPOINT-NETWORK-V1.md#72-xnd1--node-descriptor)
and [DR-0081](../../../docs/survival-program/decisions/DR-0081-did2-mailbox-selection-grant-clean-break.md).
Execution order: [S00–S13](../../../docs/architecture/IMPLEMENTATION-PLAN-V1.md).

The first genuine distinct-ID/key native mailbox test stopped before any
mailbox admission: `XPointNetworkOperationalGenesisAuthor.AuthorNodeAsync`
required node ID equal to generation-zero Ed25519 public key. That equality is
not in the frozen XND1 registry or its verifier. Node ID and identity public key
are independent canonical fields, and both remain immutable in successor lineage.
The author now follows that existing contract, without changing grammar, API,
domains, machine allocations or accepted successor rules. It still requires
generation zero and validates bounded nonzero ID/key metadata before signing.
Returned signatures remain independently verified against the descriptor key.

Eight producer cases cover genuine signed independent fields; zero/short IDs,
duplicate ID, zero/short keys and nonzero key generation reject before any
operational signer callback; signing with a key derived from node ID cannot
satisfy the descriptor key. These are pending network-candidate tests, not DID2
completion or dispatch authority. The matching [native consumer checkpoint](../../../xnode/docs/testing/s03-descriptor-keys-2026-10-04.md)
uses actual DID2 completion, protected time/MGR floors, two independent native
stores and pinned TLS/HTTP2, not raw copied or forged authority.

No production identity, key, network floor, package or device state was changed.
Existing source consumers need this exact Protocol revision; published packages
and installed images are not automatically repinned or qualified. Global guarded
startup/rollback, retained-history/object retention and Program/DI remain open.

## Verification

Fresh Release production solution build: **0 warnings / 0 errors**.
Focused producer: **8 passed / 0 failed / 0 skipped**;
`artifacts/s03-descriptor-keys/focused/genesis-descriptor-keys.trx`.
SHA-256 `de3a6a4f56587a609d5c6b26b1a421da514ef7c06e80a1d59b079f1efc3cba21`.
Full production solution: **2079 passed / 1 failed / 12 skipped** (2092 total).
The unchanged failure is
`Dnp1PackageBlockingWitnessTests.PackageExactThreeSessionFree_InspectsActualPackageZipsAssembliesResourcesAndPublicApi`:
actual package/assembly inspection still finds retired `MCG2`. The 12 existing
capture/native-provider skips are not positive platform evidence. No assertions
were removed, skipped or weakened in this change.

`eng/Test-ProductionProtocolGraph.ps1 -Configuration Release` also remains
**FAIL**: the unchanged `ProductionMailboxAuthorityCodec.cs` contains retired
`MAU2`. This source/package cleanup is still an activation blocker, not fixed
by the new author or tests. `eng/Test-Dnp1EvidenceOwnership.ps1` passes the
ownership classification: exact314/package219/final95, mapped=0 and
packageMissing=219. That is not a package-complete gate.

Full TRX are in `artifacts/s03-descriptor-keys/full`. Matching source/node
matrix and additional transport gates are recorded in the native checkpoint.
SHA-256: Protocol `a0b85a12aaac34281de8a780879d7509f06c66ec06263c53c18ad6f9112ca689`,
MembershipRoutes `740a390f14b880c0b1fc4b0144f67e2450dab69475bb85c31427ca07af2b4ae3`,
ProfileCarrier `437bbb92ed5a8dce2f7eece657c1415f6bd2bb7172f93758aca0a230b2321f3f`.
