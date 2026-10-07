# S01 retained mailbox read selection — 2026-10-07

Scope: source host/selection/MGR1 API increment under
[DR-0099](../../../docs/survival-program/decisions/DR-0099-retained-mailbox-read-selection.md).
This is not renewed issuance, native holder custody, node admission, remote
object availability, retained ACK replication, whole S01 or physical E2E.

## Actual producer and consumers

| Boundary | Actual source | Guarantee / limitation |
| --- | --- | --- |
| Verified history facts | `XPointOnionCapabilityProducer.VerifyAsync` / `CaptureRetainedPmts` | Captures only authenticated ordered PMT2 steps, including the actual verified predecessor. Existing count/byte caps apply to the aggregate; no silent eviction. Forward-only joins retain only their terminal current fact. |
| Retained selection | `VerifiedMailboxHostAuthorityV2.GetSelectedRetainedReadReplicasAsync` | Captures exact MCG3 before clock I/O; Active Retrieve only, exact verified PMT hash/epoch; current issuer/signature/generation/lifetime/full interval twice. Uses old ranking and current admitted Mailbox descriptors, without rerank. Copied facts, not dispatch authority. |
| Signed revocation | `VerifiedMailboxGrantRevocationV1.EnsureRetainedReadGrantNotRevokedAsync` | Exact current MGR1 role/issuer, protected floor read-back and current retained-grant checks around each floor callback; revoked serials reject. No replay reservation or floor deletion. |
| Unchanged current lane | `RequireGrant` / `EnsureGrantCurrentAsync` / `ResolveGrantReplicasAsync` | Exact current membership and selection epoch remain mandatory for current methods. Store cannot cross-feed retained read; expired grants are never revived. |

The fixture signs every changed PMT2/XVP1/XNV1/XNH1 and current PMA2/MGR1.
Cold cases export actual DNH2 and verify its complete signed history again.
The monotonic clock and protected MGR1 floor I/O are test-owned; this does not
prove OS secure storage, a production handover or physical delivery.

## Focused results and preserved failures

Initial compilation stopped at a fixture referencing a nonexistent method;
the fixture now calls the actual `ResolveGrantReplicasAsync`. No test receipt
was produced by that compile failure and no acceptance was claimed.

First executing focused run:191 passed /1 failed /0 skipped, terminal1.
The hostile-issuer fixture selected the Deposit public key but attempted signing
with the Retrieve private key; the signer rejected that mismatch before the
verifier ran. It now creates a genuine wrong-role signature with the matching
Deposit key; the product must still reject it.
`artifacts/s01-retained-read-focused/s01-retained-read-focused.trx` SHA256:
`115410382A98FE517DC7D8ECE8BD0E4E023A349E6A99AF664E31E89AA19EA633`.

Corrected run:192/0/0, terminal0.
`artifacts/s01-retained-read-corrected/s01-retained-read-corrected.trx` SHA256:
`818523BBC980B19100EFA2D4AAF54CCC85CBC9D344778812C54E8CE75111DC32`.

Adding actual terminal-only/removal negatives produced193 passed /1 failed,
terminal1: the terminal-only fixture expected a minted context but the existing
complete verifier rejects missing genesis even earlier. The assertion now
requires that precise `network-genesis-required` rejection; no lineage guard
was weakened.
`artifacts/s01-retained-read-final-focused/s01-retained-read-final-focused.trx` SHA256:
`CCA5551E577A71C9CC7849071FFB408F01C56E974901E004B9E8AA2958E11395`.

Final focused:194/0/0, observed terminal0. This covers both host/MGR1 APIs plus
the existing host/network/MGR1 classes, including signed unchanged/advanced
epochs, old projection expiry, actual cold history, wrong roles/issuer/signature,
missing exact history, terminal-only rejection, actually removed Mailbox node,
clock rollback/expiry/boot/cancellation, captured buffers, current protected-floor
changes/absence and revoked serials.
`artifacts/s01-retained-read-qualified-focused/s01-retained-read-qualified-focused.trx` SHA256:
`BE021C16CDF158678284A15245DDFB1488C601114935D45B6282B7100E44B9EC`.

Command:

```powershell
dotnet test tests/Deep.Protocol.Tests/Deep.Protocol.Tests.csproj --filter 'FullyQualifiedName~MailboxHostAuthorityV2VerifierTests|FullyQualifiedName~XPointOnionCapabilityProducerTests|FullyQualifiedName~MailboxGrantRevocationV1Tests' --logger 'trx;LogFileName=s01-retained-read-qualified-focused.trx' --results-directory artifacts/s01-retained-read-qualified-focused -m:1
```

Strict registry gate:terminal0. Reviewed source repin changes exactly
`protocol-registry-v1`, `xpoint-network-v1`, `production-wire-source` hashes;
175 normative anchors unchanged. Generator updates derived registry hashes,
not wire/domain/suite allocations or approved frozen Git blobs.

## Mandatory current-source qualification

Candidate source: `550de0109677d18739c743af13047582e0006f3e`; workspace
`406f96534c38dfaad991ee8584f0662905de1035`. Restore and Debug solution build
complete terminal0,0 warnings/errors. Current full solution completes with
**2057 passed /1 failed /7 skipped, observed terminal1**; this is not a green
shipping/package gate. No source edit or build overlapped that test run.

| Actual assembly receipt, under `artifacts/s01-retained-read-full/` | Pass/fail/skip | SHA256 |
| --- | --- | --- |
| `nikit_SURFACE-LT_2026-10-07_09_03_27_net10.0.trx` | 14/0/0 | `C51B3C335D0BCD5BCF08B7926936F77F44986EF7250D51CEF592E70A95DF1066` |
| `nikit_SURFACE-LT_2026-10-07_09_03_29_net10.0.trx` | 105/0/0 | `588237E8BC1433E0B723869A6D2A2CDBEB48E30A31169C0247CF4562DC068D79` |
| `nikit_SURFACE-LT_2026-10-07_09_03_34_net10.0.trx` | 1938/1/7 | `797F279E4004879E503765A74FFE5EE3D836F344188E1A3FE89E48D583CC0E16` |

Main interval:2026-10-07T09:03:33.1912901+05:00 through
09:05:14.9537183+05:00. The one failure is the unchanged
`Dnp1PackageBlockingWitnessTests.PackageExactThreeSessionFree_InspectsActualPackageZipsAssembliesResourcesAndPublicApi`:
actual packed Deep.Protocol assembly bytes contain retired `MAU2`. The separate
`Test-ProductionProtocolGraph.ps1 -Configuration Debug` also returns terminal1
at `ProductionMailboxAuthorityCodec.cs`/MAU2. Neither allowlist/assertion changed.
The seven skipped native/capture cases are exactly the preceding baseline set,
not new skips. This source increment is qualified locally under DR-0095's
source/shipping separation; actual package/API/resource acceptance remains blocked.

All194 required focused names independently map to exactly one Passed result
and exact definition/execution in the full main receipt. All701 candidate input
hashes match before/after, with the same source/workspace commits.
All2065 actual execution/result pairs map to exact TestEntries and their method
definitions. The existing non-serializable MemberData adapter shape has22 rows
with shared method definitions/primary executions; it is identical to the
preceding receipts, not194 current-case metadata and not2065 unique test IDs.
Case-sensitive comparison preserves every2024 distinct preceding display name
in the current2063-name set, including differently cased negative parameters.

Qualification comparator correction is explicit: the original
`expected-qualification.json` selected an obsolete Oct5 pre-retirement full.
It expected seven already removed legacy tests and is preserved, not silently
rewritten. The preceding current full receipts under
`artifacts/s01-epoch-exclusion-protocol/` were selected **after terminal**:
main `42C8963B2F863CE74C3FB3057655B99812904566DC66CEC2926E44A85C4F8FC3`,
routes `7E84F250A1C7B2D233F5BA495CD4158D924AE04B000ED016D5A91D71E66281BA`,
carrier `B8ABBF883C7BEF3B94910C5C5C2B1658FF3C61196FCB54220A5CB47E7A243923`.
`corrected-qualification.json` SHA256
`F399B09A30C110073B3F62BBBAED2B18F42C2B69E36A6F2D841D198061D0DE00`
retains the original candidate inputs/current194 requirements and records this
post-terminal comparator correction. Do not call the corrected prior-name set
a pre-run frozen expectation. No retired source/tests were restored.
`verify-full.ps1` validates actual TRX TestEntry pairs (not a false universal
one-definition-per-data-row assumption), case-sensitive names and the precise
unchanged failure/skip classification. Its terminal0 qualifies that mapping,
not the native full/package exit code.

Evidence ownership terminal0: exact314/package219/final95, mapped219,
packageMissing0. Static mapping is not219 executed native/package approvals.
Root documentation174 and exact selected-source scanner16 files/0 findings pass.

Commands:

```powershell
dotnet restore Deep.Protocol.slnx
dotnet build Deep.Protocol.slnx --no-restore -m:1 -warnaserror
dotnet test Deep.Protocol.slnx --no-build -m:1 --logger trx --results-directory artifacts/s01-retained-read-full
./eng/Test-ProductionProtocolGraph.ps1 -Configuration Debug
$mappingPaths = @(git ls-files artifacts/dnp1-vector-fragments)
./eng/Test-Dnp1EvidenceOwnership.ps1 -MappingPaths $mappingPaths -RequirePackageComplete
./artifacts/s01-retained-read-full/verify-full.ps1
```

Renewed retained issuance, actual account-owned holder/counter scopes, node
typed Retrieve/ACK admission and peer tombstones remain unimplemented consumers.
The codec still has its shorter object lifetime. No TTL constant, deployment,
account reset, operator key, scheduler or GitHub Release changes in this slice.
