# S00 contact codec / governance checkpoint — 2026-10-03

Owner: Mr. X. Evidence only, not a second protocol specification or roadmap.
Execution order and residual release scope belong to the superproject's
[implementation plan](../../../docs/architecture/IMPLEMENTATION-PLAN-V1.md) and
[current status](../../../docs/NEXT-SPRINT.md).

## Input and scope

Input root: `4e1b2eccb7d903c3f2096e87e80397bdd6c4d87b`.
Input Protocol: `17a7c8be2b222eb0855d381b5040864dc14b4c9e`, plus the source
changes committed with this checkpoint. No production deployment, device,
account reset, secret, public API, wire format or crypto domain was changed.

The current contact vectors were already approved at root
`2c777eac7a97330c446e5d1ad5e33a95d67fad58`. Their canonical SHA-256 remains
`9a567ec9066b956f7dfbabcc3502861766df0c3cbd57f85d9ea08664b10e844e`.
No vector, schema, anchor or normative digest was regenerated in this slice.
DR-0069 authorizes removal of identity-bound V1 positives; DR-0063/0081 own
the current private reply-route and selector-bound grant contracts.

## Changes and failure mapping

The seven retained contact negative IDs now execute in
`CurrentContactSecurityTests`, rather than pointing to a deleted V1 test file:

| ID | Executed boundary |
| --- | --- |
| `xir-xra-binding` | Current private route rejects an individually canonical changed invite XRA reference |
| `xrc-xra-sealing-binding` | Complete in-band graph rejects mismatched sealing binding |
| `xrc-pmt-xnv-binding` | Complete in-band graph rejects mismatched network-view reference |
| `xrr-device-binding` | Complete in-band graph rejects mismatched device reference |
| `route-validity-intersection` | Complete in-band graph rejects an enlarged reachability interval |
| `xrr-minimum-reader-zero` | Scalar parser rejects reader zero |
| `pms-tie-break` | Actual shared issuer/verifier comparator orders equal scores by node ID |

The comparator was extracted unchanged into one internal function; score
priority and lexicographic node tie-break are unchanged. Equal-score evidence
is a component test, not a fabricated hash collision or signed authority.
Unknown positive primitive mappings now throw instead of silently returning
a default. Existing exact-byte, malformed and signature checks remain.

Five full-suite failures in `ContactServiceWireCodecTests` were stale XPU
fixtures: V1 header/hash/authorization ID, ciphertext below the current minimum,
and effective expiry before the publication expiry. The raw V1 XPU positive
golden was removed, not repinned. Its binding scenarios now use a current V2
fixture, explicit version/suite, exact canonical bytes, ciphertext/body/route
hashes and the current authorization-ID domain. Synthetic witness rows are
parsed-wire inputs only; they do not grant publication authority.

| Initial failing case | Retained current assertion |
| --- | --- |
| `XpuClosesAuthorizationProjectionAndCiphertextHash` | V2 body/authorization/ciphertext/route correspondence and tamper rejection |
| `ResultCodecsEnforceClosedMatricesAndExactPadding` | Bound committed result, status matrix, unknown status, padding and mutation outcome |
| `XpuAndXisAcceptOnlyTheirExactExpandedBounds` | Maximum XPU/XPA sizes, one-byte overflow refusal and unchanged XIS/padding boundaries |
| `RequestGrammarRejectsUnknownTagsLengthsScalarsAndCaps` | Independent valid-authorization ciphertext cap and valid-ciphertext short-authorization refusal; other grammar assertions retained |
| `ClosedFailureStatusMatricesAcceptTheirOnlyPayloadShapes` | All existing closed failure/retry/payload matrix checks against current XPU |

Two new cases reject the retired XPU version and suite. The API snapshot
failure was separately reconciled with accepted DR-0025/0026, not merely the
observed reflection list: the two existing responder store types are allowed
by name, and reflection asserts sealed/disposable/no-public-constructor,
exact getter-only property sets and a zero-input transfer to the closed payload.
No API was added or widened by this change. Downstream package repin/physical
acceptance is still open; no consumer reset or package publication was performed.

## Fresh commands and results

From Protocol:

```powershell
dotnet restore Deep.Protocol.slnx --verbosity quiet
dotnet build Deep.Protocol.slnx -c Release --no-restore --verbosity quiet
dotnet test Deep.Protocol.slnx -c Release --no-build --logger trx --results-directory artifacts/s00/contact-final-checkpoint --verbosity quiet
pwsh -NoProfile -File eng/Test-DeepProtocolRegistry.ps1
pwsh -NoProfile -File eng/Test-ProductionProtocolGraph.ps1 -Configuration Release
pwsh -NoProfile -File eng/Test-Dnp1ExecutableVectors.ps1 -Configuration Release -NoBuild -IntegrityOnly
$contactOwnershipFragments = @(git ls-files artifacts/dnp1-vector-fragments)
& ./eng/Test-Dnp1EvidenceOwnership.ps1 -MappingPaths $contactOwnershipFragments -RequirePackageComplete
```

Restore/build exit 0, build **0 warnings / 0 errors**. Registry source/resolved
manifest consistency passes. The ten checked-in ownership fragments pass the
exact314/package219/final95 ownership check: mapped219, packageMissing0. This
is a static mapping check, not execution of 219 cases. Manifest integrity-only
passes and explicitly performs no executable case discovery/evidence.

| Full suite | Pass | Fail | Skip | Total | TRX SHA-256 |
| --- | ---: | ---: | ---: | ---: | --- |
| Protocol | 1771 | 1 | 12 | 1784 | `20369c9b5517d888dd698b2ab9ab582fdd7b1ab7855683badb6b675c8f82d828` |
| MembershipRoutes | 131 | 0 | 0 | 131 | `5c2c42f2cc548dc5eb0d08842993f5ec75cfda56fcb754d15b44333531ffbf63` |
| ProfileCarrier | 105 | 0 | 0 | 105 | `ba3b8efca073faec730b7683e8700756103c83c409cbe2f7d1710564de100f91` |
| **Total** | **2007** | **1** | **12** | **2020** | **exit 1, not qualified** |

Earlier fresh full baseline in this same slice: 1999 pass / 7 fail / 12 skips
on 2018 cases. Six failures are closed; the remaining package failure below
is reproduced by the final full run, not assumed resolved.

Focused final selection: `ContactServiceWireCodecTests`,
`CurrentContactSecurityTests`, `ContactCodecTests`, `MessagingCryptoSurfaceTests`:
**40 pass / 0 fail / 0 skip**, built from edited source. Command uses the same
test project, `-c Release --filter` with those four class names joined by `|`,
`--logger trx --results-directory artifacts/s00/contact-surface-checkpoint`.
TRX SHA-256: `9ebdc2c18e9a4ec38d0fb8fc7549c91035e1c67d6d8db160206723b5ffa34941`.

## Open package and skip classification

`PackageExactThreeSessionFree_InspectsActualPackageZipsAssembliesResourcesAndPublicApi`
builds actual package ZIPs with zero build warnings/errors, normalizes exact-three
closure, then fails the compiled assembly gate: retired **MCG2** token in
`Deep.Protocol`. Source occurrences include PMR1 revocation codec/model
diagnostics; this old authority implementation is not current signed revocation
evidence. Renaming strings is not a current consumer implementation.

The separate production graph exits 1 on **MAU2** in
`ProductionMailboxAuthorityCodec`: its actual transport check requires
`AuthenticatedMau2`. This is a retained old consumer, not just an obsolete
test expectation. Replace that authority through accepted S01/S02; do not
weaken either source or assembly gate, restore fallback, or claim package GO.

The twelve skips were not removed or introduced in this slice:

- Five `ManagedMlKemBraidStateMachineTests`: reviewed Windows incremental
  candidate absent (role reversal, out-of-order, tamper, restart and state import).
- Three `DeepMlKemNativeProviderTests`: delegated to explicit Windows wrapper
  evidence harness; that harness was not run here.
- Three `DeepMlKemBraidNativeProviderTests`: delegated to explicit incremental
  wrapper evidence harness; that harness was not run here.
- One `ProtectedPredecessorCaptureTests`: authenticated operator capture inputs
  absent; not device/release evidence.

These are classified omissions, **not successful native/physical qualification**.
S00's unexplained-failure/skip closure and later package/release acceptance remain
open. An initial ownership invocation without fragments correctly rejected
219 missing rows; the later invocation above used the existing tracked fragments.

## Root gate scope and residuals

From root, both `scripts/check-deep-crypto-spec.ps1` and
`scripts/check-contact-codec-spec.ps1` pass after replacing obsolete counts/path
with the exact approved retained target/hostile/negative-ID sets and current
private-route/XMC2 bounds. Every independent hash/schema/signature-input and
zero-callback declaration check remains. Source ID presence is only mapping
consistency; the Protocol execution above supplies the seven codec negatives.

`node --test scripts/tests/contact-governance-contracts.test.mjs`: **10/10**.
It copies nine explicit public inputs into isolated temporary fixtures and
mutates targets, bytes, signature inputs, hostile/policy coverage, callbacks
and mapping source. Its synthetic reminted fixture anchors never modify the
reviewed inputs. Initial guard-test reason-regex mismatches were harness failures;
the gate rejected each mutation throughout. They were corrected to the actual
PowerShell schema diagnostics, without changing the rejection contract.

Fresh root ONION gate still fails `ContactResolve exact pairing or bounds`.
Fresh `check-survival-program.ps1 -RequiredEvidenceClaim ClassificationOnly`
still fails machine-set digest: expected `92b23996...`, actual `504d184e...`.
Prior read-only Git-blob comparison also differs (`eac72024...`), so this is
not solved by CRLF normalization alone. No blind hash/count repin was performed.
Node's remaining signed one-time invite prerequisite and Windows atomic-replace
nondeterminism remain as recorded in the [node baseline](../../../xnode/docs/testing/s00-node-baseline-2026-10-03.md).
This checkpoint closes neither S00/S01 nor shipping contacts, messages,
attachments, groups, production readiness or physical Windows/Android E2E.
