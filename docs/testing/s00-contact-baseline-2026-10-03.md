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

### Explicit Windows native execution, 2026-10-05

Runtime/test source is unchanged; documentation HEAD is `981ab767`, runtime
HEAD `d1ccb573`. On this Windows ARM64 host the default Braid test discovery
looks for a locally built `native/.../aarch64-pc-windows-msvc` candidate, not the
already reviewed `src/Deep.Protocol/runtimes/win-arm64/native` asset. The latter's
exact size and SHA match `DeepMlKemBraidApprovedAssets`; no C++/Rust build or
approval-manifest change is made. Explicit test input uses that reviewed asset.

Against the existing Release test assembly, the six state-machine cases execute
and pass with0 skips, including all five previously omitted cases. The existing
standard ML-KEM and incremental Braid wrapper probes each directly execute their
three delegated Windows methods and finish exit0. Digest/tamper, production
approval, disposal/concurrency, interop, role reversal and restart assertions are
unchanged. Repeat execution in an x64 process also passes6 state-machine and3+3
wrapper cases. x64 runs under emulation on this same ARM64 machine, not separate
x64 hardware; neither run is Android, UI/message E2E or release qualification.

Both managed probe projects build with0 warnings/errors. Test assembly SHA-256:
`dc543d9522bea91885006199dd06939162a58dcabab7c0fec638e8785df79e86`;
its Protocol dependency is the test-seam assembly, SHA-256
`0e50d42f782b835e74ae499871a818fc12c332f261cdc3543cbbd58186d5d9b6`.
This is prebuilt-assembly execution; a current-source rebuild/recheck remains
necessary before treating it as a newly qualified source matrix.

| Receipt under `artifacts/s00-native-wrapper/` | SHA-256 |
| --- | --- |
| `state-machine/nikit_SURFACE-LT_2026-10-05_08_28_21_net10.0.trx` | `63490f1dceab4c75fcacd1d85bafd54ae7372dc3fdc63fb3c809a28d2947801c` |
| `state-machine-x64/nikit_SURFACE-LT_2026-10-05_08_32_00_net10.0.trx` | `d3c7c6510acfdf5bb92458620cfca41e6d0d8c19302345a6e4c56628f62c9584` |

State-machine execution sets `DEEP_MLKEM_BRAID_TEST_ASSET` only for its command
and restores the prior environment value. ARM64 uses Release/no-build focused
`dotnet test`; x64 uses the existing ARM64 SDK's `dotnet vstest /Platform:x64`
over the same test assembly. The initial x64-host `dotnet test` command cannot
start because that host has runtimes but no SDK; it executes no product test.
No SDK is installed and no SDK pin is changed. The separate existing probes
are `eng/Deep.MlKem.RuntimeWrapperProbe` and
`eng/Deep.MlKemBraid.RuntimeWrapperProbe`, invoked with the test assembly and
the corresponding exact reviewed standard/Braid asset paths. After the probes'
deliberate corruption tests, all four staged Windows asset digests again match
their reviewed source assets. Source binaries are untouched.

The previous full2087/1/12 remains that previous full, not a new zero-skip run.
These executions provide evidence for eleven formerly omitted Windows cases;
the six delegated Fact skips are still intentional in ordinary test discovery.
The authenticated operator capture is absent. MAU2 source / MCG2 package failures
remain open; no package/API/resource gate or physical scenario is claimed passed.

After the Node full and sequential Registry check finish, rebuild the current
Protocol test project into isolated Release output with0 warnings/errors:
`dotnet build tests/Deep.Protocol.Tests/Deep.Protocol.Tests.csproj -c Release --no-restore -m:1 -warnaserror -o artifacts/s00-native-wrapper/current-test-assembly`.
The freshly compiled test DLL SHA-256 is
`fab3759ae7bc04467c000b03c9db3270713fc6a5fb3d3066bc050cb9ecd44835`;
its test-seam Protocol DLL is
`338533f81d289c38a3b2bc5a0a3fa62d40a16b26ba75122baf4f83504766901e`.
Run `dotnet vstest` against that exact fresh test DLL, the same focused filter
and process-scoped reviewed Braid input; use `/Platform:x64` for the x64 host.
Both current-source runs complete6/0/0; the existing standard/Braid probes
against that same DLL each complete3/0 on both architectures. All assertions
remain unchanged. All four staged ML-KEM/Braid digests still match their reviewed
source assets after deliberate corruption checks. No native source is rebuilt.

| Current-source receipt under `artifacts/s00-native-wrapper/` | SHA-256 |
| --- | --- |
| `current-state-machine-arm64/nikit_SURFACE-LT_2026-10-05_08_54_50_net10.0.trx` | `d34a9396e732a483634b70f8ddc9afc29ccd89f9309f986aa0cdb9f7ec8eb7ff` |
| `current-state-machine-x64/nikit_SURFACE-LT_2026-10-05_08_55_13_net10.0.trx` | `c499f5ea86cb85a4f4c109140a48a48104b86cedc6f62aed85871756f4e96c70` |

This qualifies the focused Windows cases against current source, not a new
whole-suite, independent x64-hardware, Android or shipping-client result.

### Default Windows native discovery correction, 2026-10-05

Input Protocol `739cc5325117e8afc249912086d85d9c9f53cdce`. Only the
`ManagedMlKemBraidStateMachineTests` harness changes. It locates the tracked
reviewed asset for the current Windows RID and uses the production-approved
loader, instead of searching for a local Rust build and using the candidate
loader. No runtime, registry, crypto byte/domain, public API or native binary
is changed. All state-machine, role reversal, tamper, restart and import
assertions are unchanged. On supported Windows, a missing asset fails execution,
never discovery-skips. An explicitly selected absent input fails without
falling back to a repository asset. Unsupported OS/architecture still skips.

With `DEEP_MLKEM_BRAID_TEST_ASSET` cleared only in each command and restored
afterwards, current-source Release focused6/0/0 passes on ARM64. An x64 process
over that same fresh test DLL also completes6/0/0 without an explicit input;
this remains emulation on the same ARM64 host, not separate device evidence.
The missing-explicit-input negative run deliberately exits1 with one failed
case, zero skips and the exact missing-input exception before staging; its
outer harness verifies that result and completes exit0. It is a rejection
test, not an unexplained product failure or a passing positive TRX.

```powershell
dotnet test Deep.Protocol.slnx -c Release -m:1 -warnaserror --logger trx --results-directory artifacts/s00-native-discovery/full
```

The new unfiltered whole-solution run finishes exit1, not GO. Actual result
outcomes are2121 passed,1 failed,7 skipped (total2129):
main Protocol1885/1/7, MembershipRoutes131/0/0, ProfileCarrier105/0/0.
All five state-machine native cases execute and pass in this full run.
The sole failure is still the actual-package witness rejecting compiled MCG2;
no assertion, package policy or public-API snapshot is relaxed. The seven
NotExecuted results are the six explicitly delegated wrapper tests and absent
authenticated operator capture. Use actual result outcomes: this TRX adapter
reports `Counters.notExecuted=0` despite seven NotExecuted test results.
Builds finish with0 warnings/errors. Current test DLL SHA-256:
`97a2eff95276fbad770d52a1847cd0d62d950d876ec54e7366be9d2147cc817a`.

| Receipt under `artifacts/s00-native-discovery/` | SHA-256 |
| --- | --- |
| `focused/nikit_SURFACE-LT_2026-10-05_09_06_45_net10.0.trx` | `238b2f0f5fad0603273866c6686922dea061762c35498cecf604451a9e6ab559` |
| `x64/nikit_SURFACE-LT_2026-10-05_09_10_30_net10.0.trx` | `37c38fdeaee739348d2ec52954bdbf6b72412fb63dea73fb41521e8229d50568` |
| `explicit-missing/explicit-missing-negative.trx` | `1201036b7844ca2e05b271784b03eedc66903074e28633021f99ad59bb1fbfbe` |
| `full/nikit_SURFACE-LT_2026-10-05_09_07_36_net10.0.trx` | `cebead1eb05af31dc0ed11787b471714d1e18977bd4a5970d04a4913e8383991` |
| `full/nikit_SURFACE-LT_2026-10-05_09_07_41_net10.0.trx` | `4986c3f30e0558f372228b16ca0f771bd1302fec9a967659a83a98f8694d9c9d` |
| `full/nikit_SURFACE-LT_2026-10-05_09_07_45_net10.0.trx` | `e04cadb7d6102bd238ff5fe67d42a6647891ff933a3ba59d6caeff0b8e32a6b4` |

Registry source/resolved consistency and exact314/package219/final95 evidence
ownership pass. The source production graph still rejects MAU2 in the retained
PMA1 codec. This closes the default Windows five-case omission only; S00,
package graph, recovery/capture and physical client qualification remain open.

### Focused recheck, 2026-10-05

Source HEAD `d1ccb573d552960f0c1cb21a655483f4065e74d5`, unchanged runtime.
`./eng/Test-ProductionProtocolGraph.ps1 -Configuration Release` exits1 on
retired MAU2 in `ProductionMailboxAuthorityCodec`. Its actual transport check
still requires `ProductionMailboxAuthorityTransport.AuthenticatedMau2`; this
is not merely a source-name assertion mismatch.

The existing actual-package witness was run alone with Release/no-build:
`dotnet test tests/Deep.Protocol.Tests/Deep.Protocol.Tests.csproj --configuration
Release --no-build --filter FullyQualifiedName~PackageExactThreeSessionFree_InspectsActualPackageZipsAssembliesResourcesAndPublicApi
--logger 'trx;LogFileName=s00-package-status.trx' --results-directory
artifacts/s00/status-sequential-20261005 -m:1`.
The witness itself rebuilds/packages the captured current source, including
locked restores and normalization; no-build applies only to its test runner.
Result **0 pass /1 fail /0 skip**, terminal exit1,1m21s: actual `Deep.Protocol`
package inspection rejects MCG2 in assembly bytes. TRX
`artifacts/s00/status-sequential-20261005/s00-package-status.trx`, SHA-256
`9eff54a8b3fe15800a85ab905ac20fe5ca09b7cdac8ac34b04e8395afca7a74c`.
The witness-owned temporary package/source directory was removed by its guarded
finally cleanup; the TRX remains local. No runtime, frozen input, assertion,
package policy or consumer was changed. This reproduces an open S00 blocker,
not a repaired defect or full-suite result. Removing the old authority requires
following its compiled producer/consumer dependencies; string renaming does
not qualify the current graph.

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

### Authorized route-control leaf retirement, 2026-10-05

Input Protocol `83a0f32656d1cc5315b548c3488111cc6fa05886`, root
`c7284f6d373bc5cec11f552b4bb7f76bfa676b83` and Node
`65fdf1fa7163b3ae0013af0710c797590675c990`. This source batch follows
[DR-0093](../../../docs/survival-program/decisions/DR-0093-retired-mailbox-route-control-source-api.md),
not a new wire generation or an authorization to weaken native recovery.

Removed27 old MembershipRoutes route-control source files,14 wholly owned
positive test files and the parent Protocol route-verification facade. All120
removed route-control results were Passed in the preceding unfiltered receipt
`artifacts/s00-native-discovery/full/nikit_SURFACE-LT_2026-10-05_09_07_36_net10.0.trx`
(SHA-256 `cebead1eb05af31dc0ed11787b471714d1e18977bd4a5970d04a4913e8383991`).
They are not unexplained failures being discarded. The retained six replica-proof
and five descriptor tests remain. The exact300-second bound moves privately out
of the deleted topology constants; no proof bytes/signature checks change.

Three new actual-assembly tests require absence of the retired namespace/facade
and retain exactly9 membership public types with90 reviewed semantic API lines.
The latter fingerprint, captured independently before removal and sorted Ordinal,
is `998b290e3e8a41b2fb9017c3b77bd6fd33ad173bd5d8284f780c672d61fd7904`.
The routes assembly no longer exports the139 retired route-control public types.
The new parent registry test checks absence of both public encoding APIs for
all21 removed local allocations and preserves current MCG3 inactive allocation.

Source inventory was independently reproduced from the exact old Git source:
`7dcb83a0fc0135c9e16c4ca350a8c68ae9d563b429d543032230d8172fd607d4`.
Current inventory is
`2815cb250b59344c85cd9b826b1324e5fbfd4d2f3a3cccdd9076b84d8f8a9d3a`.
Only references from the27 authorized deleted files differ; no new symbol or
unrelated path delta exists. All244 resolved allocation rows remain. Of23
changed rows,21 become RETIRED_REJECT/allocation-only and PMA1/PMR1 lose only
the deleted leaf implementation paths. Frozen versions, grammars, domains,
suites and byte bounds do not change. Generated allowed/retired policy sets
change exactly229 to208 and28 to49; the two non-protocol literals are unchanged.

The human registry's three reviewed rows and10 lifecycle/anchor bindings are
updated together. Existing repin/generation scripts mechanically refresh that
source hash and those10 anchors; no approved DNP1 blob or strict API/package
snapshot is repinned. The registry gate's empty planned-retirement collection
now enumerates safely. Its schema-negative test creates an invalid proposed
retirement on a retained current row instead of requiring an old positive row.
The mixed lifecycle test retains its invariant using current DGI1, not PMT1.
Initial harness failures (missing Xunit import, empty collection and obsolete
PMT1 fixture) were corrected without weakening a rejection predicate.

Commands and completed results on this batch:

```powershell
./eng/Test-DeepProtocolRegistry.ps1
dotnet build Deep.Protocol.slnx -c Release --no-restore -m:1 -warnaserror
dotnet test tests/Deep.Protocol.Tests/Deep.Protocol.Tests.csproj -c Release -m:1 -warnaserror --filter FullyQualifiedName~DeepProtocolRegistryTests --logger trx --results-directory artifacts/s00-route-control-removal/final-registry
dotnet test tests/Deep.Protocol.MembershipRoutes.Tests/Deep.Protocol.MembershipRoutes.Tests.csproj -c Release --no-build --logger trx --results-directory artifacts/s00-route-control-removal/final-focused
dotnet test Deep.Protocol.slnx -c Release --no-build --logger trx --results-directory artifacts/s00-route-control-removal/full
./eng/Test-ProductionProtocolGraph.ps1 -Configuration Release
```

Registry consistency exits0; whole solution build exits0 with0 warnings/errors.
Registry focused10/0/0 and routes focused14/0/0 complete terminal0.
Unfiltered full completes terminal1: **2005 passed /1 failed /7 skipped**
(main1886/1/7, routes14/0/0, carrier105/0/0). Actual result elements, not the
TRX notExecuted counter, identify the seven skips. The one actual-package failure
now names MAU2 in compiled Deep.Protocol; MCG2 was the preceding witness's first
observed token, not a defect repaired by this leaf. Both remain unresolved.
Source graph also exits1 on MAU2 in ProductionMailboxAuthorityCodec. Neither
strict gate is weakened; current native PMA1/PMR1 governance/recovery dependency
and package/API closure still prevent S00 acceptance.

Receipts below are local under `artifacts/s00-route-control-removal/`:

| Receipt | SHA-256 |
| --- | --- |
| `final-registry/nikit_SURFACE-LT_2026-10-05_09_43_00_net10.0.trx` | `beba6e30c90797e12196c2055a07a4a2158046ee31ba3b819557d3d044a00c32` |
| `final-focused/nikit_SURFACE-LT_2026-10-05_09_43_01_net10.0.trx` | `8c64cef82339d58372f318c6c7d044564b66a46ed9739501fe80ddbf92a3685b` |
| `full/nikit_SURFACE-LT_2026-10-05_09_43_14_net10.0.trx` | `e0ca30b83f08003600788a84304acff72e9f554663c11635250f484fcb3570be` |
| `full/nikit_SURFACE-LT_2026-10-05_09_43_15_net10.0.trx` | `51011eec653397067a77067f41acde8488304cd9ffee3648c32194066e8cc448` |
| `full/nikit_SURFACE-LT_2026-10-05_09_43_15_net10.0[1].trx` | `8777119c69e7cf02b2bdd988b9b0d0bd372a8e98cbca48be8b1e51dd9bf0243b` |

Shared production solution build completes0/0 warnings/errors; Node and Registry
source-cutover solution builds also complete0/0. Node's retired adapter depended
on the removed PMT1 helper and is removed, not adapted into current MCG3 authority;
its neutral capacity tests and mixed peer/ingress assertions survive. Node
focused94/0/0 completes; sequential unfiltered full completes terminal0,
1216/0/0 after the initial full's three setup/budget failures and isolated9/0/0
on unchanged binaries and budgets; see
[Node checkpoint](../../../xnode/docs/testing/s02-retired-forwarding-2026-10-04.md#s00-route-control-consumer-removal-2026-10-05).
MAUI consumer checks follow below; shipping composition, real HTTPS/ONION client
data and physical Windows/Android scenarios are not qualified. No production,
account, registered key, secret, authority lineage or protected floor is changed.

#### Remaining native dependency: source findings, 2026-10-05

Read-only inspection of Protocol `2ae11346af2d1c691627e395702ac78fc1210ef8`
and Shared `b238fb4f9bc750185e4fc431b1bf4ae6f33c2b1f` narrows the next S00
change. This is not a frozen replacement mapping or runtime qualification.

| Existing dependency | Current owner observed in source | Boundary still requiring review |
| --- | --- | --- |
| `NativeRoutingVerifier` verifies DNR1 fields4/6 against exact PMA1/PMR1, issuer signature and authority window | `VerifiedOnionNetworkContext` resolves node identity keys; `VerifiedMailboxHostAuthorityV2.ResolveReplicaAsync` consumes that verified network and exact PMT2 membership | PMA2 is a grant-issuer policy, explicitly not node/certificate issuance authority. Substituting PMA2 into the old DNR1 verifier is not a valid owner mapping |
| `VerifiedGenesisBaseIdentityContext` binds identity/device/mailbox/router facts, exact Distributed GMD1 and four DCM1 component rows | DID2 local genesis uses independent DNP1 account/device issuance, `ApplicationCoreVerifier.CreateIdentityClosure`, DAB2/DMD1/DCA1V2/ADC1V2 and protected bootstrap | Local DID2 account creation does not implement the four-component deployment/reset barrier. Removing Router or inserting an empty fact would discard that guarantee |
| `RecoveryVerifier` restores exact DPM1 → PMA1/PMR1 → DNR1 predecessor chains; recovery manifest requires these exact typed rows | Current network authority, grant-revocation floors and client/node protected custody have separate current owners | No reviewed join to the generic ReleaseRoot/reset/recovery closure is established by these source findings. Preserve its integrity, predecessor, nonterminal and protected-floor requirements |

Evidence owners: `DeepNative/Dnp1NativeRoutingVerifier.cs`,
`Dnp1GenesisAuthoringContexts.cs`, `Dnp1RecoveryProvider.cs` and
`Dnp1RecoveryManifest.cs`; current network owners:
`DeepExtension/PrivacyRouting/PrivacyRoutingProductionBoundary.cs`,
`XPointNetworkV1/MailboxAuthorityV2Verifier.cs` and
`MailboxHostAuthorityV2Verifier.cs`; Shared account producer:
`Persistence/DeviceV2/DeepIdV2OfflineGenesisIssuer.cs`.
The frozen DNP1 specification §6 still requires independent membership and
mailbox-authority closures and their atomic protected join; DR-0093 excludes
changing that native contract without separately reviewed authorization.

A bounded search of current Shared DeviceV2/ContactV2/account-service sources
and MAUI Core.Did2 finds no direct calls to `NativeRoutingVerifier`,
`VerifiedGenesisBaseIdentityContext`, `GenesisManifestAuthor` or
`RecoveryVerifier`. The two downstream old-authority codec callers found in
Shared `ProductionMailboxControlPlane` and MAUI
`ProductionMailboxCredentialAcquirer` are outside the current production
compile lists. This is source reachability evidence only, not permission to
drop recovery from release scope or claim deployed composition is qualified.
No parser, factory, wire record, public API, timeout or gate is changed here.

#### Downstream MAUI consumer qualification, 2026-10-05

MAUI `56065e0bf311f6b61aa22bf693792d6256951c03` consumes the same Protocol
source removal and Shared production project. After the sequential Node full
is terminal, the Core.Did2 Release and unpackaged Windows ARM64 Debug app
builds complete exit0 with0 warnings/errors. No app is installed or launched.
The Android Debug app build also completes exit0 with0 warnings/errors,
5m03s; it is not installed, launched or device-qualified.

```powershell
dotnet build src/Deep.Client.Maui.Core.Did2/Deep.Client.Maui.Core.Did2.csproj -c Release -m:1 -warnaserror -p:DeepProtocolSourceCutover=true
dotnet build src/Deep.Client.Maui/Deep.Client.Maui.csproj -c Debug -f net10.0-windows10.0.19041.0 -m:1 -warnaserror -p:DeepProtocolSourceCutover=true -p:RuntimeIdentifierOverride=win-arm64 -p:WindowsPackageType=None -p:UseSharedCompilation=false -nodeReuse:false
dotnet test tests/Deep.Client.Maui.Clean.Tests/Deep.Client.Maui.Clean.Tests.csproj -c Release -m:1 -warnaserror -p:DeepProtocolSourceCutover=true --logger trx --results-directory artifacts/s00-route-control-removal/clean
dotnet test tests/Deep.Client.Maui.SmokeTests/Deep.Client.Maui.SmokeTests.csproj -c Release -m:1 -warnaserror -p:DeepProtocolSourceCutover=true --logger trx --results-directory artifacts/s00-route-control-removal/smoke
dotnet build src/Deep.Client.Maui/Deep.Client.Maui.csproj -c Debug -f net10.0-android -m:1 -warnaserror -p:DeepProtocolSourceCutover=true -p:UseSharedCompilation=false -nodeReuse:false
```

Clean95/0/0 and Smoke119/0/0 complete terminal0. Local receipts in MAUI:

| Receipt under `artifacts/s00-route-control-removal/` | SHA-256 |
| --- | --- |
| `clean/nikit_SURFACE-LT_2026-10-05_11_02_53_net10.0.trx` | `55edfdf2cdd27cedbd6f5a91ea65b2f5a596ad001b79dcd75cd6b06952388628` |
| `smoke/nikit_SURFACE-LT_2026-10-05_11_03_32_net10.0.trx` | `19fd43d03d9d4648ee698c370534d5868d28a2e55194f7ae273ee9dfdcdef270` |

The default Debug composition is not the authenticated physical HTTPS lane
or Release composition. These tests do not prove contacts, messages, files or
groups on devices, signing, artifact publication, S00 acceptance or release.
