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
