# S00 ONION terminal metadata checkpoint — 2026-10-03

Owner: Mr. X. Evidence only; execution order and release status belong to the
[implementation plan](../../../docs/architecture/IMPLEMENTATION-PLAN-V1.md) and
[current queue](../../../docs/NEXT-SPRINT.md).

## Inputs and bounded change

Input root: `94ef215f66507ab4d58a8a1bf0d4692135fec61e`.
Input Protocol: `873eb0618620e31047315db70e7ac4163d869000`, plus the changes
committed with this checkpoint. No runtime, public API, crypto, production,
device, account or secret was changed.

Accepted DR-0049/0079/0081 already own current coordination and selector-bound
mailbox contracts. The root ONION metadata/schema still described MAU2/XMC1 and
older publication bounds; its checker expected an even older ContactResolve set.
The added `OnionTerminalMachineParityTests` first reproduced four stale rows:
**5 pass / 4 fail / 0 skip**. Initial test-authoring compile errors were corrected
before that executable baseline; they are not product failures.

Schema 1.3.0 synchronizes only terminal metadata with those accepted contracts:

| Operation | Current request maximum derivation | Result maximum |
| --- | --- | ---: |
| Store | MAU3 header16 + MCP3[440] + body81920 = 82376 | 776 |
| Retrieve | 16 + 440 + 112 + 256 = 824 | min(HTTP cap1048576, XPR1 cap1048576 − header20) = 1048556 |
| Acknowledge | 16 + 440 + 112 + 256 + 100×40 = 4824 | 77840 |
| ContactResolve | XCA2 header12 + DR79 V3 publisher envelope171598 = 171610 | 131072 |

The exact ContactResolve request/result sets remain closed. XMC2 replaces the
retired XMC1 row; XPP1/XCA2 and XIC1/XCS2 are explicitly checked. XPP staging
acknowledgments do not constitute signed XIC1 authority. GroupControl is unchanged.
The five frame field maps, deterministic positive bytes/hashes and all eighteen
hostile classes compare unchanged against input root HEAD.

The single normative ONION owner was corrected in the same slice. The provided
source repin tool changed **only privacy-routing-v1** document digest; the anchor
tool validated all **174 anchors**, with **zero** anchor changes. Strict generation
changed only the derived registry digest in resolved JSON/generated C#; no wire
identifier, allocation, approved Git blob, evidence count or activation changed.
Downstream package resource repin remains unqualified; no package was published
and no consumer reset was performed.

## Fresh verification after source repin

From Protocol:

```powershell
dotnet restore Deep.Protocol.slnx --verbosity quiet
dotnet build Deep.Protocol.slnx -c Release --no-restore --verbosity quiet
dotnet test Deep.Protocol.slnx -c Release --no-build --logger trx --results-directory artifacts/s00/onion-terminal-repinned --verbosity quiet
dotnet test tests/Deep.Protocol.Tests/Deep.Protocol.Tests.csproj -c Release --no-build --filter FullyQualifiedName~DeepExtension.PrivacyRouting --logger trx --results-directory artifacts/s00/onion-terminal-focused-repinned --verbosity quiet
pwsh -NoProfile -File eng/Test-DeepProtocolRegistry.ps1
pwsh -NoProfile -File eng/Test-ProductionProtocolGraph.ps1 -Configuration Release
pwsh -NoProfile -File eng/Test-Dnp1ExecutableVectors.ps1 -Configuration Release -NoBuild -IntegrityOnly
$onionOwnershipFragments = @(git ls-files artifacts/dnp1-vector-fragments)
& ./eng/Test-Dnp1EvidenceOwnership.ps1 -MappingPaths $onionOwnershipFragments -RequirePackageComplete
```

Restore/build exit 0; **0 warnings / 0 errors**. Focused privacy suite:
**64 pass / 0 fail / 0 skip**, including the nine new metadata/boundary cases.
Focused TRX SHA-256:
`357cf7c12a4838d365b1ff9481f0c57012930d27faa42a4b2960a09ff497cb08`.
The tests compare actual endpoint/codec limits and execute selected max/max+1
framing and oversize rejection. They do not mint signed authority or simulate
successful authenticated node dispatch.

| Full suite | Pass | Fail | Skip | Total | TRX SHA-256 |
| --- | ---: | ---: | ---: | ---: | --- |
| Protocol | 1780 | 1 | 12 | 1793 | `4fd9d07370a31260c853ec67c42e927e666c447d02802a122e0632dc1add6f96` |
| MembershipRoutes | 131 | 0 | 0 | 131 | `51b7f9a15557a19966fcd147fee2c6f91b8bc7adebc3619de3c69d3dcb1d6e96` |
| ProfileCarrier | 105 | 0 | 0 | 105 | `4c22543258291a69998785e80b627a9ed170ed75c70780b70dd06b107f40d6fe` |
| **Total** | **2016** | **1** | **12** | **2029** | **exit 1, not qualified** |

Strict registry passes. Exact314/package219/final95 ownership mapping passes:
mapped219, packageMissing0; this is static mapping, not executable case coverage.
Manifest integrity-only passes and explicitly performs no executable discovery.
The full package test still fails on retired **MCG2** in the actual assembly;
production graph separately fails on the **MAU2** consumer in
`ProductionMailboxAuthorityCodec`. These are not solved by this metadata change.
The same twelve native/capture omissions remain classified in the
[contact checkpoint](s00-contact-baseline-2026-10-03.md#open-package-and-skip-classification);
no corresponding evidence harness or physical qualification was run here.

From root, `scripts/check-onion-01-spec.ps1` passes with strict exact schema,
sets, bounds, five wire records, one deterministic positive and eighteen hostile
classes; runtime remains inactive. `scripts/Test-XPointDocumentation.ps1` passes
174 checks. `git diff --check` passes.

## Remaining scope

Fresh root `check-survival-program.ps1 -RequiredEvidenceClaim ClassificationOnly`
still rejects machine-set digest: expected `92b23996...`, actual `504d184e...`.
Read-only history review identifies three changed inputs since the old manifest
pin: DNP1 registry/schema (offline issuance source) and classical checker
(matching source contracts, canonical text hashing/toolchain harness). This
does not authorize a blind repin or establish root governance GO.

Current one-time invitation, remaining unsafe XPP fixtures, Windows native
atomic-replace nondeterminism, current node authority/revocation/peer integration,
client lifecycle/Release composition and physical contact/text/files/groups
remain open. This checkpoint closes the reproduced ONION metadata drift, not
S00, ONION runtime activation, full application E2E or release readiness.
