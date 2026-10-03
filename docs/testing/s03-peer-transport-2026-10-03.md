# S03 — current selected replica transport facts

Date: 2026-10-03. Baseline Protocol `de1c220`, root `a284117`.
Normative owner: [XPOINT-NETWORK §9](../../../docs/architecture/XPOINT-NETWORK-V1.md),
[DR-0085](../../../docs/survival-program/decisions/DR-0085-current-mailbox-replica-transport-facts.md).

The existing closed `VerifiedMailboxReplicaV2` now exposes the existing closed
`VerifiedOnionNextHopTransport`. Both selected-grant and member-resolution paths
mint it from the same actually admitted node; complete source/time checks still
precede release. Copied facts are not a dispatch capability and have no public
constructor, trust flag, new wire/domain or crypto suite. Tests bind network/node,
exact descriptor origin/port/SPKI and defensive copies, using distinct node ID
and descriptor key in the Protocol fixture. The remaining current-host negative
and callback tests remain intact.

Consumers must rebuild/repin; XNode's current HTTP client consumes this getter
instead of parsing retired peer evidence. No identity/node-key/client-state reset
is implied. Current grant, protected floors and live operation checks remain
mandatory across transport callbacks. Shipping packages/devices remain separate
activation gates; see the [connected HTTP checkpoint](../../../xnode/docs/testing/s03-current-peer-http-2026-10-03.md).

## Fresh gates

```powershell
dotnet test tests/Deep.Protocol.Tests/Deep.Protocol.Tests.csproj -c Release --no-restore --filter 'FullyQualifiedName~MailboxHostAuthorityV2VerifierTests|FullyQualifiedName~DeepProtocolRegistryTests|FullyQualifiedName~XPointRegistryMachineParityTests' --logger 'trx;LogFileName=current-peer-transport.trx' --results-directory artifacts/s03-current-peer-transport/focused
dotnet test Deep.Protocol.slnx -c Release --no-restore --logger trx --results-directory artifacts/s03-peer-transport/full
dotnet restore Deep.Protocol.slnx
dotnet build Deep.Protocol.slnx -c Release --no-restore -m:1 -warnaserror
./eng/Test-DeepProtocolRegistry.ps1
$ownershipPaths = @(git ls-files artifacts/dnp1-vector-fragments)
./eng/Test-Dnp1EvidenceOwnership.ps1 -MappingPaths $ownershipPaths -RequirePackageComplete
./eng/Test-Dnp1ExecutableVectors.ps1 -Configuration Release -NoBuild -IntegrityOnly
./eng/Test-ProductionProtocolGraph.ps1 -Configuration Release
```

| Gate | Result |
| --- | --- |
| Focused host/registry/parity | 38 pass / 0 fail / 0 skip |
| Complete Release tests | 2067 pass / 1 fail / 12 skips, total 2080; Protocol 1831/1/12, MembershipRoutes 131/0/0, ProfileCarrier 105/0/0 |
| Restore / Release build | PASS, 0 warnings / 0 errors |
| Actual package/assembly/resource/API graph | FAIL: unchanged retired MCG2 in Deep.Protocol assembly; not package/API approval |
| Production source graph | FAIL: unchanged retained MAU2 in ProductionMailboxAuthorityCodec |
| Strict registry | PASS, 175 anchors; one normative source hash and derived registry hash updated through reviewed scripts, no approved blob changes |
| Evidence ownership | PASS exact314/package219/final95, mapped219/packageMissing0; mapping consistency, not release evidence |
| DNP1 manifest integrity | PASS integrity only; no executable/native qualification |

The native/operator capture skips retain the prior
[S00 classification](s00-contact-baseline-2026-10-03.md). No gate, retired-token
rule, malformed assertion or skip was relaxed. Full Protocol TRX SHA-256:
`34dbe42a9c25d4bd6bbfad88aad283288185fe460f0b298bdba1b302edc43cbb`;
MembershipRoutes: `7ad88f2989874aea305ccdaec799d710a648f05d6271e1e8de069bfa8cb75e2a`;
ProfileCarrier: `1ce40ef7fce0cd8f05ff9aaf8b91dbbbb75a0e4f72d16c7fa4e8fd22d76a7add`.
