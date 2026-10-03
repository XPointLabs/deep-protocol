# S01 — signed grant revocation producer checkpoint

Date: 2026-10-03. Baseline Protocol `4af284766b1d9fdfb2a2e3285d248e4d30ca02e5`,
root `bc0ccf6d693872933cb767990571623ef14fc8b3`.
Normative owner: [CONTACT-RESOLVER §3.8](../../../docs/architecture/CONTACT-RESOLVER-V1.md#38-current-mailbox-grant-revocation),
[DR-0083](../../../docs/survival-program/decisions/DR-0083-current-mailbox-grant-revocation.md).
This closes a bounded Protocol input, not S01, node admission or delivery.

## Implemented boundary

- MGR1 canonical codec and independent signed/hostile vectors; existing PMA2
  role keys, no new crypto or client grant/presentation version. Exact size is
  `327 + 16*N`: twelve-byte header, twelve eight-byte field headers and 219 fixed
  bytes. Initial unpublished draft arithmetic was corrected before freeze.
- Genesis/successor planning from actual signed complete host authority;
  candidate plans are not committed authority. Actual role signatures, scope,
  full protected interval, generation/predecessor and cumulative serials verify.
- Closed revocation capability needs exact protected read-back and current
  scoped floor I/O. Old capabilities reject when the current floor changes.
  Signed empty input is distinct from missing/unavailable protected state.
- Grant bytes are captured before callbacks; grant and snapshot time are both
  checked before/after floor I/O. Grant expiry cannot be extended by a still-fresh
  snapshot. Authenticated floor conflicts are separate from unsigned bad inputs.
- Primary registry binds all four machine/schema/vector input hashes and resolves
  an exact **inactive** MGR1 row. Imported approved DNP1 blobs are untouched.
  Generated graph-policy set adds only MGR1; mechanical ordering changes add no
  other allowed token. No retired reader is reactivated or renamed to pass a gate.

The signed network/role fixture is real; floor/clock I/O in these unit tests is
explicitly test-owned memory. It proves neither native durability nor deployed
signer readiness. There is no current XNode consumer of this capability yet.

## Fresh verification

From `deep-protocol`:

```powershell
dotnet test tests/Deep.Protocol.Tests/Deep.Protocol.Tests.csproj -c Release --filter FullyQualifiedName~MailboxGrantRevocationV1 --logger 'trx;LogFileName=mgr1-signed-floor.trx' --results-directory artifacts/s01/mgr1-signed-floor --verbosity quiet
dotnet restore Deep.Protocol.slnx --verbosity minimal
dotnet build Deep.Protocol.slnx --no-restore -warnaserror --verbosity minimal
dotnet test Deep.Protocol.slnx --no-build --logger trx --results-directory artifacts/s01/mgr1-final-full --verbosity quiet
./eng/Test-DeepProtocolRegistry.ps1
./eng/Test-ProductionProtocolGraph.ps1 -Configuration Debug
$ownershipPaths = @(git ls-files artifacts/dnp1-vector-fragments)
& ./eng/Test-Dnp1EvidenceOwnership.ps1 -MappingPaths $ownershipPaths -RequirePackageComplete
./eng/Test-Dnp1ExecutableVectors.ps1 -Configuration Debug -NoBuild -IntegrityOnly
```

| Gate | Fresh result |
| --- | --- |
| MGR1 focused | 49 pass / 0 fail / 0 skip; both role signatures, scope/time, owned callbacks, replay/fork/gap/removal, empty/max capacity, four independent signed and eight hostile golden cases |
| Default Debug solution restore/build | Exit 0; 0 warnings / 0 errors |
| Complete Debug solution tests | 2,065 pass / 1 fail / 12 skips, total 2,078 |
| Full per assembly | Protocol 1,829/1/12; MembershipRoutes 131/0/0; ProfileCarrier 105/0/0 |
| Strict primary registry | PASS; 175 anchors, 244 imported/local magics; MGR1 exact inactive source/schema/vector binding |
| Actual package test | FAIL: unchanged retired MCG2 in compiled Deep.Protocol; packages build without warnings/errors, but that does not qualify the graph |
| Production source graph | FAIL: unchanged retained MAU2 in ProductionMailboxAuthorityCodec |
| DNP1 ownership | PASS exact314/package219/final95; 219 mapped, no package mapping missing; mapping consistency only |
| DNP1 manifest integrity | PASS integrity only, no executable/native qualification |
| Root/public docs | 174 checks pass; both new closed JSON schemas pass Test-Json |

Twelve existing native/operator-capture skips retain the classification in the
[S00 contact checkpoint](s00-contact-baseline-2026-10-03.md#open-package-and-skip-classification).
The one failing package case was not deleted, renamed or bypassed. Full TRX
uses automatically unique filenames: a preliminary fixed-name solution run
overwrote the two small assembly reports, so the final full run retained all
three distinct reports above.

Sanitized local TRX SHA-256, without copying their test outputs into public docs:

- focused: `71ce5e04cb2e9a694282a237da916e47c2178916b77fa6431b792109f96d46f9`;
- full Protocol: `c98c78507bb7f410df221f6d242f5921172a6bb0733b47254b92172a092c5452`;
- full MembershipRoutes: `1ef75fc58095416ca3b7533bcc176e4bfb023c8ce4e9b606b2e7496ad61e4517`;
- full ProfileCarrier: `800f3f1291cde985e443048ee101e9e7d3c739d83eb5cd5cedfa41b63ac3e061`.

Independent vector corpus (UTF-8/LF) SHA-256:
`b49b4778f01c55870487ba82ba98c33349bc23cefd9608627436f7e940d10314`.
The reference generator writes fixed public test seeds only and independently
assembles headers, projection, domains and signatures; it never calls the
product codec or accepts operator custody.

## Remaining integration/reset impact

S01 grant/send/route settlement, compaction and application receipts remain open.
S02 needs a real externally protected floor owner, explicit enrollment (never
auto-genesis from missing state), atomic install/read-back/reopen and the same
scoped concurrency owner around floor replacement and admission/mutation.
S02/S03 must then enforce holder/body/selected exit/replay and rechecks before
reservation, after peer callbacks, before mutation and receipt release. S05
still owns actual issuer cumulative authoring, renewal and bounded history catch-up;
this single-step verifier does not claim an operational history distributor.

Consumers must use current source/package pins and provision both role records
before activation; no account, identity, client journal or node-key reset is
required by the unchanged MCG3/MCP3/MAU3/XMC2 bytes. Native floor loss still needs
recovery, not reset. No package publication, device reset, production deployment
or physical E2E was performed in this checkpoint. Existing local dev state is
unchanged. S00 failures and S01–S13 acceptance remain as tracked by NEXT-SPRINT.
