# S01 retained-read request/time prerequisite

Source: `7bc90f0e3b78c103d1108516d3879d458a0e402b`.
Workspace contract checkpoint: `fb87288706de80f8c00c751c8071d07257c2b47a`.
Contract: workspace DR-0100 / CONTACT-RESOLVER section3.7.1. This is the same
unfinished S01 retained-route Retrieve–ACK closure, not a separate execution stage.

## Implemented boundary

`VerifiedMailboxHostAuthorityV2.VerifyRetainedReadRequestAsync` captures exact
XMG1 before callbacks, verifies holder proof, requires Retrieve/exact network
and one matching PMT2 ArtifactRef already in actual protected signed lineage.
Its closed `VerifiedMailboxRetainedReadRequestV2` rechecks the original bounded
request window against current PMA2/NET/time, not old route time. Public request,
projection and PMS hash properties return copies. `ReadCurrentTimeAsync` returns
current authenticated interval facts; no caller UTC or historical flag is accepted.

The host's existing time/rollback checks were factored into one private
ReadAtReading method, retaining the current-only grant/Store behavior. No wire,
magic, suite, signing domain, algorithm profile, storage generation, TTL, public
endpoint, scheduler, key or production state changed. Reviewed mechanical registry
repin updates three source hashes and adds this source to existing PMT2/XMG1
references; no allocation or approved frozen Git blob changes.

The PMS hash/capability are intentionally still untrusted lookup inputs. This
context does not verify original publication/route provenance, capability ownership,
selected mailbox replicas, MGR1 floor, issuance, owned holder, replay, dispatch,
availability, mutation or deletion. Actual bounded retained custody at both current
selected stores, renewed issuance/owned request and node consumers remain open.
An issuer cannot use this request alone or simply choose the latest publication.

## Focused tests and builds

Initial compilation ended1 because the new test file lacked the ProtocolMagic
alias (CS0103); no tests executed or TRX was produced. The alias was added without
changing production checks. The first focused run passed23/0/0. Additional factory
recheck/header/window coverage brought the required request cases to31.

Final coupled command (Release):

```powershell
dotnet test tests/Deep.Protocol.Tests/Deep.Protocol.Tests.csproj -c Release --no-build `
  --filter 'FullyQualifiedName~MailboxHostAuthorityV2VerifierTests|FullyQualifiedName~MailboxGrantRevocationV1Tests|FullyQualifiedName~XPointOnionCapabilityProducerTests' `
  --logger 'trx;LogFileName=retained-request-final-coupled.trx' `
  --results-directory artifacts/s01-retained-request/final-coupled --verbosity quiet
```

Terminal0:225/0/0, comprising the previous194 and31 new cases. The new cases
exercise actual signed history and cold DNH2, unchanged/advanced epochs, expired
old projection versus current request time, holder proof/role/network/projection,
full interval and exact deadline boundary, maximum120s, buffer mutation/copies,
factory and later-use cancellation/rollback/boot/expiry, hostile headers/sizes and
actual closed public API. Their arbitrary PMS hash/capability is not an original
verified route or ownership fixture; no issuance/physical claim is made.
Receipt SHA256:
`3E1FA24B4DF628AA1F7D291E3448CBB47561F7668342F9CE5C6ACBF9812A6D7B`.

Restore, Release solution build and final Debug solution build finished terminal0;
both builds0 warnings/errors. Registry and root documentation174 checks pass.

## Current full qualification; shipping failure remains

After the source/contract commits and final Debug build, expectations were captured
before launch. The native command:

```powershell
dotnet test Deep.Protocol.slnx --no-build -m:1 --logger trx `
  --results-directory artifacts/s01-retained-request/full --verbosity quiet
```

Observed terminal1:2088 passed /1 failed /7 skipped,2096 results. No source edit,
build or expectation correction overlapped this run. Private expectations SHA256:
`6EB8ADC5DFF165562E2893B63B0FA59504CA60DA3269D1D1C0F74ABB00DF9E08`.
All881 captured inputs, including the seven Debug assemblies, remain unchanged.
All225 current required cases have exact Passed result/definition/execution mapping;
all2063 distinct prior display names remain. Every2096 actual result maps to its
exact TestEntry and method definition. The22 existing non-serializable MemberData
metadata rows match the prior baseline, not invented unique definitions.

| Receipt under artifacts/s01-retained-request/full | Pass/fail/skip | SHA256 |
| --- | --- | --- |
| nikit_SURFACE-LT_2026-10-07_10_56_24_net10.0.trx | 14/0/0 | `57A95194350D9EE9D8C714346ACACF20A7FB64BC443BBBD2B6323434A4AAE3BB` |
| nikit_SURFACE-LT_2026-10-07_10_56_26_net10.0.trx | 105/0/0 | `6099A338B4F7E903D481CE6ACA1780D9BD27CF9D57BB9C1E647DA3182A826EC1` |
| nikit_SURFACE-LT_2026-10-07_10_56_30_net10.0.trx | 1969/1/7 | `488A379FF437AB0DAB6BB00D0B846DBCEE6665C556A63F47B3087EF359730F41` |

The unchanged failure is
`Dnp1PackageBlockingWitnessTests.PackageExactThreeSessionFree_InspectsActualPackageZipsAssembliesResourcesAndPublicApi`:
actual packed assembly contains retired MAU2. All seven skips match the prior full.
`Test-ProductionProtocolGraph.ps1 -Configuration Debug` separately ends1 at
ProductionMailboxAuthorityCodec.cs / MAU2. No assertion, allowlist, skip or retired
reader was changed. These are failures, not a green actual package/resource gate.

The existing TRX verifier was reused for the fresh matrix, with only manifest name,
observed terminal1 and expected full-count checks added. It ends0 qualifying
source/mappings under DR-0095, not overriding the native/package failure. Verifier
SHA256 `2F6888F86B785939FB248AB2176B3EE2D0BFF69CB7D4E5186C62E1FE3FA07C76`.
Evidence ownership ends0 (exact314/package219/final95, mapped219, packageMissing0);
that mapping does not mean219 executed native/package approvals.

Consumer rebuild/repin and actual package acceptance remain separate gates. No
production deploy/reset, public export, GitHub Release or merge-main action occurred.
This locally qualifies only the closed request/time prerequisite, not whole S01,
renewed grant issuance, accepted-object horizon or physical E2E.
