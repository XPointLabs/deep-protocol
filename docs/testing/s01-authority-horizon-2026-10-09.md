# S01 authority rollover across the object horizon — working batch

Uncommitted source work within S01, not stage acceptance or runtime activation.
The sole directory semantics owner is
[ACCOUNT-DIRECTORY](../../../docs/architecture/ACCOUNT-DIRECTORY-TRANSPARENCY-V1.md).
No public API, wire field, suite, signature domain or lifetime bound is added.

The actual V2 head author previously required its protected predecessor to name
the terminal current XNA1 and current witness-policy hash. This prevented normal
head renewal after DTS1/XNA1 renewal. It now re-authenticates the original head
against its exact member of the already verified authority chain, including its
original witness signatures and interval. New signing still uses current
authority/witnesses and current validity. Reader floors, complete journal/map
replay, exact predecessor, and output replay remain mandatory before publication.

The new genuine fixture keeps the original pinned genesis/root/witness keys.
It signs two XNA1/DTS1 successors, each policy at most30 days, with overlapping
DTS intervals. It derives a current issuance epoch after the original route's
accepted-object horizon, while original and intermediate DTS1 correctly reject
that time. Missing predecessor, cross-paired policy, changed signature and
uncertainty across the policy boundary reject. A new directory head retains the
original protected empty map/log and verifies via the existing catch-up reader.
Forged signature, foreign ancestor, reader downgrade and invalid current window
reject before new witness callbacks. This is not a nonempty owned-client test.

## Actual evidence

Windows PowerShell5.1.26100.9457/Desktop; SDK10.0.301. Release build of
`tests/Deep.Protocol.Tests/Deep.Protocol.Tests.csproj`, `--no-restore -m:1`;
matching tests use `--no-build --no-restore`.

- First source build: native1,38.82s,0 warnings/2 errors; new test incorrectly
  used `PublicKey` instead of the existing `Ed25519PublicKey` property. Corrected.
- `artifacts/s01-authority-horizon/object-horizon-01/object-horizon-01.trx`:
  native1,8 Passed/2 Failed/0 Skipped,127ms; preceding build0,5.88s,zero
  warnings/errors. The genuine directory rollover positive passed. Failed test
  setup assumed invariant policy hash and attempted unsupported reader3 journal
  authoring. The hash assertion now checks preserved actual witness keys while
  positively requiring the changed DTS-bound policy hash. Reader-downgrade input
  is independently threshold-signed, not manufactured via invalid journal output.
  SHA256 `029D85A65545A805601BAC7DCFF32081AF5E8CBB27591944D0C87C32B4A59AA4`.
- Next build: native1,1.75s,0 warnings/1 error; new test held a span over `await`.
  Corrected by completing signing before taking the span. No test launched.
- `artifacts/s01-authority-horizon/object-horizon-03/object-horizon-03.trx`:
  native0,17 Passed/0 Failed/0 Skipped,119ms; preceding build0,2.35s,zero
  warnings/errors. Ten new horizon cases and seven existing authority verifier
  cases. The requested `DeepIdV2DirectoryCatchupVerifierTests` class filter
  matched no cases (actual class is `AccountDirectoryFreshnessVerificationTests`);
  do not claim that existing catch-up corpus was included.
  SHA256 `F45C70B53E4BF2E317B43EB8F1BF438CF91B25F7E4984385F10BE6F8A9D706E1`.
- `artifacts/s01-authority-horizon/object-horizon-04/object-horizon-04.trx`:
  native0,47 Passed/0 Failed/0 Skipped,702ms; preceding build0,4.06s,zero
  warnings/errors. Ten new horizon cases, seven existing authority verifier
  cases, the actual `AccountDirectoryFreshnessVerificationTests.Did2*` cases
  (including4 catch-up cases), and registry/machine parity cases. The canonical
  `Read-TestGateReceipt` validated all result/definition/execution mappings,
  exact47 counters, all10 new horizon cases and4 existing catch-up cases.
  SHA256 `29F96966666932283D24ECC4A0E96047DCF3C0287788886D15CB56E70D9A86DF`.
- Matching Shared production solution build, native0,4.20s,zero warnings/errors,
  Windows PowerShell5.1/Desktop and SDK10.0.301,
  `--configuration Release --no-restore -m:1 -p:EnableDeepTestInternals=true`.
  This compiled the consumer against the changed Protocol source; Shared owner
  tests were not repeated without the remaining network/exclusion implementation.

Normative clarification was reviewed in the sole directory owner. Registry repin
changed only the `account-directory-v1` source hash, the resolved copy and derived
registry digest; no wire inventory/allocation changed. Mechanical anchor preview
validated176 anchors with0 updates. Actual PowerShell7.6.5 source repin/generator
and strict registry checks completed native0:44 frozen artifacts,245 magics,
10 suites,5 carriers,4 deployment profiles,11 retired aliases. This was not the
executable witness/full gate (which separately requires PowerShell7.5.4).

All failures remain. Canonical full/source qualification remains pending; the
focused current proof/catch-up regression above passed. Existing package FAIL is not
waived. Shared's positive joint archived-path scenario remains unqualified:
current network author/history restoration and original namespace exclusion
still require genuine authority-continuity implementation. Do not turn retained
history into current issuance, drop old PMT facts through a reset, widen signed
windows, or replace the genesis to reach the horizon. No commit, push, deployment,
physical device run, Release publication or main merge in this working increment.

## Network authority-history continuation

[DR-0107](../../../docs/survival-program/decisions/DR-0107-protected-authority-lineage-continuity.md)
extends the initial same-root restriction of DR-0012. The sole network owner is
XPOINT-NETWORK §8. The source verifier now authenticates every historical policy,
view/head pair and PMT step under its exact ancestor's keys and thresholds in
the already verified XNA1 chain. Policy/view authority generations cannot
regress. Current terminal bindings, DTT1, live time/descriptor checks, exact
predecessors, transparency append and selection-epoch guards remain unchanged.

Cold restoration additionally proves that the included prior policy/view/head
actually name the protected predecessor's exact ancestor authority. The actual
old PMT and checkpoint marker remain retained. A caller-supplied ancestor hash
does not grant permission. Neither current issuer APIs nor Shared's held
epoch-exclusion same-root boundary were changed by this continuation.

The network unit fixture genuinely signs root/DTS and root/witness-key rotation
and signs each old/new network artifact with its own generation's keys. It uses
the existing isolated network-time test seam; it is **not** an independently
admitted DID2 account, a native account-floor store or a physical device scenario.
The original custody bytes and exact predecessor are checked on warm/cold paths.
Wrong-generation policy/view/head/PMT signatures, current PMT signed by old keys,
epoch regression, stale terminal, forged capsule authority and a signed policy
returning to an ancestor all reject.

- `artifacts/s01-authority-horizon/network-rollover-01/network-rollover-01.trx`:
  native1,16 Passed/1 Failed/0 Skipped,264ms; preceding build0,15.04s,zero
  warnings/errors. Cold rollover passed. Warm rollover preserved its actual
  predecessor, but the new test incorrectly required a cold-capsule binding
  digest from the warm API. Corrected to require that binding only on cold and
  additionally compare exact prior head/view/root on both paths. No verifier
  assertion or history guard was removed.
  SHA256 `EA60905EC8531CD5F7E2ABD0995B29DCACFF7574682B90CA963DBCB9BD43CB04`.
- `artifacts/s01-authority-horizon/network-rollover-02/network-rollover-02.trx`:
  native0,125 Passed/0 Failed/0 Skipped,1s; preceding build0,4.34s,zero
  warnings/errors. Whole current XPointOnionCapabilityProducerTests corpus,
  including19 new network rollover cases, plus the earlier47-case
  authority/directory/registry set. Canonical Read-TestGateReceipt validated
  all125 mappings/counters and exactly19 rollover cases.
  SHA256 `470C2DB71F9E2A8E88DA5AFBAA59EC2A325E911D7F74922791BB8B710414EA4C`.
- Matching Shared production solution build: native0,19.74s,zero warnings/errors,
  same Windows PowerShell5.1/Desktop, SDK10.0.301 and commands as above. Shared's
  unqualified positive owner path was not rerun before its next dependency fix.

Reviewed mechanical repin changed the XPOINT-NETWORK document hash and added
the existing XNA1 magic's actual use in XPointOnionCapabilityProducer to the
source inventory; no allocation/domain/wire count changed. The preceding
directory source repin remains.176 anchors require0 updates; actual PowerShell7.6.5
strict registry/native0 retains44 artifacts/245 magics/10 suites/5 carriers/
4 profiles/11 retired aliases. This is not the7.5.4 executable witness/full gate.

The network verifier's ancestor continuity is now implemented with focused
evidence. Operational successor authoring still takes a generation-zero bootstrap;
its protected predecessor/history checks are same-authority only. That authoring
boundary and the whole owned client original-namespace exclusion must be closed
before the real object-horizon/SQL/protected/native matrix can qualify. Do not
cast historical verification into new signing permission. Whole S01, canonical
full/API/package/native floor and physical/release acceptance remain open. Source
is uncommitted; no push, release, deployment, account reset or main merge occurred.

## Current-authority operational producer — DR-0108

The earlier bootstrap-only limitation above is closed in the current source.
[DR-0108](../../../docs/survival-program/decisions/DR-0108-current-authority-operational-successor.md)
freezes the clean-break request, original-namespace metadata API and routine
same-key XNA1/DTS1 renewal producer. Historical predecessor verification uses
its own ancestor; new offline/delegated signing uses terminal authority. No
bootstrap adapter or historical current-issuer capability is retained.

Windows PowerShell5.1/Desktop, SDK10.0.301, Release/no-restore/no-build evidence:

- `operational-rollover-01`: native1,39 passed/2 failed/0 skipped. Positive warm/
  cold offline-to-delegated rollover passed; two negative test inputs supplied
  three XNV/XNH signatures with count2 and failed in their fixture codec. Fixed
  the supplied set to two, without removing a verifier assertion. TRX SHA256:
  `AEDB3D0B6DDB1075F9049FF8FC54AD8F7E54E39B15B94A4F3E634DC8222E5D13`.
- `operational-rollover-02`: build native1,zero warnings/one CS9035,12.38s;
  no tests launched. An existing binding-only claim fixture omitted the newly
  required retained-authority map. Its map is explicitly empty: that synthetic
  fixture verified no ancestor and cannot grant namespace permission.
- `operational-rollover-03`: build native0,zero warnings/errors,5.34s;
  tests native0,171 passed/0 failed/0 skipped,3s. Canonical receipt mappings
  validate; all previous125 network/authority/directory/registry cases remain,
  with25 operational cases and the actual view-log/PMA/bootstrap classes.
  TRX SHA256: `7B5D0BD18570FFD25ABB0621C3CE801FE874DCB886A2EF3FC8712FEA0F265892`.

Receipts are under `artifacts/s01-authority-horizon/<run>/<run>.trx`.
The25 new cases include genuine current changed-root/witness offline signing,
then delegated append over the mixed prefix, exact retained namespace metadata,
two routine same-key renewals, and hostile input/signature/signer/prefix refusals
before callbacks. Network tests use the existing isolated time seam, not native
account admission or physical devices. DevOps' real FileSigner renewal/current-
successor and caller builds pass separately on synthetic custody. Whole S01,
canonical full/API/package and physical/release acceptance remain open. No
production authority or machine was changed, and no Release/main action occurred.

## Current full reference identity correction — 2026-10-10

`protocol-authority-path-full-01` completed native execution on Windows
PowerShell5.1.26100.9457/SDK10.0.301 with the verified PowerShell7.5.4 witness:
build0/zero warnings/errors in39.46s, preflight0 in3.15s, actual test1.
The three full receipts contain2196 Passed,1 known actual-package Failed and
7 explicitly named skips (six native-provider cases and the operator-only
protected-predecessor capture),2204 cases. Their SHA256 values are:

- `916A74B5E54996C89281292617D169FD1B519CD6E782C797486B2DE271E7B729`;
- `5EEA36FF6339D4823E548A0CC7FA9545DB70857CEFC63C470DB1DEFB3FBF382E`;
- `B2AC1632A130C95C07AE5C2C3ACB41492B627E997230D44CE2D69E232D734057`.

Qualification1/FullAccepted=false is retained: the predeclared16-receipt union
requires2205 cases, including the original
`ObjectHorizon_DtsRenewalUsesActualSignedLineageAndPreservesGenesisKeysAndWitnessPolicy`.
An earlier focused failure under that name preceded renaming the corrected
keys/object-horizon test; references contain both names. Neither removing the
original reference nor allowing its absence is qualification.

The original case now independently checks preservation of configured witness
trust parameters/genesis keys and rejects replay of the preceding signed DTS in
the renewed paired chain. It explicitly requires the DTS-bound witness-policy
commitment to change, rather than reviving the incorrect unchanged-hash assertion.
The separate keys/object-horizon case remains. This adds no product compatibility
alias, legacy vector or authority bypass. The focused ObjectHorizon regression
completed11/0/0/native0 in98ms after build0/zero warnings/errors in7.47s, on
Windows PowerShell5.1.26100.9457/SDK10.0.301. The canonical reader validates the
11-case receipt and exact zero counters in both other filtered-project receipts.
The nonempty receipt SHA256 is
`D2ABE8A0E48BAA2E6BBC5E78DE71ACEEACC11A4AC110655EC2ACCEA3A535E617`.
The fresh canonical full02 declared25 original/subsequent receipts and the same
2205-case union. It completed on Windows PowerShell5.1.26100.9457/SDK10.0.301
with witness7.5.4: build0/zero warnings/errors in1.46s, preflight0 in3.00s,
2197 passed/1 known actual-package failed/7 explicitly named skipped, native1.
Canonical qualification0 confirms exact2205 mappings and unchanged1563 inputs;
FullAccepted=false remains. Full receipt SHA256 values:

- `4D952ECB6792FA570C1AEC89F66EA3FC077E6BF6DC2CC2AD7204D5D28B485BB0`;
- `9FE25BD3E13932F8DDAF620C79EC37605075BB46AEA6CA4BBD5FA9F64912D0CD`;
- `C619E0625CC8D9D064BC35F3D1C0633A556453CCA81FDC4367217EDA54B4E856`.

The previous known package FAIL/skips are not waived; source qualification does
not qualify shipping packages, activation, physical clients or release.
