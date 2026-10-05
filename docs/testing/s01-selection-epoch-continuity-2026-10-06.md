# S01 selection-epoch continuity — 2026-10-06

Scope: source verification prerequisite within the one open S01 retirement
contract. Not a completed retirement API, native cleanup, deployment, installed
device evidence or shipping qualification. Decision:
[DR-0096](../../../docs/survival-program/decisions/DR-0096-mailbox-selection-epoch-continuity.md).
Normative rule:
[XPOINT-NETWORK section9](../../../docs/architecture/XPOINT-NETWORK-V1.md#9-mailbox-placement-and-storage-swarms).

## Defect and correction

Signed, append-only PMT2 generations previously permitted selection-epoch
rollback. Four fresh negative fixtures failed with **no exception thrown** for
`7 -> 6 -> 9` and `7 -> 8 -> 7`, using both the process-local predecessor and
actual exported DNH2/full-history restore. This is not an observation that
production signers issued such records.

The complete verifier now authenticates signatures and rejects a decreasing
epoch at every PMT step. Equal epochs and ordinary increases remain valid.
The original protected tip is unchanged after rejection. Eight added cases
cover negative and positive transitions in both restore paths; the fixture
authors genuine signatures and exact generation/predecessor links, not tampered
records that would fail at an unrelated check.

No wire, signature input, crypto, public API, local reader, limit or floor
format changes. No data is deleted and no retirement capability is minted.
Tuple-only XNF1/NFP1 recovery still does not bind an existing exact DNH2 floor;
no fallback or new forward-history adapter is introduced.

## Inputs and receipts

Source base: Protocol `ed7153e12cc0749e875a047705566bf0a99338b9` plus the exact
guard/test patch and mechanical source-hash repin. The source hashes for
XPOINT-NETWORK and already accepted TRANSPORT-NEUTRAL section8.4 are refreshed;
the latter document has no edit in this change. All175 normative anchors
validate with zero anchor updates. Approved DNP1 inputs and strict API/package
allowlists are unchanged.

| Frozen input, repository-relative | SHA-256 |
| --- | --- |
| `src/Deep.Protocol/XPointNetworkV1/XPointOnionCapabilityProducer.cs` | `933B6D356BFB53A0DBBA75C5584B408C0EB1193002931470E7B6D7347AA4CC39` |
| `tests/Deep.Protocol.Tests/XPointNetworkV1/XPointOnionCapabilityProducerTests.cs` | `63346D6D8A85BC041EDAB5CFCC61964837B161791DC35C6850A4701ED2DDA7C4` |
| `registry/deep-protocol-v1.registry.json` | `029AE43BC761E6C5077F966ADFA6928CA0187F63CBBF8E2C2C49E45AA778A423` |
| `src/Deep.Protocol/Generated/DeepProtocolRegistry.Generated.cs` | `705B97B16D75D8C54E7F9D734D0CFBDFCA1FD2C3EA8CBE2F633A7373EBAAD052` |
| `tests/Deep.Protocol.Tests/bin/Release/net10.0/Deep.Protocol.Tests.dll` | `3BE704153EE3F1DB1A814C3ED0F8E4FABCBE30B5059B7CB3D55B1E2BC9AC2729` |
| `src/Deep.Protocol/bin/Release/test-seam/net10.0/Deep.Protocol.dll` | `06BE10A86BAD7685ED658DA4173FE6AC543274EE44E4906ED411EC54976145DC` |
| `src/Deep.Protocol/bin/Release/net10.0/Deep.Protocol.dll` | `28558C60CF585B9AD13C3A6DB03F77B1685D53B5778ACBEDB123B0E28AD6BF57` |

All seven inputs matched after the full gate. No rebuild/source edit overlapped
that gate. Subsequent actual Shared Production compilation also retained the
same three Protocol/test assembly hashes.

| Check | Result | Receipt SHA-256 |
| --- | --- | --- |
| New negatives before correction | 0/4/0, terminal1 | `9736601B90CBD4DA7C16FF45729D613CED0D20555CAEBEA46168494B1CCCF1A8` |
| Focused successor/protected-history checks | 24/0/0, terminal0 | `882C1DFF9379B008666CB683034714EA9B99B7F726978FEFEF9009A2D838453A` |
| Full main Protocol test assembly | 1899/1/7, terminal1 | `C8AEE08C4DAE772BB2BC6BCF8D399800A5200CC5D5B970444BC7E91ECBA0D29C` |
| MembershipRoutes, same no-build inputs | 14/0/0, terminal0 | `0B5723B8BEF765E92BA662EAA6ECC4D86F5F6DF25BA6F7E64EBB81E8D426CEA8` |
| ProfileCarrier, same no-build inputs | 105/0/0, terminal0 | `EA947FDA81A1693CD348EB8DEE5112ECEB485FD9F2586C7BDDA7C61086E37888` |

Counts are pass/fail/skip. Whole solution: **2018/1/7, terminal1**, not green.
Every one of the24 focused test names independently maps to Passed in the
final main TRX, including all eight new cases. Main TRX interval is
2026-10-06T02:58:57.7532180+05:00 to 03:00:19.6603279+05:00.

The solution's explicit shared TRX filename overwrote the first two assembly
receipts. Its surviving TRX is main Protocol only. Both companion projects
were rerun without build/restore into distinct files to retain their own exact
receipts; this is not a second whole-solution run.

Restore terminal0; Release solution build0 warnings/0 errors terminal0.
Actual Shared Production project build0 warnings/0 errors terminal0 against
this Protocol source; no new Shared full-test or device claim follows.
Strict registry generator/check passes. Evidence ownership with current tracked
fragments and `-RequirePackageComplete` passes mapped219/packageMissing0;
that is a static mapping check, not execution/qualification of219 vectors.
Root documentation174 and governance22/0/0 pass.

## Remaining gate and next boundary

The sole full-suite failure remains
`Dnp1PackageBlockingWitnessTests.PackageExactThreeSessionFree_InspectsActualPackageZipsAssembliesResourcesAndPublicApi`:
actual package/assembly bytes contain retired `MAU2`. The strict production
graph gate separately returns terminal1 at the retained MAU2 source surface.
Neither assertion/allowlist is weakened. Shipping closure stays blocked under
DR-0095; this unrelated lane is not reopened here.

Continue the single S01 irreversible namespace-retirement producer/consumer:
current signed policy plus actual protected floor/read-back, known versus
unresolved original scopes and dependency closure through crash/reopen.
Epoch continuity alone is not that capability. No new files/groups/calls work
is opened, and no production reset, deployment, Release publication or main
merge was performed.
