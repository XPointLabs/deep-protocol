# S05 — logical prekey publication placement

Date: 2026-10-15. Source candidate; contract owner:
[DR-0121](../../../docs/survival-program/decisions/DR-0121-prekey-publication-placement-lifecycle.md).
Only publication uses the new logical placement commitment; other requests keep
their current view/PMT binding. No wire layout, suite or public API changes.

Focused03:155/0/0/native0 in
`artifacts/s05-prekey-placement-20261015/focused-03/prekeys.trx`.
Real signed operational renewal, cold history restore, exact receipt pair,
epoch/service/shard separation and the independent fixed machine vector are
covered. Focused02's fixture accidentally advanced the epoch and failed one
case; that failure was preserved and the fixture explicitly retains its epoch.

Canonical full01 under Windows PowerShell5.1/SDK10.0.301:
`artifacts/s05-prekey-placement-20261015/full-01/`.
Build/preflight/qualification0, native test1;2330 passed,1 failed,7 skipped;
2338 exact mappings,1588 unchanged inputs. `FullAccepted=false`.
The sole existing failure is
`Dnp1PackageBlockingWitnessTests.PackageExactThreeSessionFree_InspectsActualPackageZipsAssembliesResourcesAndPublicApi`:
the actual package still contains retired MAU2 in its PMA1 producer. All seven
baseline skips remain. Classification does not waive S08/package qualification.

Reviewed registry repin changes two normative source digests and anchor
positions/hashes, not existing semantic allocations/anchor ownership. The
`preKeyPublicationPlacement` machine domain/vector is an intentional DR-0121
addition. Strict generation/check passed. Commit verification now attaches
only decoded closed status/mutation codes to its existing rejection exception;
it still rejects non-committed responses before clock/signature processing.

[Connected evidence](../../../deep-devops/docs/S05-PREKEY-LIFECYCLE-2026-10-15.md)
proves actual prekey completion and unchanged protected pair reopen, not contact
acceptance, claims, messages or installed Windows/Android delivery.

## 2026-10-17: committed allocation versus current carriage

[DR-0136](../../../docs/survival-program/decisions/DR-0136-committed-claim-original-carriage.md)
keeps claim mutation/initiator placement current-only, but authenticates an
already committed recipient allocation through its exact original signed
projection and unchanged continuous current cohort. Current admitted identity
keys verify both receipt signatures; current endpoint/inventory/time gates and
recipient-purpose checks remain. No public API, wire, schema, reset or replay
freshness change. These facts cannot mint a historical dispatch capability.

Focused13 PASS/native0/0skip/no compiler diagnostics (Windows PowerShell5.1,
SDK10.0.301), `artifacts/s05-committed-initial-carriage-20261017/focused-01`:
real signed renewal/cold retained history, original byte preservation and
view/placement/interval/service/shard/epoch negatives, plus existing publication
placement and closed surface checks. This narrow run does not execute the
monolithic claim-cryptography witness; that witness and the actual owned
two-account receive/accept/reply regression remain required, alongside registry
source/anchor repin and full/package/consumer/device qualification.

The subsequent `crypto-02` executes those13 plus the actual monolithic
`Dab2_RequiresExactAccountClosureAndBothRootSignatures` claim-cryptography witness:
14PASS/native0/0skip/no compiler diagnostics. Shared's final encrypted owned
receive/ContactAccept/reply scenario also passes after correcting its public
policy-chain fixture; see its
[checkpoint](../../../deep-client-shared/docs/testing/s05-logical-grant-custody-2026-10-16.md#committed-initial-on-the-next-carriage-view).
The mechanical registry preview detects7 accumulated source digests and175/178
anchors needing review. No repin was applied blindly; strict registry/full/package
qualification remains pending for the whole business batch. Installed clients
still precede DR-0136 until separately rebuilt and exercised.

Security scope: the22-file scan reports one pre-existing sensitive-assignment
finding at frozen DEEP-CRYPTO line266 (`722254bf84c9def5`). The line is unchanged
from HEAD and is a mnemonic-normalization expression with no quoted or long
hex literal, not a stored password. The other21 changed files scan with0 findings.
The original whole-scan failure is not reclassified as PASS, and no scanner rule
or normative formula was changed. Full release security qualification remains open.
