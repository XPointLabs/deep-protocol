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
