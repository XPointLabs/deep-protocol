# S05 — owned prekey service succession

Date: 2026-10-16. Semantic authority is
[DR-0129](../../../docs/survival-program/decisions/DR-0129-owned-prekey-service-succession.md)
and its CONTACT-RESOLVER owner. This file records implementation/evidence only.

`DeepIdV2ContactObjectLineage.RequireServiceSuccessors` is the single internal
predicate reached by owned object authoring and independent publication issuer
verification. The existing bounded canonical codec and device signatures remain
mandatory, including an unchanged service. Current authorization/time validation
remains separate. No public capability or authoring API was added. The object
author no longer requires service generation1 at object genesis; the fixed
scope diagnostic changed accordingly and MAUI's closed classifier follows it.

Under `artifacts/s05-prekey-service-succession-20261016/`, `protocol-03` passed
9 cases, with no failure/skip and native exit0, Windows PowerShell5.1/SDK10.0.301.
The existing signed application-core case covers unchanged/valid successor,
scope/policy changes, replay/gap, substituted predecessor, issue/expiry ordering,
both signatures, generation overflow and malformed/duplicate bounded lists.
This case uses real Ed25519 with a test PQ verifier; it is not native PQ or
multi-device ordering evidence. `build-06` compiled the Protocol solution with
zero warnings/errors and native exit0.

The mechanical registry repin updates four source hashes and175 shifted
normative anchors; reviewed DR-0128 observation docs were stale hash inputs from
the preceding source slice. No allocation value, wire width, suite/domain,
evidence owner or public API is changed by this repin. The strict generator
check and registry gate pass. Generated C# changes only its registry digest;
consumer package/API/assembly gates are not replaced by that check.
`protocol-final-08` repeats the9 focused cases after repin, native exit0 with no
failures/skips. The native short-service scenario subsequently exposed the
publication request expiry exceeding the signed object's effective expiry.
`AuthorRequestBodyCoreAsync` now caps at the lesser object/route request bound;
the existing canonical wire/issuer bounds remain strict. Shared retains the
red/green evidence, including an actually expired service predecessor.

Canonical `full-11` completed under Windows PowerShell5.1/SDK10.0.301 with
PowerShell7.6.5/.NET10 ARM64 witnesses:2361 passed,1 failed,7 explicitly named
skips,2369 exact case mappings and1620 unchanged captured inputs. Build and
fixture preflight exited0; test native exit1, qualification exit0,
`FullAccepted=false`. The only failed case is the existing DNP1 package witness
rejecting retired MAU2. This classifies the original failure; it neither waives
shipping qualification nor marks the full run accepted. No new source regression
was found by this run.

The native owned-account/device/witness and target5 independent issuer scenario
is recorded by
[Shared](../../../deep-client-shared/docs/testing/s05-prekey-service-succession-2026-10-16.md).
Actual multi-generation SQL custody, crash/CAS/reopen, retained pending Initial,
two deployed replicas, matched client/runtime activation and successful full/
shipping graph qualification remain open. Existing MAU2 shipping graph failure
is not waived. No installed-device or release acceptance is claimed here.
