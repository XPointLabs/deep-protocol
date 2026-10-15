# S05 — closed contact-scope diagnostic

Date: 2026-10-15. The existing advertisement-scope rejection keeps its exact
predicate, exception type and message. It now attaches only the closed
`Deep.ContactRoute.Scope` classification: `pmt-reference` or
`device-or-delegation`. No identifiers, keys, signed bytes or caller values are
logged or returned in this diagnostic. No wire, suite, public API or compatibility
path is added. Consumers retain all current authority and signature checks.

The real retained Windows owner established the PMT-reference boundary; Shared's
signed publication-successor negative case verifies the closed diagnostic.
[Connected scope](../../../deep-devops/docs/S05-CONTACT-TRANSPORT-2026-10-15.md).

Canonical `artifacts/s05-contact-diagnostic-20261015/full-01/` completed under
Windows PowerShell5.1/SDK10.0.301 with PowerShell7.6.5/.NET10 ARM64 witnesses:
**2330/1/7**,2338 exact case mappings,1587 unchanged captured inputs.
Build/preflight/qualification0, native test1, **FullAccepted=false**. Build has
zero warnings/errors. The sole failure remains the actual DNP1 package graph
rejecting retired MAU2 in the old PMA1 producer (S08 under DR-0095); all seven
named skips remain explicit. Classification does not waive either requirement
or qualify shipping composition, PMT rollover, a physical device or the release.
