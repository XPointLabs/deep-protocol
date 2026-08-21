# Agent Specification - Deep Protocol V3

Last updated: 2026-08-11.

## Mission

`deep-protocol` owns the managed Deep-native protocol surface. Wave 1 is a
clean break under DR-0003: no Session identity, protobuf, envelope, onion,
compatibility, Nearby, LoRa, or database fallback is part of production.

The production package closure is exactly:

1. `Deep.Protocol`;
2. `Deep.Protocol.MembershipRoutes`;
3. `Deep.Protocol.ProfileCarrier`.

`Deep.Protocol.Native*` is a separate source/test dark path. It must remain
unreferenced by production projects and absent from packages and consumer
graphs.

## Normative Source

The frozen Wave 1 source plus executable-evidence ownership is docs repository
commit `2562b11cdacdcc6e60cf79bdb6265b4f4687fbbe` (36 records, 158 domains,
314 executable vector IDs; 219 package-blocking and 95 final-release):

- `docs/survival-program/releases/v3.0.0/specs/DNP1-CLASSICAL-IDENTITY-RESET-MRL2-V1.md`;
- `dnp1-classical-v1.registry.json` and its schema;
- `dnp1-classical-v1.vectors.skeleton.json` and its schema;
- `dnp1-classical-v1.evidence-ownership.json` and its schema;
- the evidence manifest, attestation, and self-test schemas;
- DR-0003.

Machine registry widths, suites, domains, field order, package inventory and
activation order are normative. Do not infer missing grammar.

## Ownership Boundaries

Owned here:

- the retained P03B/mailbox/membership core;
- reviewed D--G route-continuity APIs and bytes;
- DNP1 classical identity/reset/native-routing records when separately
  authorized;
- exact-three package and static graph gates;
- malformed, negative, replay and canonical-vector coverage.

Not production inputs:

- `reference/session-compatibility-v0/**`, which is an immutable offline
  evidence corpus only;
- `Deep.Protocol.Native*`, including recovery/PQ experiments;
- consumer runtime orchestration, databases, transport deployment and key
  custody.

## Clean-Break Rules

- No Session compatibility shim, type forward, reflection bridge, legacy
  package, resource, public API or fallback.
- Do not relabel DPE1/DPB1 bytes as a native payload.
- Ed25519 signing and X25519 agreement keys are independent; conversion is
  forbidden in DNP1.
- Existing reviewed D--G bytes, domains and public APIs remain byte/API
  identical unless a later frozen specification explicitly replaces them.
- Unknown suites, old generations and hostile sizes reject before allocation
  or callbacks as required by the registry.
- A package candidate does not authorize publication, consumer reset, or a
  production/security claim. Follow the normative activation order.

## Required Verification

```powershell
dotnet restore Deep.Protocol.slnx
dotnet build Deep.Protocol.slnx --no-restore
dotnet test Deep.Protocol.slnx --no-build --collect:"XPlat Code Coverage" --results-directory artifacts/test-results
powershell -NoProfile -File eng/Test-LegacyReferenceCorpus.ps1
powershell -NoProfile -File eng/Test-ProductionProtocolGraph.ps1 -Configuration Debug
$mappings = @(
  'artifacts/dnp1-vector-fragments/authority-recovery.json',
  'artifacts/dnp1-vector-fragments/drm3-recovery.json',
  'artifacts/dnp1-vector-fragments/identity.json',
  'artifacts/dnp1-vector-fragments/recovery-exact193.json',
  'artifacts/dnp1-vector-fragments/wire.json',
  'artifacts/dnp1-vector-fragments/drm19-replay.json',
  'artifacts/dnp1-vector-fragments/drm19-recovery-container.json',
  'artifacts/dnp1-vector-fragments/devops-package.json',
  'artifacts/dnp1-vector-fragments/genesis-full-dag.json'
)
& ./eng/Test-Dnp1EvidenceOwnership.ps1 -MappingPaths $mappings -RequirePackageComplete
```

Run `Deep.Protocol.Dark.slnx` independently only when changing the dark path.
It is not part of production closure verification.

## Acceptance Gates

A change is complete only when:

- exact canonical bytes have positive and negative vector coverage;
- parsers enforce arithmetic and allocation bounds before callbacks;
- assembly metadata, resources, public APIs, nuspec dependencies, lock graphs
  and package ZIP entries pass the actual-artifact gates;
- the production solution contains only the exact-three source projects and
  their tests, with no Native or legacy project reference;
- the offline corpus hash manifest still verifies;
- downstream reset/repin impact is recorded for public-surface changes.
- package evidence is complete only with all 216 Protocol-owned rows and the
  exact three package-blocking DevOpsWitness rows; consumer-owned evidence is
  never relabeled as Protocol evidence.

## Stop-The-Line Conditions

- Session or quarantined compatibility material enters build/runtime/package.
- `Deep.Protocol.Native*` enters the exact-three graph.
- Reviewed D--G wire/API changes without a separately frozen authorization.
- A new wire format or domain is invented outside the machine registry.
- A production path uses fake crypto or claims unavailable confidentiality/PQ.
- Package checks inspect source names only instead of produced artifacts.

## Workflow

1. Read this file, DR-0003, and every frozen normative registry/schema/vector
   file relevant to the work.
2. Confirm the exact authorized source scope and excluded dirty files.
3. Add or update canonical/negative gates.
4. Implement the smallest fail-closed change.
5. Build and test the exact-three graph; verify actual package artifacts.
6. Report consumer reset/repin impact. Do not publish or reset consumers
   without the separate ordered GO.
