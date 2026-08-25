# Deep Protocol agent rules

The workspace rules in `../AGENTS.md` apply. This file defines the protocol-specific closure.

## Production boundary

The production package graph is exactly `Deep.Protocol`, `Deep.Protocol.MembershipRoutes` and
`Deep.Protocol.ProfileCarrier`. `Deep.Protocol.Native*` is an isolated dark path and must remain
absent from production projects, packages, resources and consumer lock graphs.

Frozen DNP1 registries, schemas, vectors and evidence ownership under the superproject's
`docs/survival-program/releases/v3.0.0/specs/` are normative. Do not infer missing grammar or
change reviewed D--G bytes/domains/APIs without a separately frozen authorization.

## Repository rules

- No Session shim, migration, type forward, alias, reflection bridge or compatibility fallback.
- `reference/session-compatibility-v0/**` is immutable offline evidence only; it never builds,
  packages or executes in production.
- Ed25519 signing and X25519 agreement keys are independent; conversion is forbidden.
- Unknown suites/generations, non-canonical encodings and hostile sizes reject before allocation,
  mutation or callbacks as required by the frozen registry.
- Positive vectors require matching malformed, replay and boundary coverage.
- Validate actual assemblies, package ZIP entries, public APIs, resources and dependency graphs;
  source-name checks alone are insufficient.
- Record downstream reset/repin impact for every production-surface change. Do not publish or
  reset consumers without separate authorization.

## Verify

```powershell
dotnet restore Deep.Protocol.slnx
dotnet build Deep.Protocol.slnx --no-restore
dotnet test Deep.Protocol.slnx --no-build
./eng/Test-LegacyReferenceCorpus.ps1
./eng/Test-ProductionProtocolGraph.ps1 -Configuration Debug
```

Run the evidence-ownership gate with the applicable mapping fragments. Run
`Deep.Protocol.Dark.slnx` separately only for an authorized dark-path change.
