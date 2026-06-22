# Agent Specification - Deep Protocol

Last updated: 2026-06-10.

## Mission

`deep-protocol` owns the managed .NET protocol surface for Deep. It preserves Session wire/protobuf/envelope semantics where specified and keeps crypto-sensitive behavior behind explicit adapters and tests.

This repo is a parity gate. Do not invent replacement wire formats when Session semantics are required.

## Source Of Truth

- Workspace entry point: `../prompts/00_Agent_Entry_Point.md`.
- Protocol surface: `docs/protocol-surface.md`.
- Compatibility matrix: `docs/compatibility-matrix.md`.
- Verification report: `docs/protocol-verification-report.md`.
- Unsupported/unspecified areas: `docs/unsupported-or-unspecified.md`.
- Porting rules: `docs/SESSION_PORTING.md`.

## Ownership Boundaries

Owned here:

- protocol models and abstractions,
- generated protobuf C# bindings,
- managed codecs/parsers/padding/envelope helpers,
- crypto adapter interfaces and sodium-backed adapters,
- golden vectors, differential tests, parser/codec fuzz smoke tests.

Not owned here:

- Client runtime orchestration,
- router/runtime transport,
- storage/file/push service contracts,
- staking semantics.

## New Deep Solution Rules

New protocol APIs must be explicit about whether they are:

- Session-compatible,
- Deep extension,
- test-only helper,
- placeholder pending crypto/upstream verification.

Deep extensions must not collide with Session namespaces or protobuf fields. Add docs and tests before exposing them to clients/services.

## Session Compatibility Rules

- Preserve protobuf field numbers, envelope layouts, padding rules, namespace semantics, and known vector behavior.
- Crypto behavior must use adapter interfaces and verified implementations. Do not substitute fake crypto outside tests.
- Missing upstream semantics must be documented in `docs/unsupported-or-unspecified.md`.
- Every parser/codec change needs golden-vector or differential coverage where possible.

## Required Verification

```powershell
dotnet restore Deep.Protocol.slnx
dotnet build Deep.Protocol.slnx --no-restore
dotnet test Deep.Protocol.slnx --no-build --collect:"XPlat Code Coverage" --results-directory artifacts/test-results
```

Run focused fuzz/differential tests when changing parsers or codecs.

## Acceptance Gates

A protocol change is complete only when:

- wire-visible behavior has vector or differential coverage,
- malformed input behavior is tested for parsers,
- unsupported semantics are documented,
- downstream repo impact is noted when public APIs change,
- generated protobuf changes include source `.proto` context.

## Stop-The-Line Conditions

- A production path uses fake crypto.
- A wire format is changed without vector evidence.
- Parser fuzz coverage is removed or weakened.
- Unknown Session semantics are guessed and shipped as final.
- Protocol docs are stale after a public-surface change.

## Agent Workflow

1. Read this file and `docs/SESSION_PORTING.md`.
2. Locate the relevant protocol docs and tests.
3. Add/update vectors or fuzz tests first.
4. Implement the smallest codec/model change.
5. Run protocol build/tests.
6. Update compatibility and unsupported docs.
