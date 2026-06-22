# Deep.Protocol

Managed C#/.NET 10 port of the shared Session application protocol surface from
`session-foundation/libsession-util`.

This repository preserves protobuf and envelope wire semantics where they are unambiguous and keeps
libsodium-dependent behavior behind adapter interfaces. Code paths that require exact Session crypto
do not invent replacement formats.

## Agent Specs

- Start with [`AGENTS.md`](AGENTS.md) before changing protocol, protobuf, crypto adapter, vector, or fuzz behavior.
- Use [`docs/SESSION_PORTING.md`](docs/SESSION_PORTING.md) for Session wire/protobuf/crypto porting rules.
- Read `docs/unsupported-or-unspecified.md` before wiring any incomplete protocol surface into production.

## Projects

- `Deep.Protocol.Abstractions`: protocol models, state models, crypto/onion adapter interfaces.
- `Deep.Protocol.Protobuf`: C# classes generated from upstream `SessionProtos.proto` and `WebSocketResources.proto`.
- `Deep.Protocol`: managed protocol codec, padding, envelope/community parsing, state helpers.
- `Deep.Protocol.GoldenVectors`: deterministic parity fixtures.
- `Deep.Protocol.Tests`: unit tests and golden-vector harness.

## Build

```powershell
dotnet restore Deep.Protocol.slnx
dotnet build Deep.Protocol.slnx --no-restore
dotnet test Deep.Protocol.slnx --no-build --collect:"XPlat Code Coverage" --results-directory artifacts/test-results
```

See `docs/unsupported-or-unspecified.md` before wiring this into production crypto bindings.
