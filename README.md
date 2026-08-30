# Deep Protocol

Production protocol libraries for Deep messaging, membership routes and self-hosted profile
carriers. The repository targets .NET 10 and is a clean-break implementation: production packages
contain no compatibility shims, aliases or fallback runtime paths.

## Start here

- [`AGENTS.md`](AGENTS.md) defines the production boundary and required checks.
- [`docs/protocol-surface.md`](docs/protocol-surface.md) lists the implemented protocol surface.
- [`docs/unsupported-or-unspecified.md`](docs/unsupported-or-unspecified.md) records surfaces that
  must not be wired into production.
- The extension specifications in [`docs/`](docs/) are the repository-level contracts.
- The superproject's `docs/survival-program/releases/v3.0.0/specs/` contains the frozen DNP1
  registries, schemas and ownership rules.

## Production projects

- `Deep.Protocol`: canonical codecs and cryptographic protocol behavior.
- `Deep.Protocol.MembershipRoutes`: signed membership and mailbox route contracts.
- `Deep.Protocol.ProfileCarrier`: bounded self-hosted profile carrier contracts.

The former `Deep.Protocol.Native` dark identity path has been clean-break promoted into
`Deep.Protocol.Identity` and removed. `reference/session-compatibility-v0/` remains immutable offline
evidence and must never be packaged or executed by a client, service or node.

## Verify

```powershell
dotnet restore Deep.Protocol.slnx
dotnet build Deep.Protocol.slnx --no-restore
dotnet test Deep.Protocol.slnx --no-build
./eng/Test-LegacyReferenceCorpus.ps1
./eng/Test-ProductionProtocolGraph.ps1 -Configuration Debug
```
