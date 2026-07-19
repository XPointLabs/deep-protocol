# Deep exact profile carrier V1

Status:

`DORMANT-EXACT-CARRIER-GO / PRODUCTION-VERIFIER-NO-GO / ACTIVATION-NO-GO`

`Deep.Protocol.ProfileCarrier` owns the unsigned `DPF1` carrier format shared
by profile producers and clients. It is a Deep extension, not Session wire
behavior. It does not modify protobufs or Session namespaces.

## Trust boundary

The package depends on exactly `Deep.Protocol 0.3.0-p04.b887fa0`, source
commit `b887fa088f486390be182cac4cbcb59b60ce8931`, contract
`Deep.Protocol/P04-canonical-v1`.

The carrier package owns only:

- deterministic `DPF1` framing and minimal unsigned LEB128;
- fixed component order and public bounds;
- deterministic public genesis-approval encoding;
- exact parse, P04 verification and byte-for-byte recomposition.

P04 remains the sole authority for canonical genesis, delegations, bridges,
signature domains, signer roles, quorum policy, network and policy binding,
validity, protocol compatibility, sequence and previous-hash verification.
The carrier package calls P04 for every signed artifact. It has no signing,
private-key, key-generation, endpoint-selection, persistence, network,
dependency-injection or activation API.

## Exact framing

All integers are unsigned. `varuint` is minimal unsigned LEB128.

1. ASCII magic `DPF1`
2. version byte `1`
3. component-count byte
4. total component-body length as `varuint`
5. each component: type byte, byte length as `varuint`, exact bytes

The component order is:

1. canonical P04 genesis;
2. exactly three public P04 genesis approvals, ordered by signer ID;
3. canonical P04 signed delegation with exactly three offline approvals;
4. one or more canonical P04 signed bridges, ordered by sequence and then
   canonical bytes, each with exactly two online approvals.

The maximum file payload is 49,152 bytes, each component is at most 16,384
bytes, and the component count is at most 16. The accepted XNode source
`eff452368fa4cb1324c5b3c8ee06e2f10e96b835` is pinned by the public synthetic
golden vector in `tests/Deep.Protocol.ProfileCarrier.Tests/Vectors`.

## API and downstream use

`ProfileCarrierComposer.ComposeExact` verifies caller-provided public P04
artifacts and returns the deterministic exact carrier.

`ProfileCarrierVerifier.VerifyExact` parses, verifies and recomposes an
existing carrier. Success requires byte-for-byte equality with the canonical
recomposition. The result exposes defensive copies of the exact payload and
payload hash plus a genesis fingerprint, signed protocol range and component
counts. It does not expose an activation handle.

The client must consume this package rather than implement another parser.
The dormant client `DSIG` genesis-only envelope is not a `DPF1` format and
must not be converted into one or used as an activation path.

## Offline package source

The project and its test project have exact lock files. Their package source
is `vendor/p14-profile-carrier/packages`; its hashes and sizes are pinned by
`offline-closure-manifest.json`. Reproduce a locked restore without network
sources:

```powershell
dotnet restore tests/Deep.Protocol.ProfileCarrier.Tests/Deep.Protocol.ProfileCarrier.Tests.csproj `
  --configfile eng/p14-profile-carrier.NuGet.Config `
  --locked-mode
dotnet test tests/Deep.Protocol.ProfileCarrier.Tests/Deep.Protocol.ProfileCarrier.Tests.csproj `
  --no-restore --configuration Release
```

Production signature verification, signer custody and ceremony, client trust
persistence, runtime registration, UI, networking and activation remain
separate blocked work.
