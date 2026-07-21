# Deep exact profile carrier V1

Status:

`REVIEW-PENDING / ED25519-VERIFY-ONLY-CANDIDATE / CLIENT-ACTIVATION-NO-GO /
EXTERNAL-CRYPTO-PROFILE-REVIEW-PENDING`

`Deep.Protocol.ProfileCarrier` owns the unsigned `DPF1` carrier format shared
by profile producers and clients. It is a Deep extension, not Session wire
behavior. It does not modify protobufs or Session namespaces.

## Trust boundary

The package depends on exactly `Deep.Protocol 0.3.0-p04.b887fa0`, source
commit `b887fa088f486390be182cac4cbcb59b60ce8931`, contract
`Deep.Protocol/P04-canonical-v1`, plus exact direct verify-only dependencies
`Sodium.Core 1.4.1` and `libsodium 1.0.22`.

The carrier package owns only:

- deterministic `DPF1` framing and minimal unsigned LEB128;
- fixed component order and public bounds;
- deterministic public genesis-approval encoding;
- exact parse, P04 verification and byte-for-byte recomposition.

P04 remains the sole authority for canonical genesis, delegations, bridges,
signature domains, signer roles, quorum policy, network and policy binding,
validity, protocol compatibility, sequence and previous-hash verification.
The carrier package calls P04 for every signed artifact. It has no signing,
secret-key, key-generation, endpoint-selection, persistence, network,
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
artifacts and returns `ProfileCarrierComposition`, the deterministic exact
carrier including its raw payload for an operator-controlled export path.

`ProfileCarrierVerifier.VerifyExact` parses, verifies and recomposes an
existing carrier. Success requires byte-for-byte equality with the canonical
recomposition. Its least-privilege `ProfileCarrierVerificationResult` exposes
only a bounded payload hash, genesis fingerprint, signed protocol range and
component counts. It never returns the raw payload, canonical signed
components, signatures, contacts or endpoints, and it does not expose an
activation handle.

The client must consume this package rather than implement another parser.
The dormant client `DSIG` genesis-only envelope is not a `DPF1` format and
must not be converted into one or used as an activation path.

## Dormant transition and Ed25519 prerequisites

`ProfileCarrierTransitionVerifier.VerifyExact` independently reverifies the
previous and candidate carrier using separate trusted time snapshots. During
that call only, it derives the verified delegation statement commitment and
the bounded ordered bridge `(sequence, canonical-statement-hash)` chain. The
projection is never added to the public verification result and its mutable
commitment buffers are cleared on every return and exceptional path.

The verifier returns only one fixed decision: exact `Idempotent`, alternate
quorum `EquivalentSameState`, exact-prefix `ForwardSameGenesis`,
`ExplicitNetworkSwitchCandidate`, `RollbackRejected`, `ForkRejected`, or
`TrustRejected`. A different genesis is never an update. DPF1 v1 represents
only the genesis-rooted delegation step: a same-sequence different statement
is a fork, while lower/higher delegation rotation fails P04 and remains
unsupported. No transition decision persists or activates a profile.

`SodiumEd25519MembershipSignatureVerifier` is a sealed detached-verification
candidate. It accepts only exact 16-byte signer IDs, 32-byte public keys,
64-byte signatures and already framed P04 bytes whose first 16 bytes equal the
selected fixed domain tag. It verifies those supplied bytes once without
rehashing or reframing. It has no signing, key-generation or custody surface.
External cryptographic/profile review remains pending.

## Offline package source

Every solution project has an exact lock file. The package source is
`vendor/p14-profile-carrier/packages`; the exact 21-file name, hash and size
set is pinned by `eng/p14-profile-carrier.offline-packages.json`. The mandatory
isolated restore/build/test/pack gate is:

```powershell
eng/verify-p14-profile-carrier-offline.ps1
eng/verify-p14-profile-carrier-reproducible.ps1
eng/verify-p14-profile-carrier-provenance.ps1 -XNodeRoot C:\path\to\pinned\xnode
```

The first gate uses isolated empty NuGet and CLI homes, an explicit cleared
NuGet configuration, locked restore, a dead network proxy, exact dependency
asset allowlisting and ancestor build/config injection checks. The second
proves deterministic binary and normalized package identity across two clean,
randomized extraction paths. The third verifies the accepted XNode
commit/tree/blob identities and executes the source-to-source differential
oracle. All three gates are required for review;
their existence is not a production approval.

The same offline gate proves exact path, length and SHA-256 for the native
libsodium assets carried for `win-arm64`, `win-x64`, `linux-arm64`,
`linux-x64` and `android-arm64`, without downloading runtime packs or mutating
one lock file across RIDs. Host Windows ARM64 build and provider KAT run here.
Cross-RID execution is explicitly `CROSS-RID-EXECUTION-PENDING`: Linux belongs
to the P14C3 XNode/container rebind, and Android/Windows client execution to
P14A2b. The preflight rejected sequential RID locked restores because they
would mutate the lock (`NU1004`) and require runtime packs outside the exact
offline closure (`NU1101`).

## Deterministic source identity

The carrier project maps every physical extraction root to the fixed logical
source root `/_/Deep.Protocol.ProfileCarrier`. The reproducibility gate
archives the exact clean commit into two independently randomized paths,
restores each into an empty cache, and requires byte-identical release DLL and
portable PDB outputs.

NuGet packages are OPC/ZIP containers whose relationship and core-property
parts may contain random identifiers. Therefore a raw `.nupkg` SHA-256 is
reported only as `exact-carrier-file-only-sha256`; it is never a reproducible
source identity. `Get-P14ProfileCarrierNormalizedIdentity.ps1` rejects entries
outside the exact semantic/OPC allowlist, requires the root relationships to
bind the actual nuspec and core-property part with the exact OPC types,
requires the exact sorted content-type model, and validates canonical core
properties against nuspec semantics. Only relationship IDs, the GUID core-part
name, and a valid optional creation timestamp are normalized. The canonical
OPC model, canonical nuspec and exact README/DLL/portable-PDB bytes are all
hashed. The two clean packs must produce the same
`normalized-source-identity-sha256`.

The provenance gate reads objects from the supplied XNode repository but does
not build its current checkout. It materializes the exact accepted
`eff452368fa4cb1324c5b3c8ee06e2f10e96b835` tree with `git archive`, verifies
the complete 167-file materialized tree against every accepted Git blob,
proves a deliberate source drift is rejected, and only then runs the
differential build from that exact tree.

Production signer custody and ceremony, client trust
persistence, runtime registration, UI, networking and activation remain
separate blocked work.
