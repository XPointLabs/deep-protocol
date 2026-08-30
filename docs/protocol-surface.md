# Protocol Surface - DNP1 Wave 1

Updated: 2026-08-30.

The production package closure is exactly `Deep.Protocol`,
`Deep.Protocol.MembershipRoutes`, and `Deep.Protocol.ProfileCarrier`.

## Production surface

`Deep.Protocol` contains the retained Deep mailbox, membership, authority and
managed-ingress primitives. Its only direct NuGet dependency is
`Sodium.Core`. It has no project dependency on a legacy protocol assembly.

`Deep.Protocol.MembershipRoutes` depends exactly on `Deep.Protocol` and owns
the reviewed D--G route-continuity surface. D--G bytes, domains and public APIs
remain unchanged by the Wave 1 quarantine.

`Deep.Protocol.ProfileCarrier` retains its existing carrier surface and exact
`Deep.Protocol` package dependency.

## Explicit exclusions

- `Deep.Protocol.Native*` is a separate source/test dark path and is absent
  from the production solution and package/consumer graph.
- Session, protobuf, P03A compatibility, DPB/DPE, Nearby and LoRa material is
  retained only in `reference/session-compatibility-v0` as immutable offline
  evidence. It is not compiled, embedded, packed or loaded at runtime.
- Shared/MAUI legacy Session messaging is not made DNP1-native by renaming old
  bytes. The active application message path uses its separately reviewed E2EE,
  MAU2 and Deep privacy-routing contracts; it is outside the DNP1 classical
  Wave 1 surface. A DNP1-native message/ratchet successor remains absent.

## DNP1 classical Wave 1

The DNP1 classical identity/reset/MRL2 design is frozen in docs repository
commit `2562b11cdacdcc6e60cf79bdb6265b4f4687fbbe` (36 records,
158 domains and 314 executable vector IDs). `Deep.Protocol` implements the
classical grammar, closed artifact registry, relative identity/revocation and
ReleaseRoot chains, protected cutover state, recovery-candidate parsing,
MRL2/RIP2 membership, native peer frames and the protected outer-peer journal.

The DRM20 first-deployment author path is constructible through sealed facts:
governance and reset reservation, dual-signed DCM distribution, genesis base
identity and release head, transaction/key/protector contexts, DTC2/RSM2/DRC,
durable GAS/GQP/GAJ state, exactly three selected witness DCN receipts,
canonical DCQ/GQS, dedicated-key DPL materialization, and external then local
commit. Witness callbacks receive only Protocol-created bounded requests;
immediately before them Protocol performs one consumer-owned bounded current
DWD/RRL/WHL read, HMAC-verifies and byte-compares it to the sealed release
context, and aborts before all selected witnesses if that head moved;
their returned DCN bytes are re-decoded, signature/tree/window verified and
aggregated by Protocol before any GQS or commit transition.

The forward commit API has no short, unchecked publication overload. It
replays and byte-compares the sealed reset and transaction reservations,
artifact set, quorum Pending and author journal, and revalidates the protected
key-set and recovery-protector sources before and after consumer CAS calls and
journal transitions. It also rereads and authenticates the exact DWD/RRL/WHL
head immediately before and after the external zero-to-one CAS. Movement
before the external CAS publishes nothing;
movement after an external or local CAS returns no continuation capability and
is recoverable only through the authenticated replay phase matrix.

Every public verification result is sealed, defensively owned and explicitly
relative or data-only. Caller keys, raw pins and callback booleans cannot mint
deployment authority. Recovery output has `NoAuthorityClaim`; ReleaseRoot
genesis remains pinned by each consumer's immutable deployment source.
Protocol never claims persistence, durability, publication, activation or a
successful consumer CAS.

The package candidate is not a clean-break production activation until the
reviewed exact-three closure is atomically repinned by each authorized
consumer and its protected state is reset under the separate cutover plan.
