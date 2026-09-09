# Protocol Surface - DNP1 Wave 1

Updated: 2026-09-07.

The production package closure is exactly `Deep.Protocol`,
`Deep.Protocol.MembershipRoutes`, and `Deep.Protocol.ProfileCarrier`.

## Production surface

`Deep.Protocol` contains the retained Deep mailbox, membership, authority and
managed-ingress primitives. Its only direct NuGet dependency is
`Sodium.Core`. It has no project dependency on a legacy protocol assembly.

`Deep.Protocol.Identity` contains production `DeepRecoveryV1`: exact 24-word
English BIP-39 verification/generation, the frozen PBKDF2/HKDF derivation, a
generation-one floor, permanent Deep ID address material and sealed,
role-specific Ed25519 account-authority capabilities. It exports no entropy,
role seed, PQ-signing or Ed25519/X25519-conversion surface and derives no device key.

`Deep.Protocol.MembershipRoutes` currently depends on `Deep.Protocol` and owns
the reviewed D--G route-continuity evidence. DR-0004 makes those bytes
pre-cutover/release-rejected; only their tested continuity/CAS properties are
ported to PMA2/PMT2/PMS2 and XRA1/XRC1/XRR1/XSS1. No compatibility reader is a
target production surface.

`Deep.Protocol.ProfileCarrier` retains its existing carrier surface and exact
`Deep.Protocol` package dependency.

`Deep.Protocol.ContactV1` contains the frozen, inactive CONTACT-CODEC parser
and structural closure grammar. Ed25519 promotion is protocol-owned: no public
signature callback or accept-all verifier can mint a bundle or route result.
`VerifiedContactBundleClosure` additionally requires an unforgeable witnessed
ADL1/ADH1 freshness capability, and route promotion requires a distinct
`VerifiedContactRouteClosure` rooted in exact XNV1/XNH1/ADH1 witness authority
and one trusted instant. These capability producers are deliberately not wired
into the production composition, so `ContactCodec.RuntimeActivation` remains
false and parsing does not authorize state mutation or emission.

`Deep.Protocol.DeepExtension.PrivacyRouting` contains the implemented frozen
ONION-01 XRF1/XRL1/XRE1/XPR1/XRS1 codec and deterministic conformance seam. Its
production public API remains inactive. The only authorized successor surface is
the sealed section-7 capability boundary: verified XNA1/XVP1/XNV1/XND1 plus non-wire
DTT1-backed XTT, exact-three path/receive-position capabilities, mandatory durable
replay transaction/key lease, separate exit/client reply contexts, closed
operation-specific exact MAU2/MQR3/MRP1/MAR1 and ContactV1 request/result-pairing
verifiers, and a protected CSPRNG uniqueness
authority. Internal vector helpers and process-local replay memory are not a
release API or durability claim.

## Explicit exclusions

- `Deep.Protocol.Native*` and its dark solution no longer exist. Production and
  lock/package gates reject any reintroduced project edge, source token or build artifact.
- Session, protobuf, P03A compatibility, DPB/DPE, Nearby and LoRa material is
  retained only in `reference/session-compatibility-v0` as immutable offline
  evidence. It is not compiled, embedded, packed or loaded at runtime.
- Shared/MAUI legacy Session messaging is not made DNP1-native by renaming old
  bytes. The active application message path uses static-key E2EE, MAU2 and
  pre-cutover Deep privacy-routing contracts; it is outside the DNP1 classical Wave 1
  surface and is not releasable. The DNP1-native message/ratchet successor is
  specified in the superproject architecture/crypto documents but remains
  absent from production packages and consumers.
- The frozen XRF1/XRL1/XRE1/XPR1/XRS1 codec is implemented, but its sealed
  production capability producers, asynchronous public API and runtime composition
  are absent/inactive. PMA2/PMT2/PMS2 route-authority activation remains a separate
  producer gate; codec presence cannot substitute for it.

## DNP1 classical Wave 1

The DNP1 classical identity/reset/MRL2 design is frozen in docs repository
commit `2651599913bf92c021d36b6a53395499b6a091fb` (36 records,
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
