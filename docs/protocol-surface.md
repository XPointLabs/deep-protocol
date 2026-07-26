# Protocol Surface

Source of truth: `session-foundation/libsession-util` at commit
`3033fbc7485a72afb2715931ff5eba324ff64594`.

Primary upstream areas reviewed:

- `include/session`
- `proto`
- `src`
- `tests`
- `docs/api`

## Managed Projects

`Deep.Protocol.Protobuf` generates C# classes directly from the upstream proto2 schemas:

- `SessionProtos.proto`
- `WebSocketResources.proto`

`Deep.Protocol.Abstractions` defines:

- identity constants and `SessionId`
- envelope, destination, Session Pro, decode result models
- `ISessionProtocolCrypto` for libsodium-compatible operations
- `IProtocolHashing` for personalized BLAKE2b-256
- onion request adapter surface matching the `ENABLE_ONIONREQ` area
- one-to-one state and group update domain events
- shared config namespace state models and merge outcomes

`Deep.Protocol` implements:

- 160-byte Session padding with `0x80` terminator
- Pro feature classification for UTF-8 and UTF-16 message text
- one-to-one websocket-wrapped envelope build/parse
- groups v2 envelope build/parse through crypto adapter boundaries
- community compatibility parsing for both `Content` and `Envelope`
- Session Pro proof extraction/status evaluation once crypto/hash adapters are supplied
- group update extraction from existing protobuf messages
- onion request encryption name mapping and adapter handoff
- sodium-backed onion request build/decrypt + response envelope parsing
- shared config envelope parsing and namespace seqno-based merge state machine
- opt-in Deep-extension opaque bundle V1 encoding/decoding and version negotiation, isolated in
  `Deep.Protocol.DeepExtension.OpaqueBundles`
- P03A authenticated compatibility-envelope orchestration and production crypto/replay interfaces,
  isolated in `Deep.Protocol.DeepExtension.CompatibilityEnvelopes`; no production crypto
  implementation or runtime registration is shipped
- P03B canonical mailbox capability, free-admission and accepted/durable receipt contracts,
  isolated in `Deep.Protocol.DeepExtension.MailboxCapabilities`; crypto, replay and capability
  production remain host-provided interfaces with no production registration
- strict authenticated mailbox V2 `MCG2`/`MCP2`, peer `MIP1`/`PRQ1` and aggregate ACK `MAR1`
  contracts in the same isolated namespace; sodium Ed25519 adapters are available but no keys,
  durable replay/revocation store, runtime registration or transport is supplied
- dormant P09C client mailbox `MEO1`/`MST1`/`MRT1`/`MRP1`/`MAK1` frames, explicit adjacent
  `E/E+1` overlap, local-only delivered transition and placement/membership-bound `MRR2`/`MQR2`
  receipts in the same isolated namespace; no runtime activation or default changes
- additive P10B `PRQ2` peer Store/Tombstone request with Ed25519/SHA-256 router, freshness and
  durable replay binding, plus dormant exact HTTP metadata for `MST1`/`MRT1`/`MAK1` and native
  `MQR2`/`MRP1`/`MAR1` responses
- P03C contact-scoped nearby rendezvous, canonical handshake framing, replay scope and
  platform-neutral lifecycle, isolated in `Deep.Protocol.DeepExtension.NearbyHandshakes`; the
  mutually authenticated AKE remains a blocked host adapter with no production implementation
- DPF1 exact self-hosted profile carrier composition and verification, isolated in the
  `Deep.Protocol.ProfileCarrier` package and
  `Deep.Protocol.DeepExtension.SelfHostedProfiles`; it is an unsigned wrapper over the exact
  pinned P04 authority and has no signer, network, persistence or activation API

## Wire Semantics Preserved

- No new protobuf fields are introduced.
- Proto classes are generated from the upstream schemas without schema edits.
- 1:1 payloads are padded before content encryption.
- 1:1 envelopes are wrapped in `WebSocketMessage.request.body`.
- Group v2 messages encrypt the serialized `Envelope` through a crypto adapter.
- Community messages accept both transition formats documented in `SessionProtos.proto`.
- Envelope `proSig` is kept as a 64-byte field and only interpreted when a `Content.proMessage`
  exists.

## Adapter Boundaries

The managed library ships a production default crypto/hash adapter (`SodiumSessionProtocolCrypto`)
and also keeps explicit extension points for hosts that require alternative native bindings.

Custom hosts may provide:

- Ed25519 seed normalization, signing, verification
- Ed25519 to X25519 public key conversion
- Session `encrypt_for_recipient` and `decrypt_incoming`
- blinded recipient encryption
- groups v2 encrypt/decrypt semantics
- personalized BLAKE2b-256
- onion request build/decrypt behavior

Remaining upstream parity gaps are documented in `unsupported-or-unspecified.md`.

## Deep extension isolation

The opaque bundle V1 contract is not Session-compatible wire behavior and does not modify generated
protobufs, Session namespaces or existing vectors. It is disabled unless a host completes explicit
feature negotiation. See `deep-extension-opaque-bundle-v1.md`.

P03A adds an explicitly negotiated payload kind that can carry exact DPE1 bytes only after a future
sender-authenticated recipient-encryption adapter seals them. Current sodium sealed-box adapters do
not prove control of the claimed application sender key, so they are not registered for P03A.
Production activation remains blocked by `docs/adr/0001-p03a-compatibility-metadata-envelope.md`.

P03B adds three non-convertible runtime/wire domains (deposit, retrieve and placement), bounded
generation/lifecycle/overlap/replay/idempotency fields, and canonical `MRR1`/`MQR1`/`MBE1`
receipts. A durable quorum verifies two different replica identifiers and signatures plus a
coordinator signature over ordered receipt digests, then binds the verified result to the caller's
expected operation/generation/payload/tombstone context. Replay guards distinguish new,
idempotent-retry, stale-replay and conflict decisions. The library does not claim opaque bytes are
secret or unlinkable and does not create keys, persist lifecycle/replay state, execute storage,
choose a signature/digest primitive, apply billing, or enable a runtime feature.

The strict V2 profile addresses the opaque MCP1 authority gap without changing or converting MCP1.
An offline/self-hosted, mailbox/domain-scoped Ed25519 issuer signs fixed `MCG2`; the authorized
holder signs an exact Store/Retrieve/Ack `MCP2`. Both bind network, epoch, generation, membership,
placement, validity, operation ID, replay counter and canonical request digest. Deposit authorizes
only Store; retrieve authorizes only Retrieve/Ack. A host supplies trusted issuer keys, durable
revocation state and an atomic replay journal. Typed MEO1/MBR2/MBA2 transcripts and the strict
`MAU2` carrier prevent a caller-supplied digest or mixed V1/V2 outer wrapper. Issuer authority
entries constrain key/domain/generation/lifecycle/hard validity. No Session ID, payer, wallet, subscription or
payment entitlement is present.

P09C extends that dormant surface additively. Fixed 32-byte `BlindedMailboxId` and
`BlindedPlacementId` types keep raw Session/user identity out of canonical frames. `MEO1` bounds
opaque ciphertext to 32..81768 bytes, the complete frame to 81920 bytes, and TTL to 60
seconds..7 days. Store accepts only deposit
presentations; retrieve and ack accept only retrieve presentations. Pages contain at most 100
items, continuation tokens are at most 256 bytes, and encoded retrieve pages are at most 1 MiB.
Every retrieved item binds a strictly increasing cursor to its envelope and derives the matching
ack entry from the envelope's exact deduplication/ack digest.
`MRR2` conceptually maps the xnode `a193dcc` storage-router/mailbox/blob/expiry/stored-at/disposition
receipt while additionally binding operation, epoch, cursor, placement and membership commitment.
It is not byte-compatible with the implementation-local xnode JSON receipt. See
`adr/0005-p09c-client-mailbox-wire-contract.md`.

`PRQ1` authenticates exact MEO1 Store replication or a 32-byte tombstone digest between two
membership-proven storage replicas. `MIP1` has a concrete `RIP1` adapter in
`Deep.Protocol.MembershipRoutes`, verifying replica identity, Ed25519 key, Storage role/capability,
epoch, validity and MRL1 Merkle inclusion against the exact commitment. Responses remain signed
`MRR2`/`MQR2`, with factories/verification derived from PRQ1 and exact MIP1 keys; RouterId and
Ed25519 key are independent fields. Placement commitment is one domain-separated SHA-256 of the
blinded placement ID. `MAR1` orders at most 100 exact tombstone `MQR2` receipts and adds no new durability
meaning.

P10B preserves every P03B2 frame and adds `PRQ2` version 2. It signs a SHA-256
operation-domain-framed digest with the sender MIP1 Ed25519 key and binds sender/recipient router
IDs, operation, epoch/cursor, mailbox/placement/membership, exact payload/digest/expiry, creation
time and a 32-byte durable replay nonce. Replay records persist through bounded epoch expiry plus
seven days and use bounded GC. The recipient returns one durable native `MRR2` after persistence;
two exact MIP1-keyed replicas form an MQR2 whose coordinator sequence binds the complete signed
PRQ2 and rejects the PRQ1 cursor convention. Dormant public client metadata maps Store to `MQR2`,
Retrieve to `MRP1`, and exact MAK1 order to bounded verified `MAR1(MQR2[])`; exact routes, media
types, limits and empty-body error statuses are in
`adr/0012-p10b-mailbox-wire-and-ingress-contract.md`.

P03C adds fixed `NRV1` advertisements and bounded `NHS1` initiator/responder frames. The public
orchestrator passes exact canonical transcript bytes, expected contact identity, period,
resumption counter, bundle version and hop-local attempt ID through
`INearbyAuthenticatedKeyExchange`. Stable peer identity and session key material appear only after
adapter authentication and replay acceptance. No radio transport, permission, UI, background
scheduler, production AKE adapter or runtime registration is included.

P04 separates canonical network genesis, offline-root delegation/revocation, public bridge
discovery, node-only membership commitments and fork witnesses. The approved Beta policy is
canonical policy data: three of five offline roots authorize a time-bounded three-signer online
set, and two distinct active online signers authorize bridge or membership statements. Bridge
snapshots contain public entry contacts, not full core/storage membership. Signature verification,
durable last-known-good state, registry/client integration and production keys remain outside this
library.

`Deep.Protocol.MembershipRoutes` is a separate Deep-extension package that gives the opaque
`MemberCommitment` leaf a bounded, canonical route-descriptor meaning for the route-activation
migration. An `MRL1` leaf binds router identity, Ed25519 and X25519 public keys, an authority-only
RPC endpoint, roles, capabilities, epoch and validity. Domain-separated SHA-256 leaf/node hashes,
power-of-two empty-leaf padding and exact-depth inclusion proofs bind each descriptor to a P04
membership root. It does not sign or publish a catalog and contains no signer keys.

DPF1 V1 adds one deterministic unsigned carrier around canonical P04 genesis, public genesis
approvals, a canonical signed delegation and canonical signed bridges. Exact parse success requires
P04 verification followed by byte-identical recomposition. DPF1 introduces no signing domain,
authority override or alternate trust protocol. See `deep-extension-profile-carrier-v1.md`.

Tests use an explicit fake adapter only to verify managed state and wire container behavior.
