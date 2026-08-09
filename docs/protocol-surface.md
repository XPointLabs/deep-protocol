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
  durable replay binding, plus native authenticated public client HTTP metadata for strict
  `MAU2(MCP2,MEO1|MBR2|MBA2)` and `MQR3`/`MRP1`/`MAR1` responses; historical
  `MST1`/`MRT1`/`MAK1` codecs are unmapped
- P03C contact-scoped nearby rendezvous, canonical handshake framing, replay scope and
  platform-neutral lifecycle, isolated in `Deep.Protocol.DeepExtension.NearbyHandshakes`; the
  mutually authenticated AKE remains a blocked host adapter with no production implementation
- DPF1 exact self-hosted profile carrier composition and verification, isolated in the
  `Deep.Protocol.ProfileCarrier` package and
  `Deep.Protocol.DeepExtension.SelfHostedProfiles`; a capability-specific post-consent seam
  defensively projects verified activation authority, gates exact-LKG updates or explicitly
  consented genesis switches, and verifies canonical online-quorum-signed SHR1 UserManaged
  runtime envelopes without changing the generic verifier or exposing signing/private keys;
  network, protected persistence and runtime registration are not shipped
- P03D typed fresh-only nearby secure-channel and durable replay-commit boundary, isolated in
  `Deep.Protocol.DeepExtension.NearbySecureChannels`; the fixed profile remains explicitly
  unassigned pending external crypto review and no channel implementation is shipped
- P18A compact authenticated fragmentation/planning and durable replay-store orchestration for
  exact DPB1 bytes, isolated in `Deep.Protocol.DeepExtension.LoRaFragments`; no production
  authenticator, replay store, radio runtime or DI registration is shipped
- production-only `production-mailbox-authority.v1` canonical PMA1 authority, isolated in
  `Deep.Protocol.DeepExtension.MailboxAuthority`; it is public signed configuration/anti-rollback
  verification only and contains no holder, mailbox grant, secret, runtime activation or token logic
- hash-bound `production-mailbox-revocation-snapshot.v1` PMR1 artifact in the same namespace;
  its verified immutable result supplies exact MCG2 serial revocations for one verified PMA1 issuer
  and has no signer, key-custody, network-fetch, persistence, or legacy compatibility API
- `production-mailbox-topology.v1` PMT1 plus per-mailbox `production-mailbox-selection.v1` PMS1 in
  `Deep.Protocol.DeepExtension.MailboxTopology`; strict issuer-signed current/next catalogs bind the
  final PMA1 hash, and deterministic Rendezvous-SHA256-v2 returns exactly two MIP1/RIP1-proven
  storage replicas with public HTTPS endpoints and current/next SPKI pins
- explicit PSS1 selection successor proof in the same namespace; DirectPromotion embeds exact
  old/new PMS1 and current PMA1 bytes, requires direct PMA1/PMT1 lineage, preserves the promoted
  route with controlled SPKI-pin promotion, and uses separate old/current issuer domains.
  OfflineCheckpoint verifies the embedded live PMA1 against the pinned Mr. X trust floor, binds the
  exact local old PMS1/owner/blinded route to a live new closure with the current issuer only, and
  caps local-anchor age at 365 days without tying recovery to rotation count or retaining retired
  keys; forward-checkpoint primitives are internal to the high-level PSS1 verifier
- fixed PHP1 production mailbox holder/owner proof transcript in
  `Deep.Protocol.DeepExtension.MailboxAuthority`; it binds network, PMA1, intent, platform,
  stable owner, active holder, route, release attestation and anonymous challenge without exposing
  signing or HTTP/service concerns
- fixed issuer-signed PRC1 route certificate and owner-signed PRA1 contact advertisement in
  `Deep.Protocol.DeepExtension.MailboxTopology`; they bind a stable dedicated owner key to the
  blinded route and verified PMA1 while excluding holder/device and topology identity. PRA1 is
  contact-scoped authorization, never a directory or replica proof; exact PMT1/PMS1 verification
  remains mandatory and private-key custody/transport/persistence stay host-owned

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

P10B preserves every P03B2 frame and adds `PRQ2` version 2 plus the PRQ2-only `MQR3` quorum domain. It signs a SHA-256
operation-domain-framed digest with the sender MIP1 Ed25519 key and binds sender/recipient router
IDs, operation, epoch/cursor, mailbox/placement/membership, exact payload/digest/expiry, creation
time and a 32-byte durable replay nonce. Creation after verification time is rejected (zero
future skew). Replay records persist through bounded epoch expiry plus
seven days and use bounded GC. The recipient returns one durable native `MRR2` after persistence;
two exact MIP1-keyed replicas form an `MQR3` whose distinct magic/version/signing transcript
prevents PRQ1/MQR2 cross-verification and whose coordinator sequence binds the complete signed
PRQ2. Native public client metadata accepts only operation-specific `MAU2`, maps Store to `MQR3`,
Retrieve to `MRP1`, and exact MBA2 order to bounded verified `MAR1(MQR3[])`; exact routes, media
types, limits and empty-body error statuses are in
`adr/0012-p10b-mailbox-wire-and-ingress-contract.md`.
Opaque MCP1 client frames are not translated and have no public runtime route.

P03C adds fixed `NRV1` advertisements and bounded `NHS1` initiator/responder frames. The public
orchestrator passes exact canonical transcript bytes, expected contact identity, period,
resumption counter, bundle version and hop-local attempt ID through
`INearbyAuthenticatedKeyExchange`. Stable peer identity and session key material appear only after
adapter authentication and replay acceptance. No radio transport, permission, UI, background
scheduler, production AKE adapter or runtime registration is included.

P03D preserves the P03C wire framing but replaces any downstream assumption of a raw traffic key
with a typed, dormant boundary. An abstract verifier converts an untrusted credential descriptor
into a non-publicly-constructible capability. A provider-issued local key handle binds the verified
local credential to an opaque platform-key reference. The fresh-only context binds those local and
expected-peer capabilities, roster epoch, role and P03C binding. Disposable flights transfer their
owned state once. A pending session owns the exact immutable replay claim and can activate only
once by asking the durable committer to commit that claim; the committer returns classification,
not a reusable acceptance. The activated `INearbySecureSession` owns role-derived send/receive
directions and record sealing/opening; callers cannot select a seal direction. No raw key, AKE,
record crypto, replay persistence, concrete credential verifier/key provider or runtime
implementation is included. The sole profile is `UnassignedPendingExternalCryptoReview`.

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

P10B adds bounded public HTTP/2 opaque-transit constants, a canonical fixed-size outer-error codec
and a bounded advisory capability-document codec in
`Deep.Protocol.DeepExtension.ManagedIngress`. It adds no Session or mailbox authority semantics:
HTTP success is only `TransitCompleted` and cannot represent mailbox acceptance, durability or
delivery. ASP.NET, proxy/TLS configuration, bridge selection, retry scheduling and inner receipt
verification remain outside this library.

P18A adds fixed `LF` V1 frames, a canonical ten-byte DPB1 descriptor and optional one-XOR-shard
groups. Authentication and replay scopes are provider-issued opaque handles. The coordinator
returns bundle bytes only after strict DPB1 validation and a durable generation-CAS completion
tombstone. It includes no link-key implementation, BLE/USB, radio, region defaults, billing,
rewards or battery/background behavior.

Tests use an explicit fake adapter only to verify managed state and wire container behavior.

Slice D keeps route continuity authoring capability-scoped. A sealed historical anchor restores
only from exact RCD1(552), RDA1(320), pre/enrolled ROL1(224 each), a verified historical
PMA/PMR/PRC/PRA2 closure, and a protected exact OCR1 binding. Fresh PRC1 and live
RTC1/PRA2-or-RCH1+RCA1/PSS2 are constructed internally. The public result is cryptographic only:
it exposes a defensive `CommitPlan` and domain-separated `PlanHash`, never a storage committer,
durability receipt, publication capability, raw unsigned draft, or injectable production verifier.

Slice D2 makes continuity genesis a two-step cryptographic operation. `VerifyGenesisIntent`
freezes and production-verifies the exact owner RCD1, pre-enrollment ROL1 and historical
PMA/PMR/PRC/PRA2 closure before Registry prepares an HSM responder key. After Registry durably
reserves that intent and chooses authoritative `acceptedAt`, `AuthorGenesisAsync` signs RDA1 then
OCR1 outside the store and derives the enrolled ROL1 and initial RHC1. It returns only a defensive
`ProductionMailboxRouteContinuityGenesisCommitPlan`: exact anchor and genesis artifacts, both
protected restore contexts, predecessor CAS fields and a domain-separated `PlanHash`. There is no
public partial enrollment committer, standalone OCR authorer, precommit anchor/cursor conversion,
durability result or publication capability. Registry atomically writes and protected-rereads the
plan before restoring the sealed anchor and anchor-bound cursor.

Owner control uses OCR1(272), PMCQ1(344), PMCR1(384), and PMFA1(header 48). The OCR1 hash is not a
PMCQ wire field: it is appended to both the owner signature transcript and request operation-hash
context. PMCR transitively binds it through the request hash and accepts only the exact protected
OCR responder key. Its public stream path first verifies the fixed header, request tuple, time and
responder signature into a sealed read context; only then can bounded payload allocation/read,
incremental hash verification and nested semantic decoding occur. Codecs are carry-only; Registry and
client own HTTPS authentication plus confidentiality, durable request-id CAS, response persistence,
retry and post-CAS authority. Node/path/log exposure is forbidden.
