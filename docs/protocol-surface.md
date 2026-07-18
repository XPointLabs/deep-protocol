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

Tests use an explicit fake adapter only to verify managed state and wire container behavior.
