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

Tests use an explicit fake adapter only to verify managed state and wire container behavior.
