# Compatibility Matrix

| Area | Upstream Source | .NET Status | Notes |
| --- | --- | --- | --- |
| `SessionProtos.proto` | `proto/SessionProtos.proto` | Implemented | Generated with `Grpc.Tools`, schema copied unchanged. |
| `WebSocketResources.proto` | `proto/WebSocketResources.proto` | Implemented | Generated with `Grpc.Tools`, schema copied unchanged. |
| 160-byte message padding | `src/session_protocol.cpp` | Implemented | Uses `0x80` terminator and zero suffix padding. |
| Pro feature text limits | `include/session/session_protocol.h` | Implemented | 2k standard and 10k Pro limits. |
| 1:1 envelope wrapping | `src/session_protocol.cpp` | Implemented | WebSocket request body contains serialized `Envelope`. Crypto is adapter-backed. |
| 1:1 content encryption | `src/session_encrypt.cpp` | Implemented | Backed by `SodiumSessionProtocolCrypto` with libsodium-compatible sealed-box semantics. |
| Envelope decode | `src/session_protocol.cpp` | Implemented | Decrypt operation is adapter-backed. |
| Community content/envelope migration | `proto/SessionProtos.proto`, `src/session_protocol.cpp` | Implemented | Accepts padded `Content` or `Envelope` and handles community-only Pro signature. |
| Session Pro proof extraction | `src/session_protocol.cpp` | Implemented | Verification requires `IProtocolHashing` and `ISessionProtocolCrypto`. |
| Session Pro proof hash | `src/session_protocol.cpp` | Implemented | Uses personalized BLAKE2b-256 via sodium generic hash personalization. |
| Ed25519 seed normalization | `src/session_encrypt.cpp` | Implemented | 32-byte seed to 64-byte secret key expansion follows sodium keypair generation. |
| Ed25519 to X25519 conversion | `src/session_encrypt.cpp` | Implemented | Public key conversion uses sodium conversion primitive. |
| Blinded recipient encryption (`0x15`/`0x25`) | `src/session_encrypt.cpp` | Implemented | Both blinded recipient prefixes are supported in adapter path. |
| Groups v2 envelope flow | `src/session_protocol.cpp`, `src/session_encrypt.cpp` | Partial | Envelope state and sodium-backed encrypt/decrypt with compression/padding recovery are implemented. Remaining gaps: full bt encoding and complete upstream groups key lifecycle semantics. |
| Group update domain extraction | `proto/SessionProtos.proto` | Partial | Extracts shared protobuf domain events. Config merge/key lifecycle is not ported yet. |
| One-to-one state transitions | `SessionProtos.MessageRequestResponse`, protocol docs/tests | Partial | Managed state machine covers request/approval/block transitions without adding wire format. |
| Onion request support | `include/session/onionreq`, `src/onionreq`, `ENABLE_ONIONREQ` tests | Partial | Onion request build/decrypt crypto path is implemented in `SodiumOnionRequestCrypto`, including v3/v4 response envelope parsing edge-cases. Remaining gaps: router path management, repair/strike logic, and cache persistence. |
| Network routers/snode pool | `include/session/network`, `src/network` | Not ported | Out of scope for the protocol library except onion abstractions. |
| Config namespaces/merge logic | `include/session/config`, `src/config`, `docs/api` | Partial | `SharedConfigMessage` parsing and per-namespace seqno merge semantics (applied/duplicate/stale/invalid) are implemented. Remaining gaps: full upstream namespace families and key lifecycle integration. |
| Deep opaque bundle V1 | Deep extension; not a Session wire format | Implemented, disabled by default | Canonical allocation-bounded codec, explicit negotiation, separate opaque deposit/retrieve capability types and exact opt-in DPE1 compatibility payload. Capability derivation/authentication is not implemented and requires external review. |
| P03A authenticated compatibility envelope | Deep extension; not a Session wire format | Contract implemented, runtime blocked | Production crypto/replay interfaces, canonical outer binding, exact post-decrypt DPE1 recovery and test-only vectors exist. No approved sender-authenticated recipient-encryption adapter is implemented or registered; no production default. |
| P03B mailbox capability and durable receipt contract | Deep extension; not a Session wire format | Contract implemented, runtime blocked | Canonical MCP1/MRR1/MQR1/MBE1 codecs, strict domain/lifecycle/replay fields, two-replica client verification and test-only crypto vectors exist. No capability producer, durable guard, storage executor, production crypto or runtime registration is shipped. |

Golden vectors currently cover deterministic managed protocol surfaces: padding, protobuf
serialization, and known upstream identity fixtures. Crypto parity vectors should be added alongside
native binding adapters.
