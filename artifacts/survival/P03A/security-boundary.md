# P03A security boundary

Decision: contract implemented; production runtime activation BLOCKED.

## Implemented and testable

- explicit `AuthenticatedLegacyDpe1` payload kind and
  `AuthenticatedCompatibilityEnvelope` critical feature;
- implementation-owned critical-feature mask and explicit V1/legacy negotiation;
- exact DPE1 recovery only after two authenticated adapter opens;
- sender authentication data returned only after header and payload open, fixed-time equality,
  header/length validation, DPE1 validation and replay acceptance;
- fixed codec-owned header/payload domains and distinct 32-byte nonce contexts;
- canonical associated data binding capability role/value, hop-local attempt, padding, expiry,
  replay material, payload kind/features and both nonce contexts;
- zero optional outer metadata for P03A;
- strict component/overhead/total bounds;
- wrong-recipient, tamper, domain swap, replay, expiry/downgrade, malformed post-decrypt data,
  truncation and mutation gates;
- production assembly contains zero implementations of `ICompatibilityEnvelopeCrypto`.

## Existing adapter rejection

`SodiumSessionProtocolCrypto.EncryptForRecipient` derives a sender public identifier and embeds it
inside a recipient sealed box (`SodiumSessionProtocolCrypto.cs:65-77`). A sealed box provides
recipient confidentiality/integrity but this method does not sign or prove control of the embedded
sender identity. `SodiumOnionRequestCrypto.Build` creates anonymous destination/hop sealed boxes
(`SodiumOnionRequestCrypto.cs:12-35`). Neither is a P03A sender-authentication adapter.

The deterministic test adapter is deliberately synthetic and located only under
`tests/Deep.Protocol.Tests/Fakes`. It must never be copied into a production assembly.

## Production blockers

- no approved sender-authenticated recipient-encryption primitive/adapter;
- no upstream differential crypto vectors or independent primitive review;
- no durable atomic replay implementation;
- capability derivation, expiry/epoch authentication, revocation and recovery remain P03B/P07A;
- no runtime registration or production feature offer;
- external cryptographic and observer-model review not run.

P03A does not provide forward secrecy, a ratchet, MLS, anonymous credentials, traffic-flow
confidentiality or proof of sender unlinkability. P01 remains unresolved.

## Observer and collusion limits

Storage sees the opaque capability, exit, expiry bucket, padded size and activity timing. Access
networks see client endpoints/timing/volume; routed hops see adjacency; platform push remains a
separate correlation surface. Ingress plus storage, storage plus push, all routed hops, endpoint
compromise and a global passive observer can still correlate timing, size, topology and device
activity. Capability equality remains linkable within the lifecycle epoch defined by later work.

