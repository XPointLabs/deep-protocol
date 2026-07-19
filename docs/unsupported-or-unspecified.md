# Unsupported Or Unspecified

This document lists areas where the .NET port intentionally stops at an adapter boundary or marks a
TODO instead of inventing behavior.

## Crypto

Implemented in managed production adapter (`SodiumSessionProtocolCrypto`):

- libsodium-compatible 1:1 envelope encryption/decryption (`crypto_box_seal` semantics)
- Ed25519 seed (32-byte) to libsodium-style secret key normalization (64-byte)
- Ed25519 public key to X25519 conversion
- blinded recipient encryption for `0x15` and `0x25` paths
- personalized BLAKE2b-256

Still not fully implemented in managed code:

- deterministic Session encryption variant specifics that differ from sealed-box behavior
- full upstream-equivalent groups v2 bt encoding and key lifecycle/rekey semantics
- ONS, push notification, and attachment encryption helpers

`ISessionProtocolCrypto` and `IProtocolHashing` remain extension points for hosts that need alternative native bindings.

### B1 acceptance criteria mapping

- Envelope encrypt/decrypt: round-trip and sodium differential tests are green.
- Ed25519 seed normalization: adapter output matches direct sodium key expansion.
- Ed25519/X25519 conversion: adapter output matches direct sodium conversion.
- Blinded recipient paths: both `0x15` and `0x25` prefixes are preserved and decryptable.
- Personalized BLAKE2b-256: adapter output matches direct sodium `HashSaltPersonal`.

## Onion Requests

Implemented in managed production adapter (`SodiumOnionRequestCrypto`):

- `xchacha20`
- `aes-gcm`
- `gcm` alias for `aes-gcm`
- sealed-box onion request build path (destination + optional hops)
- encrypted response decrypt with JSON envelope parsing (`statusCode`/`code`, object/array headers)
- fallback to raw plaintext body when response is not JSON

Remaining gaps / blockers:

- path construction, repair, strike counting, cache persistence, and router scheduling

## Groups

Implemented:

- protobuf group update extraction (`GroupUpdateParser`)
- groups v2 message encrypt/decrypt through production sodium adapter
- group payload compression + padding restoration on decrypt path

It does not yet port:

- `groups/info`
- `groups/members`
- `groups/keys`
- key rotation and rekey state
- full bt encoding parity for groups payload internals
- legacy closed group behavior

## Config Namespace Merge

Implemented:

- `SharedConfigMessage` parsing from `Content` envelopes
- per-namespace merge policy with seqno ordering: `Applied`, `Duplicate`, `Stale`, `Invalid`

Remaining gaps / blockers:

- full upstream config namespace families and merge conflict resolution nuances
- coupling with group key lifecycle/rotation state

Legacy group `0x05` encryption is rejected, matching the upstream high-level protocol helper.

## Community Migration

The compatibility path for `Content` vs `Envelope` community messages is implemented. The final
network transition stage is not assumed. The code keeps both parse paths active, matching the
transition comments in `SessionProtos.proto`.

## Protobuf Unknowns

The schemas are copied unchanged. Unknown protobuf fields are handled by Google.Protobuf according
to its runtime behavior; no custom unknown-field policy has been added.

## Golden Vectors

Current fixtures are deterministic managed fixtures. Cross-language crypto vectors should be added
when native bindings are available. Failing vector tests write diffs under `artifacts/vector-diffs`.

## Deep opaque bundle producer gaps

The Deep extension opaque bundle V1 codec and canonical vector are implemented, but the following
security-sensitive producer semantics remain deliberately unsupported:

- cryptographic derivation and domain separation for deposit/retrieve capabilities;
- sender authentication and abuse controls without a stable storage-visible sender identity;
- authenticated expiry, rotation epoch, bounded replay, durable revocation and failure proofs;
- multi-device/offline recovery and bounded rotation overlap;
- rotating push handles and unlinkability across accounts, epochs and transports;
- a reviewed sender-sealed-header encryption construction.

P03A defines `ICompatibilityEnvelopeCrypto` and `ICompatibilityEnvelopeReplayGuard`, plus
deterministic contract vectors through a test-assembly-only adapter. It deliberately does not ship
a production implementation. The current recipient sealed-box helper encrypts a claimed sender
identifier but does not cryptographically authenticate control of that sender key; the onion
adapter is anonymous by design. Treating either as P03A sender authentication is unsupported.

Production P03A remains blocked on:

- selection and independent verification of an established authenticated recipient-encryption
  construction;
- codec-domain-to-key/nonce mapping and upstream differential vectors;
- durable atomic replay state scoped to capability epoch;
- runtime registration and external cryptographic review.

The codec only carries caller-provided opaque/encrypted bytes. It is not a ratchet, MLS, sealed
sender implementation or proof of forward secrecy. P01 privacy findings therefore remain unresolved
until the producer/verifier and downstream storage/push contracts exist and receive external
cryptographic review.

## P03B mailbox contract gaps

P03B defines canonical capability and receipt bytes plus strict client-side verification behavior.
It deliberately does not implement:

- deposit/retrieve/placement value generation, derivation, rotation or recovery;
- secrecy, unlinkability, entropy or unforgeability of caller-provided opaque bytes;
- durable replay/idempotency/lifecycle state;
- replica/coordinator key distribution, signature or digest primitives;
- replica write/storage execution, cursor allocation, tombstone persistence or repair;
- free-admission issuance/accounting or any paid quota, wallet, payer or subscription identity;
- legacy migration execution, production registration, service defaults or deployment.

`IMailboxReceiptCrypto` and `IMailboxCapabilityReplayGuard` are trust boundaries. The replay guard
must durably compare the supplied canonical presentation and return a previously committed bounded
outcome only for an exact idempotent retry; P03B defines this decision contract but supplies no
persistence. Test fixtures use deterministic SHA-256-based signatures only to make codec and
verifier vectors reproducible; they are not production cryptography. Production activation
remains blocked until later producer, storage, client integration and external security work
supplies and verifies those dependencies.

## P03C nearby handshake gaps

P03C defines contact-scoped rendezvous framing, a two-message transcript boundary, replay scope and
platform-neutral lifecycle. It deliberately does not implement:

- contact discovery-secret issuance, synchronization, rotation or recovery;
- a production mutually authenticated AKE, key schedule, resumption-ticket protection or durable
  replay state;
- BLE advertisements/scanning, radio permissions, Wi-Fi transfer, UI or background scheduling;
- open first-contact discovery;
- forward secrecy, post-compromise security, deniability, global anonymity, radio unlinkability or
  a foreground/background availability SLA.

The existing Session sealed-box and onion-request adapters do not satisfy the complete
transcript-bound mutually authenticated AKE contract and are not registered for P03C. The
deterministic adapter exists only in tests. Production activation requires selection and external
review of an established AKE, cross-language vectors, durable state and mobile/Windows E2E.

## P04 membership and bridge contract gaps

P04 defines canonical trust documents and fail-closed verifier decisions. It deliberately does not
implement:

- live offline-root or online-signer generation, custody, ceremony, rotation or recovery;
- a production signature implementation, key resolver or dependency-injection registration;
- durable atomic last-known-good, delegation-revocation or equivocation state;
- registry persistence, bridge publication, endpoint crawling resistance or client bootstrap UI;
- core/storage topology distribution, storage execution, reward, billing or update authorization;
- production/self-hosted deployment, migration from current bootstrap DTOs or P06/P07 integration;
- cross-language crypto verification or external cryptographic review.

The deterministic signature verifier and key material exist only in the test assembly. Canonical
bridge contacts are public discovery data and do not provide anonymity against a network observer.
Fork witnesses record candidate ancestry but do not select a winning branch. Production activation
remains blocked until the verifier/key lifecycle and durable state are supplied, independently
reviewed, and exercised by registry/client E2E work.

## P10B managed ingress H2 gaps

P10B defines only the public opaque-transit contract, canonical fixed-size outer errors and a
bounded advisory capability document. It deliberately does not implement:

- an ASP.NET/HTTP server, reverse proxy, TLS policy or ingress-to-core authentication;
- bridge selection, signed control-plane fetching or endpoint rotation;
- queueing, retry timers, stream/concurrency budgets or network cancellation handling;
- inner DPB1/MCP1 composition, mailbox receipt verification or P05A evidence;
- mailbox acceptance, durability or recipient-device delivery state;
- traffic-analysis resistance, global anonymity, endpoint unblockability or full-IP-cutoff
  operation;
- Docker, deployment, monitoring, production registration or live-network evidence.

Production activation remains blocked on P07B/P10/P11B/P15 implementations, accepted inner
producer/receipt/storage contracts, device/network E2E and independent security review.
