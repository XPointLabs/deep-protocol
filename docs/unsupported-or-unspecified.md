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
The strict non-convertible V2 profile now implements real Ed25519 issuer and holder authentication,
exact operation/request/epoch/membership/placement binding, explicit generation/overlap checks and
an executable replay state machine. Typed MEO1/MBR2/MBA2 transcripts are carried only by MAU2;
MCP1 and MST1/MRT1/MAK1 are not converted. It deliberately does not implement:

- mailbox/domain-scoped issuer or holder key custody, backup, derivation, rotation ceremony or
  recovery;
- proof that host-generated blinded identifiers or mailbox-scoped keys are unlinkable;
- trusted-issuer distribution or durable revocation/replay/idempotency/lifecycle persistence;
- coordinator key distribution;
- replica write/storage execution, cursor allocation, tombstone persistence or repair;
- free-admission issuance/accounting or any paid quota, wallet, payer or subscription identity;
- legacy migration execution, production registration, service defaults or deployment.

`IMailboxReceiptCrypto`, legacy `IMailboxCapabilityReplayGuard`,
`IMailboxCapabilityRevocationSource` and `IMailboxCapabilityReplayJournal` are trust boundaries.
The V2 journal must atomically reserve/read a claim and atomically complete its bounded outcome;
crash recovery must retain an explicit in-flight reservation, using the canonical scope key and
state-machine transition. The legacy replay guard
must durably compare the supplied canonical presentation and return a previously committed bounded
outcome only for an exact idempotent retry; P03B defines this decision contract but supplies no
persistence. Test fixtures use deterministic SHA-256-based signatures only to make codec and
verifier vectors reproducible; they are not production cryptography. Production activation
remains blocked until later producer, storage, client integration and external security work
supplies and verifies those dependencies.

## P09C dormant client mailbox contract gaps

The additive P09C contract defines canonical client frames, bounded opaque encrypted envelopes,
adjacent epoch overlap, cursor-bound pagination, local delivery transitions and
placement/membership-bound V2 receipts. The full `MEO1` frame is bounded to xnode's current
81920-byte default rather than treating that storage bound as payload-only. It deliberately does
not implement:

- recipient master-secret generation, capability/identifier derivation, encryption or decryption;
- proof that caller-provided blinded identifiers are unlinkable or derived without raw identity;
- durable epoch, replay, idempotency, cursor, continuation-token or acknowledgement persistence;
- xnode runtime adoption of native PRQ1/MRR2/MQR2 and removal of its local JSON receipt;
- coordinator key resolution and receipt signing integration;
- client outbox/SQLite integration, dual-read/mirror execution, networking, DI or feature activation.

The sender-facing store model intentionally has no retrieve or master material. Test-only
SHA-256-based signatures produce stable vectors but are not a selected cryptographic scheme.
PRQ1 uses real Ed25519. The optional MembershipRoutes RIP1 adapter verifies storage-role MRL1
membership, but catalog acquisition, last-known-good persistence, transport and runtime wiring
remain downstream work.

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
- signed catalog publication, signer custody, storage execution, reward, billing or update authorization;
- production/self-hosted deployment, migration from current bootstrap DTOs or P06/P07 integration;
- cross-language crypto verification or external cryptographic review.

The deterministic signature verifier and key material exist only in the test assembly. Canonical
bridge contacts are public discovery data and do not provide anonymity against a network observer.
Fork witnesses record candidate ancestry but do not select a winning branch. Production activation
remains blocked until the verifier/key lifecycle and durable state are supplied, independently
reviewed, and exercised by registry/client E2E work.

The `Deep.Protocol.MembershipRoutes` package now defines canonical route leaves and Merkle proof
verification. It does not claim that an arbitrary registry response is authoritative: consumers
must first quorum-verify the enclosing P04 `SignedMembershipCommitment`, enforce monotonic LKG
state, and require one valid proof for every catalog member.

## DPF1 exact profile carrier gaps

`Deep.Protocol.ProfileCarrier` defines one unsigned framing implementation and
delegates every trust decision to the exact pinned P04 package. P14E2 adds a
dormant exact transition verifier with ephemeral ordered bridge-prefix state
and a sealed sodium-backed detached Ed25519 verification candidate. It
deliberately does not implement:

- an externally reviewed and approved production signature profile;
- root/online signer generation, custody, ceremony or private-key handling;
- client trust persistence, last-known-good updates or atomic activation;
- endpoint selection, network access, transport, dependency injection or runtime registration;
- QR/file UI, billing, wallet or deployment behavior.

The existing dormant client `DSIG` genesis-only signature envelope is not
interchangeable with DPF1 genesis approvals and does not carry the delegation
or bridge chain. Conversion between these formats is unsupported. A future
activation path must reverify the exact staged DPF1 bytes using this shared
package and atomically import the complete trust chain; it must not maintain a
second parser or reinterpret legacy dormant rows.

DPF1 v1 carries only the single genesis-rooted delegation step. It cannot
represent a verifiable delegation rotation chain: lower/higher delegation
sequence inputs fail P04 verification, while equal-sequence different
statements are forks. Cross-RID native assets are hash-pinned for Windows,
Linux and Android, but execution outside the current Windows ARM64 host is
deferred to the exact P14C3/P14A2b downstream package rebinds.
