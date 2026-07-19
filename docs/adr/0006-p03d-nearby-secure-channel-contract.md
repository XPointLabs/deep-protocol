# ADR 0006: P03D dormant nearby secure-channel contract

- Status: Accepted as a dormant contract; production activation blocked
- Date: 2026-07-19
- Decision owner for activation: Mr. X
- Source work package: P03D

## Context

P03C defines canonical `NRV1` rendezvous advertisements, `NHS1` handshake
frames and the `NBV1` binding. Its host adapter deliberately leaves the
mutually authenticated key exchange and durable replay state unspecified, and
its legacy result type exposes caller-provided session-key bytes.

P12 must not choose an AKE, construct AEAD nonces or receive raw traffic-key
material. A separate fail-closed contract is required before radio work can
consume an authenticated nearby channel.

## Decision

P03D adds a Deep-extension contract in
`Deep.Protocol.DeepExtension.NearbySecureChannels`. It does not change the
P03C wire codecs.

The contract:

- uses typed opaque account identities, device-key identifiers and transcript
  digests with bounded, nonzero representations;
- binds an expected peer credential to an explicit roster epoch, validity
  interval and revocation status;
- passes the P03C `NearbyHandshakeBinding` through a fresh-only
  `NearbyAkeContext`;
- exposes an opaque local device-key handle, never key bytes;
- separates initiator/responder handshake flights from application records;
- returns an opaque pending session after peer authentication;
- requires a durable fresh replay acceptance before activation;
- gives the caller only an `INearbySecureSession` that owns seal/open behavior
  and directional counters;
- fixes the only profile identifier to
  `UnassignedPendingExternalCryptoReview`.

P03D v1 rejects P03C resumption mode and a nonzero resume counter. No suite
negotiation is defined.

`NearbyReplayAcceptance` binds local device, peer device, P03C transport
attempt, transcript digest, roster epoch and `AcceptedFresh`
classification. Only an abstract replay-committer boundary may create it.
Persistence, atomicity and crash recovery remain host responsibilities; a
claim is never a rollback token.

## Security boundary

The assembly contains no concrete implementation of:

- `INearbyFreshAke`;
- `INearbyPendingSession`;
- `INearbySecureSession`;
- `INearbyReplayCommitter`.

It contains no AKE suite, DH operation, discovery PRF, AEAD, nonce schedule,
key issuance, device authenticator, credential verifier, persistence or
runtime registration. `NearbyHandshakePayload` is marked for authenticated
key-exchange bytes only and is bounded by the existing P03C adapter payload
limits. Application and bundle bytes are carried only after an external
implementation activates an opaque secure session.

The contract does not establish forward secrecy, post-compromise security,
deniability, radio unlinkability or lost-device recovery.

## Consequences

P12 can compile against a channel boundary without learning traffic keys, but
cannot exchange payloads until all external gates close. P03C test adapters
and `NearbyEstablishedSession.SessionKey` are not valid P03D implementations
and must not be adapted into a production default.

Production activation requires:

1. human approval of device identity, roster authority, revocation rollback
   and credential lifetime;
2. selection and supply-chain review of an exact maintained AKE
   implementation and fixed suite;
3. independent cryptographic review of transcript, discovery, record and
   erasure mappings;
4. independently verified cross-language vectors;
5. durable replay/roster/period state outside this repository;
6. fuzzing, Android key-storage review and physical-device E2E evidence.

Account signing derived on every recovery-phrase-restored device is not, by
itself, a lost-device revocation authority.
