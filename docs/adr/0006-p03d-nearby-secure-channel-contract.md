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
- separates an untrusted serialized credential descriptor from a
  verifier-issued opaque credential capability with visible account/device,
  roster epoch, validity interval and revocation status;
- passes the P03C `NearbyHandshakeBinding` through a fresh-only
  `NearbyAkeContext`;
- exposes a provider-issued opaque local device-key handle that binds the
  independently supplied verified local credential to a redacted platform-key
  reference, never key bytes or key operations;
- makes initiator/responder flights disposable owners whose state or pending
  session can be transferred exactly once;
- returns an opaque pending session after peer authentication;
- makes that pending session own the exact immutable replay claim derived from
  its context and transcript;
- performs one-shot asynchronous activation through
  `INearbyReplayCommitter`, with no caller-supplied acceptance token;
- gives the caller only an `INearbySecureSession` that owns seal/open behavior
  and role-derived send/receive directions and counters;
- fixes the only profile identifier to
  `UnassignedPendingExternalCryptoReview`.

P03D v1 rejects P03C resumption mode and a nonzero resume counter. No suite
negotiation is defined.

`NearbyFreshReplayClaim` has value equality over local device, peer device,
P03C transport attempt, transcript digest and roster epoch. The pending
session base validates that claim, including the pending handshake hash, against
its immutable AKE context and passes only that exact claim to
`INearbyReplayCommitter`. The committer returns only a
classification. `AcceptedFresh` contractually means the durable commit has
completed; duplicate, collision and rejected outcomes consume and dispose the
pending session without activating a channel. There is no reusable replay
acceptance object or rollback token.

`NearbyPendingSessionBase` serializes activation/disposal, rejects concurrent
or repeated activation, and transfers channel ownership only after an
`AcceptedFresh` commit. Transfer verifies the exact expected verified peer
capability and its account/device/roster/validation context. Once a committer
returns `AcceptedFresh`, acceptance wins a cancellation observed afterwards:
the base does not re-check the cancellation token and never asks for replay
rollback. `Seal` has no direction argument. Channel send and
receive directions are derived from the immutable local initiator/responder
role. `NearbySecureSessionBase` supplies the expected direction to external
record operations and rejects a reflected opened result. Canonical AKE frames
are bounded P03C frame values before reaching an external AKE, while encoded
records are capped at the existing opaque-bundle maximum plus 4096 bytes of
format-agnostic envelope overhead; the same cap is enforced on adapter output.

## Security boundary

The assembly contains no concrete implementation of:

- `INearbyFreshAke`;
- `INearbyPendingSession`;
- `INearbySecureSession`;
- `INearbyReplayCommitter`;
- `INearbyDeviceCredentialVerifier`;
- `INearbyLocalDeviceKeyProvider`.

It contains no AKE suite, DH operation, discovery PRF, AEAD, nonce schedule,
key issuance, credential signature implementation, platform key operation,
persistence or runtime registration. Abstract verifier and local-key-provider
base contracts may issue opaque capabilities only to external implementations.
The local-key-provider base verifies that its returned handle retains the exact
credential capability requested, and `NearbyAkeContext` independently checks
that binding again. Direct implementations supplied through DI remain a trusted
integration boundary and must provide the same guarantee; the context rejects
mismatched handles it receives.
`NearbyHandshakePayload` is marked for authenticated key-exchange bytes only
and is bounded by the existing P03C adapter payload limits. Application and
bundle bytes are carried only after an external implementation activates an
opaque secure session.

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
