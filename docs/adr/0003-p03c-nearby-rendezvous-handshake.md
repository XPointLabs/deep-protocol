# ADR 0003: P03C contact-scoped nearby rendezvous and handshake

Status: proposed contract; production AKE adapter unavailable; runtime activation BLOCKED.
Date: 2026-07-18. Human owner: Mr. X.

## Scope and privacy claims

Beta discovery is contact-scoped only. Open first-contact discovery is a different threat model and
is deferred until Mr. X explicitly approves a separate design. Advertisements contain a version,
negotiated opaque-bundle version and a rotating contact-derived hint. They contain no raw Session
ID, account identifier, payment identity or clear contact identifier.

An unknown scanner learns that a device emits a Deep-shaped fixed-length advertisement, its
supported bundle version, radio timing, signal/location metadata supplied by the platform, and
whether the same rotating hint repeats inside its period. The contract does not claim global
anonymity, resistance to a global observer, radio-fingerprint protection, crowd anonymity,
foreground availability or a background discovery SLA.

## Rendezvous periods

A future reviewed adapter derives a 16-byte hint from a contact discovery secret, the fixed
`Deep/P03C/RendezvousHint/v1` domain, bundle version and unsigned period number. The managed
contract never derives one contact secret from another and never accepts a raw Session ID as the
secret. Public rendezvous APIs require an opaque, non-exportable `ContactDiscoverySecret` handle
returned by `IContactDiscoverySecretProvider`; neither the protocol nor adapter API accepts secret
bytes. This structurally enforces the provider boundary but does not prove that a future provider
uses correct entropy, storage or contact derivation, which remains a production review blocker.

The platform supplies a monotonic/wall-clock mapping and period number. The default policy accepts
the current and immediately previous period, with at most one future period for configured clock
skew. Every create/respond/complete handshake call requires this period policy, so bypassing
advertisement matching cannot bypass the window. Hints/frames outside the set fail before adapter
or replay state changes. Period length and scanner scheduling are host policy, not wire promises.

## Canonical wire messages

`NRV1` is the fixed-length advertisement. `NHS1` frames use explicit message kind:

- initiator hello;
- responder response.

Frames bind version, negotiated opaque-bundle version, rendezvous period, a 16-byte hop-local
transport attempt ID, a 16-byte simultaneous-open token, an explicit fresh/resumption marker and
bounded adapter-owned payload. Unknown flags/kinds, nonzero reserved bytes, malformed lengths and
trailing bytes fail closed.

The transport attempt ID is the nearby-hop value carried into
`OpaqueBundles.TransportAttemptId`. It is never an end-to-end dedup ID and must change for a new
hop/transport attempt. The negotiated bundle version is part of every AKE binding and cannot be
downgraded after authentication.

## AKE and identity timing

`INearbyAuthenticatedKeyExchange` is a high-level boundary for an approved existing AKE. The
adapter receives codec-owned fixed domain bytes
`Deep/P03C/AuthenticatedAKE/v1` and exact canonical initiator/responder transcript bytes,
expected contact identity, negotiated bundle version, period and hop-local attempt ID. It must
authenticate both peers, derive session keys, bind the transcript and reject wrong-contact,
tamper, role reflection and downgrade.

Managed decode returns only opaque adapter payloads. Stable peer identity and established key
material may be returned only by successful adapter completion. No current repository primitive
meets the whole contract; Session sealed boxes and onion encryption must not be relabeled as AKE.
Test vectors may use a deterministic adapter in the test assembly only.

This ADR makes no forward-secrecy, post-compromise-security or deniability claim. Those properties
remain blocked until the selected established AKE, parameter mapping, vectors and external review
prove them.

## Replay, resumption and simultaneous open

Fresh and resumed handshakes are different canonical markers. A durable replay guard sees the
contact scope, period, hop-local attempt, simultaneous-open token and exact transcript. Resumption
requires an adapter-authenticated opaque ticket and a strictly advancing resume counter; it is
never inferred from cached transport state. Its decision must explicitly match `AcceptedFresh` or
`AcceptedResumption`; a mode/decision mismatch and repeated/non-advancing resumption fail closed.

Simultaneous initiators compare their random 16-byte tokens lexicographically. The lower token
continues as initiator and the higher switches to responder; equality fails and restarts with new
attempt material. Tokens are attempt-local and must not be derived from identity.

Lifecycle is platform-neutral: idle, hint matched, initiator hello sent, responder response sent,
established, failed and closed. Invalid transitions fail without exposing identity or keys.
Foreground/background execution, radio permissions and transport lifecycle belong to P12/P13.

## Consequences and activation blockers

P03C can freeze framing, lifecycle and adapter boundaries without inventing cryptography.
Production activation remains blocked until:

1. an established mutually authenticated AKE is selected and mapped by a production adapter;
2. cross-language vectors and external cryptographic/privacy review approve the mapping;
3. contact discovery-secret issuance/rotation and durable replay/resumption state exist;
4. mobile/Windows nearby E2E proves wrong-contact, tamper, skew, simultaneous-open and lifecycle;
5. P12/P13 implement transport behavior without expanding the claims in this ADR.

Rollback disables P03C negotiation and new advertisements while retaining no stable discovery
identifier. It never falls back to open discovery or clear Session IDs.
