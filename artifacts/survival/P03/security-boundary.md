# P03 security boundary

Implemented and testable:

- canonical versioned DPB1 framing and strict maximum lengths;
- allocation-bounded synchronous parser with no cancellation-dependent state;
- separate opaque deposit/retrieve runtime and wire roles;
- transport-attempt versus local E2E-dedup separation at encoding;
- expiry-bucket policy, padding classes and opaque replay-material carriage;
- explicit negotiation, minimum safe version, downgrade rejection and unknown-critical fail-closed;
- exact opt-in legacy DPE1 compatibility payload.

Not implemented and release-blocking:

- capability generation, domain separation proof and unlinkability evidence;
- authenticated sender-sealed headers and abuse control;
- authenticated expiry/epoch, durable replay window, revocation and failure proof;
- multi-device/offline recovery and rotation;
- storage/push server adoption and collusion tests;
- independent external cryptographic review.

The local code contains no new cryptographic primitive and makes no forward-secrecy claim. Mr. X is
the accountable human owner. Independent code review is the next internal gate; external crypto
review remains blocked/not-run.
