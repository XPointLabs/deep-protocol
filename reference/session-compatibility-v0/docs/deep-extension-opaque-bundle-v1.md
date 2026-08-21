# Deep extension opaque bundle V1

Status: P03 local contract, feature negotiation required, not a production default.

This document specifies a Deep-only extension. It does not change Session protobufs, namespaces,
envelopes or DPE1 bytes. It does not select a capability derivation, sender-authentication,
ratchet, MLS or encryption construction and makes no forward-secrecy claim. External
cryptographic review remains a release blocker.

## Threat boundary

The codec prevents managed outer fields from requiring payer, plan or raw Session identifiers.
It does not hide IP addresses, timing, direction, endpoint choice or traffic volume. A caller must
provide independently constructed opaque mailbox capabilities and already-encrypted header and
payload bytes. Passing a raw account identifier as capability bytes violates this contract even
though an opaque byte parser cannot determine the bytes' origin.

Deposit and retrieval capabilities have distinct .NET types and distinct wire role values. They
must be derived with distinct domains outside this codec. Equality between transport-local attempt
ID and the local end-to-end dedup ID is rejected during encoding. The end-to-end ID is never
serialized by this outer format.

## Canonical V1 wire layout

All integers are unsigned, big-endian. Header length is exactly 64 bytes.

| Offset | Length | Field |
| ---: | ---: | --- |
| 0 | 4 | ASCII `DPB1` |
| 4 | 1 | wire version (`1`) |
| 5 | 1 | minimum reader version (`1`) |
| 6 | 1 | payload kind: `1` native opaque, `2` exact legacy DPE1, `3` authenticated legacy envelope |
| 7 | 1 | capability role: `1` deposit, `2` retrieve |
| 8 | 1 | padding class: 256, 1024, 4096 or 16384 byte block |
| 9 | 1 | reserved zero |
| 10 | 4 | critical feature bits |
| 14 | 4 | optional feature bits |
| 18 | 4 | caller-defined expiry bucket |
| 22 | 16 | transport-local attempt ID |
| 38 | 16 | opaque replay material |
| 54 | 2 | capability length |
| 56 | 2 | encrypted-header length |
| 58 | 4 | encrypted-payload length |
| 62 | 2 | reserved zero |
| 64 | variable | capability, encrypted header, encrypted payload, zero padding |

V1 requires critical bits `SenderSealedHeader`, `MailboxCapabilities` and
`TransportLocalCorrelation`. Unknown critical bits fail closed; unknown optional bits are carried
to the caller. Reserved bytes and padding must be zero. The exact encoded length is the smallest
selected padding block containing the header and declared bodies; non-canonical alternatives fail.
The implementation-owned `OpaqueBundleFeatureSet.KnownCriticalFeatures` mask is the upper bound for
offers, negotiated profiles and decode policies. Callers may narrow that mask, but cannot extend it
by marking an unknown critical bit as locally supported.

Strict bounds:

- capability: 32..512 bytes;
- encrypted header: 1..4096 bytes;
- encrypted payload: 1..1,048,576 bytes;
- encoded input: at most 1,064,960 bytes;
- transport attempt ID and replay material: exactly 16 bytes each.

The synchronous span parser has no cancellation input or asynchronous side effects. It validates
all lengths and canonical size before allocating component copies. Thus cancellation cannot create
a partially accepted protocol result, while total parser allocations remain bounded by the public
limits.

## Negotiation and downgrade

The extension has no implicit/default activation. Peers exchange explicit minimum/maximum versions
and supported critical features through a transport-owned negotiation channel. The negotiator
chooses the highest common version at or above the caller's minimum safe version. No intersection,
missing V1 features or an unimplemented selected version fails closed.
Offers containing critical bits outside the implementation-owned known mask fail before
intersection. The encoder and decoder apply that same independent mask in addition to the caller's
profile or policy.

A strict reader configures accepted version and expiry-bucket windows. An older/unknown version,
version below the strict floor, unknown critical feature, expired/future-out-of-window bucket or
malformed canonical encoding is rejected. Consumers must not catch these results and retry raw
Session-ID addressing.

## Legacy DPE1 migration

Payload kind `LegacyDpe1` contains the exact complete legacy bytes beginning with ASCII `DPE1`.
The codec neither decrypts nor rewrites those bytes. Encoding and decoding both require:

- an explicit `AllowLegacyDpe1` migration profile;
- the critical `LegacyDpe1Compatibility` bit;
- exact `DPE1` prefix validation.

The default profile rejects legacy payloads. Mr. X must approve a bounded compatibility window.
Disabling new opaque writes must not delete either legacy or new-format state. A strict release
must never fall back silently after an opaque read/write failure.

Payload kind `AuthenticatedLegacyDpe1` additionally requires the
`AuthenticatedCompatibilityEnvelope` critical feature. Its payload is ciphertext rather than
clear DPE1 and is accepted only through the P03A orchestration contract. P03A has no production
crypto adapter or runtime registration in this package; see
`adr/0001-p03a-compatibility-metadata-envelope.md`.

## Replay, revocation and authenticated failures

V1 carries expiry bucket and opaque replay material but intentionally does not invent their
cryptographic verification. A capability producer/verifier must define authenticated expiry,
epoch, replay-window, revocation and failure semantics, plus bounded multi-device recovery and
rotation overlap. Until that producer is implemented and externally reviewed, P01 capability
findings remain unresolved and the extension must not be enabled in production.

Application logs and telemetry must not include capability bytes, encrypted bodies, replay
material, attempt IDs or per-account failure details. Only aggregate reason counters are allowed.

## P11 consumer API

Consumers reference `Deep.Protocol.DeepExtension.OpaqueBundles` and:

1. obtain an `OpaqueBundleNegotiatedProfile` from `OpaqueBundleNegotiator.Negotiate`;
2. construct either `OpaqueDepositCapability` or `OpaqueRetrieveCapability`;
3. supply different `TransportAttemptId` and `EndToEndDedupId` values;
4. call `OpaqueBundleCodec.Encode`;
5. decode only with an explicit `OpaqueBundleDecodePolicy`;
6. treat `OpaqueBundleException.Error` as a local aggregate reason, never as permission to
   downgrade.

No existing Session codec or protobuf consumer changes for P03.
