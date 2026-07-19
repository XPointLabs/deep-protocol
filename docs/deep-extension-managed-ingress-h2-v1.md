# Deep extension managed ingress HTTP/2 V1

Status: P10B local contract; runtime blocked.

This Deep-only extension defines a bounded outer transport for an opaque, already sealed
route/onion frame. It is not Session wire behavior and does not modify protobufs.

## Surface

- contract: `Deep.Protocol/P10B-managed-ingress-h2-v1`;
- frame: `POST /api/ingress/v1/frame`;
- capability document: `GET /api/ingress/v1/capabilities`;
- public hop: HTTP/2 only;
- opaque media: `application/vnd.xpoint.deep.ingress-opaque-v1`;
- error media: `application/vnd.xpoint.deep.ingress-error-v1`;
- capability media: `application/vnd.xpoint.deep.ingress-capabilities-v1+json`.

The frame body is raw ciphertext, never JSON/base64 or a clear DPB1/capability/receipt. V1 has no
outer accepted, durable or delivered state. Only an independently opened and verified inner
result can advance such application state.

## Limits

| Item | Bound |
| --- | ---: |
| opaque request or response | 64..1,572,864 bytes |
| decoded header list | 8,192 bytes |
| decoded header fields | 32 |
| capability document | 4,096 bytes |
| canonical error | exactly 64 bytes |
| retry delay when present | 1..60 seconds |

Header-list accounting is the RFC 9113 decoded calculation: name bytes + value bytes + 32 for
each field. For requests this includes `:method`, `:scheme`, `:authority`, `:path`, `accept`,
`content-length` and, for frame requests, `content-type`; an adapter must not also put these
fields in the supplemental header collection. Public requests permit no supplemental headers.
Responses include `:status`, `content-type` and `content-length` in the same limits; the only
supplemental response fields are exact `cache-control: no-store` and, on a canonical error that
requires it, `retry-after`. The opaque application body may span multiple HTTP/2 DATA frames.

`ManagedIngressStreamingAdmission` accounts for each received chunk without allocating from the
declared length. It allows forwarding only after the actual byte count exactly matches a bounded
declared length. Truncation or overflow permanently poisons that admission instance; it cannot be
resumed or forwarded. Cancellation before the transition cannot be reported as forwarded.
Cancellation after the transition is always `OutcomeUnknown`.

## Canonical `DIE1`

All integers are unsigned big-endian.

| Offset | Length | Field |
| ---: | ---: | --- |
| 0 | 4 | ASCII `DIE1` |
| 4 | 1 | version `1` |
| 5 | 1 | minimum reader version `1` |
| 6 | 1 | stable error class |
| 7 | 1 | certainty: before-forward or unknown-after-forward |
| 8 | 1 | retryable marker |
| 9 | 1 | reserved zero |
| 10 | 2 | retry delay or zero |
| 12 | 52 | reserved zero |

The codec is canonical and allocation-bounded. It has no string, request identifier, digest,
capability or evidence field.

An opaque success is `TransitCompleted` only when the actual complete body bytes equal the
declared bounded length. Metadata alone cannot produce success. An error response is authoritative
only when HTTP/2, status, exact media type, fixed body length,
canonical `DIE1` mapping and the optional decimal `Retry-After` all agree. `Retry-After` is present
exactly once only for a nonzero `DIE1` delay and must be the same canonical integer in `1..60`.
Malformed, proxy-generated or contradictory responses are `OutcomeUnknown`.

The capability response is exact HTTP `200`, the capability media type and canonical JSON bytes.
Unknown fields, alternate field order/whitespace, duplicate features, overlap between critical
and optional features, and unknown critical features fail closed.

## Host requirements

A host must drive the admission state before forwarding, reject partial/over-limit bodies,
prohibit compression/redirect/0-RTT and preserve the forward boundary for cancellation. P10B
provides the bounded contract state but not the host, server, queue, timers, TLS, retry scheduler
or inner verifier.

Logs and metrics are aggregate bounded reason counters only. Do not log frames, prefixes,
digests, IPs, capabilities, receipt identifiers, attempts, accounts or topology.
