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
each field. The opaque application body may span multiple HTTP/2 DATA frames.

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

## Host requirements

A host must stream with bounds before forwarding, reject partial/over-limit bodies, prohibit
compression/redirect/0-RTT and distinguish the forward boundary for cancellation. P10B does not
provide the host, server, queue, timers, TLS, retry scheduler or inner verifier.

Logs and metrics are aggregate bounded reason counters only. Do not log frames, prefixes,
digests, IPs, capabilities, receipt identifiers, attempts, accounts or topology.
