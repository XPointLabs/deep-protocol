# ADR 0010: P10B managed ingress HTTP/2 opaque transit

Status: accepted and implemented for direct HTTP/2 transit; masked client
carrier binding remains blocked. Date: 2026-07-19. Human owner: Mr. X.

Normative contract identifier: `Deep.Protocol/P10B-managed-ingress-h2-v1`.

Implementation status reviewed 2026-08-30: XNode exposes the bounded managed
ingress and the client sends canonical opaque frames to it. XNode also has a
VLESS/Reality ingress, but MAUI does not yet route this request through its
Reality runtime. Therefore this ADR supports the inner transit contract but
does not establish censorship-resistance end to end.

## Decision

The public ingress contract carries one bounded, already sealed route/onion frame over HTTP/2.
It is a transport boundary, not a mailbox authority. The ingress does not parse or branch on
legacy bundle/capability/receipt formats, future storage evidence, account state or billing state.

The exact V1 frame endpoint is:

```text
POST /api/ingress/v1/frame
Content-Type: application/vnd.xpoint.deep.ingress-opaque-v1
Accept: application/vnd.xpoint.deep.ingress-opaque-v1
```

A canonical successful response is HTTP `200` with one complete opaque response frame. It means
only `TransitCompleted`. HTTP success, TLS success, an ingress buffer write or response-body
completion never means mailbox acceptance, durability or delivery. `202`, `204` and redirects are
not successful P10B outcomes. Declared response metadata without the exact complete bounded body
is `OutcomeUnknown`.

The exact bounded advisory capability endpoint is:

```text
GET /api/ingress/v1/capabilities
Accept: application/vnd.xpoint.deep.ingress-capabilities-v1+json
```

It contains only public transport versions, media types, limits, bounded feature names, aggregate
readiness and bounded retry delay. It is not signed membership, cannot add a trust root and cannot
widen a client policy. Unknown critical features fail closed.

## Resource and privacy boundary

Opaque frames are 64..1,572,864 bytes. Decoded header lists are at most 8,192 bytes and 32 fields.
Capability documents are at most 4,096 bytes. Canonical outer errors are exactly 64 bytes and
contain no text, request identifier, digest or evidence.

Queries, compression, redirects, cookies, authorization, idempotency headers and distributed
tracing/correlation headers are forbidden. Account, plan, payer, wallet, operation, attempt,
session, capability, receipt, forwarding and hop-by-hop headers are also forbidden. Mandatory
HTTP/2 routing and media fields are included in both the 32-field and 8,192-byte decoded limits
and cannot be duplicated by an adapter. TLS early data is rejected. The public ingress still
observes source IP, timing, connection reuse, direction, endpoint choice and padded ciphertext
length. This contract makes no global-anonymity, endpoint-unblockability or full-IP-cutoff claim.
Supplemental public request headers are forbidden. Supplemental responses are limited to exact
`cache-control: no-store` and a contract-bound `retry-after`.

## Retry and cancellation

Before a full bounded request is admitted, truncation, overflow or cancellation proves that P10B
did not forward it. After forwarding begins, cancellation, reset, timeout, disconnect and
upstream ambiguity yield `OutcomeUnknown`; they do not prove non-acceptance or rollback. A retry
uses a newly sealed outer attempt while preserving the separately defined inner logical
idempotency context.

## Error contract

`DIE1` is a fixed 64-byte big-endian outer error. It distinguishes before-forward failures from
unknown-after-forward outcomes and permits a bounded 1..60 second retry value only where the
status mapping allows it. When nonzero, the HTTP `Retry-After` header must occur exactly once and
equal the canonical decimal value in `DIE1`; it must otherwise be absent. Unknown versions,
classes, certainty values, reserved bytes, malformed outer responses and noncanonical retry
combinations become `OutcomeUnknown` rather than definite rejection.

## Non-goals and activation blockers

P10B does not implement ASP.NET, ingress-to-core authentication, proxy configuration, TLS
deployment, bridge discovery, P03/P03B producers, P05A storage evidence, outbox state or client
runtime wiring. It changes no protobuf or Session-compatible wire. Production activation remains
blocked on P07B/P10/P11B/P15, reviewed inner crypto/evidence producers, deployment evidence and
independent security review.
