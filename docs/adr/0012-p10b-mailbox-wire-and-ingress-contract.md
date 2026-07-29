# ADR 0012: P10B mailbox peer wire and dormant public ingress

Status: accepted for contract implementation; production activation blocked. Date: 2026-07-27.
Human owner: **Mr. X**.

## Decision

P10B is an additive Deep-extension contract. It does not change the P03B2 `MST1`, `MRT1`,
`MAK1`, `MRP1`, `MRR2`, `MQR2`, `MAR1`, `MIP1` or `PRQ1` encodings and does not register runtime
routes. It adds the PRQ2-only `MQR3` quorum domain; legacy PRQ1 continues to use `MQR2`.

The authenticated peer request is `PRQ2` version 2. It has two operations, Store and Tombstone,
and no legacy JSON representation or conversion. The direct peer response is exactly one durable,
recipient-signed Ed25519 `MRR2`; there is no response wrapper. The sender combines its own
persisted `MRR2` and the recipient response into one verified `MQR3`. A public client Store
response is exactly one durable `MQR3`, Retrieve returns `MRP1`, and ACK returns one `MAR1`
containing one ordered tombstone `MQR3` for every ordered `MAK1` item. The aggregate ACK choice
avoids 100 independent HTTP outcomes without assigning any new durability meaning to `MAR1`.

All integer fields are unsigned big-endian. Reserved bytes are zero. Trailing bytes, unknown
versions, alternate signature lengths and non-canonical nested frames fail closed.

## PRQ2 exact layout

| Offset | Bytes | Field |
| ---: | ---: | --- |
| 0 | 4 | ASCII `PRQ2` |
| 4 | 1 | version `2` |
| 5 | 1 | operation: Store `1`, Tombstone `2` |
| 6 | 2 | zero |
| 8 | 8 | epoch |
| 16 | 16 | operation ID |
| 32 | 32 | sender router ID |
| 64 | 32 | recipient router ID |
| 96 | 32 | membership commitment |
| 128 | 32 | placement commitment |
| 160 | 32 | blinded mailbox ID |
| 192 | 8 | nonzero cursor |
| 200 | 8 | request creation Unix seconds |
| 208 | 8 | envelope/request expiry Unix seconds |
| 216 | 32 | random durable replay nonce |
| 248 | 32 | SHA-256 of the exact payload |
| 280 | 4 | payload length |
| 284 | 2 | sender `MIP1` length |
| 286 | 2 | recipient `MIP1` length |
| 288 | 2 | Ed25519 signature length, exactly `64` |
| 290 | 6 | zero |
| 296 | variable | payload, sender `MIP1`, recipient `MIP1`, signature |

Store payload is exactly one canonical `MEO1` and is 184..81920 bytes. Tombstone payload is
exactly the 32-byte envelope/deduplication digest being removed. Both use
`SHA-256(exact payload)` in the payload-digest field. The sender and recipient proofs occur in
that order and must bind their respective router ID, Ed25519 key, epoch, storage role and exact
membership commitment. The placement commitment is the existing
`deep.mailbox.placement-commitment.v2` digest of the blinded placement ID.

The Store request is 786..90712 bytes and the Tombstone request is 634..8824 bytes. The only
successful peer response is an exact 296-byte Ed25519 `MRR2` with `Durable` status. Store permits
`Stored` or `Duplicate`; Tombstone permits only `Tombstone`. The recipient must persist the exact
mutation before constructing or signing the response.

## Signature, digest and replay domains

Ed25519 signs one 32-byte SHA-256 digest. For Store the ASCII domain is
`deep.mailbox.peer.store-request.v2`; for Tombstone it is
`deep.mailbox.peer.tombstone-request.v2`. Its preimage is:

```text
U16BE(domain byte length) || ASCII(domain) ||
U32BE(unsigned PRQ2 byte length) || exact unsigned PRQ2
```

The unsigned PRQ2 includes every byte through the ordered nested `MIP1` proofs but excludes the
64-byte signature. The sender `MIP1` Ed25519 public key verifies the signature. The durable replay
request identity uses the same length-framing with
`deep.mailbox.peer.request-identity.v2` over the complete signed `PRQ2`.

The epoch-scoped replay key and finite retention contract are specified below. The host must
atomically reserve before storage work. Exact pending retries remain pending after a crash. An
exact completed retry returns the cached canonical `MRR2`. Reusing the same live scope with
different complete request bytes is an equivocation/replay conflict. Completion accepts only the
exact effective persisted reservation and one verified durable recipient `MRR2`. Replay evaluation
returns the persisted reservation timestamp for pending/completed scopes; retry-time clock values
must never replace it when recreating a receipt or completing recovered pending work.

`MRR2` itself is intentionally unchanged and does not add the transport replay nonce. It signs the
business outcome fields: recipient replica, operation, epoch, cursor, blinded mailbox,
placement/membership commitments, envelope digest, expiry, disposition and durable timestamps.
The verified `PRQ2` replay transaction binds that existing outcome to the request. Adding the nonce
to `MRR2` would silently break P03B2 and was rejected.

Initial-admission freshness is fixed rather than host-selectable: creation may be at most 120
seconds old and must not be later than verification time (future skew is exactly zero). Once that
fresh admission is durably reserved, an exact pending/completed retry may exceed 120 seconds only
through a read-only lookup of the existing request-identity scope; an unknown stale request cannot
create replay state. Expiry must remain strictly after verification time. Expiry is also bound to
`MEO1` for Store. Tombstone expiry must be no more than seven days after request creation.
Every successful `MRR2`, including a validly signed cached response, must have
`AcceptedAtUnixSeconds >= PRQ2.CreatedAtUnixSeconds`.

P03B2 response signing is preserved exactly: Ed25519 signs the 224-byte `MRR2` signing transcript
beginning with magic `MRR2` and version `2`; PRQ1 `MQR2` remains byte-for-byte unchanged. PRQ2 uses
the distinct 116-byte `MQR3` signing transcript beginning with magic `MQR3` and version `3`.
That transcript contains the coordinator ID and sequence, exact nested lengths, and SHA-256
digests of the two exact canonical `MRR2` frames in router-ID order. `MQR2` and `MQR3`
magic/version bytes are separate signing domains. Changing only magic/version cannot transfer a
valid signature between them.

## PRQ2 durable quorum and aggregate ACK

A PRQ2 durable quorum contains exactly two 296-byte Ed25519 `MRR2` frames. Their router IDs must be
the distinct sender and recipient from the verified PRQ2 and must appear in ascending byte order.
Each signature is verified with its own MIP1-authorized key. Both statements must be Durable, use
the same allowed disposition, and exactly match PRQ2 operation ID, epoch, cursor, blinded mailbox,
placement/membership commitments, envelope digest, expiry and request creation lower bound.

The MQR3 coordinator must be one of those two routers and its signature is verified with that
router's MIP1 key. P10B binds the complete signed PRQ2, including nonce and request version, into
the MQR3 `CoordinatorSequence`:

```text
CoordinatorSequence =
  U64BE(PRQ2 request-identity SHA-256[0..8]) OR 0x8000000000000000
```

The canonical `MQR3` frame is:

| Offset | Bytes | Field |
| ---: | ---: | --- |
| 0 | 4 | ASCII `MQR3` |
| 4 | 1 | version `3` |
| 5 | 3 | zero |
| 8 | 32 | coordinator router ID |
| 40 | 8 | coordinator sequence |
| 48 | 2 | first canonical `MRR2` length |
| 50 | 2 | second canonical `MRR2` length |
| 52 | 64 | zero |
| 116 | 2 | coordinator Ed25519 signature length, exactly `64` in P10B |
| 118 | 2 | zero |
| 120 | variable | first `MRR2`, second `MRR2`, coordinator signature |

Each nested Ed25519 `MRR2` is exactly 296 bytes, so a P10B `MQR3` is exactly 776 bytes.
The 116-byte signing transcript uses the same offsets, except bytes 52..83 and 84..115 contain
the SHA-256 digests of the exact first and second `MRR2` frames instead of zeros.

The high bit makes the value nonzero. The `MQR3` magic/version/signing transcript is the
cryptographic PRQ1/PRQ2 domain boundary; the sequence additionally binds the exact PRQ2 request.
The PRQ1 API accepts only `MQR2`, while the PRQ2 API accepts only `MQR3`. A cross-domain frame,
PRQ1 cursor-sequence quorum, noncanonical router order, duplicate/substitute router, wrong MIP1
key or changed coordinator fails verification. No PRQ1 request or receipt is synthesized by the
PRQ2 API.

For ACK, the exact decoded canonical MAK1 acknowledgement order is authoritative. Count is 1..100.
For each index, the verified PRQ2 must be Tombstone and match MAK1 epoch, operation ID, blinded
mailbox, placement, cursor and exact envelope digest. All items use one exact sender/recipient
fanout and membership commitment. Each nested MQR3 passes the PRQ2 durable-quorum verifier before
MAR1 construction. MAR1 verification repeats those checks by index; duplicate, reordered or
substituted acknowledgement, PRQ2 or MQR3 bytes fail closed. Legacy P03B2 `MAR1(MQR2[])` remains
unchanged and is rejected by the PRQ2 aggregate API; `MAR1(MQR3[])` is rejected by the PRQ1
aggregate API.

## Durable replay retention and GC

Replay scope is epoch-specific:

```text
SHA-256(
  U16BE(domain length) || "deep.mailbox.peer.replay-scope.v2" ||
  U64BE(epoch) || senderRouterId || recipientRouterId || replayNonce)
```

The verification policy supplies the authoritative epoch expiry. It must be after verification
time, contain request expiry, and be no more than seven days after request creation. The durable
claim and snapshot persist exact request creation, request expiry, initial reservation time, epoch
expiry and:

```text
RetainUntil = EpochExpiresAt + 7 days
```

Pending and completed records are retained through that instant, including restart. GC may delete
either state only at or after `RetainUntil`, in atomic batches of at most 1024. Thus the journal is
bounded by a hard 1,209,600 records per sender/recipient/epoch partition (120/minute for seven
days) plus a finite seven-day post-epoch window; capacity exhaustion fails closed. The host must
retire the epoch before GC; an old exact or conflicting frame is then stale at policy verification
and never reaches an empty journal. Reusing the same nonce in the same live epoch remains exact
retry or conflict. Reuse in a later epoch is an explicitly new, domain-separated scope,
eliminating post-retention nonce ambiguity.

## Dormant HTTP mapping

Every request is `POST`. Content-Type is the exact listed ASCII value with no parameters.
`Content-Encoding` is absent; compression and transcoding are forbidden. The raw body is supplied
unchanged to the canonical decoder. Content-Length must be rejected before allocation when outside
the stated bounds. Requests without Content-Length, including chunked transfer, are rejected before
body processing; a declared length below the canonical frame minimum is malformed and a length
above the endpoint maximum is too large.

| Route | Request | Success response | Request bytes | Response bytes | Deadline | Concurrency | Rate |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: |
| `/api/client/mailbox/v1/store` | `MST1`, `application/vnd.deep.mailbox.mst1` | 200 `MQR3`, `application/vnd.deep.mailbox.mqr3` | 380..82836 | 776 | 15 s | 16 | 60/min/capability scope |
| `/api/client/mailbox/v1/retrieve` | `MRT1`, `application/vnd.deep.mailbox.mrt1` | 200 `MRP1`, `application/vnd.deep.mailbox.mrp1` | 268..1244 | 48..1048576 | 10 s | 16 | 120/min/capability scope |
| `/api/client/mailbox/v1/acknowledge` | `MAK1`, `application/vnd.deep.mailbox.mak1` | 200 `MAR1`, `application/vnd.deep.mailbox.mar1` | 308..5244 | 818..77840 | 15 s | 16 | 60/min/capability scope |
| `/api/peer/mailbox/v2/store` | Store `PRQ2`, `application/vnd.deep.mailbox.prq2` | 200 `MRR2`, `application/vnd.deep.mailbox.mrr2` | 786..90712 | 296 | 15 s | 32 | 120/min/sender router |
| `/api/peer/mailbox/v2/tombstone` | Tombstone `PRQ2`, `application/vnd.deep.mailbox.prq2` | 200 `MRR2`, `application/vnd.deep.mailbox.mrr2` | 634..8824 | 296 | 15 s | 32 | 120/min/sender router |

Concurrency is a hard in-flight cap per endpoint. Rate windows are fixed 60-second windows.
Capability partitions use the verified blinded capability replay scope, never a raw user,
sender-recipient pair or IP-derived identity. Peer partitions are created only after the sender
router and membership proof verify; unauthenticated traffic uses a separate host-global pre-auth
limit that is required operationally but is not an identity or wire field.

Error bodies are always empty and have no Content-Type. The exact privacy-coarsened status mapping
is: malformed canonical body `400`; authentication `401`; authorization `403`; wrong method `405`;
replay, idempotency, stale or expired `409`; missing Content-Length/chunked transfer `411`; size
`413`; Content-Type/Content-Encoding `415`; rate or concurrency `429`; unavailable
authority/storage `503`; deadline `504`. No parser error, membership detail, replica ID, cursor,
digest, nonce or capability material is reflected.

Metrics/logs may include only endpoint operation, the coarse status bucket, response status and
bounded duration/size buckets. Raw bodies, signatures, capabilities, router IDs, blinded
identifiers, commitments, operation IDs, cursors, digests, nonces and continuation tokens must not
be logged, tagged or traced.

## Compatibility and activation

This contract is not Session wire, does not modify protobuf, and is not compatible with XNode's
legacy `/api/peer/mailbox/replica` JSON request or receipt. That route must not translate to or
from `PRQ2`, `MRR2`, `MQR3` or `MAR1`.

The public `MST1`/`MRT1`/`MAK1` metadata freezes transport interop only. Those V1 frames still carry
opaque `MCP1`; strict authenticated V2 uses `MAU2` and remains non-convertible. Neither surface is
activation authority. Issuer/key custody, authority distribution, durable membership LKG,
revocation, persistent replay/outbox/storage, placement selection, coordinator operation,
transport registration and Android/Windows E2E remain required before runtime activation.

The P10B package must be pinned by exact source commit, exact package version and SHA-256 content
hashes. Existing P03B2 `PRQ1`/`MQR2`/`MAR1(MQR2[])` consumers remain byte-compatible and need no
migration unless they opt into the new `PRQ2`/`MQR3` and dormant HTTP metadata APIs.
