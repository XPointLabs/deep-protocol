# Deep extension privacy routing V1

Status: normative local clean-break contract; runtime and production activation remain gated.

Contract identifier: `Deep.Protocol/Deep-extension-privacy-routing-v1`.

This Deep-only extension carries an exact canonical mailbox request through exactly three
independently keyed XNodes. It reuses the opaque body of the managed-ingress HTTP/2 contract and
does not change MAU2, MQR3/MRP1/MAR1, PRQ2 replication, mailbox placement, or frozen DNP1 bytes.
It is not Session wire compatibility.

All integers are unsigned big-endian. All reserved bytes and padding bytes are zero. Unknown
magic, versions, suites, purposes, layer kinds, operations, result kinds and failure codes reject.
An implementation validates the complete bounded envelope before public-key opening and validates
the complete canonical plaintext before forwarding or invoking mailbox code.

## Limits and route

| Item | Bound |
| --- | ---: |
| route hops | exactly 3 |
| router id | exactly 32 nonzero bytes |
| independent router X25519 public/private key | exactly 32 nonzero bytes |
| operation id, attempt id, per-hop replay id | exactly 32 nonzero bytes each |
| canonical request or complete `DPR1` response | 0..1,048,576 bytes |
| success body inside `DPR1` | 0..1,048,556 bytes |
| managed-ingress frame | 64..1,572,864 bytes |
| padding block | power of two, 256..65,536 bytes; default 4,096 |
| in-memory replay window | 1..65,536 entries |

The route is ingress relay, core relay, mailbox exit. Router ids must be distinct. A relay layer
contains no operation, mailbox, endpoint, response key, operation id or attempt id. It contains
only its local replay id, the next router id and the next opaque request frame. Endpoint resolution
is an authenticated membership/runtime responsibility outside these bytes.

Ed25519 and X25519 keys are independent. Key conversion is forbidden. Each sealed layer uses a
fresh ephemeral X25519 key pair and nonce. The reply uses a separate fresh client ephemeral
X25519 key pair owned by a disposable reply context.

## `DRF1` encrypted envelope

Suite 1 is the Sodium `crypto_box` construction exposed by `PublicKeyBox`: ephemeral X25519
agreement with XSalsa20-Poly1305 authenticated encryption. Purpose 1 is a request layer; purpose 2
is an end-to-end response.

| Offset | Length | Field |
| ---: | ---: | --- |
| 0 | 4 | ASCII `DRF1` |
| 4 | 1 | version 1 |
| 5 | 1 | minimum reader version 1 |
| 6 | 1 | suite 1 |
| 7 | 1 | purpose 1 request or 2 response |
| 8 | 32 | ephemeral X25519 public key |
| 40 | 24 | nonce |
| 64 | 4 | ciphertext length |
| 68 | variable | ciphertext including the 16-byte authenticator |

The ciphertext length equals the remaining frame length exactly. Authentication failure does not
expose plaintext classification.

## `DRL1` relay plaintext

The fixed prefix is 80 bytes.

| Offset | Length | Field |
| ---: | ---: | --- |
| 0 | 4 | ASCII `DRL1` |
| 4 | 1 | version 1 |
| 5 | 1 | minimum reader version 1 |
| 6 | 1 | layer kind 1 |
| 7 | 1 | reserved zero |
| 8 | 32 | nonzero hop replay id |
| 40 | 32 | nonzero next router id |
| 72 | 4 | inner `DRF1` request-frame length |
| 76 | 4 | zero-padding length |
| 80 | variable | exact inner request frame, then exact zero padding |

The inner frame is checked as a canonical bounded purpose-1 `DRF1` envelope before forwarding.
The relay registers the replay id before beginning the forward. Replayed ids reject. Saturation
fails closed and must not evict an accepted id during the key epoch. `PrivacyRoutingReplayWindow`
provides the bounded process-local primitive; a host owns epoch persistence and restart policy.

## `DRE1` exit plaintext

The fixed prefix is 144 bytes. Operation is 1 Store, 2 Retrieve or 3 Acknowledge.

| Offset | Length | Field |
| ---: | ---: | --- |
| 0 | 4 | ASCII `DRE1` |
| 4 | 1 | version 1 |
| 5 | 1 | minimum reader version 1 |
| 6 | 1 | layer kind 2 |
| 7 | 1 | operation |
| 8 | 32 | nonzero exit replay id |
| 40 | 32 | nonzero logical operation id |
| 72 | 32 | nonzero outer attempt id |
| 104 | 32 | client ephemeral reply X25519 public key |
| 136 | 4 | canonical mailbox request length |
| 140 | 4 | zero-padding length |
| 144 | variable | exact canonical request, then exact zero padding |

`BuildForCanonicalMailboxRequest` derives the stable logical operation id as:

```text
SHA-256(
  ASCII "Deep/PrivacyRouting/V1/canonical-mailbox-operation-id" ||
  u64be exactCanonicalMailboxRequestLength ||
  exactCanonicalMailboxRequest)
```

It generates a fresh nonzero CSPRNG attempt id each time the outer route is sealed. Retries retain
the inner mailbox idempotency material but use a new outer attempt and new layers. The exit checks
its replay id before mailbox dispatch and passes the exact request bytes unchanged to the native
mailbox verifier.

## `DPR1` terminal result

`DPR1` is the HTTP-independent result sealed inside the end-to-end response. Success contains the
exact canonical MQR3, MRP1 or MAR1 bytes selected by the operation. Failure contains no body or
text.

| Offset | Length | Field |
| ---: | ---: | --- |
| 0 | 4 | ASCII `DPR1` |
| 4 | 1 | version 1 |
| 5 | 1 | minimum reader version 1 |
| 6 | 1 | kind 1 success or 2 failure |
| 7 | 1 | operation |
| 8 | 2 | zero on success; stable failure code on failure |
| 10 | 1 | retryable marker |
| 11 | 1 | reserved zero |
| 12 | 4 | body length |
| 16 | 4 | reserved zero |
| 20 | variable | success body; absent on failure |

Failure codes are: 1 malformed request, 2 authentication rejected, 3 authorization rejected,
4 replay rejected, 5 mailbox not found, 6 conflict, 7 capacity exceeded, 8 unavailable,
9 outcome unknown and 10 internal failure. Only capacity exceeded, unavailable and outcome unknown
have retryable marker 1. The mapping is exact; contradictory markers reject.

`OutcomeUnknown` means dispatch may have crossed the mailbox mutation boundary. It must not be
reported as definite non-acceptance. The inner mailbox idempotency contract remains authoritative.

## `DRS1` response plaintext

The exit encodes one `DPR1`, then encrypts this plaintext to the client reply key in a purpose-2
`DRF1`. Relays return the opaque response without opening or re-encrypting it.

| Offset | Length | Field |
| ---: | ---: | --- |
| 0 | 4 | ASCII `DRS1` |
| 4 | 1 | version 1 |
| 5 | 1 | minimum reader version 1 |
| 6 | 1 | operation |
| 7 | 1 | reserved zero |
| 8 | 32 | operation id copied from `DRE1` |
| 40 | 32 | attempt id copied from `DRE1` |
| 72 | 4 | `DPR1` length |
| 76 | 4 | zero-padding length |
| 80 | variable | exact `DPR1`, then exact zero padding |

The client opens the response only with its disposable reply context and verifies operation,
operation id and attempt id before decoding `DPR1`. A successful managed-ingress transit without
this verified inner result cannot advance durable application state.

## Padding and privacy boundary

For each request layer and response, zero padding makes the complete `DRF1` frame length an exact
multiple of the selected block. Every hop is padded independently. The selected block size is
local policy but is fixed for a sealed route attempt; alternate encodings, nonzero padding and
length mismatches reject.

This construction prevents one honest non-colluding node from observing both the client source
and the mailbox exit. It does not hide the client IP from the first ingress, the blinded mailbox
from the exit, timing, direction, connection reuse or padded length. It makes no global-observer,
collusion-resistance, unblockability or Tor-equivalence claim. Production activation requires
runtime TLS/membership binding, rate limits, replay-epoch policy, chaos and traffic-analysis
evidence, and independent privacy/crypto review.

## Downstream cutover and reset impact

This adds public `Deep.Protocol.DeepExtension.PrivacyRouting` APIs, so XNode and client consumers
must repin the exact protocol package revision when they adopt the runtime. It changes no frozen
DNP1 artifact, MAU2 byte, mailbox database row or durable inner operation id and therefore does
not require a mailbox/account data reset. The clean-break cutover does require independently
generated router X25519 keys, empty replay epochs and removal of the direct release transport;
those operational inputs must be provisioned atomically with the consumer repin.
