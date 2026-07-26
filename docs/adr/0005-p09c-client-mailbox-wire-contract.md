# ADR 0005: Dormant P09C client mailbox wire contract

Status: proposed additive contract; no production default. Date: 2026-07-26.
Human owner: Mr. X.

## Decision

The client mailbox adapter uses an additive Deep-extension contract isolated in
`Deep.Protocol.DeepExtension.MailboxCapabilities`. Nothing in this ADR changes Session protobufs,
existing Session addressing, runtime registration or feature defaults.

The canonical frames are:

- `MEO1`: bounded encrypted opaque envelope;
- `MST1`: store request carrying only an `MCP1` deposit presentation;
- `MRT1`: retrieve request carrying only an `MCP1` retrieve presentation;
- `MRP1`: bounded retrieve page;
- `MAK1`: bounded acknowledgement page;
- `MRR2`: replica receipt transcript with placement and membership binding;
- `MQR2`: exactly-two-replica durable quorum over canonical `MRR2` digests.

Every frame has a magic and exact version byte, rejects trailing bytes and nonzero reserved fields,
and is dormant until a downstream host explicitly registers reviewed crypto, durable lifecycle and
transport implementations. V1 receipt bytes remain supported only through the existing V1 codec;
V1 and V2 cannot be cross-decoded.

## Addressing and capabilities

Deposit and retrieve values remain different runtime and wire domains. A store frame cannot carry
a retrieve capability. No store model contains a retrieve or recipient-master field. A sender is
given only a contact-scoped rotating deposit presentation over the authenticated E2EE contact path.

`BlindedMailboxId` and `BlindedPlacementId` are separate fixed 32-byte opaque types. Raw Session
IDs, user IDs and sender-recipient pairs are not fields in any client-mailbox frame. The word
“blinded” describes the required producer contract, not a cryptographic claim by the codec: the
future producer must use reviewed, independent derivation under the published domain labels and
must not pass a stable identity through these constructors.

Only a bounded adjacent epoch window is accepted. It contains current `E` and next `E+1`, with an
explicit finite overlap. Epoch `E+2`, non-adjacent generations and unbounded overlap fail closed.
The outer operation, capability presentation and encrypted envelope bind the same epoch and
operation ID.

## Envelope, pagination and state

`MEO1` carries blinded mailbox and placement identifiers, a 16-byte operation ID, a 32-byte
end-to-end deduplication/ack digest, creation/expiry seconds and 32..81768 bytes of opaque
ciphertext. The complete canonical `MEO1` frame is therefore at most 81920 bytes, matching xnode
`a193dcc`'s default `MaxBlobBytes`; the earlier 81920-byte ciphertext limit produced an
incompatible 82072-byte frame and is rejected by the corrected contract. TTL is 60 seconds through
7 days. The protocol library does not encrypt, decrypt or inspect the ciphertext.

Retrieve and ack page sizes are 1..100. Continuation tokens are opaque and at most 256 bytes.
Retrieve responses are at most 1 MiB including framing and nested envelopes. Ack entries use
strictly increasing nonzero cursors and fixed envelope digests. Every `MRP1` item canonically binds
one cursor to one nested `MEO1`; its acknowledgement uses that cursor and the exact nested
deduplication/ack digest. Item cursors are unique and strictly increasing, and `nextCursor` equals
the last item cursor. Pre-correction `MRP1` bytes without item cursors fail canonical decoding. A
final ack page has no continuation token; a non-final page must have one.

`accepted`, `durable` and `delivered` are deliberately distinct:

- accepted means a request was admitted, not persisted to quorum;
- durable requires a verified two-replica durable quorum;
- delivered is client-local and requires authenticated decryption plus a verified durable ack
  tombstone. No server receipt can synthesize delivered.

## Receipt V2 and xnode compatibility

The current xnode mailbox implementation at `a193dcc` signs a JSON receipt over
`storageRouterId`, `mailboxId`, `blobId`, `expiresAtUnixMs`, `storedAtUnixMs` and
`stored|duplicate`. That JSON is an implementation-local wire and is not redefined as canonical
Deep protocol.

`MRR2` freezes the client-facing conceptual mapping:

| xnode `a193dcc` concept | Canonical `MRR2` field |
| --- | --- |
| `storageRouterId` | 32-byte replica ID |
| `mailboxId` | 32-byte blinded mailbox ID |
| `blobId` | 32-byte encrypted-envelope digest |
| `expiresAtUnixMs` | expiry in canonical Unix seconds |
| `storedAtUnixMs` | accepted/durable Unix seconds |
| `stored` / `duplicate` | stored / duplicate disposition |

`MRR2` additionally binds the operation ID, epoch, monotonic cursor, placement commitment,
membership commitment and tombstone disposition. `MQR2` requires two distinct replica IDs, two
valid durable statements that agree on all client context, and a coordinator signature over the
ordered canonical replica-receipt digests. Signature and digest algorithms remain
`IMailboxReceiptCrypto` host boundaries; deterministic test vectors are not production crypto.

xnode must adopt or explicitly translate this pinned contract in a later consumer change. No
claim is made that its current JSON bytes are byte-compatible with `MRR2`.

## Downgrade, replay and activation

Legacy mirror overlap is accepted only when both outer policy and the nested capability policy
explicitly allow it. Unsupported versions, changed magic, mixed outer/inner markers, stale epochs,
capability-domain substitution, replay rejection and idempotency conflict all fail closed. There
is no fallback to raw identity or a V1 receipt after a V2 verification failure.

This change adds no producer, master-secret derivation, encryption, signature implementation,
storage, transport, persistence, DI registration, feature flag or runtime default.
