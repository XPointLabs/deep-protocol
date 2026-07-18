# ADR 0002: P03B mailbox capability and durable receipt contract

Status: proposed contract; no production default. Date: 2026-07-18. Human owner: Mr. X.

## Context and non-claims

P01 requires distinct storage-visible authorization values instead of raw Session IDs. P03/P03A
provide an opaque container and a blocked authenticated compatibility-envelope boundary. P03B must
define the contact/storage wire contract before P07A or P09 agents implement lifecycle or storage.

An `opaque` value in this ADR means only that this codec treats bytes as uninterpreted. It does not
mean secret, unlinkable, random, unforgeable or privacy-preserving. Those properties depend on a
future reviewed producer. Storage can compare repeated bytes, timing, size, generation and cursor.
The P01 observer/collusion limitations remain.

## Capability domains

Three runtime and wire domains are distinct:

- deposit capability: may be shared with an authenticated contact;
- retrieve capability: must never be shared with a sender;
- placement key: storage placement/routing input distinct from both capabilities and raw identity.

The codec has no derive/convert API between domains. Equal caller-supplied bytes remain equal at the
byte level and are not made safe by a type name. A future producer must use independently reviewed
domain separation and must prove cross-domain/cross-generation unlinkability.

Canonical `MCP1` presentation contains:

- version and exact domain;
- lifecycle marker: active, overlap, revoked or recovery;
- mixed-version marker: strict V1 or bounded legacy overlap;
- issuance generation, not-before, expiry and overlap-until buckets;
- replay counter and 16-byte idempotency key;
- bounded opaque domain value;
- optional separately framed free-admission slot.

Generation is nonzero. Expiry is after not-before. Overlap markers require a finite overlap ending
no later than expiry. Revoked presentations cannot be used as active authorization. Recovery is an
explicit marker, not permission to derive from a raw Session ID. Mixed-version legacy overlap is
bounded and never permits silent downgrade in a strict profile.

## Free admission

The optional free-admission slot is an orthogonal bounded authorization:

- 16-byte slot ID;
- validity window;
- nonzero message/use limit;
- bounded opaque authorization bytes.

It contains no payer, wallet, account, plan, token balance or payment identity. It does not change
capability domain, generation, replay or receipt rules. Billing and quota algorithms are out of
scope.

## Receipts and errors

Canonical receipt schemas are Deep extensions:

- `MRR1`: one replica statement with accepted/durable status, replica ID, operation ID,
  generation, monotonic cursor, accepted/durable buckets, tombstone marker, payload digest and
  bounded signature;
- `MQR1`: coordinator durable-quorum statement containing exactly two canonical replica receipts,
  coordinator ID/sequence and bounded coordinator signature; its signing bytes bind the
  verifier-provided digests of both ordered replica receipts, while the corresponding wire-header
  region remains reserved zero so the codec does not select a digest primitive;
- `MBE1`: accepted-stage or durable-stage error with a stable error class, retryable flag,
  generation and bounded retry-after.

Durable verification requires exactly two different replica IDs, two valid replica signatures,
durable status, and identical operation/generation/cursor/tombstone/payload digest. The coordinator
signature binds the ordered replica statement digests. Signature and digest operations are
interfaces; P03B ships no production implementation and chooses no new primitive.

Coordinator equivocation evidence contains two independently verified canonical `MQR1` statements
with the same coordinator ID and sequence but different signed statement bytes. The contract
preserves evidence; it does not publish, punish or resolve equivocation.

## Replay, idempotency and tombstones

The 16-byte idempotency key is scoped to one operation and generation. It is not a stable message,
account or cross-transport ID. Replay counters are monotonic within producer-owned state, which is
not implemented here. A client must reject stale/repeated counters through a future durable guard.

A tombstone is an explicit signed receipt state at a cursor. It is not inferred from an empty
payload and does not delete evidence. Accepted status is not durable. Only a verified `MQR1` with
two independent durable replica statements satisfies the durable contract.

## Bounds and rollback

Parsers are canonical, allocation-bounded and reject trailing bytes, unknown enums, nonzero
reserved fields, impossible windows, cross-domain decode, duplicate replicas and malformed nested
lengths. Old readers reject the distinct magic/version. Rollback stops new V1 issuance while
retaining V1 receipts/tombstones and a separately bounded legacy mirror window; it never silently
converts retrieve/deposit/placement values or falls back to raw identity.

Production activation remains disabled until a reviewed producer, lifecycle persistence, replay
guard, replica/coordinator signature implementation and storage/client E2E evidence exist.
