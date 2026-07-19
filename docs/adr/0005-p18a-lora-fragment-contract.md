# ADR 0005: P18A compact authenticated fragment contract

Status: proposed contract; production authentication and durable replay
adapters unavailable; runtime activation BLOCKED.

Date: 2026-07-18. Human owner: Mr. X.

## Context

Deep needs a compact optional carrier for small, already encrypted `DPB1`
opaque bundles. The phone or Windows client creates and verifies complete
frames; an external powered radio may spool those opaque frames over a future
BLE/USB boundary. This contract does not add LoRa to a phone, change existing
E2EE, expose plaintext, define mesh routing or select radio parameters.

P18A is a Deep extension and does not change Session wire behavior, protobuf
fields, P03/P03C semantics, mailbox capability derivation or sender
authentication.

## Decision: canonical V1 frame

An encoded frame is:

```text
16-byte header || exact fixed-size shard || 16-byte authentication tag
```

The header is ASCII `LF`, version `1`, canonical FEC flags, an opaque nonzero
eight-byte hop-local message ID, ordinal, data count, parity count and shard
size. Absolute limits are 8..192 shard bytes, 1..64 data shards, 0..8 parity
shards, 72 total fragments, 224 encoded bytes per frame and 4096 encoded
bundle bytes. Caller policy may only lower these ceilings.

Data shard zero starts with the ten-byte canonical descriptor: descriptor
version, opaque-bundle kind/version, hop/limit nibbles, exact big-endian bundle
length and expiry bucket. The remaining data capacity contains the exact
`DPB1` bytes followed only by zero padding. Decode succeeds only when the
caller-supplied `OpaqueBundleDecodePolicy` accepts those exact bytes and its
expiry bucket equals the descriptor.

The hop byte is forwarding policy, not an end-to-end security guarantee. A
relay must reassemble, increment the current hop, allocate a fresh message ID
and authentication context, and re-fragment. Relay runtime is outside P18A.

## Decision: deliberately small FEC

V1 accepts only:

- `None`: flags zero and no parity;
- `Xor1`: flag bit zero set and one XOR shard for each consecutive group of
  at most eight data shards.

Parity ordinals follow data ordinals. Exactly one absent data shard in a group
may be reconstructed from authenticated parity and every other authenticated
member. Two missing data shards stay incomplete. Unknown flags, noncanonical
parity counts, malformed parity and partial output fail closed.

## Decision: authentication and scope handles

The codec owns ASCII domain
`Deep/P18A/LoRaFragmentAuth/v1`. The adapter receives this domain, explicit
sender/receiver direction and the exact transcript:

```text
domain || direction byte || exact header || exact shard
```

Production-facing APIs use opaque provider-issued authentication and replay
scope handles whose constructors are not public. They accept no raw key,
identity, Session ID, wallet, capability or account bytes. A future reviewed
provider and authenticator must bind link scope plus network/profile scope to
the handle and its tag computation. Tag length is exactly 16 bytes.

P18A ships interfaces only. It contains no production authenticator, key
derivation, secret storage or dependency-injection registration. A
deterministic truncated HMAC-SHA-256 helper is permitted only in the test
assembly and is not a selected production construction.

## Decision: durable replay boundary and bounded admission

A durable replay-store interface owns atomic admission, durable completed and
poisoned tombstones, expiry and restart behavior. An in-memory implementation
may exist only as a test fixture.

Processing order is fixed:

1. parse header and exact frame length without copying the shard;
2. reject noncanonical fields;
3. authenticate the exact transcript;
4. atomically reserve bounded capacity;
5. only then copy/store a shard and evaluate reassembly.

Authentication uses one absolute-bounded ephemeral transcript snapshot so
the bytes retained after verification are exactly the bytes that were
authenticated even if caller-owned input is mutable. The decoded frame takes
ownership of that same buffer and does not make a second shard copy. This
transient authentication object is not admitted reassembly state. The durable
store performs the first persistent shard copy only after atomic admission.

One message may reserve at most 4352 data-shard bytes. A replay scope admits
at most four incomplete messages; the process admits at most sixteen and
64 KiB total. Policy may lower but not raise those ceilings. Expired state is
evicted first; live state is never silently evicted for an attacker-selected
ID.

Exact duplicates are idempotent. A different authenticated frame for an
existing ordinal poisons its scope/direction/message ID through expiry.
Different scopes, directions and IDs never mix. Missing input returns only
`Incomplete`. Completed, poisoned and expired IDs reject replay after
simulated restart. No detailed local failure requires a distinct over-air
response.

### Atomic store boundary

Independent pre-implementation review rejected a split
`reserve -> store -> complete` API because a crash or concurrent processor
could leak quota, accept conflicting bytes or emit payload before its durable
tombstone. The public store contract therefore has exactly two mutating
linearization points:

1. `ApplyAuthenticatedFragmentAsync` performs expired-state eviction,
   tombstone and shape checks, full-message reservation and shard copying in
   one serializable transaction. It returns an immutable generation-pinned
   snapshot only when enough authenticated shards exist.
2. `TryCommitTerminalAsync` generation-CASes `Completed` or `Poisoned` before
   reconstructed bytes may be returned. A CAS loss or unknown outcome never
   emits payload and must be reconciled through the durable record.

`ReadAsync` returns a bounded discriminated durable record for `Absent`,
`Incomplete`, `Completed`, `Poisoned` or `Expired`, including generation,
expiry/retention and only the completed bundle digest. Reconciliation uses a
caller-bounded timeout independent of a cancelled mutation token. A confirmed
read never converts an uncertain mutation into payload emission.

The key is the provider-owned replay scope handle, direction and exact
eight-byte message ID. The same logical scope may be reissued after restart,
but only the provider/store can resolve it; protocol code never serializes
`ToString`, object hashes, identity or raw scope bytes. Per-scope incomplete
quota counts both directions. Duplicate equality covers the exact authenticated
header and shard after tag verification; the tag itself is excluded.
If a corrupt store returns a snapshot for a different key, scope or direction,
the coordinator returns `OutcomeUnknown` and never poisons that foreign key.
Only same-key shape/content corruption may create a poisoned tombstone.

Incomplete state is durable. The store state machine is:

```text
Absent -> Incomplete -> Completed | Poisoned | Expired
```

A conflicting authenticated ordinal atomically replaces `Incomplete` with a
`Poisoned` tombstone. Store corruption, unavailability, cancellation with an
unknown commit outcome, or reconciliation failure is fail-closed with no
in-memory fallback.

### Reorder expiry and measurable quotas

Because descriptor expiry appears only in ordinal zero, admission of an
authenticated nonzero ordinal uses an explicit caller-supplied provisional
expiry bucket. It must be within the same
`OpaqueBundleDecodePolicy.MinimumExpiryBucket..MaximumExpiryBucket` window and
cannot exceed its maximum. Arrival of ordinal zero may only tighten that
deadline to the descriptor expiry; it can never extend it. Retention adds the
explicit accepted skew with checked arithmetic; overflow rejects policy.
If authenticated XOR recovery reconstructs ordinal zero before its physical
frame arrives, successful DPB1 validation supplies the same descriptor expiry.
The terminal generation CAS must atomically tighten the provisional deadline
to that recovered expiry before completion may emit the bundle.

The mandated per-message admission test remains
`dataCount * shardSize <= 4352`. The exact global in-memory reservation charge
is:

```text
(dataCount + parityCount) * shardSize + 256 bytes
```

The fixed 256-byte charge covers the required contiguous-state metadata,
bitmap, shape, generation and deadline. Implementations must not allocate a
per-shard object graph inside this budget. All charges use checked arithmetic;
their sum is at most 64 KiB. A caller may lower the 64 KiB cap and the message
counts, but never raise them. This preserves the 4096-byte bundle plus `Xor1`
boundary without pretending parity storage is free.
Snapshot constructors enumerate at most the authenticated expected shard
count plus one sentinel element; a corrupt or unbounded store enumerable is
rejected without materializing its tail.

Successful reassembly returns the validated immutable descriptor together
with the exact unchanged DPB1 bytes. A relay can therefore increment
`currentHop`, retain `hopLimit`, choose a fresh hop-local message ID and
re-fragment without interpreting message plaintext.

Durable terminal records have separate absolute ceilings: at most 256
tombstones per replay scope, 1024 globally and 128 KiB of canonical logical
tombstone records. A record charge is measured by the store's canonical
serialized key/status/retention/digest bytes, never object allocator
estimates. Expired tombstones are purged before admission; an unexpired record
is never evicted to admit a new ID. Hitting any tombstone ceiling rejects new
admission. Policy may lower these ceilings only.

## Privacy, power and regulatory consequences

Fragment authentication is not encryption. Observers and the untrusted
external gateway can learn Deep-shaped traffic, sizes, counts, timing,
retries, loss, the hop-local ID and radio/location observations. Reassembly
reveals the already documented `DPB1` outer metadata but not message plaintext.
Fixed shards reduce some length variation; they do not provide traffic-flow
confidentiality.

This contract makes no claim of global anonymity, unobservability, radio
unlinkability, triangulation or jamming resistance, deniability, forward
secrecy, censorship-proof delivery, range, battery acceptability or a
background SLA.

The external powered radio, not the phone, owns continuous receive. P18A
requires no periodic BLE scan, wake lock, foreground service or autonomous
phone relay. Real battery evidence belongs to P18C.

P18A defines no frequency, channel, region, spreading factor, bandwidth,
power, duty-cycle, dwell-time, antenna or certification value. Transmission
remains disabled until P18B/P18C receive a current approved legal and hardware
profile.

## Commercial boundary

P18A is part of the free communication plane. There is no per-message,
per-fragment, per-byte, per-hop or gateway fee and no XPNT, wallet,
subscription, entitlement, reward or managed-node dependency. User-owned
gateways are free and unrewarded. Future separately governed infrastructure
funding cannot alter this wire contract.

## Activation blockers

Runtime remains blocked until all of the following exist and are independently
approved:

1. reviewed link-key provisioning and production fragment authenticator;
2. durable atomic replay/quota store;
3. P18B vector-pinned loss/airtime feasibility results;
4. named P18C hardware and current legal region profile;
5. BLE/USB lifecycle, queue, permissions and two-device E2E;
6. external cryptographic/privacy review and real-device battery evidence.

Rollback disables P18A negotiation and radio transport. It never downgrades
to plaintext, reuses Session/onion/wallet keys or deletes existing opaque
bundle state.
