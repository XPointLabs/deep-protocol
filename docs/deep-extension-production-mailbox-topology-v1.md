# Production Mailbox Topology V1

`production-mailbox-topology.v1` (`PMT1`) and `production-mailbox-selection.v1` (`PMS1`) are
public, deterministic, verify-only artifacts. They turn one already verified PMA1 authority into
an exact two-replica route without putting a mailbox identifier, private key, signing API, storage
operation, token rule, or network fetch in the protocol package.

## Trust and publication order

1. Verify and durably commit PMA1/PMR1.
2. Publish PMT1 signed by the exact PMA1 mailbox-issuer Ed25519 key. PMT1 contains the final
   canonical PMA1 SHA-256, so PMA1 never refers back to PMT1 and there is no signature/hash cycle.
3. For a mailbox, compute `SHA-256("Deep/PMT1/selection-input/v1" || BlindedPlacementId32)`. The
   API accepts the existing strongly typed blinded placement identifier, not a raw mailbox ID; the
   identifier itself is never encoded in PMT1/PMS1.
4. Compute the independent per-mailbox
   `MailboxPlacementCommitment.Compute(BlindedPlacementId32)`. Publish PMS1 signed by the same
   issuer. PMS1 binds the canonical PMT1 SHA-256, the caller's selection-input commitment, and this
   per-mailbox commitment.
5. Verify both embedded canonical MIP1/RIP1 proofs against the exact selected epoch membership
   commitment before using the returned endpoint and SPKI pins.

Hosts must atomically persist the PMT1 `(generation, canonical hash)` last-known-good state. A
verified-PMA-bound PMT1 genesis is exactly generation `1` with a zero previous hash; after genesis,
PMT1 accepts only the exact successor and exact nonzero previous hash. PMS1 is immutable and does
not advance that lineage.

The separate bounded-forward PMT1 verifier exists only for an authenticated PSS1
`OfflineCheckpoint` after the exact current PMA1 has passed pinned-Mr. X forward-checkpoint
verification. It requires a live current-issuer signature and a strictly forward non-terminal
generation. It is internal to the high-level offline PSS1 verifier, not a generic shortcut around
ordinary PMT1 LKG lineage.

## PMT1 canonical binary

All integers are unsigned big-endian. PMT1 is fixed order: `PMT1`, version `1`, three zero bytes,
network (16), authority generation, final authority hash (32), topology generation, previous
topology hash (32), issued/expires, then exactly current and next epoch sections, followed by the
64-byte issuer signature. Each epoch contains epoch/generation, membership and global topology
placement commitments, PMA validity times, node count, and strictly increasing nodes. The topology
placement commitment is catalog/policy state and is never copied into a per-user MCG2. A node contains its
32-byte MRL1 router ID, length-prefixed canonical HTTPS origin, and distinct current/next 32-byte
SPKI SHA-256 pins.

There must be at least two nodes and at most 4096. Node IDs and endpoints are distinct. Unknown
versions, nonzero reserved fields, malformed UTF-8, trailing bytes, HTTP, credentials, query,
fragment, non-root paths, development names, all-zero IDs/hashes/pins, invalid time windows, and
unordered/duplicate nodes fail closed. Private numeric endpoints are accepted only when the
verified PMA1 explicitly says `UserManagedPrivateHttps`; official topology is public HTTPS only.
DNS resolution, TLS handshake validation, live SPKI enforcement, fetch and atomic file replacement
remain host responsibilities.

## Rendezvous-SHA256-v2

For every PMT1 node compute:

`SHA-256("Deep/PMT1/rendezvous-sha256/v2" || network16 || epoch8 || generation8 || membership32 || placement32 || selectionInput32 || nodeId32)`

V2 deliberately excludes the outer PMA1 authority generation from the rendezvous score. PMS1 still
binds and is signed over the exact PMA1 generation/hash, while a promoted old-next/new-current epoch
with identical epoch generation and catalog commitments retains the same ordered replicas. This is
required for explicit PSS1 overlap verification during authority rotation.

All fields after the domain are fixed width. Sort ascending by the 32-byte score, breaking an
improbable tie by ascending node ID, and take the first two. PMS1 must encode those two distinct
IDs in rank order; a verifier recomputes the ranking rather than trusting publisher ordering.

## PMS1 canonical binary

PMS1 is fixed order: `PMS1`, version `1`, three zero bytes, algorithm `2` plus three zero bytes,
network/authority generation/authority hash, topology generation/topology hash, epoch/generation,
membership/global-topology-placement/per-mailbox-placement/selection-input commitments,
issued/expires, replica count `2` plus three zero
bytes, then exactly two `(replicaId32, proofLength16, two zero bytes, canonical MIP1)` entries and a
64-byte issuer signature. Its lifetime is at most 24 hours.

Verification requires a `VerifiedProductionMailboxAuthority`, a
`VerifiedProductionMailboxTopology` and one caller-owned, strongly typed `BlindedPlacementId`.
The verifier domain-computes both the selection-input commitment and per-mailbox placement
commitment internally; callers cannot accidentally source either expected hash from an untrusted
PMS1. Thus two users can share one PMA1/PMT1 while receiving distinct MCG2 placement bindings.
Substituting the caller placement ID or either signed commitment fails closed.
Each MIP1 must be canonical, name the ranked node and exact epoch/root, contain a
canonical RIP1 proof, and prove Storage role/capability and its independent Ed25519 key at the
verification time. The result is an immutable two-replica handle with endpoint and both pins.

There is deliberately no legacy topology parser or compatibility conversion: Deep is not yet in
production, so PMT1/PMS1 is a clean production boundary.
