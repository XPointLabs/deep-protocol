# ADR 0004: P04 membership, bridge and key hierarchy contracts

Status: proposed contract; verifier adapter only; runtime BLOCKED. Date: 2026-07-18.
Human owner: Mr. X.

## Separation and disclosure

`NetworkGenesis`, signer delegation/revocation, `BridgeSnapshot`,
`NodeMembershipCommitment`, inclusion proof and fork witness are distinct canonical Deep-extension
domains. Update, membership, bridge, reward and billing signing bytes have fixed non-interchangeable
domain tags. A bridge signer cannot authorize membership and membership keys cannot authorize
updates/rewards/billing.

Bridge snapshots expose only public entry contacts needed by clients. They never contain the full
core/storage topology. Membership commitments and proofs are node/operator material and remain
distinct from bridge discovery.

## Genesis and policy

Genesis binds network ID, genesis sequence/hash, policy version, minimum/maximum protocol, five
offline root public signer descriptors and the initial policy. Approved Beta policy data is:
3-of-5 offline roots delegate a time-bounded set of three online signers; snapshots require 2-of-3
distinct active online signatures plus a fork-witness record. Thresholds and public keys are
canonical data, not private keys or constants hidden in verifier code.
Policy version 1 is strict: no other root/signer counts or thresholds are valid under that version.
Every offline and online descriptor carries a distinct 16-byte signer ID, its exact role and a
distinct 32-byte public key. The verifier adapter receives that canonical public key; it never
looks up a key from ambient process configuration.

Self-hosted networks import their own independently signed genesis. They do not inherit Deep
production authority, network ID or signer set.

## Updates and verification

Every delegation, revocation, bridge snapshot and membership commitment binds network ID,
monotonic sequence, previous canonical hash, issued/valid bounds, min/max protocol and policy
version. Delegation/revocation requires the offline threshold. Snapshot/commitment requires the
online threshold under an unexpired, non-revoked delegation.

Canonical statement and LKG hashes are always SHA-256 computed by this contract. Hash selection is
not injected through the signature provider. Authority updates have their own LKG chain:
delegation/revocation sequence must be the exact next unsigned 64-bit sequence and previous hash
must equal the authority LKG hash. Overflow fails closed. An online verification context pins the
active delegation sequence and canonical SHA-256 hash to its authority LKG, preventing replay of an
older or alternate still-valid delegation.

`IMembershipSignatureVerifier` is the only crypto boundary. It verifies an approved existing
signature primitive against the canonical descriptor public key and exact codec-owned
domain-separated bytes. Fixed 16-byte tags cover update, membership, bridge, reward, billing,
delegation, revocation, genesis and fork domains before the signature adapter is called; provider
interpretation of a domain enum is not the separation mechanism. P04 supplies deterministic
test fixtures only and no production implementation/registration/key material.

One signer never meets quorum. Unknown, duplicate, wrong-role, revoked, expired or cross-domain
signatures fail. Clock evaluation uses one caller-supplied verification instant and bounded skew.

## Fork, equivocation and LKG

Clients/nodes persist last-known-good network ID, policy version, sequence and exact canonical hash.
A candidate must advance sequence and match previous hash. Same sequence with different canonical
hash, or two valid successors of one previous hash, yields portable fork/equivocation evidence;
neither branch silently replaces LKG.

Fork witness records bind the candidate domain, sequence, previous hash and candidate hash. They
are evidence, not automatic fork resolution. Recovery requires a separately authorized policy
decision; rollback to lower sequence or expired delegation fails closed.

## Boundaries

P04 defines bytes, models and verification decisions only. Registry persistence, endpoint crawling,
client state/UI, live ceremonies, core endpoint publication and production keys are out of scope.
Runtime remains blocked pending approved verifier implementation, independent review,
cross-language vectors and P06/P07 integration evidence.
