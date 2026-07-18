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

Self-hosted networks import their own independently signed genesis. They do not inherit Deep
production authority, network ID or signer set.

## Updates and verification

Every delegation, revocation, bridge snapshot and membership commitment binds network ID,
monotonic sequence, previous canonical hash, issued/valid bounds, min/max protocol and policy
version. Delegation/revocation requires the offline threshold. Snapshot/commitment requires the
online threshold under an unexpired, non-revoked delegation.

`IMembershipSignatureVerifier` is the only crypto boundary. It verifies an approved existing
signature primitive against exact codec-owned domain-separated bytes. P04 supplies deterministic
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
