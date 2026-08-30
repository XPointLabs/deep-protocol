# Production mailbox holder proof V1

Status: **pre-cutover evidence; release-rejected by DR-0004**.

`ProductionMailboxHolderProof` owns the canonical, replay-domain-separated proof-of-possession
transcript used by anonymous production mailbox issuance. It is protocol code so coordinator and
clients cannot silently encode different security statements.

`GetSigningBytes` returns the ASCII domain `Deep/production-mailbox/holder-proof/v1` followed by
one fixed 400-byte PHP1 payload: magic/version, issuance intent, platform, reserved zero byte,
network ID, canonical PMA1 hash, active holder key, stable mailbox-owner key, three route fields,
release signing-certificate and build hashes, a nonzero idempotency key, an optional opaque
entitlement commitment (all zero for base-free service), anonymous challenge ID/value, and
proof-of-work nonce. All numeric fields are big-endian. The total signing input is exactly 439 bytes.

`LocalOwner` requires both holder and stable-owner Ed25519 proofs. Its three route fields must all be
zero while the issuer-side protected service deterministically derives the owner route.
`PeerDeposit` requires all three recipient route fields and only the
requesting holder proof; an owner proof is not meaningful for that intent. Partial routes, unknown
intent/platform, zero trust/identity/attestation/challenge fields, bad lengths, and signature
substitution fail closed.

The protocol exposes only transcript construction and detached-signature verification. It does not
contain an HTTP DTO, challenge store, proof-of-work policy, issuer PRF, signing function, private
key, account, billing rule, token rule, or network call.
