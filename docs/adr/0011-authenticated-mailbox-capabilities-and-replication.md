# ADR 0011: authenticated mailbox capabilities and replica protocol

Status: accepted for contract implementation; runtime activation blocked.

Decision owner: Mr. X.

## Context

`MCP1` is a bounded opaque presentation, not a cryptographic authority. It has no issuer,
holder authentication, exact request binding, membership/placement binding, revocation source or
durable replay transaction. `MST1`/`MRT1`/`MAK1` and `MRR2`/`MQR2` are useful canonical client and
receipt frames, but they do not authenticate a peer replication request or prove that a receipt
signer belongs to the committed storage replica set.

The replacement must not contain a raw Session ID, payer, wallet, subscription or entitlement.
P2P and self-hosted use remains free. Resource admission and hosted storage quotas are separate
runtime policy.

## Decision

Add a strict, non-convertible V2 profile:

- `MCG2` is a fixed-size Ed25519-signed grant. A mailbox/domain-specific issuer key authorizes a
  holder public key for one domain, generation, epoch, network, membership commitment, placement
  commitment and bounded validity window.
- `MCP2` embeds exactly one `MCG2` and adds operation kind, outer operation ID, replay counter and
  exact canonical request digest. The holder signs the complete presentation.
- deposit grants authorize only `Store`; retrieve grants authorize only `Retrieve` or `Ack`.
- issuer signatures use distinct fixed tags for deposit and retrieve. Holder signatures use
  distinct fixed tags for Store, Retrieve and Ack.
- trusted issuer keys and durable revocation state are host-owned inputs. Rotation is monotonic by
  generation; overlap is explicit and bounded.
- replay evaluation is an atomic durable reserve/read operation followed by an atomic completion
  operation. A crash leaves an explicit in-flight reservation; it never silently becomes new.
- V1 and V2 magic/version values are not cross-decoded. There is no legacy JSON bridge or raw
  fallback.

Ed25519 is selected because this repository already pins `Sodium.Core`, has native Ed25519 parity
tests, and uses Ed25519 membership keys. SHA-256 is selected only for domain-framed commitments and
request digests; it is already used by P04/MRL1.

Add `MPR1`, a bounded authenticated peer Store/Tombstone request. It carries the exact source and
target replica identifiers, membership and placement commitments, operation ID, cursor, expiry,
payload digest, canonical payload and a bounded membership proof. The source replica signs the
whole request with an operation-specific Ed25519 tag. A membership-proof verifier must prove the
source signing key and both source/target storage replicas against the exact P04/MRL1 commitment.
The response is the existing canonical signed `MRR2` replica receipt; a durable coordinator result
is the existing `MQR2`.

Add `MAR1`, an ordered bounded aggregate ACK response containing one exact `MQR2` tombstone quorum
per requested acknowledgement. It introduces no new durability meaning.

## Alternatives

1. Recommended and selected: Ed25519 issuer grant plus Ed25519 holder presentation. It supports
   offline issuance, self-hosting, deterministic verification and exact operation binding using
   primitives already present.
2. Macaroons/HMAC caveats: smaller and derivable, but verification requires shared issuer secrets
   at storage nodes, expanding compromise impact and complicating offline multi-node verification.
3. Blind signatures/anonymous credentials: stronger issuer unlinkability, but no reviewed or
   pinned primitive exists in this repository. This remains a future externally reviewed profile,
   not an implementation choice.

## Privacy and non-claims

Issuer and holder keys must be mailbox/domain scoped; reusing them creates a correlation handle.
The wire contains only blinded mailbox/placement values and random operation/serial values. It does
not provide network-layer anonymity, hide timing/size, implement quota policy or prove payment.

This ADR does not activate runtime registration, storage, transport, Docker, billing or keys.

