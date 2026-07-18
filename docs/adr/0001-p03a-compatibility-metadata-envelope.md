# ADR 0001: P03A authenticated compatibility metadata envelope

Status: proposed contract; production crypto adapter unavailable; runtime activation BLOCKED.

Date: 2026-07-18. Human owner: Mr. X.

## Context

Legacy DPE1 authenticates inner fields but exposes sender and recipient identifiers in its clear
header. Putting DPE1 directly in managed storage therefore preserves content secrecy while leaking
the relationship P01 is intended to remove. P03 introduced an opaque DPB1 container, explicit
negotiation, bounded parsing and a legacy migration mode, but intentionally did not choose a
sender-authenticated recipient-encryption construction.

The P01 observer matrix remains authoritative. An access network still observes endpoints, timing
and byte counts; routed hops observe adjacency; storage sees its exit and opaque capability; push
is a separate correlation surface. Ingress plus storage, storage plus push, all routed hops, a
global passive observer, or an endpoint compromise can still correlate timing, size, topology and
device activity. This ADR makes no traffic-flow-confidentiality, anonymity-set or forward-secrecy
claim.

## Existing primitive inventory

`SodiumSessionProtocolCrypto.EncryptForRecipient` uses libsodium sealed boxes, but the supplied
sender secret only determines a claimed public identifier embedded in the encrypted plaintext. It
does not sign or otherwise prove control of that sender key. `SodiumOnionRequestCrypto` is an
anonymous hop/destination sealed-box adapter. These are useful verified primitives for their
existing Session/onion roles, but neither meets the P03A sender-authentication contract.

Reusing either method as if it authenticated the claimed sender is rejected. No production P03A
crypto adapter will be registered in this package.

## Decision

Define a production interface for a future reviewed adapter and a versioned orchestration
contract. Tests may use an explicitly test-only deterministic adapter. Fake cryptography must
never be present in production assemblies.

The future adapter must provide all of the following as one reviewed construction:

1. recipient confidentiality and ciphertext integrity;
2. cryptographic sender authentication, with sender authentication data returned only after
   successful recipient decryption;
3. independent header and payload key domains;
4. unique nonce contexts for each domain and attempt;
5. authentication of canonical associated data binding the opaque outer metadata;
6. uniform failure for tamper, wrong recipient, wrong domain and malformed ciphertext.

The adapter interface receives fixed codec-owned domains:

- `Deep/P03A/CompatibilityHeader/v1`;
- `Deep/P03A/CompatibilityPayload/v1`.

Callers cannot replace those domains. Header and payload nonce contexts are exactly 32 bytes and
must differ. A production adapter may map these contexts into an approved primitive only after a
focused cryptographic review; this ADR does not select a KDF, AEAD, HPKE mode or signature scheme.

## Versioned envelope contract

P03A is a Deep extension and does not modify Session protobufs or DPE1 bytes.

Activation requires an explicit DPB1 V1 negotiated profile containing both
`LegacyDpe1Compatibility` and `AuthenticatedCompatibilityEnvelope`. It uses payload kind
`AuthenticatedLegacyDpe1`. A generic native or clear-legacy profile cannot silently accept it.

The managed outer DPB1 fields remain limited to framing/version and critical negotiation bits,
padding class, expiry bucket, replay material, opaque capability role/value and a hop-local
transport-attempt identifier. The local end-to-end dedup identifier is never serialized. No raw
sender, recipient, account, plan, payer, provider token or cross-transport stable attempt value is
added.

The encrypted-header body is:

`header nonce context (32 bytes) || adapter ciphertext`

The encrypted-payload body is:

`payload nonce context (32 bytes) || adapter ciphertext`

The header plaintext is the fixed marker `P3A1` followed by the exact unsigned big-endian DPE1
length. The payload plaintext is the exact complete legacy DPE1 byte sequence, beginning `DPE1`.
The marker and DPE1 bytes are visible only after adapter decryption.

Canonical associated data binds:

- DPB1 version, payload kind, capability role and padding class;
- critical features and expiry bucket;
- hop-local transport-attempt ID and replay material;
- opaque capability length/value;
- both nonce contexts.

Changing a hop or transport requires a fresh transport-attempt ID and fresh nonce contexts, so the
compatibility layer does not introduce a stable cross-transport attempt identifier. The opaque
capability may remain linkable within its separately defined epoch; capability lifecycle is owned
by later P03B/P07A work.

After both authenticated decryptions succeed, the codec requires matching non-empty sender
authentication data from both domains, validates the exact header marker and length, then validates
the `DPE1` prefix. Only then may a replay guard atomically accept the authenticated
capability/expiry/replay scope. A repeat, expired bundle, tamper, wrong recipient, wrong domain,
unsupported critical feature or downgrade fails closed without returning sender data or DPE1
bytes.

## Bounds

- nonce context: exactly 32 bytes per domain;
- sender authentication data after decryption: 1..512 bytes;
- legacy DPE1: 4..1,048,576 bytes;
- adapter ciphertexts must fit the existing DPB1 encrypted-header/payload and total encoded bounds;
- no parser allocates from an unvalidated declared length.

## Consequences and blockers

The production interface and test vectors can be reviewed now. Runtime feature registration,
production negotiation and claims that P01 is resolved remain BLOCKED until:

- an approved sender-authenticated recipient-encryption adapter is implemented with independent
  vectors against its upstream primitive;
- durable atomic replay state and authenticated capability lifecycle exist;
- wrong-recipient/tamper/domain behavior receives independent security review;
- external cryptographic review approves the construction and its observer claims.

Rollback disables P03A negotiation/new writes while retaining separately readable legacy and
opaque state. It must never reinterpret an authenticated-envelope failure as permission to retry
clear DPE1 or raw account addressing.

