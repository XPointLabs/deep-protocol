# P03B security boundary

Status: contract implemented; production activation blocked. Human owner: Mr. X.

## What is enforced

- Deposit, retrieve and placement have distinct runtime types and wire domains.
- Decode requires an expected domain and rejects cross-domain presentation.
- There is no production derive/convert method between mailbox domains.
- Generation, validity, overlap, mixed-version, replay and idempotency fields are bounded and
  canonical.
- Revoked, recovery and legacy overlap require explicit policy.
- Free admission is separately framed and has no payer, wallet, account, plan or payment field.
- Durable verification requires two different replica IDs, two valid replica signatures, durable
  status, matching operation/generation/cursor/tombstone/payload digest and a valid coordinator
  signature.
- Coordinator signing bytes bind verifier-provided digests of canonical ordered replica receipts.
- Coordinator equivocation evidence requires two different fully verified statements with the
  same coordinator ID and sequence.
- Parsers reject trailing bytes, unknown markers, nonzero reserved bytes and malformed lengths.

## What is not claimed

`Opaque` means uninterpreted by this codec. It does not mean secret, random, unforgeable,
unlinkable, non-correlatable or forward-secure. Repeated caller bytes, timing, length, generation
and cursor remain observable.

P03B supplies no capability producer, key derivation, entropy source, lifecycle database, durable
replay guard, storage engine, replica key distribution, signature/digest implementation, billing
logic or runtime registration. `IMailboxReceiptCrypto` and `IMailboxCapabilityReplayGuard` are
host trust boundaries. The SHA-256 test adapter is deterministic test code only.

## Production blockers

1. Reviewed deposit/retrieve/placement producer with strict domain and generation separation.
2. Durable atomic replay/idempotency and lifecycle persistence.
3. Reviewed replica/coordinator signature, digest and key-distribution implementation.
4. Storage execution, cursor/tombstone durability, repair and client integration.
5. Cross-language vectors, mobile/Windows E2E, adversarial tests and external security review.

No seed phrase, wallet, contract or production credential was accessed. No network service,
container, deployment, package registry or Git remote was changed.
