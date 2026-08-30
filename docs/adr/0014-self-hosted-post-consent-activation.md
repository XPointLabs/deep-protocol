# ADR 0014: Post-consent user-managed profile activation

Status: Accepted as a dormant protocol capability; runtime activation remains blocked.

Product constraint reviewed 2026-08-30: on-prem is intentionally later than
the first release, but first-release changes must preserve this separate
`UserManaged` authority path. Official Registry, PMA1, billing and Mr. X must
not become dependencies of the generic message/group/outbox contracts.

## Context

DPF1 already carries and exactly verifies a P04 genesis, its quorum approvals,
the genesis-rooted online delegation and an ordered bridge chain. Its generic
verification result intentionally does not expose enough authority material to
activate endpoints. A Release client needs a narrow, auditable path for a user
to select a user-managed network without treating Registry, billing, official
mailbox endpoints, PMA1 or a legacy bootstrap row as authority.

Changing genesis is a trust switch, not an update. A signed runtime document
also needs to bind the exact selected DPF and use the DPF online delegation,
without adding a signing or private-key-custody API to the client library.

## Decision

The ProfileCarrier package adds three isolated, clean-break surfaces in
`Deep.Protocol.DeepExtension.SelfHostedProfiles`:

1. `VerifiedSelfHostedActivationDescriptor` is produced publicly only by
   `SelfHostedActivationGate`, after the existing exact DPF/P04 verification and
   the required atomic activation commit both succeed. The raw projection helper
   is internal, so a caller cannot feed an inspected-but-uncommitted candidate
   to the runtime verifier. The descriptor defensively exposes the
   exact DPF SHA-256, network ID, genesis fingerprint, effective protocol range,
   latest verified delegation commitment/quorum and ordered latest bridge
   contacts. The generic verifier remains unchanged and generic verification
   alone does not confer activation capability.
2. `SelfHostedActivationGate` requires a local single-use
   `SelfHostedSwitchConsent` for initial activation and for every different-
   genesis switch. Consent is bound to the current account generation, exact
   candidate DPF hash and exact candidate genesis fingerprint. The host-provided
   asynchronous `ISelfHostedActivationCommitter.TryCommitAsync` receives one
   immutable commit containing the
   consent, expected current LKG, exact candidate bytes and candidate LKG, and
   must consume consent plus replace active state in one CAS transaction. A same-genesis
   update is accepted only after the current exact DPF matches the caller's LKG
   and the existing DPF transition verifier reports an exact forward-prefix
   transition or exact idempotence.
3. `SHR1` is a canonical, signed UserManaged runtime envelope. It binds the
   exact DPF/network/genesis/delegation, its own generation and predecessor,
   validity/protocol range, distinct coordinator and MAU2 HTTPS origins,
   current/next SPKI hashes, topology generation/hash, revocation lineage and
   window, current/next epochs and a bounded sorted capability set. An exact
   DPF online quorum signs the fixed 16-byte `DEEP-SHR-V1` domain followed by
   the canonical unsigned payload. Runtime rollback, same-generation forks,
   successor gaps, terminal counters and predecessor mismatches throw and never
   produce a verified result. The persisted runtime LKG also closes topology and
   revocation lineage, epoch continuity, immutable origins and unchanged-or-
   promoted current/next SPKI pairs; ABBA pin promotion is rejected.

The codec accepts canonical HTTPS origins on public, private, loopback and
name-based networks. It does not apply the official-network public-address
policy because user-managed deployments commonly use private addressing. TLS
validation and exact current/next SPKI enforcement remain mandatory host
responsibilities.

The sodium adapter is detached-verification only. The library exposes no
signing, key generation, private key, custody, Registry, PMA1 or billing API.

## Canonical SHR1 payload

All integers are unsigned big-endian. Strings and byte strings use an unsigned
16-bit byte length and strict UTF-8 where applicable. The signed payload is:

`SHR1 | version=1 | network | exactDpfSha256 | genesisSha256 |
delegationSequence | delegationCommitment | generation | previousEnvelopeHash |
issuedAt | validFrom | validUntil | minProtocol | maxProtocol |
coordinator(origin,currentSpki,nextSpki) | mau2Ingress(...) |
topologyGeneration | topologyHash | revocationGeneration |
previousRevocationHead | revocationHead | revocationIssuedAt |
revocationExpiresAt | currentEpoch | nextEpoch | sortedCapabilities`.

The encoded envelope appends an exact-threshold, signer-ID-sorted list of
`signerId | signatureLength | signature`. The total document is capped at
64 KiB, validity at 365 days, origins at 512 bytes, capabilities at 16 entries
of 64 bytes and signatures at 32 entries of 512 bytes. Decoding recomposes the
document and requires byte-for-byte equality.

## Required host transaction

Protocol verification does not provide a database. The mandatory
`ISelfHostedActivationCommitter.TryCommitAsync` call is the activation transaction boundary:
it must consume switch consent when present, compare the expected current LKG,
and replace the exact active DPF plus candidate LKG atomically before returning
`true`. A crash must leave either the complete old tuple or the complete new
tuple. Runtime envelope acceptance must similarly compare the complete stored
runtime closure and atomically replace envelope bytes/hash/generation and all
security-state LKG fields. Updating SQLite separately from protected state
without a recoverable journal is not conforming.

The Gate freezes caller-owned bytes and completes all cryptographic verification
before its first await. It returns the activation descriptor only after the
committer returns `true`; `false`, cancellation and commit exceptions expose no
capability. Cancellation before durable commit is allowed. Detection and
reconciliation of cancellation or failure after a durable SQLite commit is an
internal committer responsibility, so it must not report an ambiguous state as
a clean pre-commit cancellation.

## Consequences and remaining gates

- User-managed activation derives no authority from Registry, billing,
  official endpoints, PMA1 or Mr. X.
- Direct P2P is not modeled as self-hosted MAU2 and does not require this
  envelope.
- DPF1 v1 still cannot express delegation rotation beyond its single
  genesis-rooted delegation. No new crypto semantics are invented here.
- Production remains blocked on protected atomic persistence, consent UI,
  acquisition/import, TLS/SPKI enforcement, endpoint transport, operator-side
  signing/custody, cross-language vectors, fuzzing and Android/Windows E2E.
