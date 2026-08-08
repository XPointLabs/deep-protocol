# ADR 0015: owner-authorized production mailbox route continuity

Status: proposed design freeze, 2026-08-08.

## Context

PRC1 is bound to one exact PMA generation/hash and PRA1 embeds that exact PRC. Copying old PRC/PRA
into a successor authority therefore fails verification. A PSS1 selection transition does not
authorize a route transition and cannot extend an expired owner signature.

Keeping old issuer or owner keys online would enlarge the compromise window and is rejected.
Letting the current issuer silently replace an owner route is also rejected.

## Decision

Use a clean-break, owner-authorized continuity chain:

- RCD1 is an explicit, bounded `RouteContinuityOnly` owner delegation for one exact blinded route,
  chained to the prior delegation and capped by authority generation and activation sequence.
- RDA1 proves the old live issuer accepted that delegation while the anchor route was valid.
- RCR1 is the owner's one-way terminal revocation for one exact delegation; RCH1 is a short-lived
  current-issuer checkpoint of the exact active-zero or revoked-RCR state.
- RCA1 is a short-lived current-issuer activation of one exact fresh PRC under the delegation.
- PRA2 is the owner-online alternative. PRA2 and RCA1 share one tagged exact+1 predecessor chain.
- RTC1 is the shared unsigned route/selection transition commitment. RCA signs its hash; PSS2
  signs the exact RCA hash, avoiding mutual hash cycles.
- The pre-delegation ROL1 is sealed before RCD/RDA and is what both artifacts bind. Only after live
  RDA acceptance does one atomic commit create the next ROL containing exact RCD/RDA hashes; no
  artifact hashes a transcript containing itself.
- One high-level verifier atomically advances selection and route LKG state.

RCD lifetime is at most 365 days and 512 activations, but application policy defaults to at most
30 days and requires an explicit Mr. X choice for longer windows. Each RCA/RCH/PRC/PRA activation
is at most 24 hours and final verification is live. The 365-day anchor policy is not a 365-day
Registry/XNode outage guarantee; availability is limited by the prepositioned live schedule.
Historical route recovery uses resumable canonical batches of at most 16 links and 8 MiB, never a
single 512-hop allocation. Historical batches exclude PMT/PMS/PSS; only the final PSS2 activates a
selection. Each batch has an absolute 8,394,304-byte envelope bound, canonical unique artifact
table, exact predecessor checkpoint and cumulative nonterminal link count. One refresh is bounded
to 32 batches, 512 links and 256 MiB of streamed canonical payload; only the compact sealed
464-byte RHC1 checkpoint survives between batches. RHC1 has an exact hash domain, initial state,
field layout, retained PMA/PMR lineage, rolling exact-batch transcript head and exact last-batch hash
with a +1 update/CAS rule, so Registry and client resume or replay from identical bytes.
Unreferenced artifact rows are forbidden.

## Security consequences

Compromise of the current mailbox issuer while a delegation is active can keep the identical
blinded route alive, but cannot change owner, route, selection input, trust root, predecessor or
authorized sequence range. Owner revocation is monotonic. Once learned, it fails closed; a
previously fetched activation has a maximum 24-hour residual lifetime.

RDA prevents an attacker from manufacturing a backdated delegation using only old artifacts.
Exact predecessor hashes and sequences prevent rollback, same-sequence fork and mode downgrade.
The current issuer cannot mint an owner signature. XNodes receive only changing PRC/RTC/PSS2 and
selection closure plus tagged PRA2, or RCH/RCA1 for the delegated path; they never receive
RCD/RDA/raw-RCR/RHB/RHC or signing
keys and remain carry-only transports. A fresh salted per-activation commitment hides stable
delegation identifiers from XNode artifacts, while the sealed ROL1 hash binds the exact original
route LKG and immutable `RouteVerifiedAt`.

Per-delegation revocation deliberately has only Active `0/zero` and terminal Revoked
`1/exact-owner-RCR`. An issuer-signed Active checkpoint cannot prove that an owner revocation not
yet delivered to the verifier does not exist. Therefore learned revocation fails immediately, but
an already-issued activation has an explicit residual lifetime of at most 24 hours.
An issuer-signed Revoked checkpoint without the exact owner-signed RCR blocks that candidate but
cannot advance durable terminal revocation state; only verified canonical RCR bytes can do that.
That TTL is not proof against a compromised current issuer repeatedly issuing stale-head Active
checkpoints to a client that has never learned the owner's RCR. Only exact verified owner RCR bytes
advance the durable terminal head and make rollback/forks fail across candidates. An unaccompanied
issuer RCH is candidate-local negative evidence only until its own expiry.

## Operational consequences

Registry promotion is fail-closed unless every affected owner has either:

1. a complete durable RCD/RDA/revocation-head chain that can produce RCA/PSS2, or
2. a fresh owner-signed PRA2 for the candidate closure.

The Registry keeps bounded immutable per-owner route history for the delegation window and uses
one transaction for owner predecessor CAS, selection LKG, publication outbox and capacity receipt
barrier. XNodes preposition only changing activation artifacts and serve exact requested LKG
lineages. No-LKG devices require sealed state transfer or an explicit new-route reset.

Artifact-specific validity intersections, transaction-owned time, exact replay and fork rules are
normative in the extension document. No implementation may replace them with one generic timestamp
rule or publish node-visible bytes before the durable route+selection transaction commits.

## Rejected alternatives

- Reuse old PRC/PRA: cryptographically invalid under the new PMA and expired owner authorization.
- Treat PSS as route authorization: PSS1 binds no PRC/PRA hash or route sequence.
- Retain old issuer/owner private keys: unacceptable compromise window.
- Numeric revocation generation without a signed head: no proof of absence or fork resistance.
- Mutual RCA/PSS hashes: an unresolvable hash cycle.
- Preissued single-successor PRA as the survival design: useful only as a short owner-online Beta
  gate; it does not cover unattended or incident rotations.

## Implementation gate

This ADR authorizes no code until independent review approves the fixed layouts in
`deep-extension-production-mailbox-route-continuity-v2.md`. Existing Registry capacity work may be
committed separately only when documentation states that route activation remains NO-GO.
