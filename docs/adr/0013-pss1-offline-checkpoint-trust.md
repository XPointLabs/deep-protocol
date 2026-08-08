# ADR 0013: PSS1 offline checkpoint trust

Status: accepted for protocol implementation; runtime activation remains blocked on host integration.

## Context

A client can miss multiple daily PMA1/PMT1 rotations. Requiring every historical PSS1 to remain
live strands that client. Asking a retired mailbox issuer to sign on reconnect would instead keep
old signing keys available for months, increasing compromise impact. Asking Mr. X to sign each
per-mailbox reconnect would put the offline root in an online, privacy-sensitive hot path.

PMA1 already has a stable trust floor: every canonical PMA1 carries a Mr. X signature and clients
pin the hash of the Mr. X public key. The current PMA1 mailbox issuer can authenticate a
per-mailbox recovery statement without learning or using any retired private key.

## Decision

PSS1 has DirectPromotion and OfflineCheckpoint modes.

DirectPromotion is exact `+1`, dual old/current issuer signed, and preserves the promoted route.

OfflineCheckpoint embeds the exact canonical current PMA1. An internal verifier accepts only a live,
strictly forward non-terminal PMA1, validates its existing signature against
the pinned Mr. X key, and enforces non-rollback revocation state. The current issuer then signs the
PSS1 containing the caller's exact locally pinned old PMS1 bytes/hash, owner/blinded route, exact
current PMA1 and live new PMS1. A matching bounded-forward PMT1 verifier is anchored to that
verified PMA1/current issuer. The old issuer signature slot is canonical zero.

The old anchor may be at most 365 days old. Generation delta is deliberately not capped: one
checkpoint has constant size/work, while a delta cap would strand a 365-day client after enough
daily or incident rotations. Terminal `ulong.MaxValue` generations are rejected. A greater number
of root/current-issuer-authorized rotations increases reliance on the live trust closure but does
not give an attacker a signing capability; the exact local owner/route/PMS anchor remains required.

## Rejected alternatives

- Retaining retired issuer private keys for 90/365 days: rejected because it expands the signing
  compromise window and makes survival depend on retired key availability.
- Mr. X per-mailbox signatures: rejected because it makes an offline root online and creates a
  linkable operational bottleneck.
- Historical transition chains only: viable but substantially more stateful; the existing
  old-next/new-current selection form does not naturally provide exact new-hash to next-old-hash
  linkage without another artifact. It may be added later, but is not required by this checkpoint.
- Public standalone forward verifier: rejected because it could become a shortcut around owner and
  old-PMS binding. Forward PMA1/PMT1 primitives are internal and return handles only inside the
  high-level offline PSS1 path.

## Consequences

Clients must retain exact old PMS1 bytes/hash and old verified closure for historical checking.
Registry responses must carry the exact live PMA1/PMT1/PMS1 closure. Host persistence must commit
the complete new closure only after PSS1 success. `VerifyForwardCheckpoint` is restricted to this
authenticated recovery flow and must not replace normal exact-successor LKG verification.
