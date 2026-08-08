# Production mailbox selection successor V1

`PSS1` advances one exact locally pinned `PMS1` to one live `PMS1` without treating a downloaded
route as trusted. It has two fail-closed modes:

- `DirectPromotion` (`1`) is the normal exact PMA1/PMT1 `+1` transition. The old issuer and the
  current issuer both sign it.
- `OfflineCheckpoint` (`2`) is bounded recovery after a long disconnect. It embeds the exact live
  current PMA1, verifies that PMA1's existing Mr. X signature against the locally pinned root, and
  requires only the current PMA1 mailbox issuer to sign the per-mailbox PSS1.

OfflineCheckpoint never asks Mr. X to sign per mailbox, never retains a retired issuer private key,
and never accepts an unsigned current closure. The old `PMS1` bytes/hash, owner key, blinded mailbox
ID and blinded placement ID come from local durable state and are covered by the current issuer
signature. See `adr/0013-pss1-offline-checkpoint-trust.md`.

## Clean-break selection algorithm

Only `RendezvousSha256V2` (`2`) is accepted:

`SHA-256("Deep/PMT1/rendezvous-sha256/v2" || network16 || epoch8 || epochGeneration8 ||
membershipCommitment32 || topologyPlacementCommitment32 || selectionInput32 || nodeId32)`

The outer PMA1 authority generation is excluded so an unchanged old-next epoch promoted to
new-current keeps its ordered replicas. Epoch generation and all route commitments remain inputs.
The removed V1 value is rejected; there is no fallback or compatibility decoder.

## Canonical artifact

The fixed core is 416 bytes. It is followed by exact canonical current PMA1 bytes, old PMS1 bytes,
new PMS1 bytes, and two fixed 64-byte signature slots. Maximum size is 34,608 bytes. Integers are
unsigned big-endian.

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | ASCII `PSS1` |
| 4 | 1 | version `1` |
| 5 | 1 | mode (`1` direct, `2` offline checkpoint) |
| 6 | 2 | zero reserved |
| 8 | 16 | network ID |
| 24 | 8 | old epoch |
| 32 | 8 | old epoch generation |
| 40 | 8 | new epoch |
| 48 | 8 | new epoch generation |
| 56 | 32 | dedicated mailbox-owner Ed25519 public key |
| 88 | 32 | blinded mailbox ID |
| 120 | 32 | blinded placement ID |
| 152 | 32 | selection-input commitment |
| 184 | 32 | old canonical PMA1 SHA-256 |
| 216 | 32 | new canonical PMA1 SHA-256 |
| 248 | 8 | old PMT1 generation |
| 256 | 32 | old canonical PMT1 SHA-256 |
| 288 | 8 | new PMT1 generation |
| 296 | 32 | new canonical PMT1 SHA-256 |
| 328 | 32 | old canonical PMS1 SHA-256 |
| 360 | 32 | new canonical PMS1 SHA-256 |
| 392 | 8 | issued-at Unix seconds |
| 400 | 8 | expires-at Unix seconds |
| 408 | 2 | embedded current PMA1 length |
| 410 | 2 | old PMS1 length |
| 412 | 2 | new PMS1 length |
| 414 | 2 | zero reserved |
| 416 | PMA1 length | exact canonical live current PMA1 |
| variable | old length | exact old canonical PMS1 |
| variable | new length | exact new canonical PMS1 |
| variable | 64 | previous-issuer signature slot |
| variable | 64 | current-issuer signature |

Both transcript domains cover the header, fixed core and all three embedded artifacts, excluding
the signatures. DirectPromotion uses
`Deep/production-mailbox/selection-successor/old-issuer/v1` and
`Deep/production-mailbox/selection-successor/new-issuer/v1`; both slots must be nonzero.
OfflineCheckpoint requires the previous-issuer slot to be exactly zero and uses only the new-issuer
domain. This canonical zero is an explicit statement that no retired key participated.

## DirectPromotion verification

The verifier freezes all caller buffers and requires:

1. live PSS1, exact local network/owner/blinded IDs and exact locally pinned old PMS1 hash;
2. embedded PMA1 canonicality, pinned-Mr. X signature, live rollout/revocation/current epoch,
   exact PMA1 `+1` generation and previous hash;
3. exact PMT1 `+1` generation/previous hash and exact old-next/new-current epoch promotion;
4. historical verification of old PMS1 at its own issuance time and live verification of new PMS1;
5. identical route commitments, replica IDs/order, exact MIP1 proofs and HTTPS endpoints;
6. either an unchanged `(current,next)` SPKI pair, or `old.next == new.current` with a fresh
   `new.next`; unrelated pins fail closed;
7. valid old-domain and current-domain issuer signatures.

## OfflineCheckpoint verification

The old PMS1 is locally pinned exact state, not downloaded bootstrap authority. The verifier:

1. verifies the embedded current PMA1 canonically and live against the pinned Mr. X public-key
   hash, requiring a strictly forward, non-terminal authority generation;
2. rejects revocation rollback/conflict and terminal revocation generations;
3. accepts only a `VerifiedProductionMailboxTopology` produced from that exact PMA1/current issuer;
   bounded-forward PMT1 recovery is strictly forward and non-terminal;
4. historically verifies the exact old PMS1 with the retained old closure at old PMS1 issuance;
5. requires the old anchor to be no more than 365 days old, the new epoch/generation to move
   forward, and the new PMA1/PMT1/PMS1 plus PSS1 to be live now;
6. recomputes the V2 replica selection and both exact MIP1 proofs for the new closure; replicas may
   legitimately change across epochs, but caller substitution cannot pass;
7. verifies the current issuer signature over the exact old anchor, owner/blinded route, embedded
   current PMA1 and live new PMS1. The retired-issuer slot must be zero.

Generation `ulong.MaxValue` is rejected for authority, revocation and topology checkpoints so an
accepted state always has successor capacity. There is deliberately no generation-delta cap:
verification is constant-size, and limiting rotations would contradict the 365-day offline promise
during daily or incident-driven rotations. The 365-day local-anchor age is the recovery policy and
does not require retaining a private key for that duration.

Forward-checkpoint verifiers are internal recovery primitives. The only public offline entry point
constructs the current verified PMA1/PMT1 handles inside an authenticated PSS1 OfflineCheckpoint
flow with exact local-anchor binding. There is no public generic shortcut around ordinary exact LKG
successor verification.

## Atomic host commit

After success, the host atomically commits the new PMA1/PMR1/PMT1 LKG state, new current/next
bundle and PSS1 audit hash. Failure leaves old durable state unchanged. A host must not commit the
embedded PMA1 or downloaded route before the whole PSS1 verification and storage transaction
succeeds.
