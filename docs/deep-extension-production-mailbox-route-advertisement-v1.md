# Production mailbox route advertisement V1

Status: **pre-cutover evidence; release-rejected by DR-0004**. Target route
publication is XRA1/XRC1/XRR1/XSS1.

`PRC1` and `PRA1` solve one narrow problem: a mailbox owner can give an authenticated contact a
stable managed-mailbox deposit route without sharing the owner's private key and without binding
that route to the currently active holder/device.

They do **not** solve initial contact discovery. The clean-break first-contact
protocol is `permanent DID1 or one-time DIA1 -> DCR1/DCB1 -> encrypted contact
rendezvous -> ContactHello/Accept`, specified in the superproject
`docs/architecture/CONTACT-AND-GROUP-PROTOCOL-V1.md`. Only after that
authenticated pairwise channel exists do contacts exchange PRA/route-update
artifacts. A bare account ID plus PRA lookup is forbidden.

They are Deep extension artifacts. They are not Session wire fields, a public directory, a mailbox
grant, a replica-selection proof, an entitlement, or a payment/token artifact.

## Security boundary

1. During `LocalOwner` issuance, the coordinator derives the three blinded route values and returns
   an issuer-signed `PRC1` to the owner.
2. The client holding the dedicated mailbox-owner Ed25519 key signs a `PRA1` containing the exact
   canonical `PRC1`.
3. The client transmits exact canonical `PRA1` bytes only inside an already authenticated,
   end-to-end encrypted contact channel. The protocol package does not publish or transport it.
4. A sender presents the exact `PRA1` for `PeerDeposit`. The coordinator verifies both signatures,
   the current PMA1 binding, validity and durable sequence state before issuing deposit grants.
5. The coordinator independently selects and returns exact current/next `PMS1` artifacts against
   its retained immutable PMT1 closure. A sender must verify those artifacts. `PRA1` never proves a
   storage replica, PMT1 generation, endpoint, or SPKI pin.

The dedicated mailbox-owner key and blinded route are linkable to recipients of the advertisement.
They must not be a global account/profile key and the artifact must not be placed in a public
directory, logs, metrics, crash reports, push payloads, or cleartext contact metadata.

## Stability and topology separation

Neither artifact contains the active holder key, platform, build, device identifier, PMT1 hash,
topology generation, storage epoch, replica, endpoint, or SPKI pin. Consequently:

- holder/device rotation leaves the route and existing live advertisement unchanged;
- topology rotation leaves the contact route unchanged;
- topology safety remains entirely in the separately issuer-signed PMT1/PMS1 verification path;
- a host must never treat successful PRA1 verification as authorization to contact a caller-chosen
  replica or as proof that any previously selected replica is still current.

## Canonical PRC1

The issuer signature transcript is ASCII
`Deep/production-mailbox/route-certificate/v1` followed by the first 240 bytes below. The complete
artifact is exactly 304 bytes. Integers are unsigned big-endian.

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | ASCII `PRC1` |
| 4 | 1 | version `1` |
| 5 | 3 | zero reserved bytes |
| 8 | 16 | network ID |
| 24 | 8 | PMA1 authority generation |
| 32 | 32 | SHA-256 of exact canonical PMA1 |
| 64 | 32 | PMA1 mailbox issuer Ed25519 public key |
| 96 | 32 | dedicated mailbox-owner Ed25519 public key |
| 128 | 32 | blinded mailbox ID |
| 160 | 32 | blinded placement ID |
| 192 | 32 | `SHA-256("Deep/PMT1/selection-input/v1" || blindedPlacementId)` |
| 224 | 8 | issued-at Unix seconds |
| 232 | 8 | expires-at Unix seconds |
| 240 | 64 | issuer Ed25519 signature |

All identifiers, hashes and public keys are fixed-length and non-zero. The lifetime is positive and
at most 86,400 seconds. It must be contained by the verified PMA1 current epoch, Mr. X rollout and
revocation-snapshot windows. The verifier checks network, authority generation/hash and issuer key
against the immutable verified PMA1 and recomputes the selection-input commitment from the blinded
placement ID.

## Canonical PRA1

The owner signature transcript is ASCII
`Deep/production-mailbox/route-advertisement/v1` followed by the first 336 bytes below. The complete
artifact is exactly 400 bytes. Integers are unsigned big-endian.

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | ASCII `PRA1` |
| 4 | 1 | version `1` |
| 5 | 3 | zero reserved bytes |
| 8 | 304 | exact canonical issuer-signed PRC1 |
| 312 | 8 | owner advertisement sequence |
| 320 | 8 | published-at Unix seconds |
| 328 | 8 | expires-at Unix seconds |
| 336 | 64 | mailbox-owner Ed25519 signature |

The sequence is non-zero. The PRA1 window is positive, at most 86,400 seconds and wholly contained
by its PRC1 window. The owner signature is verified with the exact owner key embedded in PRC1.

## Durable sequence rules

The protocol computes a stable route-domain hash as
`SHA-256("Deep/production-mailbox/route-domain/v1" || networkId || ownerKey || blindedMailboxId ||
blindedPlacementId || selectionInputCommitment)`. The verifier requires the caller's expected hash,
so a host cannot accidentally apply one mailbox's sequence state to another. Raw identifiers and
this stable hash must not be used in logs or metrics. A fresh state may accept any currently live
owner-signed sequence because a newly added or long-offline contact does not possess every prior
advertisement. After the first durable commit:

- the same sequence is accepted only when the canonical PRA1 SHA-256 is byte-identical, making
  retries idempotent;
- any greater live owner-signed sequence may be accepted and atomically committed, allowing an
  offline contact to skip already expired intermediate advertisements;
- a lower sequence is rollback;
- a different artifact at the same sequence is conflict;

There is no previous-hash field: the prior durable sequence/hash and the owner signature prevent
rollback, same-sequence substitution and unauthorized forward jumps. A large forward jump can only
be authorized by the owner whose route state it advances; rejecting all gaps would permanently
strand contacts that were offline longer than an intermediate artifact's validity. Before a new
contact's first local commit, freshness relies on the short PMA-contained validity window and the
authenticated E2E contact channel which delivered the artifact.

## Host requirements

- Keep issuer and owner private keys outside this package; it exposes transcript bytes and
  verification only.
- Persist advertisement sequence and canonical hash atomically with any authorization depending on
  them. Do not advance sequence on a failed issuance.
- Bind a PeerDeposit request to the exact owner key and all three route values from verified PRA1.
- Load PMA1/PMR1/PMT1 from one retained immutable closure and issue freshly verified exact PMS1.
- Treat missing durable state, stale authority artifacts, signer failure, sequence conflict, and
  topology verification failure as fail-closed service errors.
- Do not add backwards-compatible or alternate encodings before production launch.
