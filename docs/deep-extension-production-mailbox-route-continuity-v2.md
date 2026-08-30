# Production mailbox route continuity V2

Status: **pre-cutover evidence; release-rejected by DR-0004**. Reviewed
continuity properties are ported to XRA1/XRC1/XSS1, not wire-compatible.

Status: design freeze candidate; no implementation or compatibility promise exists yet.

This clean-break contract advances the owner-authorized mailbox route together with a `PSS2`
selection transition. It replaces unattended reuse of expired or old-authority `PRC1`/`PRA1`
artifacts. V1 route artifacts are not accepted by the V2 transition verifier.

All integers are unsigned big-endian. All unused bytes are zero. Hashes are SHA-256 of exact
canonical bytes. Codecs must validate fixed bounds before copying caller memory and must use one
owned snapshot for validation, signing, hashing and verification.

## Trust and canonical order

The canonical delegated order is:

`sealed old route LKG -> RCD1 -> RDA1 -> fresh RCH1 + PRC1 -> RTC1 -> RCA1 -> PSS2`.

The owner-online order is:

`sealed old route LKG -> fresh PRC1 -> PRA2 -> PSS2`.

`RCA1` never hashes `PSS2`; `PSS2` hashes the exact `RCA1`. This prevents a hash cycle. `RTC1` is
an unsigned canonical transition context hashed before either signature. The final composite
verifier binds the exact `RTC1`, route authorization and `PSS2` bytes.

## Common domains and tags

- RCD signing domain: `Deep/production-mailbox/route-continuity-delegation/v1`
- RDA signing domain: `Deep/production-mailbox/route-delegation-acceptance/v1`
- RCR signing domain: `Deep/production-mailbox/route-continuity-revocation/v1`
- RCH signing domain: `Deep/production-mailbox/route-revocation-checkpoint/v1`
- RCA signing domain: `Deep/production-mailbox/route-continuity-activation/v1`
- PRA2 signing domain: `Deep/production-mailbox/route-advertisement/v2`
- RTC hash domain: `Deep/production-mailbox/route-transition-context/v1`
- PSS2 old-issuer domain: `Deep/production-mailbox/selection-successor/v2/old`
- PSS2 current-issuer domain: `Deep/production-mailbox/selection-successor/v2/current`
- composite hash domain: `Deep/production-mailbox/route-selection-activation/v1`

Route-authorization kind is `0=None`, `1=OwnerPRA2`, `2=DelegatedRCA1`. Transition mode is
`1=DirectPromotion`, `2=OfflineCheckpoint`. No other value is accepted.

## RCD1 — owner continuity delegation (552 bytes)

The owner explicitly authorizes the current mailbox issuer, within a bounded window and sequence
range, to keep exactly the same blinded route alive. A 365-day delegation is a protocol maximum,
not a default. Hosts default to at most 30 days unless Mr. X explicitly changes policy.

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | ASCII `RCD1` |
| 4 | 1 | version `1` |
| 5 | 3 | zero reserved |
| 8 | 16 | network ID |
| 24 | 32 | pinned Mr. X Ed25519 public-key SHA-256 |
| 56 | 32 | route-domain hash |
| 88 | 32 | mailbox-owner Ed25519 public key |
| 120 | 32 | blinded mailbox ID |
| 152 | 32 | blinded placement ID |
| 184 | 32 | selection-input commitment |
| 216 | 8 | anchor PMA authority generation |
| 224 | 32 | exact anchor PMA hash |
| 256 | 32 | exact anchor PRC1 hash |
| 288 | 1 | anchor authorization kind; must be `OwnerPRA2` |
| 289 | 7 | zero reserved |
| 296 | 32 | exact anchor PRA2 hash |
| 328 | 8 | anchor route-authorization sequence |
| 336 | 32 | exact domain-separated pre-delegation anchor route-origin LKG hash |
| 368 | 8 | immutable original `RouteVerifiedAt` Unix seconds |
| 376 | 1 | capability; exactly `1=RouteContinuityOnly` |
| 377 | 7 | zero reserved |
| 384 | 16 | random non-zero delegation serial |
| 400 | 8 | owner delegation sequence |
| 408 | 32 | exact previous RCD1 hash; zero only for delegation sequence one |
| 440 | 8 | inclusive maximum PMA authority generation |
| 448 | 8 | first delegated activation sequence; anchor sequence + 1 |
| 456 | 8 | last delegated activation sequence, inclusive |
| 464 | 8 | issued-at Unix seconds |
| 472 | 8 | not-before Unix seconds |
| 480 | 8 | expires-at Unix seconds |
| 488 | 64 | owner Ed25519 signature |

The RCD binds the already-durable owner-authorized route origin that exists before this RCD is
created. It never binds a transcript containing itself or its future RDA. The delegation sequence
and previous hash form a global per-route delegation chain. The maximum
authority generation is greater than the anchor, is not `ulong.MaxValue`, and advances by at most
512 generations. The activation range is positive, contains no terminal `ulong.MaxValue`, and
spans at most 512 sequences. The validity is positive and at most 365 days. The owner application
must show the chosen duration, authority ceiling and activation count to Mr. X; silent 365-day
opt-in is forbidden. `RouteContinuityOnly` never delegates route changes, owner signing, grants,
entitlements, payments, device enrollment or arbitrary mailbox issuance.

## RDA1 — live old-issuer acceptance (320 bytes)

An owner signature can be backdated. Therefore an RCD is usable only with an RDA issued while the
anchor PMA, PRC and PRA were live. RDA is an immutable event receipt; it has no artificial future
expiry. Historical verification evaluates the anchor artifacts at `accepted-at`.

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | ASCII `RDA1` |
| 4 | 1 | version `1` |
| 5 | 3 | zero reserved |
| 8 | 16 | network ID |
| 24 | 32 | route-domain hash |
| 56 | 32 | exact RCD1 hash |
| 88 | 8 | anchor PMA authority generation |
| 96 | 32 | exact anchor PMA hash |
| 128 | 32 | exact anchor PRC1 hash |
| 160 | 1 | anchor authorization kind; must be `OwnerPRA2` |
| 161 | 7 | zero reserved |
| 168 | 32 | exact anchor PRA2 hash |
| 200 | 8 | anchor route-authorization sequence |
| 208 | 32 | exact pre-delegation anchor route-origin LKG hash |
| 240 | 8 | immutable original `RouteVerifiedAt` Unix seconds |
| 248 | 8 | accepted-at Unix seconds |
| 256 | 64 | anchor mailbox-issuer Ed25519 signature |

The RDA verifier requires the exact live anchor closure and proves that RCD, PMA, PRC, PRA,
route-domain, sequence and pre-delegation anchor route-origin LKG all agree at `accepted-at`. Exact temporal rules are
`RCD.issuedAt <= acceptedAt`, `RCD.notBefore <= acceptedAt < RCD.expiresAt`, and `acceptedAt` is
inside the anchor PMA rollout/current-epoch, PMR, PRC and PRA windows. The Registry reads the latest
route predecessor and records RDA under the same serializable CAS that accepts the RCD; a
concurrent route authorization or delegation update aborts acceptance. RDA and RCD must contain
the same pre-delegation ROL hash and immutable `RouteVerifiedAt`.

## RCR1 — owner revocation hash-chain entry (224 bytes)

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | ASCII `RCR1` |
| 4 | 1 | version `1` |
| 5 | 3 | zero reserved |
| 8 | 16 | network ID |
| 24 | 32 | route-domain hash |
| 56 | 16 | target delegation serial |
| 72 | 32 | exact target RCD1 hash |
| 104 | 8 | revocation generation |
| 112 | 32 | previous RCR1 hash, zero only for generation one |
| 144 | 8 | revoked-at Unix seconds |
| 152 | 1 | reason code; `1=OwnerRevoked`, `2=OwnerKeyRotated`, `3=RouteReset` |
| 153 | 7 | zero reserved |
| 160 | 64 | owner Ed25519 signature |

RCR is terminal and per delegation, not a global route log. The only valid revocation has
generation one, a zero previous hash and the exact target delegation serial/hash. Before it exists,
the delegation state is `(generation=0, head=zero, Active)`; afterwards it is
`(generation=1, head=RCRHash, Revoked)`. Registry durably CASes that one transition. Exact bytes
replay; a different revocation conflicts; rollback and any later generation fail closed.

## RCH1 — current issuer revocation checkpoint (320 bytes)

RCH is the fresh, current-authority statement used by an offline verifier. A numeric generation
alone is not proof of the current revocation head.

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | ASCII `RCH1` |
| 4 | 1 | version `1` |
| 5 | 3 | zero reserved |
| 8 | 16 | network ID |
| 24 | 32 | route-domain hash |
| 56 | 8 | current PMA authority generation |
| 64 | 32 | exact current PMA hash |
| 96 | 32 | current mailbox-issuer Ed25519 public key |
| 128 | 8 | current owner RCR generation |
| 136 | 32 | exact current RCR head hash |
| 168 | 32 | per-transition random salt |
| 200 | 32 | continuity transition commitment |
| 232 | 1 | status; `1=Active`, `2=Revoked` |
| 233 | 7 | zero reserved |
| 240 | 8 | issued-at Unix seconds |
| 248 | 8 | expires-at Unix seconds |
| 256 | 64 | current mailbox-issuer Ed25519 signature |

RCH lifetime is at most 24 hours and wholly inside the current PMA/PMR window. An RCA requires
`Active`. Clients persist terminal `(RCR generation, head hash)` only from exact canonical RCR1
bytes verified under the owner key and exact RCD serial/hash; an issuer-signed RCH alone can never
advance owner-controlled revocation state. Learned owner revocation invalidates all later
activation attempts.

The continuity transition commitment is
`SHA-256("Deep/production-mailbox/continuity-commitment/v1" || transitionSalt || networkId ||
routeDomain || RCDHash || RDAHash || routeOriginLkgHash || RCRGeneration || RCRHeadHash ||
currentPMAHash || freshPRCHash || predecessorKind || predecessorHash || predecessorSequence ||
newSequence)`. RCD/RDA hashes never appear directly in XNode-carried artifacts.

RCH status is constrained by the per-delegation state. `Active` requires generation zero and an
all-zero head. `Revoked` requires generation one and the exact owner-signed RCR1 hash. RCA issuance
and verification require `Active`; a revoked RCH is evidence only and can never activate a route.
An unaccompanied Revoked RCH blocks that candidate but yields no durable revocation capability and
cannot poison the client's terminal LKG. Persistent revocation requires the exact RCR bytes through
the authenticated Registry/E2E state channel and full owner-signature/serial/hash verification;
RCH then only corroborates the current issuer's knowledge of that owner revocation.
Because a not-yet-observed owner revocation cannot be proven absent to an offline client, a stale
already-issued Active RCH may remain usable only until its hard expiry (at most 24 hours). This
residual window is explicit and must not be described as immediate global revocation.
If the current issuer is compromised, it can continue issuing stale-head Active checkpoints to a
client that has never learned the owner's RCR. The 24-hour bound limits an individual checkpoint,
not the duration of that compromise. Only an exact verified owner-signed RCR advances the durable
terminal head and makes the client LKG reject older or forked checkpoints. An unaccompanied RCH may
be negative-cached only for that exact candidate/hash until the RCH expires; it has no effect on
other candidates, predecessors or durable revocation state.

## Sealed route-origin LKG transcript (ROL1)

The client and Registry compute a 224-byte canonical `ROL1` transcript and hash it with
`Deep/production-mailbox/route-origin-lkg/v1`. It contains: header/version (8), network ID (16),
route-domain hash (32), authorization kind plus seven zero bytes (8), exact authorization hash
(32), authorization sequence (8), exact RCD hash or zero for owner-only state (32), exact RDA hash
or zero (32), per-delegation RCR generation (8), per-delegation RCR head hash (32), immutable original
`RouteVerifiedAt` (8), and monotonic local commit generation (8). The final two counters are
non-zero and nonterminal. This hash, not caller-asserted time fields, binds an offline transition
to one sealed durable origin.

ROL construction is explicitly two-phase and acyclic. Before continuity enrollment, the sealed
owner-only ROL has zero RCD/RDA slots. `RCD1` and `RDA1` both bind that exact pre-delegation ROL.
Only after RDA verification does one atomic commit create the next enrolled-continuity ROL with
the exact RCD/RDA hashes and the initial `0/zero` RCR state. Neither RCD nor RDA contains this next
ROL hash. Later RTC/PSS transitions bind the currently sealed predecessor ROL, which may contain
the already-existing RCD/RDA hashes. `RouteVerifiedAt` remains the original owner-route
verification time across these recomputations; the local commit generation advances exactly one.

Genesis authoring is split around Registry's durable prepare. First, `VerifyGenesisIntent`
validates and owns the exact RCD1, owner-only pre-ROL1 and historical PMA1/PMR1/PRC1/PRA2 closure;
it accepts no responder key, transaction time or callback. Registry may prepare an HSM key only
after this succeeds. Registry then persists an intent-hash reservation and chooses monotonic
authoritative `acceptedAt`. Outside the store, `AuthorGenesisAsync` repeats the owned closure at
`authorNow`, validates responder/OCR inputs before callbacks, signs RDA1 then OCR1, and derives the
enrolled ROL1 plus initial RHC1. Its commit plan is data only. The final store CAS compares the
exact predecessor ROL/hash/generation and previous-delegation tuple, and atomically writes the
full anchor, RCD1/RDA1, both ROL1 values, OCR1, genesis RHC1 and both protected restore contexts.
Only a protected reread may be used for `RestoreHistoricalAnchor` and anchor-bound `RestoreCursor`.

## RTC1 — unsigned route/selection transition context (408 bytes)

RTC is canonical bytes hashed with the RTC domain. It is not authorization by itself.

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | ASCII `RTC1` |
| 4 | 1 | version `1` |
| 5 | 1 | transition mode |
| 6 | 1 | predecessor authorization kind |
| 7 | 1 | new authorization kind |
| 8 | 16 | network ID |
| 24 | 32 | route-domain hash |
| 56 | 32 | exact old PMS hash |
| 88 | 32 | exact new PMS hash |
| 120 | 32 | exact predecessor route-authorization hash |
| 152 | 8 | predecessor route-authorization sequence |
| 160 | 32 | exact fresh PRC1 hash |
| 192 | 8 | new route-authorization sequence |
| 200 | 32 | per-transition random salt; zero for owner-PRA path |
| 232 | 32 | continuity transition commitment; zero for owner-PRA path |
| 264 | 32 | exact RCH1 hash; zero for owner-PRA path |
| 296 | 32 | exact current PMA hash |
| 328 | 8 | current PMA authority generation |
| 336 | 32 | exact sealed old ROL1 hash |
| 368 | 8 | immutable old `RouteVerifiedAt` Unix seconds |
| 376 | 8 | old local route commit generation |
| 384 | 8 | not-before Unix seconds |
| 392 | 8 | expires-at Unix seconds |
| 400 | 8 | zero reserved |

The new sequence is exactly predecessor + 1. The ROL fields must equal the sealed predecessor
state, and an offline checkpoint also binds them through PSS2. Intermediate RTC/RCA/PSS history
may be verified at its signed chain time, but only a final live closure can be committed. Bounded
history is retained for the RCD validity window and maximum 512 activations.

## RCA1 — delegated current-issuer activation (496 bytes)

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | ASCII `RCA1` |
| 4 | 1 | version `1` |
| 5 | 3 | zero reserved |
| 8 | 16 | network ID |
| 24 | 32 | route-domain hash |
| 56 | 8 | current PMA authority generation |
| 64 | 32 | exact current PMA hash |
| 96 | 32 | current mailbox-issuer Ed25519 public key |
| 128 | 8 | exact current PMR1 revocation generation |
| 136 | 32 | exact current PMR1 revocation-head hash |
| 168 | 32 | exact current PMR1 snapshot hash |
| 200 | 32 | per-transition random salt |
| 232 | 32 | continuity transition commitment |
| 264 | 32 | exact RCH1 hash |
| 296 | 32 | exact fresh PRC1 hash |
| 328 | 32 | exact RTC1 hash |
| 360 | 1 | predecessor authorization kind |
| 361 | 7 | zero reserved |
| 368 | 32 | exact predecessor route-authorization hash |
| 400 | 8 | predecessor sequence |
| 408 | 8 | activation sequence; predecessor + 1 |
| 416 | 8 | issued-at Unix seconds |
| 424 | 8 | expires-at Unix seconds |
| 432 | 64 | current mailbox-issuer Ed25519 signature |

RCA validity is positive, at most 24 hours, and contained by RCD, RCH, PRC and current PMA/PMR.
The PMR generation/head/snapshot must equal the exact current authority closure and prove the RCA
issuer is not revoked. The PMA generation must not exceed the RCD authority ceiling. The activation
sequence must be inside the RCD range. All route-transition fields must equal the referenced RTC.

## PRA2 — owner-online route authorization (448 bytes)

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | ASCII `PRA2` |
| 4 | 1 | version `2` |
| 5 | 3 | zero reserved |
| 8 | 304 | exact fresh canonical PRC1 |
| 312 | 1 | predecessor authorization kind, or `None` only for route genesis |
| 313 | 7 | zero reserved |
| 320 | 32 | exact predecessor authorization hash; zero only for genesis |
| 352 | 8 | predecessor sequence; zero only for genesis |
| 360 | 8 | owner authorization sequence; predecessor + 1 |
| 368 | 8 | published-at Unix seconds |
| 376 | 8 | expires-at Unix seconds |
| 384 | 64 | mailbox-owner Ed25519 signature |

PRA2 and RCA1 share one durable tagged predecessor chain. Switching between owner and delegated
authorization cannot reset, jump or fork the sequence.

## PSS2 route-binding extension

`PSS2` is a clean break from `PSS1`. Magic is ASCII `PSS2`, version is `2`, and
`FixedCoreLength=600`. The PSS1-compatible selection portion occupies absolute bytes `[0,416)`;
the route block occupies absolute bytes `[416,600)`. Variable canonical PMA/PMS artifacts begin
exactly at byte 600 using the length fields in the fixed core. The old/current issuer signatures
remain the terminal 128 bytes after all variable artifacts. `MaximumArtifactBytes` is exactly the
PSS1 maximum plus 184. Both issuer transcripts cover the complete fixed core and variable bytes.
The V2 model calls the second signer `CurrentIssuer`, never `NewIssuer`.

| Relative offset | Size | Field |
| ---: | ---: | --- |
| 0 | 32 | exact RTC1 hash |
| 32 | 1 | predecessor route-authorization kind |
| 33 | 1 | new route-authorization kind |
| 34 | 6 | zero reserved |
| 40 | 32 | exact predecessor route-authorization hash |
| 72 | 8 | predecessor sequence |
| 80 | 32 | exact fresh PRC1 hash |
| 112 | 32 | exact new PRA2 or RCA1 hash |
| 144 | 8 | new route-authorization sequence |
| 152 | 32 | exact RCH1 hash; zero for OwnerPRA2 mode |

No nullable or mixed mode is accepted. `DelegatedRCA1` requires non-zero RCH hash and an exact live
RCA. `OwnerPRA2` requires a zero RCH slot and an exact live owner-signed PRA2. PSS2 binds the same
old/new PMS hashes as RTC. Direct promotion retains old+current issuer signatures; offline
checkpoint retains only the current issuer signature and exact sealed old LKG binding.

PSS1 bytes, magic or version are rejected by every PSS2 entrypoint. PSS1 entrypoints do not accept
PSS2. Truncation at byte 600, treating any route-block suffix as variable data, inconsistent
lengths, trailing bytes and route-block/signature ambiguity are all non-canonical failures.

## Bounded route-history batches

Historical route authorization advances separately from selection history. One canonical `RHB1`
batch carries at most 16 exact route links and 8 MiB (8,388,608 bytes) of unique canonical payload.
Its absolute maximum encoded length is 8,394,304 bytes. At most 512 links
may be consumed across at most 32 resumable batches for one delegation. Cumulative canonical
payload processed by one refresh is at most 268,435,456 bytes (256 MiB); both counters are carried
by the sealed checkpoint and checked before the next payload is read. Historical RHB batches never embed
PMT, PMS or PSS; a link references only deduplicated PMA, PMR, PRC, RCH, RTC and RCA or PRA2 bytes.
Only the final live PSS2 activates the current selection/runtime.

RHB has a fixed 64-byte header: magic/version/reserved (8), batch sequence (8), exact previous
sealed route-checkpoint hash (32), link count (2), artifact count (2), table bytes (4), payload
bytes (4), and four zero bytes. Each artifact-table item is exactly 40 bytes: type (1), three zero
bytes, length (4), SHA-256 (32). Each link-table item is exactly 32 bytes: authorization kind (1),
three zero bytes, six unsigned 16-bit artifact indexes (PMA, PMR, PRC, RCH-or-FFFF, RTC-or-FFFF,
authorization), predecessor sequence (8), and new sequence (8). Artifact count is at most 128;
count-derived table/payload/total sizes must exactly equal the envelope before any payload copy.

Artifact tags are fixed: `1=PMA1`, `2=PMR1`, `3=PRC1`, `4=RCH1`, `5=RTC1`, `6=RCA1`,
`7=PRA2`; every other tag is rejected. The artifact table is strictly increasing by
`(type, SHA-256)` using ordinal byte order, contains no duplicate or cross-type hash alias, and
payloads occur once in that exact table order. Link tables occur after the artifact table and
before payloads. For a historical OwnerPRA2 link, both RCH and RTC indexes are exactly `0xffff`;
PRA2 does not authenticate RTC without a final live PSS2, so the route checkpoint is derived only
from the sealed predecessor plus exact PRC/PRA2. For a DelegatedRCA1 link, RCH and RTC are required
and RCA authenticates the exact RTC hash. Every other index is less than artifact count and names
the required exact tag. Table byte counts are
exactly `artifactCount*40 + linkCount*32`; checked arithmetic and the absolute envelope maximum
are validated before allocating or invoking a codec/verifier. Every artifact-table row is
referenced by at least one link; unused rows and payload bytes are non-canonical.

The verifier first performs an allocation-free structural walk of the fixed header, count-derived
table, every artifact length/hash/framing row, every tagged link index and the exact total. This
includes PMR count-derived framing. Only then does it freeze the complete bounded batch once,
repeat the structural walk over the owned bytes, and verify one artifact at a time. Links may reference the same unique frozen
artifact row; duplicate artifact-table rows are non-canonical. It emits only a sealed internal
route checkpoint containing the canonical checkpoint hash, delegation binding, new ROL hash,
exact tagged authorization/RCR state, verified PMA generation/hash, pinned Mr. X hash, batch
sequence, cumulative batch/link counts and cumulative payload bytes. The verifier discards only its
transient decoded tables and payload buffers after producing the sealed plan. The consumer must
atomically retain every exact RHB1 with its RHC1, protected context and plan hash for the complete
bounded history horizon (at most 32 batches and 256 MiB); whole-chain garbage collection is allowed
only after the history is terminal and no supported cold restore can require it. Each link's PMA is
either the exact retained generation/hash replay or a strict
successor accepted by the bounded pinned-Mr. X forward-checkpoint verifier. Authority generations
may skip only when that exact forward-checkpoint proof verifies; an unproven jump, same-generation
hash fork or rollback fails closed. RHB batch sequence and route-authorization sequence remain
contiguous exact `+1`, and authority generations above the RCD ceiling fail closed. Batch sequence and cumulative
counts advance exactly, remain nonterminal and never exceed 32 batches, 512 links or 256 MiB. The next batch
exact-binds that checkpoint and starts at its exact predecessor authorization; a batch replay is
byte-identical, while a fork, gap, rollback or changed payload at the same sequence fails closed.
The sole public ingestion surface is next-only `VerifyNextBatchForCommit` over an exact sealed
predecessor cursor. It accepts sequence `current+1` only and returns a sealed defensive
cryptographic commit plan. The plan owns the exact RHB bytes/hash, predecessor and next RHC
bytes/hashes/protected contexts, predecessor and next canonical ROL plus PRC/auth/RCH/RTC hash
bindings, cumulative counters, and the exact final PMA/PMR/PRC plus tagged Owner PRA2 or Delegated
RCH/RTC/RCA tuple. Its domain-separated `PlanHash` binds every field. It is not a durability,
storage, publication or activation capability. Same-sequence durable replay and fork decisions
belong to Registry before this next-only call; the replay-capable verifier is internal. Registry's
atomic append advances only route-history authorization state and preserves independently committed
selection, PSS and publication state byte-for-byte. No public generic historical verifier or
ordinary verified capability is returned. Registry-online
stale refresh can stream resumable exact batches; XNode preposition carries only the final live
activation for the exact old LKG lineage.

## RHC1 — sealed resumable route-history checkpoint (464 bytes)

RHC is an internal canonical capability persisted by the client and mirrored by Registry state.
It is never accepted from an unauthenticated caller and never becomes a general verified route
capability. Its canonical hash is
`SHA-256("Deep/production-mailbox/route-history-checkpoint-hash/v1" || exactRHC1Bytes)`.
The per-delegation history binding is
`SHA-256("Deep/production-mailbox/route-history-delegation/v1" || exactRCD1Hash || exactRDA1Hash)`.

| Offset | Size | Field |
| ---: | ---: | --- |
| 0 | 4 | ASCII `RHC1` |
| 4 | 1 | version `1` |
| 5 | 3 | zero reserved |
| 8 | 16 | network ID |
| 24 | 32 | route-domain hash |
| 56 | 32 | per-delegation history binding |
| 88 | 1 | current route-authorization kind |
| 89 | 7 | zero reserved |
| 96 | 32 | exact current route-authorization hash |
| 128 | 8 | current route-authorization sequence |
| 136 | 8 | exact owner RCR generation |
| 144 | 32 | exact verified owner RCR head hash |
| 176 | 32 | exact current ROL1 hash |
| 208 | 8 | immutable original `RouteVerifiedAt` Unix seconds |
| 216 | 8 | current local route commit generation |
| 224 | 32 | pinned Mr. X Ed25519 public-key SHA-256 |
| 256 | 8 | current verified PMA authority generation |
| 264 | 32 | exact current PMA hash |
| 296 | 8 | current verified PMR revocation generation |
| 304 | 32 | exact current PMR revocation-head hash |
| 336 | 32 | exact current PMR snapshot hash |
| 368 | 8 | last committed RHB batch sequence |
| 376 | 8 | cumulative committed batch count |
| 384 | 8 | cumulative verified route-link count |
| 392 | 8 | cumulative canonical payload bytes |
| 400 | 32 | rolling exact RHB history-transcript head |
| 432 | 32 | SHA-256 of the exact last committed RHB1 bytes |

The initial RHC is created from the exact sealed continuity-enrollment ROL/RCD/RDA and current
verified PMA/route authorization before fetching history. It has batch sequence and all three
cumulative counters zero; authorization, owner-RCR state, ROL, `RouteVerifiedAt`, local commit
generation, Mr. X pin and PMA fields equal that sealed state. Initial RCR state is `0/zero`; if an
exact owner-signed terminal RCR is already known, no history activation may start. PMR generation,
head and snapshot equal the exact verified PMR under the initial PMA. The history-transcript head
and last-committed-RHB hash are all zero.

For every non-empty RHB, the header previous-checkpoint hash equals the canonical hash of the exact
prior RHC, and header batch sequence equals prior sequence plus one. Verification begins from the
prior authorization/PMA/ROL fields and ends at the exact last link. The next RHC preserves network,
route domain, delegation binding, Mr. X pin and immutable `RouteVerifiedAt`; replaces authorization,
ROL, PMA and PMR with the verified final values; advances local route commit generation exactly once
per verified route link; preserves the exact owner-RCR state; sets batch sequence and cumulative
batch count to prior plus one; adds exact link count and payload bytes using checked arithmetic; and
sets the history-transcript head to
`SHA-256("Deep/production-mailbox/route-history-transcript/v1" || priorHead32 || exactRHB1Bytes)`.
It also sets the last-committed-RHB hash to `SHA-256(exactRHB1Bytes)`.
Under the same PMA, PMR is exact replay or a strictly verified forward generation/head/snapshot;
same-generation fork, rollback and stale substitution fail. When PMA advances, PMR must be the
exact verified live snapshot for that new PMA and becomes the new retained comparison tuple. The
verifier rejects terminal counters and the 32-batch/512-link/256-MiB limits before reading payload
bodies.

The next RHC bytes, rolling history-transcript head, last-batch hash and canonical hash are durably
committed with the route-history CAS before the next batch request. On a request whose batch
sequence equals the current RHC batch sequence, the verifier hashes the bounded exact RHB bytes
before any artifact/crypto callback: equality with the stored last-batch hash returns the identical
current RHC, while a different hash is a fork. Older sequences are stale. Only sequence current+1
may advance and must bind the current RHC canonical hash. A checkpoint/hash mismatch, partial or ambiguous checkpoint persistence,
counter gap/rollback, delegation substitution, PMA fork or changed sealed origin fails closed. On
normative cold restore, the client starts only from the exact genesis historical anchor and
protected genesis RHC, then applies stored batches `1..N` sequentially through
`VerifyNextBatchForCommit`, comparing every stored RHC, protected context, durable route tuple and
plan hash. A genesis anchor cannot directly restore an arbitrary post-history RHC, including a head
whose current PMA or PMR differs from that anchor. On warm restart, the client resumes only from the
exact committed RHC; Registry must present a batch whose
previous hash and sequence match it. A committed same-prior/same-sequence batch with different exact
bytes necessarily produces a different transcript head and is a fork even if its final semantic
authorization and counters would otherwise match.

## Composite verification and atomic state

The high-level verifier accepts bounded individually frozen artifacts and verifies:

1. exact sealed predecessor PMS and route authorization kind/hash/sequence;
2. current pinned-Mr. X PMA/PMR/PMT/PMS closure and PSS2;
3. RTC equality with both selection and route fields;
4. either fresh owner PRA2, or exact RCD + RDA + live Active RCH + RCA;
5. exact sequence CAS, revocation-head monotonicity, validity intersections and signatures.

Only the high-level result can construct an atomic LKG commit containing both selection and route
state. No generic route-forward verifier returns ordinary verified capabilities.

## Privacy, distribution and no-LKG rules

- RCD, RDA and raw RCR entries remain sealed on the client and Registry. Exact RCD/RDA hashes and
  delegation serials are hidden behind a fresh per-activation salt and continuity commitment. They
  are never stored on XNodes, placed in XNode publication tickets, logs, metrics, paths, query
  strings or push payloads.
- XNodes carry only changing PRC, RTC, PSS2 and selection closure plus one explicitly tagged route
  authorization: exact PRA2 for `OwnerPRA2`, or exact RCH and RCA1 for `DelegatedRCA1`. They never
  carry RCD, RDA, raw RCR, RHB or RHC. A client must already own the sealed continuity state needed
  by the delegated path. Requests remain constant-path authenticated binary bodies.
- The public PMC2 node-cache verifier is intentionally weaker than the client activation verifier.
  It snapshots an aggregate of at most 8 MiB, verifies the current PMA/PMR/PMT, current and staged
  next PMS, current-issuer PSS2 signature, PRC/RTC and tagged PRA2 or Active-RCH/RCA closure, and
  returns only a node-cache capability. It accepts neither RCD/RDA/RCR nor a sealed ROL and exposes
  no conversion to the atomic client activation capability. For `DirectPromotion`, PMC2 retains and
  canonical-checks the non-zero retired-issuer signature slot but cannot authenticate that signature
  because retired PMA1 is deliberately absent; the current issuer signature and cache transcript
  still bind/distinguish the exact unsigned closure and exact retained slot bytes. Full client
  activation separately verifies retired trust from protected LKG state.
- `VerifyOwnerRevocation` is the only public RCR verification entry point and returns a sealed exact
  verified-RCR capability. RHC cursors and commit plans export their exact durable restore tuple via
  `ToProtectedRestoreContext`; Registry does not parse RHC to reconstruct checkpoint, enrollment,
  PMA or PMR CAS bindings.
- A new contact receives the complete owner-authorized origin and current chain only through an
  authenticated E2E channel, then verifies the current PMA and RCH.
- An owner device without sealed route-origin LKG may not activate RCA offline and may not sign a
  successor PRA2 from Registry-provided state. It must import sealed LKG or explicitly reset to a
  new route identity.
- A known revocation is immediate. A previously fetched activation can remain usable only until
  its hard expiry, at most 24 hours; that residual window is an explicit threat-model decision.
- A node-delivered Revoked RCH without exact owner-signed RCR bytes is fail-closed evidence for that
  candidate only. It is never written as the client's terminal owner-revocation state.

## Required failure matrix

Reject cross-network/owner/route/MrX artifacts, RCD backdating without RDA, old/current issuer
substitution, RCR rollback/fork/gap, stale or forked RCH, revoked delegation, sequence skip/fork,
PRA/RCA mode downgrade, RTC/PSS/hash substitution, validity escape, terminal counters, oversized
allocation, mutable-input races, no-LKG activation and publication before the complete chain is
durable. Multi-missed-rotation tests verify every historical exact-linked hop at chain time and
require the final closure to be live. RHB negatives include duplicate/cross-type artifact hashes,
unused artifact rows, wrong tag/index, forbidden or missing `0xffff`, OwnerPRA2 RTC injection,
unsorted tables, payload reorder, checked-size overflow,
maximum-minus-one/exact-maximum/one-byte-over envelopes, late oversized hops with zero crypto
callbacks, batch/cumulative terminal counters, 33rd batch, cumulative-payload overflow,
checkpoint fork/gap/rollback, PMA/PMR lineage fork, and restart replay of same prior+sequence with
an equal-length exact-batch substitution that must change the last-batch hash/rolling transcript
head. Tests cover commit success followed by lost response, process restart, exact last-batch
replay returning byte-identical RHC with zero artifact/crypto callbacks, and same-sequence changed
bytes failing as a fork with zero callbacks.
Revocation negatives include a forged or conflicting issuer-only Revoked RCH, missing RCR bytes,
wrong owner/serial/RCD hash and proof that none of those can advance the durable terminal RCR LKG.

Every live counter must retain a successor: owner delegation sequence, predecessor/new route
authorization sequence, local route commit generation and active authority ceiling reject
`ulong.MaxValue`. Delegation updates require the exact previous hash and exact +1 under one durable
CAS. The sole RCR transition is exactly `0/zero -> 1/exactHash`. Same bytes replay; the same
generation/sequence with different bytes conflicts; rollback and gaps fail closed. Each artifact
uses the artifact-specific temporal rules below; no blanket rule is inferred for absent fields.

## Normative time, transaction and replay rules

- All additions and comparisons use checked unsigned arithmetic. A verifier-owned `now` snapshot
  is captured once after scalar preflight; clock skew is at most 300 seconds. Zero or terminal time
  counters and any overflow fail closed.
- RCD requires `issuedAt <= notBefore < expiresAt`, positive lifetime, and at most the explicit
  delegation-policy maximum. `RouteVerifiedAt <= RCD.issuedAt`.
- RDA requires non-zero `RouteVerifiedAt <= acceptedAt`, `RCD.issuedAt <= acceptedAt`, and
  `RCD.notBefore <= acceptedAt < RCD.expiresAt`. Accepted-at is also inside the historically
  verified PMA/PMR/PRC/PRA2 windows. Registry transaction time may differ only by allowed skew.
- RCR requires `RCD.issuedAt <= revokedAt`, non-zero revoked-at, and
  `revokedAt <= verifierNow + skew`. Registry serializes RCR against RDA/RCH issuance. If RCR wins,
  no Active RCH may commit; if Active RCH wins, the later RCR invalidates future checkpoints while
  the already-issued checkpoint retains only its signed hard-expiry window.
- Active RCH requires exact `0/zero` RCR state at the same serializable read/CAS. RCH has
  `issuedAt < expiresAt`, lifetime at most 24 hours, and its entire skew-adjusted live interval is
  inside current PMA and PMR validity.
- RTC requires `notBefore < expiresAt`; its interval is contained by the chosen PRA2 or by all of
  RCD, Active RCH, PRC, RCA, PMA and PMR. RCA requires
  `issuedAt >= max(RDA.acceptedAt,RCD.notBefore,RCH.issuedAt,PRC.issuedAt)` and
  `issuedAt < expiresAt`; RCA expiry is no later than every referenced parent expiry and at most
  24 hours after issuance. PRA2 requires `publishedAt < expiresAt` and lies inside PRC and current
  PMA/PMR validity.
- PSS2 issuance is no earlier than RTC not-before and its entire live interval is contained by
  RTC, the exact PRA2/RCA, current PMA/PMR/PMT and both current/next PMS validity. Historical RHB
  verification evaluates RCA at its signed issued-at and PRA2 at its signed published-at; only the
  final PSS2 and current control-plane artifacts are checked at live `now`.
- Registry commits RCD/RDA enrollment, the per-delegation RCR transition, route-authorization
  predecessor CAS, selection predecessor/LKG, publication outbox and capacity-barrier reference in
  one durable transaction for the affected transition. It reads acceptance/publish time inside
  that transaction. A later step cannot publish node-visible bytes before this commit.
- A prepared genesis `acceptedAt` is positive, nonterminal and no later than `authorNow`, but it
  need not remain within clock skew of a later retry. It must be historically contained by every
  signed anchor/RCD acceptance window. Every authoring retry requires strict
  `authorNow < min(RCD.expiresAt, intended OCR.expiresAt)`; equality is stale and skew never
  extends this action lifetime. Registry's authenticated prepare/CAS is the time authority;
  Protocol attests only the resulting cryptographic tuple.
- Exact canonical command/artifact replay returns the exact committed result. Same generation or
  sequence with different canonical bytes is a fork. Unknown predecessor, rollback, gap, terminal
  predecessor, partial write and ambiguous durability fail closed and reconcile from the durable
  transaction/journal before any retry.

## Owner-control wire and streaming

OCR1 is exactly 272 bytes: magic/version/reserved `[0..8)`, network `[8..24)`, owner `[24..56)`,
route domain `[56..88)`, anchor PMA hash `[88..120)`, responder key `[120..152)`, issued/expires/key
generation at `[152..176)`, previous OCR hash `[176..208)`, and issuer signature `[208..272)`.
The signature domain covers bytes `[4..208)`. Genesis requires generation 1/zero predecessor.

PMCQ1 is exactly 344 bytes: tags `[0..8)`, issued/expires `[8..24)`, request ID `[24..56)`, network
`[56..72)`, owner `[72..104)`, route/selection/predecessor-ROL/current-RHC hashes through byte 232,
batch and authorization sequences `[232..248)`, predecessor authorization hash `[248..280)`, and
owner signature `[280..344)`. Both signing and request-hash domains append SHA-256(exact verified
OCR1) as context; that hash is never serialized in PMCQ1.

PMCR1 is exactly 384 bytes: tags `[0..8)`, issued/expires `[8..24)`, request hash/ID `[24..88)`,
network/route/predecessor ROL/current and next RHC `[88..232)`, sequences `[232..248)`, payload
hash/length/reserved `[248..288)`, exact OCR responder key `[288..320)`, signature `[320..384)`.
Responder identity is rejected before payload allocation. Message lifetime is at most 300 seconds,
future issuance uses configured skew at most 300 seconds, and expiry/action/replay always requires
`now < expiresAt` without skew extension.
PMCQ1 issuance must be at or after the protected OCR1 issuance, and PMCR1 issuance must be at or
after both its exact PMCQ1 and OCR1 issuance; equality is valid. The PMCQ1 authorization tag must
equal the sealed current ROL/cursor authorization kind. History authoring repeats that equality
against the batch plan's exact current durable route state before the responder callback.

The public streaming composition is authentication-first: verify the exact fixed PMCR1 header
against the sealed OCR1, PMCQ1 and time window to obtain a sealed read context; only that context
can authorize the bounded payload reader. The reader hashes incrementally, compares the signed
payload hash, then performs nested decoding and exact History/Final semantic binding. A bad
signature/key reads and rents no payload. PMCR network/route/predecessor/current tuple is exact
PMCQ state; NoChange and Final retain the current RHC tuple, while History advances exactly one
sequence to the domain-separated hash of its carried RHC1. PMFA mode/kind must equal PMCR tags.

PMFA1 has a fixed 48-byte header: magic/version/mode/kind/reserved `[0..8)` followed by ten big-endian
u32 lengths for PMA, PMR, PMT, current PMS, next PMS, PSS2, PRC, RTC, RCH, tagged authorization.
The exact total is `48 + checked(sum10) <= 8,388,656`; Owner requires RCH=0/PRA2=448 and Delegated
requires RCH=320/RCA1=496. All lengths and nested PMR/PMT/PMS/PSS framing are preflighted before
rent/copy/crypto/callback. Each bounded artifact is read once into its final owned buffer. A History
payload reads only the first 64 RHB bytes, derives its exact count/table/payload length, requires
`derived + 464 == payloadLen`, then rents the full bounded frame. Transported RHC remains inert
until local sequential `VerifyNextBatchForCommit` recomputes the exact matching batch, durable route
state, protected context and plan hash.

The responder-side History authoring surface is only
`AuthorHistoryResponseHeaderAsync(verified PMCQ1, historical anchor, sealed batch commit plan,
issuedAt, expiresAt, typed responder signer)`. It returns a sealed, crypto-only response plan with
the exact PMCR1 header, payload length/hash, response hash, and separate exact RHB1 and RHC1
descriptors. It never constructs or exposes a combined `RHB1 || RHC1` buffer. Payload SHA-256 and
the response-domain hash are computed incrementally over the internally owned canonical RHB1 and
then the saved next RHC1. Before the responder callback, the authorer rebinds the PMCQ1 hash and
owner signature to the exact OCR1 in the supplied historical anchor and matches the anchor,
enrollment, predecessor ROL/RHC/batch/auth tuple and plan. It repeats owned validation after the
callback and self-verifies the exact PMCR1 with production Sodium. The response plan is not a
durability, replay, publication, or delivery receipt; Registry persists and rereads its exact header,
separate payload parts and response hash under the durable request-ID CAS.
Before delivery, `VerifyHistoryResponseSegments(verified header, sealed batch commit plan,
expected response hash)` incrementally repeats the exact RHB1-then-RHC1 payload binding and full
response-domain hash. The sealed result confirms equality only and cannot be converted to durable,
authorization, publication, or delivery authority.

ROL1, RTC1 and RHC1 fields always use their protocol domain hashes
(`ComputeRouteOriginLkgHash`, `ComputeTransitionContextHash`, and
`ComputeRouteHistoryCheckpointHash`); raw SHA-256 is used only where the underlying wire contract
explicitly defines it, including canonical RCH1.
