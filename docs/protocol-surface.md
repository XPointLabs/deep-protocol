# Protocol Surface - DNP1 Wave 1

Updated: 2026-10-03.

The production package closure is exactly `Deep.Protocol`,
`Deep.Protocol.MembershipRoutes`, and `Deep.Protocol.ProfileCarrier`.

## Production surface

### Retired identity source removal

[DR-0069](../../docs/survival-program/decisions/DR-0069-did2-retired-identity-surface-removal.md)
removes the old identity author/parser/verifier and their dependent directory,
contact and group capability producers. Only DID2 freshness enters the
forward-checkpoint and ONION context factories. Existing preclaim/coordination
bytes use allocated generated IPK2/XCA2/XCS2 identifiers without activation.
The neutral contact vector manifest no longer carries old identity-bound
positive fixtures; retained neutral bytes and malformed checks are unchanged.
Consumer source rebuilds, exact API/resource snapshots and package repins are
still required. Published packages and active images are not this source cutover.

[DR-0070](../../docs/survival-program/decisions/DR-0070-did2-operational-genesis-proof-order.md)
replaces the V1 operational genesis helper with a signed, non-authoritative
network candidate and a separate completion requiring genuine DID2 proof plus
an independent current monotonic clock. Directory issuance remains with the
directory owner. This source/API candidate changes no wire and grants no
production activation or permission to reset genesis, floors or node keys.

### DID2 reachability successor candidate

[DR-0071](../../docs/survival-program/decisions/DR-0071-did2-reachability-advertisement-successor.md)
adds `DeepIdV2ContactRouteAuthor.AuthorAdvertisementSuccessorAsync` for the
artifact-specific owned-device candidate. The exact signed predecessor is
authenticated against current DID2/device/PMT authority; past expiry is allowed
only as lineage input, never as a current route or dispatch capability. The
author derives issue time from the protected interval and verifies the signed
successor again at release. Existing proposal/threshold/route expiry checks and
genesis-only threshold rejection are unchanged. The full protected renewal,
private predecessor-bound coordination, publication and retained-account device
flow remain gated; there is no wire or schema reset in this API increment.

[DR-0072](../../docs/survival-program/decisions/DR-0072-did2-route-renewal-lineage.md)
adds the closed historical `VerifiedDeepIdV2ContactRoutePredecessor` and
`VerifyPredecessorAsync`, `AuthorThresholdSuccessorAsync`, `CompleteSuccessorAsync`.
These authenticate exact predecessor scope/graph/signatures independently of
current artifact expiry, derive new issuance from protected time and bind the
successor back to that exact history. The normal route verifier accepts only
current artifacts; genesis authoring still rejects successor input. XSS successor
graph handling follows its actual prior XRC reference. Current-only six-record
parsing is not a persisted route floor. Private durable per-generation issuance,
protected pending/publication lineage and device recovery remain unimplemented
activation gates. Existing bytes/domains and the reviewed D--G graph are unchanged.

### Closed retained threshold issuance candidate

[DR-0074](../../docs/survival-program/decisions/DR-0074-did2-retained-threshold-issuance-evidence.md)
adds `VerifiedDeepIdV2ContactRouteIssuance`, `VerifyRetainedThresholdAsync`,
`CompleteRetainedGenesisAsync`, `CompleteRetainedSuccessorAsync` and the object
author's `AuthorRetainedGenesisAsync`. The actual signed ADH authenticates
issuance metadata only; every current DID2/network/time/signature check remains.
The closed value is neither current route nor signing/dispatch authority.
Default current-head APIs remain strict. Publication publisher minima follow
the signed bundle, independently of current XPA witness head verification.
Exact server response and protected signed-head custody are not yet connected;
these candidates alone do not recover an owned lost response or activate devices.

### Opaque DID2 mailbox issuance candidate

Superproject DR-0054 defines `ContactV2.DeepIdV2MailboxGrantIssuanceVerifier`,
the closed `VerifiedDeepIdV2MailboxGrantIssuance`, bounded untrusted
`DeepIdV2MailboxGrantReplicaEvidence` and narrow `IMailboxGrantIssuerSigner`.
The result verifies current root/NET/PMA and both independently selected stores'
exact durable-route signatures, authors a role-key-verified candidate and checks
exact journal read-back. It exposes no public result constructor, caller clock,
issuer key override or recipient-identity claim. Neutral wire/transcripts are
unchanged. Registry owns the private signer/journal; client holder custody and
credential use remain separate. Machine/API manifests and full release graph
are final connected-batch activation gates, not satisfied by source builds.

### Private coordination transport admission

Superproject DR-0048 defines `ContactV2.ContactCoordinationTarget`,
`ContactCoordinationPeerHeaders` and `ContactCoordinationPeerAuthentication`.
These expose bounded transcript construction, canonical header/admission-window
checks and actual Ed25519 verification. They return no trusted protocol authority
or persistence capability. Registry owns its access list; XNode owns its existing
node signer and fixed-origin transport.

DR-0049 adds `ContactCoordinationOnionCodec` and the internally constructed
`ParsedContactCoordinationOnionRequest`. Defensive parsed wrapper/body/network/
nonce/PMT/shard values grant no current placement, witness or dispatch authority.
Responses are decoded only against the exact parsed request. Gateway kind
`CoordinateContact` uses existing ContactResolve, not a sixth ONION operation.
Vectors/public API manifest and consumer package repin remain final business-batch
gates; compiled source-cutover tests do not activate published package graphs.

### DID2 permanent read candidate

Superproject DR-0041 adds `DeepIdV2PermanentContactResolveRequestAuthor` and
`DeepIdV2PermanentContactResolveVerifier`. Descriptor-bound `OpenCandidate`
returns only `ParsedDeepIdV2PermanentContactCandidate`; independent current
peer proof/NETCODEC/time verification releases the closed
`VerifiedDeepIdV2PermanentContactResolveClosure`. Neither has a public result
constructor or trust setter. The neutral node receipt transcript is unchanged;
unsigned server time is not freshness. This is not consent, a claim/grant,
account persistence or delivery. The retired identity consumer producers are
removed by DR-0069; no fallback accepts their transcript.
DR-0042 corrects retained-route issuance-anchor semantics without public API or
wire changes. Current peer/network authority, minimum checkpoint binding,
threshold signatures and time bounds remain mandatory; new issuance still
requires the current anchor. Historical commits do not grant fresh dispatch.
DR-0043 adds exact current claim recipient/placement authority pairing and
private last-observed clock continuity; no public API/trust seam is added.
DR-0044 corrects full inventory/service versus later contact lifetimes while
preserving operation-time containment and current identity/support checks.

### DID2 publication candidate

The sole public XPU/XPA consumer is V2-only under superproject DR-0039.
`ContactV2.DeepIdV2PublicationCommitVerifier` requires a current closed DID2
route, owned contact object and exact publisher request to mint closed
`VerifiedDeepIdV2PublicationCommit` from two selected-node receipt signatures
(DR-0040). No public result constructor, caller key/clock/trust boolean exists.
The result is historical evidence, not persisted account state, fresh dispatch
permission, consent, mailbox authority or physical delivery. Shared owns
protected phase-7 persistence. Private shipping transport, vectors/API manifests,
consumer repins and device checks remain activation gates.

`Deep.Protocol` contains the retained Deep mailbox, membership, authority and
managed-ingress primitives. Its only direct NuGet dependency is
`Sodium.Core`. It has no project dependency on a legacy protocol assembly.

`Deep.Protocol.Identity` contains production `DeepRecoveryV1`: exact 24-word
English BIP-39 verification/generation, the frozen PBKDF2/HKDF derivation, a
generation-one floor, permanent Deep ID address material and sealed,
role-specific Ed25519 account-authority capabilities. It exports no entropy,
role seed, PQ-signing or Ed25519/X25519-conversion surface and derives no device key.

`Deep.Protocol.MembershipRoutes` currently depends on `Deep.Protocol` and owns
the reviewed D--G route-continuity evidence. DR-0004 makes those bytes
pre-cutover/release-rejected; only their tested continuity/CAS properties are
ported to PMA2/PMT2/PMS2 and XRA1/XRC1/XRR1/XSS1. No compatibility reader is a
target production surface.

`Deep.Protocol.ProfileCarrier` retains its existing carrier surface and exact
`Deep.Protocol` package dependency.

`Deep.Protocol.ContactV1` retains identity-neutral CONTACT-CODEC grammar and
shared primitives used by current DID2 consumers. Old identity-bound bundle,
route and network capability producers are removed. Current owned bundle and
route promotion belong to `ContactV2` and require their independently verified
DID2/device/directory/network authority. `ContactCodec.RuntimeActivation`
remains false; neutral parsing does not authorize state mutation or emission.

`Deep.Protocol.DeepExtension.PrivacyRouting` contains the implemented frozen
ONION-01 XRF1/XRL1/XRE1/XPR1/XRS1 codec and deterministic conformance seam. Its
production public API remains inactive. The only authorized successor surface is
the sealed section-7 capability boundary: verified XNA1/XVP1/XNV1/XND1 plus non-wire
DTT1-backed XTT, exact-three path/receive-position capabilities, mandatory durable
replay transaction/key lease, separate exit/client reply contexts, closed
operation-specific exact MAU2/MQR3/MRP1/MAR1 and ContactV1 request/result-pairing
verifiers, and a protected CSPRNG uniqueness
authority. Internal vector helpers and process-local replay memory are not a
release API or durability claim.

## Identity-neutral network distribution candidate

`XPointNetworkClosureWireCodec` provides only bounded raw public distribution
framing and an owned untrusted artifact container. It exports no verified
network/time/account/placement/route capability. Exact envelope semantics are
owned by [`XPOINT-NETWORK-V1 section 8.1`](../../docs/architecture/XPOINT-NETWORK-V1.md#81-identity-neutral-network-closure-distribution-ncq2ncp2).
Registry and Shared must rebuild against the exact same Protocol checkpoint;
older distribution frames and account-proof packages are not fallback inputs.
There is no account/database reset or repin caused by this envelope: existing
pinned authority and protected floors remain mandatory. Public API/assembly
snapshots and global generated magic allocations are updated for this candidate;
signed NETCODEC and reviewed D--G bytes are unchanged. HTTP distribution does
not activate message delivery, masked acquisition or a release claim.

## Explicit exclusions

- `Deep.Protocol.Native*` and its dark solution no longer exist. Production and
  lock/package gates reject any reintroduced project edge, source token or build artifact.
- Retired Session, protobuf, P03A compatibility, DPB/DPE, Nearby and LoRa
  source/vector corpus has been removed from the release checkout. It is
  available only in Git history, not compiled, embedded, packed or loaded.
- Shared/MAUI legacy Session messaging is not made DNP1-native by renaming old
  bytes and is excluded from the clean production composition. Exact DPH2/DPE2
  message/ratchet primitives now exist in the production package and a protected
  Shared store, but application inbox handoff, ACK authority and device E2E are
  incomplete; their presence is not a release claim. The narrow trusted
  durable-authority DMC2 handoff is separately frozen in the superproject's
  `DPE2-INBOUND-DURABLE-HANDOFF-AUTHORIZATION.md`.
- The remaining DAB1-based ContactHello/safety-number implementation is a
  pre-cutover consumer, not authority for a DID2 relationship or ACK. Its
  replacement must use the exact DID2/DAB2 endpoint closure required by
  [DR-0008](../../docs/survival-program/decisions/DR-0008-did2-dph2-wire-clean-break.md).
  MAUI inbound composition and the endpoint cutover remain incomplete.
- [DR-0017](../../docs/survival-program/decisions/DR-0017-did2-initial-claim-promotion.md)
  implements the single V2 encrypted claim prefix/current responder promotion;
  [DR-0018](../../docs/survival-program/decisions/DR-0018-did2-initiator-completion.md)
  implements the V2-only sender completion and exact recovery fixtures. The
  event-only body and V1 completion overload are removed, not fallback paths.
  Structural parsing alone cannot mint `VerifiedDph2Initiation` or authorize
  a production receive. Durable shipping mailbox/inbox/ACK composition and
  physical delivery remain incomplete.
- `DeepIdV2Dpk2PreClaimVerifier` authenticates one exact V2 offering against
  current DID2 directory custody. It advances both trusted-time bounds from
  the proof's monotonic sample to the operation sample before checking the
  offering. Expiry, a different boot, backward sample or overflow rejects;
  a still-current directory proof does not extend a pre-key's validity.
  This grants neither inventory publication nor an XPC1 receipt/session.
  The correction changes no wire or public API; consumers must rebuild before
  using the corrected operation-time check.
- `DeepIdV2PreKeyClaimReceiptVerifier.VerifyAsync` implements the bounded
  current-recipient API frozen by
  [DR-0016](../../docs/survival-program/decisions/DR-0016-did2-prekey-claim-receipt.md).
  It accepts no V1 claim input and mints no session or ACK. Both selected
  signatures, exact current DID2 service binding and the conservative union
  of protected network/recipient time intervals are mandatory; they are
  rechecked after the final protected-clock read. Exact replay retains the
  complete request and padded result, not merely the signed claim tuple.
  Shared/XNode/Registry/MAUI must rebuild against the reviewed API snapshots;
  this addition changes no remote wire or protected database generation and
  requires no authority repin/reset. Authenticated durable replica completion,
  protected initiator preparation and shipping consumers remain required
  before activation or device delivery can be claimed.
- [DR-0061](../../docs/survival-program/decisions/DR-0061-did2-committed-claim-recipient-verification.md)
  adds the same-input closed `VerifyCommittedForRecipientAsync` factory and
  uses it for initial recipient promotion. Request mutation expiry no longer
  expires a signed completed allocation; current endpoint, placement and
  inventory validity still apply. Its verifier-selected purpose is retained
  through final checks and cannot authorize initiator encryption. The existing
  initiator factory still checks request expiry. No wire/key/SQL change;
  actual public API snapshot and downstream rebuild closure remain batch gates.
- [DR-0019](../../docs/survival-program/decisions/DR-0019-did2-preclaim-secret-persistence.md)
  adds exactly three opaque local pre-XPK1 persistence types. Seal consumes
  the started claim; restore authenticates the database/intent scope and
  rechecks the exact current identity at both protected-clock samples. No
  scalar export, provider callback, device-agreement lease replay or remote
  wire change is added. Debug/Release actual API snapshots are reviewed;
  downstream consumers must rebuild. Durable Shared intent custody and the
  later atomic device-DH burn/prepared-secret boundary remain unimplemented.
- The frozen XRF1/XRL1/XRE1/XPR1/XRS1 codec is implemented, but its sealed
  production capability producers, asynchronous public API and runtime composition
  are absent/inactive. PMA2/PMT2/PMS2 route-authority activation remains a separate
  producer gate; codec presence cannot substitute for it.
- DID2 XPS1 is a separate 352-byte version-2/suite-0x0301 descriptor with
  V2 signature input, generation-1 genesis and version-2 ArtifactRef. The
  local DPD1 signer can author it; DCB1/XPI1/XPP1 DID2 consumers reject the
  retired V1 descriptor and signature domain. Local authoring does not persist
  or publish the descriptor for MAUI yet.
- The DID2 XPP1 version-2/suite-0x0301 surface now has two mutually rejecting
  closed shapes: the five-tag exact aggregate and a twelve-tag bounded
  manifest/chunk/commit transport carrier. The carrier verifies exact slice
  lengths, V2 domain-separated hashes, DID2/DCA1/XPS1 public-support
  commitments and the 65,861-byte request ceiling. A separate verifier checks
  complete XPI1/DPK2 against nonce-fresh current DID2 and signed XPS1 without
  requiring plaintext DCR1 at the selected replica. A separate XPI1 lineage
  verifier requires an exact, durably accepted predecessor for every successor
  epoch and rejects a changed service identity; it does not own that durable
  predecessor or activate the service. The XIC1 pair verifier checks both
  selected NETCODEC node signatures, exact XPP1/placement binding and receipt
  times. The ONION ContactResolve terminal now admits only the bounded V2
  fragment, binds staging acknowledgements to non-Commit phases and a V2 XIC1
  to the exact Commit network/operation/placement; it rejects the retired V1
  bounded XPP1 wire. This terminal check is structural, not a replica-signature
  or two-replica authority check. The Protocol surface does not reconstruct
  durable XNode state, verify the
  inventory's current DID2 authority at a final runtime commit, or authorizes
  a pre-key claim; those consumers must use the verifiers at exact commit
  before activation.
- `Dpk2AuthoringAuthority.AuthorInventoryV2` locally authors a complete
  ordered V2 DPK2 inventory, device-signed XPI1 and exact aggregate XPP1 only
  when a verified DID2 DAB2 belongs to the active DMD1 account. It retains
  each opaque private pre-key capability until the Shared account owner takes
  and durably seals it. This local output is neither a two-replica XIC1 commit
  nor permission to dispatch XPP1 before the durable secret transaction.

## DNP1 classical Wave 1

The DID2 offline `AccountDirectoryAdf1OfflineAuthor.AuthorSuccessorAsync`
extends an independently pinned, root-authenticated ADF1 instead of replacing
generation zero. It requires the complete threshold-signed head export from
genesis to the new target, checks the predecessor's original coverage and
target, and covers every newly intervening head before calling root custody.
The method currently supports an unchanged XNA root authority. ADF1/AFP1 wire,
signature domains and the full DID2 forward-tail reader are unchanged; existing
client/node floors are not reset. DevOps owns the offline ceremony and retains
both exact checkpoint files. This authoring API is not online root custody,
publication evidence or permission to bypass the reader's complete chain.

The DNP1 classical identity/reset/MRL2 design is frozen in docs repository
commit `2651599913bf92c021d36b6a53395499b6a091fb` (36 records,
158 domains and 314 executable vector IDs). `Deep.Protocol` implements the
classical grammar, closed artifact registry, relative identity/revocation and
ReleaseRoot chains, protected cutover state, recovery-candidate parsing,
MRL2/RIP2 membership, native peer frames and the protected outer-peer journal.

The DRM20 first-deployment author path is constructible through sealed facts:
governance and reset reservation, dual-signed DCM distribution, genesis base
identity and release head, transaction/key/protector contexts, DTC2/RSM2/DRC,
durable GAS/GQP/GAJ state, exactly three selected witness DCN receipts,
canonical DCQ/GQS, dedicated-key DPL materialization, and external then local
commit. Witness callbacks receive only Protocol-created bounded requests;
immediately before them Protocol performs one consumer-owned bounded current
DWD/RRL/WHL read, HMAC-verifies and byte-compares it to the sealed release
context, and aborts before all selected witnesses if that head moved;
their returned DCN bytes are re-decoded, signature/tree/window verified and
aggregated by Protocol before any GQS or commit transition.

The forward commit API has no short, unchecked publication overload. It
replays and byte-compares the sealed reset and transaction reservations,
artifact set, quorum Pending and author journal, and revalidates the protected
key-set and recovery-protector sources before and after consumer CAS calls and
journal transitions. It also rereads and authenticates the exact DWD/RRL/WHL
head immediately before and after the external zero-to-one CAS. Movement
before the external CAS publishes nothing;
movement after an external or local CAS returns no continuation capability and
is recoverable only through the authenticated replay phase matrix.

Every public verification result is sealed, defensively owned and explicitly
relative or data-only. Caller keys, raw pins and callback booleans cannot mint
deployment authority. Recovery output has `NoAuthorityClaim`; ReleaseRoot
genesis remains pinned by each consumer's immutable deployment source.
Protocol never claims persistence, durability, publication, activation or a
successful consumer CAS.

DR-0052 freezes complete mailbox-authority distribution and direct DID2 grant
result verification; see
[the decision](../../docs/survival-program/decisions/DR-0052-did2-mailbox-authority-distribution.md).
The returned immutable evidence has no public constructor, installation,
holder-secret or dispatch surface. Actual package API/evidence bindings and
consumer repins remain the whole-business batch gate; local checks do not
activate production or prove physical delivery.

[DR-0053](../../docs/survival-program/decisions/DR-0053-did2-mailbox-grant-restart-custody.md)
adds direct DID2 exact pending-request restoration and independent retained
winner verification. The former requires the original request to remain current;
the latter checks the current issuer/topology/grant rather than treating an old
acquisition TTL as grant lifetime. Neither restores protected holder custody or
exposes a signer/dispatch capability. Consumer/API repins remain a batch gate.

[DR-0062](../../docs/survival-program/decisions/DR-0062-did2-private-contact-mailbox-route.md)
adds bounded private DID2 mailbox-route framing and independent current-peer
route verification. The immutable parsed package is not authentication; its
closed verifier result is not publication, consent, a grant or dispatch/ACK
authority. It contains no resolver-read/retrieve/private-key material. Event
embedding follows the separately frozen
[DR-0063](../../docs/survival-program/decisions/DR-0063-did2-contact-reply-route-embedding.md):
both endpoint-bound authors now require a private parsed package and the
retired fixed control payload has no reader. Author/endpoint metadata checks
do not authenticate route signatures; Shared independently verifies the full
current route before handoff or use. Variable protected acceptance custody,
connected reverse delivery, actual API review/repins and shipping/device
consumers remain the activation gates.

DR-0013 freezes the additive read-only
`AccountDirectoryProofAuthor.RequireIssuanceReady` issuance-context verifier.
It returns no capability, signs nothing and performs no nonce/state mutation.
Its normative semantics and downstream repin/no-reset impact are in
[the decision](../../docs/survival-program/decisions/DR-0013-readonly-directory-issuance-readiness.md).
The positive actual public-API snapshots include this method; predecessor
snapshots are replaced, not accepted as an alternate production surface.

The package candidate is not a clean-break production activation until the
reviewed exact-three closure is atomically repinned by each authorized
consumer and its protected state is reset under the separate cutover plan.
