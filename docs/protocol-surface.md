# Protocol Surface - DNP1 Wave 1

Updated: 2026-09-07.

The production package closure is exactly `Deep.Protocol`,
`Deep.Protocol.MembershipRoutes`, and `Deep.Protocol.ProfileCarrier`.

## Production surface

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

`Deep.Protocol.ContactV1` contains the frozen, inactive CONTACT-CODEC parser
and structural closure grammar. Ed25519 promotion is protocol-owned: no public
signature callback or accept-all verifier can mint a bundle or route result.
`VerifiedContactBundleClosure` additionally requires an unforgeable witnessed
ADL1/ADH1 freshness capability, and route promotion requires a distinct
`VerifiedContactRouteClosure` rooted in exact XNV1/XNH1/ADH1 witness authority
and one trusted instant. These capability producers are deliberately not wired
into the production composition, so `ContactCodec.RuntimeActivation` remains
false and parsing does not authorize state mutation or emission.

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
- ContactHello endpoint verification now derives the safety number from two
  verifier-minted non-forked DAB1 lineages and checks exact DAB1/DMD1 identity
  fields plus XUR1 author, DPD1 signature and creation-time validity. The
  contact `DAB1` reference uses CONTACT-CODEC magic/version/hash bytes, not
  ApplicationCore's distinct artifact-reference encoding. This pure verifier
  does not close XUR1 to PMT2, persist a relationship or authorize ACK;
  MAUI inbound composition remains incomplete. Public API snapshot additions
  require downstream consumer rebuild/repin before activation.
  Production DPH2/XPC1 promotion retains its verified current initiator
  checkpoint and recipient bundle for the subsequent Shared responder
  ContactHello endpoint check; the test-only claim path does not mint these
  current-value capabilities.
- [`DR-0005`](../../docs/survival-program/decisions/DR-0005-inbound-dph2-claim-evidence.md)
  requires a pre-activation DPH2 initial-payload clean break because the
  existing event-only body gives the responder no exact XPK1/XPC1 proof. The
  new internal claim-prefix codec checks framing and DPH2 correlation only;
  the production sender retains exact XPK1/XPC1 wire for encrypted authoring
  and the production payload reader structurally requires the prefix. An
  internal pre-claim DPH2 header cannot authorize commit/ACK and promotes only
  with a verifier-minted exact XPC1 capability. The preview primitive derives
  only the initial AEAD key from an exact local DPK2 secret copy, then strictly
  opens the encrypted claim transcript. The responder factory now accepts a
  verified, non-forked initiator DMD1 lineage, and its unverified preview can
  promote only with the independently verified exact XPC1 wire. Shared has a
  read-only SQLCipher preview selection. The preview now calls the production
  XPC1 two-replica verifier with a verified placement, recipient bundle,
  network authority and trusted time before promoting DPH2, and requires a
  matching current initiator DMD1 checkpoint at the live monotonic sample.
  The account owner exposes this path before session-store creation; mailbox
  receive composition and new vectors are not yet wired
  end-to-end. Structural parsing alone cannot
  mint `VerifiedDph2Initiation` or authorize a production receive.
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

The package candidate is not a clean-break production activation until the
reviewed exact-three closure is atomically repinned by each authorized
consumer and its protected state is reset under the separate cutover plan.
