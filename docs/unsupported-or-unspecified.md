# Unsupported or unqualified Protocol behavior

Updated: 2026-10-05. This is a repository boundary guide, not a second protocol
specification, execution plan or release status ledger.

## Current target and source are separate facts

The sole version/lifecycle owner is the superproject
[Protocol registry](../../docs/architecture/PROTOCOL-REGISTRY-V1.md). Current
identity uses DID2/DAB2 with a hybrid PQ root; DID1/DAB1 and their dependent
authoring surfaces are retired by
[DR-0069](../../docs/survival-program/decisions/DR-0069-did2-retired-identity-surface-removal.md).
DNP1 account/device verification remains an independent input where its frozen
contract requires it. It is not a DID1 compatibility reader or authority to
replace the DID2 root with a classical-only credential.

Current mailbox selection and presentation belong to
[DR-0081](../../docs/survival-program/decisions/DR-0081-did2-mailbox-selection-grant-clean-break.md),
not the pre-cutover managed lane. There is no Session, protobuf, old identity,
database migration, authorization adapter or direct-HTTP fallback permitted by
this guide. A parsed artifact, a public codec or a test fixture never grants
current dispatch, holder, account or message authority.

The source tree still contains pre-cutover PMA1/PMR1 producers and their
membership/governance consumers. The actual source/package gates reject that
remaining graph; see the
[reproduced S00 failure and receipts](testing/s00-contact-baseline-2026-10-03.md#focused-recheck-2026-10-05).
Removal must follow actual compiled consumers and reviewed frozen API/evidence
ownership. Renaming diagnostics, ignoring retired tokens, deleting failing
assertions or enabling the old lane does not qualify its replacement.

## Qualification and activation fences

The sole unfinished-work status is
[NEXT-SPRINT](../../docs/NEXT-SPRINT.md); the sole execution sequence is
[IMPLEMENTATION-PLAN](../../docs/architecture/IMPLEMENTATION-PLAN-V1.md).
Protocol, Registry, node, Shared, MAUI, operator tools and installed artifacts
must qualify one matching graph. Compilation, native wrapper tests, local
signed ceremonies and Docker health are different evidence from physical
Windows/Android delivery. Missing provider/capture cases are not successful
native or release qualification.

Key custody, protected persistence, external latest-head floors, witness
operation, immutable pins, atomic old/new CAS and rechecks after external
callbacks remain responsibilities of the owning consumers. Source removal
does not authorize deleting registered node keys, retained signed lineage,
genesis, journals, volumes or independent protected floors. Recovery cannot
silently re-author an already issued binding or mint replacement custody.

Application confidentiality/ratchet semantics are owned by
[DEEP-CRYPTO](../../docs/survival-program/releases/v3.0.0/specs/DEEP-CRYPTO-V1-DRAFT.md)
and [contact/group semantics](../../docs/architecture/CONTACT-AND-GROUP-PROTOCOL-V1.md),
not the retired static-key diagnostic transport. Routing/placement and privacy
fences belong to [XPOINT-NETWORK](../../docs/architecture/XPOINT-NETWORK-V1.md).
An implemented component does not prove scheduler, receipts, remote attachments,
governed groups, sustained recovery or shipping composition.

Direct P2P/on-prem/Apple and the six-node profile are not activated by the
current [deployment profile](../../docs/architecture/DEPLOYMENT-PROFILES.md).
Their presence in future requirements is not permission to invent handshake,
discovery or mesh wire, reuse a retired protocol, or claim current support.
