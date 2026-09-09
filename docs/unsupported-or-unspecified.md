# Unsupported Or Unspecified - DNP1 Wave 1

Updated: 2026-09-07.

## Clean-break state

There is no Session compatibility or database migration path. Session,
protobuf, P03A, DPB/DPE, Nearby and LoRa code is offline reference evidence,
not a dormant production feature.

DNP1-native message confidentiality and ratchet remain absent from production
code. Their clean-break target is now specified by the superproject crypto and
contact/group specifications; specification does not constitute runtime
activation. Current Shared/MAUI messaging uses a separate static-key E2EE
envelope over authenticated MAU2 and Deep privacy routing and is disposable
evidence, not a public-release protocol. Managed ingress is transport-only and
does not interpret or authorize those inner bytes.

The exact ONION-01 XRF1/XRL1/XRE1/XPR1/XRS1 codec and deterministic test seam are
implemented, but production use is unsupported while `runtimeActivation=false`.
No caller may treat the internal builder/open helpers or process-local replay window
as a public codec. Missing/inactive production pieces are the sealed verified
XNA1/XVP1/XNV1/XND1 plus DTT1-backed XTT capability producers, exact-three receive-
position proof, mandatory durable replay transaction/key lease, opaque key-vault
binding, explicit exit/client reply contexts, closed operation payload verifier set,
protected monotonic expiry and durable CSPRNG nonce/key uniqueness authority. These
are specified by `deep-extension-privacy-routing-v1.md` section 7 and must be
implemented without raw-key, wall-clock, trust-callback, arbitrary-route or replay-
optional shortcuts.

The frozen internal payload verifier now rejects non-MAU2 mailbox requests,
cross-operation/cross-network MAU2, arbitrary mailbox success bodies, and invalid
ContactResolve request/result pairs. This does not activate ONION-01: Contact and
mailbox consumers still have no public synchronous/raw integration surface, and no
direct HTTP fallback is part of the protocol contract.

Pre-cutover PMA1/PMT1/PMS1 and PRA/PSS/RCD/RCA route-continuity bytes are also
not the clean-break target. DR-0004 selects PMA2/PMT2/PMS2 and
XRA1/XRC1/XRR1/XSS1. Their frozen CONTACT-CODEC grammar is present but runtime
activation is absent: production has no ADL1/ADH1 or XNV1/XNH1 authority
capability producer, and therefore cannot promote parsed bytes into contact or
route state.

Direct P2P mesh is a future architecture requirement, not part of the current
DNP1 production surface. No peer/relay handshake, authenticated neighbor
discovery, multi-hop routing, store-and-forward, TTL/loop suppression or mesh
abuse-control grammar is specified here. Nearby and Session reference code do
not satisfy that requirement. A later ADR must preserve E2EE origin/destination
authentication across both one-hop and relayed paths without depending on the
official mailbox/control plane. Its required transport-neutral boundary and
deployment guarantees are now specified in the superproject
`docs/architecture/` documents, while its wire protocol and runtime remain
deliberately absent.

## DNP1 classical baseline

The classical identity, revocation, reset, external-witness, MRL2/DNRC/DPC,
recovery-candidate and native-peer grammar is implemented as relative
cryptographic verification. This does not authorize production publication,
consumer activation or a destructive reset. Consumers still own immutable
ReleaseRoot pins, HSM/provider trust, protected HMAC keys, exact old/new CAS,
durability, external witness operation and final kill-switch/lease/key-health
rechecks.

Message confidentiality, a ratchet and a production post-quantum provider are
absent and blocked. Unknown/PQ suites are not accepted by Wave 1 grammar.

## Identity boundaries

The old `Deep.Protocol.Native` identity package is removed. `DeepRecoveryV1`
is production code under `Deep.Protocol.Identity`, but consumer activation,
secure-storage integration and destructive account reset remain later packages.
The frozen future `account-pq-signing-seed` role has no production capability:
V1 account authentication is Ed25519-only. Recovery-derived device keys,
Ed25519/X25519 conversion, non-24-word phrases and generation zero are unsupported
and fail closed.

## Host responsibilities

Key custody, protected persistence, external witness deployment, destructive
reset orchestration, consumer-owned authoritative reads and connectors,
consumer repinning and release governance remain outside this library. The
provided address policy and isolated DPC transport verify their supplied
sealed current facts, resolver results and TLS/SPKI observations; they do not
operate DNS, sockets, HSMs or deployment policy themselves.
