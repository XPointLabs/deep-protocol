# Unsupported Or Unspecified - DNP1 Wave 1

Updated: 2026-08-30.

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

Pre-cutover PMA1/PMT1/PMS1 and PRA/PSS/RCD/RCA route-continuity bytes are also
not the clean-break target. DR-0004 selects PMA2/PMT2/PMS2 and
XRA1/XRC1/XRR1/XSS1; their machine codecs/vectors and runtime are absent.

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

## Dark package path

`Deep.Protocol.Native` remains a consumer-unreferenced, unpackaged source/test
dark path. It is not the implementation of the production DNP1 classical
surface and creates no production PQ, ratchet or messaging claim.

## Host responsibilities

Key custody, protected persistence, external witness deployment, destructive
reset orchestration, consumer-owned authoritative reads and connectors,
consumer repinning and release governance remain outside this library. The
provided address policy and isolated DPC transport verify their supplied
sealed current facts, resolver results and TLS/SPKI observations; they do not
operate DNS, sockets, HSMs or deployment policy themselves.
