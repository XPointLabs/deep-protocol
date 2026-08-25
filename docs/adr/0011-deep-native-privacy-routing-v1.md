# ADR 0011: Deep-native three-hop privacy routing V1

Status: accepted local protocol contract; activation gated. Date: 2026-08-25. Human owner: Mr. X.

Normative local contract: `Deep.Protocol/Deep-extension-privacy-routing-v1`.

## Decision

Preserve the native mailbox and survival semantics as the inner protocol and add privacy routing
as an outer Deep extension. A request uses exactly three distinct routers: ingress relay, core
relay and mailbox exit. The exit continues to use the existing two-replica mailbox placement and
quorum path; replication is not an onion hop.

The public boundary remains `POST /api/ingress/v1/frame` from the managed-ingress contract. Its
body is one binary `DRF1`; no JSON/base64, Session RPC, storage compatibility endpoint or direct
release fallback is added. Relay plaintext resolves only the next router id through authenticated
membership. Endpoint text is never carried in an onion layer.

The inner MAU2/MQR3/MRP1/MAR1 bytes are not modified. Stable application operation identity is a
domain-separated SHA-256 of the exact canonical request. Every sealed outer attempt has fresh
CSPRNG attempt and per-hop replay ids, fresh ephemeral layer keys/nonces and a separate disposable
client reply key. Router X25519 keys are independently provisioned; Ed25519 conversion is
forbidden.

An exit wraps exact mailbox success or a bounded stable failure in `DPR1`, then seals it in the
client-bound `DRS1` response. HTTP/2 success alone remains transit-only and cannot advance the
durable outbox.

## Consequences

- Existing mailbox credentials, durable outbox, placement and replication remain authoritative.
- A relay cannot inspect operation, mailbox request, reply key or terminal result.
- A mailbox exit does not receive the client's network connection directly.
- Each runtime needs independent X25519 key lifecycle, authenticated router-id resolution,
  bounded replay state, rate limiting and outcome-unknown preservation.
- Direct mailbox HTTPS is not a release fallback after clean-break activation.
- Timing and padded-size correlation remain; independent review and evidence are required before
  any production anonymity claim.

Frozen DNP1 registries and bytes are unchanged. A future reviewed membership capability may
advertise activation, but this ADR does not reinterpret or widen an existing capability bit.
