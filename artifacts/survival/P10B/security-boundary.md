# P10B security boundary

- The public API sees only a sealed opaque frame and public transport metadata.
- HTTP/TLS success is not mailbox authority.
- `200` maps only to `TransitCompleted`; `202`, `204` and redirects are invalid.
- Accepted/durable/delivered application states do not exist in the P10B public API.
- A fixed `DIE1` error has no text, ID, digest, capability or receipt evidence.
- Before-forward and unknown-after-forward outcomes are distinct.
- Queries, compression, cookies, authorization, idempotency and tracing headers are rejected.
- TLS early data is rejected.
- Unknown critical capability features fail closed.
- The frame codec does not call DPB1, MCP1, MRR1, MQR1 or MBE1 codecs.

Remaining blockers: no server, bridge-fetch client, proxy/TLS configuration, production inner
producer/verifier, P05A evidence, network E2E or external security review.
