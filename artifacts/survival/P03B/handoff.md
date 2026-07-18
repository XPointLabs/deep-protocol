# P03B handoff

Branch: `survival/w01-p03b-mailbox-capabilities`.

- Base evidence: `0bb1d484408b0ad673f51e67673dce1ac34b6b12`.
- ADR/preflight: `e4aecd7df4dc16d14d81363f9edeaa6e6c922f03`.
- Red vectors: `902f8064bd67d871a01c9fddb839caea6cc4e986`.
- Green source: `312bda8e147dd1ee2be3d6a1c0f343171488b97a`.
- Local package version: `0.3.0-p03b.312bda8`.

Implemented: canonical mailbox capability presentation, bounded free-admission slot, replica,
durable-quorum and error receipt codecs, client quorum verification and coordinator equivocation
evidence. Golden, cross-domain, replay, malformed, truncation and deterministic fuzz-smoke tests
are green.

Not implemented: capability producer/lifecycle storage, real storage operations, billing, quota
accounting, production crypto, key distribution or registration. Do not wire these contracts into
a production service until the blockers in `security-boundary.md` are closed.

No push, publish, deployment or production activation occurred.
