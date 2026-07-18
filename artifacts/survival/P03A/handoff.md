# P03A local package handoff

Local package version: `0.3.0-p03a.241fca1`.

Verify all three package hashes against `package-manifest.json`. The packages were not published.
Every nuspec pins source commit `241fca1ed9999183a488a8798fdbc822eb091484`.
The older `0.3.0-p03a.a3f7036` package files are superseded and must not be selected.

Permitted downstream use:

- compile and review `ICompatibilityEnvelopeCrypto`,
  `ICompatibilityEnvelopeReplayGuard` and P03A models;
- consume the wire/framing contract for P03B design;
- run deterministic contract tests.

Forbidden until blockers close:

- registering a synthetic/test adapter;
- offering `AuthenticatedCompatibilityEnvelope` in a production negotiation;
- writing P03A bundles to production storage;
- claiming sender anonymity, forward secrecy or resolution of P01.

The future production adapter must implement both codec-owned domains, recipient confidentiality,
cryptographic sender authentication revealed only after decryption, nonce/key separation and
uniform authentication failure. It also needs independent upstream/differential vectors.
