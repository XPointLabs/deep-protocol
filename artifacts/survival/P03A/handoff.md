# P03A local package handoff

Local package version: `0.3.0-p03a.a3f7036`.

Verify all three package hashes against `package-manifest.json`. The packages were not published.
Every nuspec pins source commit `a3f70363cf8aa2eef4f5a8d80be50bc638911201`.

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

