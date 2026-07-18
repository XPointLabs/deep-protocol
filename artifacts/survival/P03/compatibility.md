# P03 compatibility evidence

- Base: `deep-protocol@8484b130a274ca7d8de574e563c83198180d7808`.
- Implementation source: `c854dbe709c345b33e10b8232adcc48dac8ae474`.
- Program revision: `096b776b0946b8ce8d661312eeb231432e2c80e6`.
- Dependency manifest SHA-256:
  `6527338b3e5b888a22fb2cc55323259306e9f41bff69e9554706701a86dc7824`.
- Session `.proto` files, generated bindings, namespaces, envelope codecs and existing vectors:
  unchanged.
- Existing full Release lane: 65/65 pass, zero skipped.
- New focused opaque-bundle lane: 18/18 pass.
- Old readers see a distinct `DPB1` Deep-extension magic and do not parse it through Session codecs.
- V1 activation requires explicit negotiation; there is no production default or runtime wiring.
- Exact legacy DPE1 bytes may be carried only inside an explicitly enabled migration profile and
  are returned unchanged.

P01 privacy findings are not marked resolved. P03 supplies a container contract, not the reviewed
cryptographic capability producer/verifier required to resolve those findings.
