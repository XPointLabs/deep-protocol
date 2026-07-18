# P03 compatibility evidence

- Base: `deep-protocol@8484b130a274ca7d8de574e563c83198180d7808`.
- Original implementation source: `c854dbe709c345b33e10b8232adcc48dac8ae474`.
- Corrective red contract: `2e26bf6fe601ff88073823fed3937c599495a936`.
- First corrective implementation: `372c5f15d6198c7af83ac9bddc9daf95dfe9cef2`.
- Overflow-guard red contract: `b81d96348f9f1ece2d24f278ef1235440c72cfea`.
- Final corrective implementation source: `814f15d8965da8728132ba35a61cf47457b2b00b`.
- Program revision: `096b776b0946b8ce8d661312eeb231432e2c80e6`.
- Dependency manifest SHA-256:
  `6527338b3e5b888a22fb2cc55323259306e9f41bff69e9554706701a86dc7824`.
- Session `.proto` files, generated bindings, namespaces, envelope codecs and existing vectors:
  unchanged.
- Full corrective Release lane: 79/79 pass, zero skipped.
- Focused corrective opaque-bundle lane: 32/32 pass, zero skipped.
- Old readers see a distinct `DPB1` Deep-extension magic and do not parse it through Session codecs.
- V1 activation requires explicit negotiation; there is no production default or runtime wiring.
- Exact legacy DPE1 bytes may be carried only inside an explicitly enabled migration profile and
  are returned unchanged.
- Caller-supplied negotiation/policy masks cannot expand the implementation-owned set of known
  critical features; native-only callers may narrow it safely.

P01 privacy findings are not marked resolved. P03 supplies a container contract, not the reviewed
cryptographic capability producer/verifier required to resolve those findings.
