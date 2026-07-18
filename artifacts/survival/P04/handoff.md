# P04 handoff

Branch `survival/w01-p04-membership-contract`.

- Final P03C GO base: `a1e48dfb24ee85af7b094bd28b59a2ec8e48278d`.
- ADR/preflight: `942e40ab3310c798472f58356a7db5625eb05d44`.
- Initial red: `8707797d5d2c465c356b021364515a7aaf053e19`.
- Initial green: `1099e6d28f1c88fc1079caf16466522f1967f21e`.
- Malformed smoke: `ab40f70621a89ac8dbc2b15428a9ac71530975e9`.
- Public docs: `03a46dd`.
- Corrective red after independent NO-GO: `3edb42b40925b2383051edc008e53417a1aa3824`.
- Corrective green: `388e482823c8e5d0844c0468ad48d76958d6065e`.
- Accepted local package: `0.3.0-p04.388e482`.

The earlier `0.3.0-p04.ab40f70` build was rejected by independent review and is not an accepted
consumer artifact. Consumers must verify the three accepted package hashes against
`package-manifest.json` and confirm the embedded repository commit.

P06/P07 receive the canonical codecs, fixed SHA-256/domain framing,
`IMembershipSignatureVerifier`, authority/content LKG models and fork evidence builders. They must
supply production verification, trusted genesis pinning, durable atomic state and migration/E2E
evidence. No push, publish, deployment, runtime registration or credential access occurred.
