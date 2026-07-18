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
- Second corrective red after rereview NO-GO: `1a41a3c709635adc00bac9f823a67650948dd22a`.
- Second corrective green: `47f2802e3b448fd3afba70d104bf6d2c0419b9f7`.
- Final verifier-edge red: `5c6a80a`.
- Accepted source with verifier-edge correction: `b887fa088f486390be182cac4cbcb59b60ce8931`.
- Accepted local package: `0.3.0-p04.b887fa0`.

The earlier `0.3.0-p04.ab40f70` and `0.3.0-p04.388e482` builds were rejected by independent review
and are not accepted consumer artifacts. Consumers must verify the three accepted package hashes against
`package-manifest.json` and confirm the embedded repository commit.

P06/P07 receive the canonical codecs, fixed SHA-256/domain framing,
`IMembershipSignatureVerifier`, authority/content LKG models and fork evidence builders. They must
supply production verification, trusted genesis pinning, durable atomic state and migration/E2E
evidence. No push, publish, deployment, runtime registration or credential access occurred.
