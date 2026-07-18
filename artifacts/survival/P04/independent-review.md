# P04 independent review and correction map

Initial read-only review of source `ab40f70621a89ac8dbc2b15428a9ac71530975e9`
returned **NO-GO**: P0=0, P1=6, P2=4, P3=1.

| Finding | Correction at `388e482` |
| --- | --- |
| Authority delegation/revocation had no LKG chain | exact next-sequence/previous-hash verification, returned authority LKG and fork evidence |
| Online keys were out-of-band and not rotatable | delegation now carries canonical online public-key descriptors; verifier receives canonical key |
| Beta policy accepted arbitrary/one-signer thresholds | policy V1 is exactly 3-of-5 offline and 2-of-3 online |
| Canonical decoders/vectors incomplete | delegation, revocation, proof and signed-container decoders plus seven statement vectors |
| Consensus digest was provider-selected | canonical hash fixed to SHA-256 in contract code |
| update/reward/billing domains lacked normative framing | fixed 16-byte tags and foreign-cryptographic-domain negative tests |
| duplicate bridge IDs and aliased descriptor keys | distinct ID/public-key validation |
| fork evidence membership-only | delegation, revocation and bridge evidence builders |
| malformed tests/docs incomplete | nine-decoder structured smoke plus public P04 docs |
| unused evidence parameter | removed by rewritten verifier flow |

The corrected source and following evidence commit require a fresh independent read-only review.
