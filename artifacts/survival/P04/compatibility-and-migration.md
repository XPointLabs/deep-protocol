# P04 compatibility and migration

P04 is a Deep extension and does not change Session protobuf schemas, namespaces or existing
Session wire semantics. The contract introduces canonical `MNG1`, `MDG1`, `MRV1`, `MBS1`, `MMC1`,
`MFW1`, `MIP1`, `MSM1` and `MSB1` records.

P06 registry and P07 client consumers must not reinterpret the current XNode bootstrap/registry
DTOs as signed P04 documents. Migration requires:

1. pin/import a reviewed genesis and initialize its SHA-256 authority LKG;
2. accept a root-quorum online delegation as the next authority record;
3. persist authority and bridge/membership LKG updates atomically;
4. reject unsigned legacy bootstrap data for trust decisions while allowing an explicitly labelled
   compatibility discovery path during migration;
5. keep node membership commitments/proofs away from ordinary bridge clients;
6. retain fork evidence and stop automatic advancement until an authorized recovery decision.

No current registry or client runtime was modified. Package `0.3.0-p04.388e482` is a local consumer
fixture only and must not be activated with the deterministic test verifier.
