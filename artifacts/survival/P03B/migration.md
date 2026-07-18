# P03B migration sequence

P03B itself performs no migration. A later production work package must:

1. freeze reviewed wire vectors and implement independently domain-separated producers;
2. persist issuance generation, expiry, overlap, revocation/recovery and replay/idempotency state;
3. register reviewed replica/coordinator crypto and key distribution;
4. deploy storage replicas capable of signed accepted/durable/error statements;
5. ship client verification dark, then enable receipt collection without trusting it for success;
6. verify two-replica durability and tombstone/cursor behavior in mobile and Windows E2E;
7. enable strict V1 issuance for a cohort;
8. use an explicitly bounded legacy mirror only where migration requires it;
9. stop legacy issuance and retain old statements/evidence according to policy.

Each activation gate requires Mr. X approval. Billing/free-admission accounting and storage quotas
remain separate later work; neither may introduce a stable payment identity into P03B bytes.
