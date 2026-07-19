# P10B migration

1. Consume the exact local package set and verify every SHA-256 before restore.
2. Map HTTP/2 request metadata into `ManagedIngressRequestMetadata`; do not duplicate mandatory
   pseudo/media fields in `Headers`.
3. Drive `ManagedIngressStreamingAdmission` for every request body before starting core forward.
4. Treat only exact bounded `200` as `TransitCompleted`; still open and verify the inner response
   before changing application state.
5. Use `ClassifyErrorResponse`; any `OutcomeUnknown` enters idempotent reconciliation with a newly
   sealed transport attempt.
6. Bind capability cache lifetime to the already verified P04/P07 bridge candidate.
7. Keep runtime disabled until P10/P11B/P15, ingress-to-core authentication, deployment and device
   E2E gates are independently accepted.

There is no compatibility fallback that sends a clear inner payload or interprets outer HTTP as
accepted, durable or delivered.
