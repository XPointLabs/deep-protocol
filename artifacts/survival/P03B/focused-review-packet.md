# P03B independent review packet

Review exact branch and source commit
`312bda8e147dd1ee2be3d6a1c0f343171488b97a`, plus the subsequent evidence-only commit.

Review priorities:

1. canonical bounds and all decode-before-allocation behavior in `MailboxCapabilityCodec` and
   `MailboxReceiptCodec`;
2. strict deposit/retrieve/placement separation and absence of a conversion/derivation API;
3. lifecycle/overlap/revoked/recovery and replay/idempotency policy ordering;
4. free-admission orthogonality to payment identity;
5. two distinct replica signatures, accepted-versus-durable semantics and agreement fields;
6. coordinator signing-byte binding, canonical replica order and equivocation evidence;
7. golden, truncation, structured mutation and deterministic malformed tests;
8. documentation consistency, non-claims, production blockers and absence of default registration.

Return `GO` or `NO-GO`, findings grouped P0/P1/P2/P3 with file/line evidence, and explicitly report
counts for P0/P1/P2. Review is read-only: do not modify files, publish packages, push or activate.
