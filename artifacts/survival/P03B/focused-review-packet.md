# P03B independent review packet

Review exact branch and source commit
`6e2c709a378ffac40c441e97e2e4da40aac9a104`, plus the subsequent evidence-only commit.

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
9. closure of the initial NO-GO findings recorded in `independent-review.md`.

Return `GO` or `NO-GO`, findings grouped P0/P1/P2/P3 with file/line evidence, and explicitly report
counts for P0/P1/P2. Review is read-only: do not modify files, publish packages, push or activate.
