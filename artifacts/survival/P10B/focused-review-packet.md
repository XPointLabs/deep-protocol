# P10B focused review packet

Review exact source `7cf846a51411b82b1e4146940a72c80fa2ec16fb` and its evidence carrier.

Review priorities:

1. outer HTTP never creates accepted/durable/delivered authority;
2. actual streaming bytes are bounded before forward or allocation;
3. mandatory pseudo/media headers cannot bypass count or byte limits;
4. all malformed, proxy-generated and ambiguous responses become `OutcomeUnknown`;
5. HTTP status, canonical `DIE1` and optional `Retry-After` agree exactly;
6. capability JSON is canonical, bounded and unable to widen trust;
7. production managed-ingress source has no inner codec dependency;
8. exact base, historical raw manifests and package source commits are immutable and correct.

Required verdict is GO only with P0/P1/P2 all zero. Runtime activation remains blocked regardless
of the contract verdict.
