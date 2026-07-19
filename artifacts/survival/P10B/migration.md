# P10B migration

P10B has no production default and no runtime registration. A later host may add the V1 endpoint
behind an explicit disabled-by-default feature gate after P07B/P10/P11B/P15 acceptance.

Rollback disables new P10B attempts without changing inner outbox/mailbox state. It does not
reinterpret ambiguous after-forward outcomes as failures and does not retry a body through a
redirect or legacy clear endpoint.
