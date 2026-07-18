# P03 migration and rollback

Default mode remains legacy runtime behavior because no consumer is wired to P03 and no feature is
enabled.

The bounded migration profile is opt-in at both encoder and decoder. It requires payload kind
`LegacyDpe1`, the critical compatibility feature and exact payload bytes beginning `DPE1`. A strict
profile rejects it. No failed opaque operation may trigger raw Session-ID addressing or legacy
retry.

Mr. X must approve:

1. the compatibility-window start and end buckets;
2. the minimum safe negotiated version;
3. the release in which strict opaque mode becomes blocking;
4. rollback from new writes while retaining readable old/new state.

Rollback disables negotiation/new writes at the consumer. It must not delete mailbox state or
silently reinterpret DPB1 bytes. P03 itself creates no persistence migration.
