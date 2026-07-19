# P10B security boundary

P10B validates only an outer HTTP/2 opaque-transit envelope. Production source under
`DeepExtension/ManagedIngress` has no reference to onion, DPB1, MCP1, mailbox, receipt or storage
codecs. The maximum-producer test uses the selected three-hop onion producer only in the test
assembly to prove that its maximum bounded opaque bundle fits the outer limit.

Fail-closed controls:

- exact HTTPS scheme, authority, method, path, query, HTTP version and media fields;
- mandatory pseudo/media fields included in the 32-field and 8,192-byte decoded limits;
- supplemental duplicates, pseudo-fields, identity, billing, correlation, forwarding and
  hop-by-hop headers rejected;
- streaming byte accounting before allocation/forward, with exact declared/received equality;
- cancellation before forward is definite; cancellation after forward is `OutcomeUnknown`;
- success is only exact `200` plus a bounded opaque response;
- malformed or contradictory outer errors are `OutcomeUnknown`, never proof of non-acceptance;
- canonical `DIE1` and exact `Retry-After` binding;
- canonical bounded capability JSON; overlap and unknown critical features fail closed.

Non-claims: the ingress can observe source IP, timing, direction, connection reuse, endpoint and
padded ciphertext length. This contract does not provide global-observer anonymity, endpoint
unblockability, a server implementation, queue/concurrency policy, ingress-to-core authentication,
TLS deployment, mailbox acceptance, durability or delivery.
