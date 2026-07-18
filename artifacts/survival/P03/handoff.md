# P03 handoff to P11

Use local package `Deep.Protocol` version `0.3.0-p03.c854dbe` with the matching
`Deep.Protocol.Abstractions` and `Deep.Protocol.Protobuf` packages from `packages/`. Verify hashes
against `package-manifest.json`. The packages were not published.

Namespace: `Deep.Protocol.DeepExtension.OpaqueBundles`.

Consumer sequence:

1. build explicit local/peer `OpaqueBundleNegotiationOffer` values;
2. call `OpaqueBundleNegotiator.Negotiate` with a minimum safe version;
3. construct a domain-separated `OpaqueDepositCapability` or `OpaqueRetrieveCapability` supplied
   by the future reviewed producer;
4. provide already encrypted header/payload, a transport attempt ID and a different E2E dedup ID;
5. call `OpaqueBundleCodec.Encode`;
6. decode with an explicit bounded `OpaqueBundleDecodePolicy`;
7. fail closed on every `OpaqueBundleException` and expose only aggregate error counters.

Do not use the codec as a capability derivation, authentication, replay database, ratchet, MLS or
forward-secrecy implementation. Do not enable production negotiation before the unresolved producer
and external-review blockers in `security-boundary.md` are closed.
