# P10B compatibility

P10B is a Deep-only extension and changes no Session protobuf or public
`Deep.Protocol.Abstractions` type. It preserves the accepted P03/P03B/P04 history and adds a
contract-only namespace in `Deep.Protocol`.

Consumers must pin all three packages to version `0.3.0-p10b.c6fcf1a` and verify the hashes in
`package-manifest.json`. P10, P11B and P15 may adapt the contract but must not redefine methods,
paths, media types, limits, `DIE1`, capability JSON, cancellation classification or authority
semantics.

Unknown versions and critical features do not downgrade to raw or legacy transport.
