# P10B compatibility

P10B is a Deep extension and does not alter Session protobuf, namespaces, envelopes or existing
wire vectors. P03/P03B/P04 remain immutable historical dependencies and are not reimplemented.

P10, P11B and P15 must consume the exact local package and golden vector hashes from
`package-manifest.json`. They must not redefine method/path/media/error bytes or turn HTTP status
into mailbox authority.
