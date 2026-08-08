# Production mailbox authority V1

`production-mailbox-authority.v1` is a public Deep-extension authority, encoded by
`ProductionMailboxAuthorityCodec` as canonical `PMA1` binary: four-byte magic, version `1`, and
three required zero bytes. It is deliberately not Session wire data and does not change any token,
smart-contract or protobuf schema.

The signed payload fixes production-only `authenticated-mau2`, ownership, one coordinator and one
node-ingress endpoint, two non-identical SPKI SHA-256 pins for each role, the mailbox issuer public
Ed25519 key, current and next epoch/generation membership and global topology-placement commitments,
a bounded revocation snapshot, and the
Mr. X approval binding. The approval binds SHA-256 of the payload plus approved Android/Windows
signing-certificate and release-artifact SHA-256 lists and a rollout window. The document's
separate Mr. X public Ed25519 key signs the payload plus approval. No private key, holder, session,
mailbox identifier, capability grant, recovery material, or log data is in the model.

`GetPayloadBytes` excludes the approval to avoid a self-referential hash. `GetSigningBytes` includes
the payload and approval but not the 64-byte detached signature. `Encode` is the signed canonical
document. `Decode` rejects non-canonical/trailing fields; binary framing consequently has no unknown
or duplicate fields.

The epoch `TopologyPlacementCommitment` is global catalog/policy state. It is never a user's
mailbox placement commitment and must never be copied into MCG2. PMS1 separately binds the caller's
`MailboxPlacementCommitment`, which MCG2 and the typed mailbox request enforce.

Production official-managed authorities require public HTTPS endpoints and distinct coordinator and
node-ingress origins. HTTP and development markers are always rejected. The only documented
user-managed exception is `UserManagedPrivateHttps`, which permits a private or loopback HTTPS
endpoint for self-operated deployments; it never permits HTTP and still requires role-specific dual
pins.

Callers must persist the accepted canonical hash and generation atomically. Verification takes the
caller-pinned SHA-256 of the Mr. X public key, expected network ID and a non-zero durable last generation/hash, accepts
only exactly the next generation with an exact previous-hash link, verifies the detached Ed25519
signature, and validates the current epoch, rollout and revocation freshness at one caller-supplied
time. The same durable state also carries the last revocation generation, head and snapshot hash:
the verifier accepts an identical snapshot at that generation or exactly one head-linked successor.
Authority and revocation generation `ulong.MaxValue` are terminal and are rejected before commit,
so every accepted durable authority retains successor capacity.
Snapshots have an explicit issuance time and a protocol-bounded maximum 24-hour lifetime. A caller
must provision initial authority and revocation last-known-good state out of band; downloaded
authority never bootstraps trust.

Downstream integration:

- XNode consumes `VerifiedProductionMailboxAuthority.Authority.NodeIngress`, checks the exact
  current-or-next SPKI pin and resolved remote address at TLS connection time (official-managed
  endpoints must resolve to public addresses), and atomically persists the verification result
  before serving MAU2.
- DevOps creates the canonical payload, computes `ComputePayloadHash`, obtains the external Mr. X
  detached signature over `GetSigningBytes`, and publishes only `Encode` output; it must retain the
  previously accepted generation/hash and never use lab keys.
- MAUI decodes then verifies before provisioning, consumes only public endpoint/pin/issuer/epoch
  fields, and persists the verifier result in the same transaction as its authority state. It must
  not treat this as a holder or capability source.
