# Production mailbox revocation snapshot V1

`production-mailbox-revocation-snapshot.v1` is the public, signed PMR1 artifact that supplies exact
MCG2 grant-serial revocations for a previously verified PMA1 authority. It is a Deep extension and
does not modify Session, protobuf, token, or smart-contract schemas.

PMR1 is deterministic fixed-order binary: `PMR1`, version `1`, three zero reserved bytes, network,
authority generation and PMB1 authority-binding hash, revocation generation/head/previous-head and
validity, a bounded count, zero reserved bytes, zero to 4,096 exact 16-byte MCG2 serials, and one
64-byte issuer Ed25519 signature. Serials are non-zero and strictly lexicographically ordered, so
duplicates and alternate set encodings are impossible. Unknown/trailing data and invalid lengths,
counts, reserved bytes, hashes, times, serials, or signatures fail closed.

## Non-circular publication workflow

PMB1 is a purpose-specific SHA-256 binding over every PMA1 policy field except only the three values
that would make publication circular: `Revocation.SnapshotHash`,
`MrXApproval.AuthorityPayloadHash`, and the detached Mr. X signature. Placeholder non-zero bytes may
occupy those three ignored fields while calling
`ProductionMailboxAuthorityCodec.ComputeRevocationBindingHash`.

The release workflow is therefore:

1. Assemble the complete draft PMA1 policy and compute its PMB1 hash.
2. Put that hash and the exact revocation lineage/time/serial set in PMR1.
3. Have the mailbox issuer sign `ProductionMailboxRevocationSnapshotCodec.GetSigningBytes` outside
   this library, then `Encode` PMR1 and compute SHA-256 of the complete signed artifact.
4. Put that PMR1 SHA-256 in PMA1 `Revocation.SnapshotHash`.
5. Compute the final PMA1 approval binding and obtain the external Mr. X signature.

Changing any PMA1 endpoint, pin, key, epoch, commitment, package/artifact approval, rollout, network,
generation, lineage, or time changes PMB1 and invalidates the PMR1-to-PMA1 binding.

## Verification and XNode use

`ProductionMailboxRevocationSnapshotVerifier.Verify` accepts exact downloaded bytes, an
unforgeable `VerifiedProductionMailboxAuthority`, caller time/skew, and the verify-only Ed25519
adapter. It freezes the bytes, requires canonical PMR1 SHA-256 to equal the signed PMA1 snapshot
hash, checks every duplicated PMA1 field and PMB1, enforces validity, and verifies the signature
with exactly the PMA1 mailbox issuer public key.

The returned `VerifiedProductionMailboxRevocationSnapshot` is immutable and directly implements
`IMailboxCapabilityRevocationSource`. It answers exact serial membership by binary search and throws
for a query naming any issuer other than the verified PMA1 issuer. XNode should atomically publish
this verified handle with the matching PMA1 generation and never construct a revocation source from
decoded-but-unverified PMR1. PMR1 contains no holder, mailbox ID, grant body, session, private key,
recovery material, or log data. Signing and key custody remain external host responsibilities.
