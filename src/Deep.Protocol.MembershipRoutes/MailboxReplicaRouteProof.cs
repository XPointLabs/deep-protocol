using System.Buffers.Binary;
using Deep.Protocol.DeepExtension.MailboxCapabilities;
using Deep.Protocol.DeepExtension.MailboxTopology;

namespace Deep.Protocol.DeepExtension.MembershipRoutes;

public static class MailboxReplicaRouteProofCodec
{
    private const byte Version = 1;
    private const int HeaderLength = 16;
    private static ReadOnlySpan<byte> Magic => ProtocolMagicBytes.RIP1;

    public static byte[] Encode(
        MembershipRouteDescriptor descriptor,
        MembershipRouteInclusionProof proof)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        ArgumentNullException.ThrowIfNull(proof);
        var descriptorBytes = MembershipRouteDescriptorCodec.Encode(descriptor);
        if (proof.SiblingHashes is null ||
            proof.SiblingHashes.Count > MembershipRouteDescriptorCodec.MaximumProofDepth ||
            proof.SiblingHashes.Any(static value =>
                value.Length != MembershipRouteDescriptorCodec.HashLength))
            throw new MembershipRouteDescriptorException(
                MembershipRouteDescriptorError.InvalidProof,
                "RIP1 sibling hashes are invalid.");
        var output = new byte[
            HeaderLength + descriptorBytes.Length +
            proof.SiblingHashes.Count * MembershipRouteDescriptorCodec.HashLength];
        Magic.CopyTo(output);
        output[4] = Version;
        output[5] = checked((byte)proof.SiblingHashes.Count);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(6), checked((ushort)descriptorBytes.Length));
        BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(8), proof.LeafIndex);
        BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(12), proof.MemberCount);
        descriptorBytes.CopyTo(output, HeaderLength);
        var offset = HeaderLength + descriptorBytes.Length;
        foreach (var sibling in proof.SiblingHashes)
        {
            sibling.Span.CopyTo(output.AsSpan(offset));
            offset += MembershipRouteDescriptorCodec.HashLength;
        }
        return output;
    }

    public static (
        MembershipRouteDescriptor Descriptor,
        MembershipRouteInclusionProof Proof) Decode(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length < HeaderLength ||
            !encoded[..4].SequenceEqual(Magic) ||
            encoded[4] != Version)
            throw new MembershipRouteDescriptorException(
                encoded.Length < HeaderLength
                    ? MembershipRouteDescriptorError.InvalidLength
                    : encoded.Length >= 4 && !encoded[..4].SequenceEqual(Magic)
                        ? MembershipRouteDescriptorError.InvalidMagic
                        : MembershipRouteDescriptorError.UnsupportedVersion,
                "RIP1 header is invalid.");
        var siblingCount = encoded[5];
        var descriptorLength = BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(6, 2));
        if (siblingCount > MembershipRouteDescriptorCodec.MaximumProofDepth ||
            descriptorLength == 0 ||
            encoded.Length != HeaderLength + descriptorLength +
                              siblingCount * MembershipRouteDescriptorCodec.HashLength)
            throw new MembershipRouteDescriptorException(
                MembershipRouteDescriptorError.InvalidLength,
                "RIP1 nested lengths are invalid.");
        var descriptor = MembershipRouteDescriptorCodec.Decode(
            encoded.Slice(HeaderLength, descriptorLength));
        var siblings = new ReadOnlyMemory<byte>[siblingCount];
        var offset = HeaderLength + descriptorLength;
        for (var index = 0; index < siblings.Length; index++)
        {
            siblings[index] = encoded.Slice(
                offset,
                MembershipRouteDescriptorCodec.HashLength).ToArray();
            offset += MembershipRouteDescriptorCodec.HashLength;
        }
        var proof = new MembershipRouteInclusionProof
        {
            LeafIndex = BinaryPrimitives.ReadUInt32BigEndian(encoded.Slice(8, 4)),
            MemberCount = BinaryPrimitives.ReadUInt32BigEndian(encoded.Slice(12, 4)),
            SiblingHashes = siblings
        };
        if (!encoded.SequenceEqual(Encode(descriptor, proof)))
            throw new MembershipRouteDescriptorException(
                MembershipRouteDescriptorError.InvalidProof,
                "RIP1 is not canonical.");
        return (descriptor, proof);
    }
}

public sealed class MembershipRoutesMailboxReplicaProofVerifier
    : IMailboxReplicaMembershipProofVerifier
{
    public bool VerifyStorageReplica(
        MailboxReplicaMembershipProof proof,
        ulong verificationTimeUnixSeconds) =>
        VerifyStorageReplica(proof, verificationTimeUnixSeconds, 0);

    /// <summary>
    /// Verifies a storage replica proof while allowing the bounded clock skew already accepted by
    /// the enclosing production mailbox topology verification context.
    /// </summary>
    public bool VerifyStorageReplica(
        MailboxReplicaMembershipProof proof,
        ulong verificationTimeUnixSeconds,
        uint clockSkewSeconds)
    {
        if (proof is null ||
            clockSkewSeconds > ProductionMailboxTopologyConstants.MaximumClockSkewSeconds)
            return false;
        try
        {
            var decoded = MailboxReplicaRouteProofCodec.Decode(
                proof.CanonicalInclusionProof.Span);
            return decoded.Descriptor.Epoch == proof.Epoch &&
                   IsWithinWindow(decoded.Descriptor.ValidFromUnixSeconds,
                       decoded.Descriptor.ValidUntilUnixSeconds,
                       verificationTimeUnixSeconds, clockSkewSeconds) &&
                   decoded.Descriptor.Roles.HasFlag(MembershipRouteRole.Storage) &&
                   decoded.Descriptor.Capabilities.HasFlag(MembershipRouteCapability.Storage) &&
                   decoded.Descriptor.RouterId.Span.SequenceEqual(proof.ReplicaId.Span) &&
                   decoded.Descriptor.Ed25519PublicKey.Span.SequenceEqual(proof.SigningPublicKey.Span) &&
                   MembershipRouteDescriptorCodec.VerifyInclusion(
                       decoded.Descriptor,
                       decoded.Proof,
                       proof.MembershipCommitment.Span);
        }
        catch (MembershipRouteDescriptorException)
        {
            return false;
        }
    }

    private static bool IsWithinWindow(
        ulong validFromUnixSeconds,
        ulong validUntilUnixSeconds,
        ulong verificationTimeUnixSeconds,
        uint clockSkewSeconds) =>
        (verificationTimeUnixSeconds >= validFromUnixSeconds ||
         validFromUnixSeconds - verificationTimeUnixSeconds <= clockSkewSeconds) &&
        (verificationTimeUnixSeconds <= validUntilUnixSeconds ||
         verificationTimeUnixSeconds - validUntilUnixSeconds <= clockSkewSeconds);
}
