using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Deep.Protocol.DeepExtension.MembershipRoutes;

[Flags]
public enum MembershipRouteRole : ushort
{
    None = 0,
    Ingress = 1,
    Core = 2,
    Storage = 4,
    Bridge = 8
}

[Flags]
public enum MembershipRouteCapability : uint
{
    None = 0,
    SessionRpc = 1,
    OnionV1 = 2,
    Storage = 4,
    BridgeFetch = 8
}

public sealed record MembershipRouteDescriptor
{
    public required ReadOnlyMemory<byte> RouterId { get; init; }
    public required ReadOnlyMemory<byte> Ed25519PublicKey { get; init; }
    public required ReadOnlyMemory<byte> X25519PublicKey { get; init; }
    public required string RpcEndpoint { get; init; }
    public required MembershipRouteRole Roles { get; init; }
    public required MembershipRouteCapability Capabilities { get; init; }
    public required ulong Epoch { get; init; }
    public required ulong ValidFromUnixSeconds { get; init; }
    public required ulong ValidUntilUnixSeconds { get; init; }
}

public sealed record MembershipRouteInclusionProof
{
    public required uint LeafIndex { get; init; }
    public required uint MemberCount { get; init; }
    public required IReadOnlyList<ReadOnlyMemory<byte>> SiblingHashes { get; init; }
}

public enum MembershipRouteDescriptorError
{
    InvalidField,
    InvalidLength,
    InvalidMagic,
    UnsupportedVersion,
    InvalidFlags,
    InvalidEndpoint,
    InvalidValidityWindow,
    InvalidProof
}

public sealed class MembershipRouteDescriptorException(
    MembershipRouteDescriptorError error,
    string message) : Exception(message)
{
    public MembershipRouteDescriptorError Error { get; } = error;
}

public static class MembershipRouteDescriptorCodec
{
    public const int KeyLength = 32;
    public const int HashLength = 32;
    public const int MaximumEndpointBytes = 256;
    public const int MaximumMembers = 4096;
    public const int MaximumProofDepth = 12;
    private const byte Version = 1;

    private static ReadOnlySpan<byte> Magic => "MRL1"u8;
    private static ReadOnlySpan<byte> LeafDomain => "deep.route-leaf/v1"u8;
    private static ReadOnlySpan<byte> NodeDomain => "deep.route-node/v1"u8;
    private static ReadOnlySpan<byte> EmptyDomain => "deep.route-empty/v1"u8;
    private static ReadOnlySpan<byte> RootDomain => "deep.route-root/v1"u8;

    public static byte[] Encode(MembershipRouteDescriptor descriptor)
    {
        Validate(descriptor);
        var endpoint = Encoding.UTF8.GetBytes(descriptor.RpcEndpoint);
        var output = new byte[
            4 + 1 + 1 + 2 + 4 + (KeyLength * 3) + 8 + 8 + 8 + 2 + endpoint.Length];
        var offset = 0;
        Magic.CopyTo(output.AsSpan(offset));
        offset += 4;
        output[offset++] = Version;
        output[offset++] = 0;
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(offset), (ushort)descriptor.Roles);
        offset += 2;
        BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(offset), (uint)descriptor.Capabilities);
        offset += 4;
        descriptor.RouterId.Span.CopyTo(output.AsSpan(offset));
        offset += KeyLength;
        descriptor.Ed25519PublicKey.Span.CopyTo(output.AsSpan(offset));
        offset += KeyLength;
        descriptor.X25519PublicKey.Span.CopyTo(output.AsSpan(offset));
        offset += KeyLength;
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(offset), descriptor.Epoch);
        offset += 8;
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(offset), descriptor.ValidFromUnixSeconds);
        offset += 8;
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(offset), descriptor.ValidUntilUnixSeconds);
        offset += 8;
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(offset), checked((ushort)endpoint.Length));
        offset += 2;
        endpoint.CopyTo(output.AsSpan(offset));
        return output;
    }

    public static MembershipRouteDescriptor Decode(ReadOnlySpan<byte> encoded)
    {
        const int fixedLength = 4 + 1 + 1 + 2 + 4 + (KeyLength * 3) + 8 + 8 + 8 + 2;
        if (encoded.Length < fixedLength)
            throw Error(MembershipRouteDescriptorError.InvalidLength, "Route descriptor is truncated.");
        if (!encoded[..4].SequenceEqual(Magic))
            throw Error(MembershipRouteDescriptorError.InvalidMagic, "Route descriptor magic is invalid.");
        if (encoded[4] != Version)
            throw Error(MembershipRouteDescriptorError.UnsupportedVersion, "Route descriptor version is unsupported.");
        if (encoded[5] != 0)
            throw Error(MembershipRouteDescriptorError.InvalidField, "Route descriptor reserved byte must be zero.");
        var offset = 6;
        var roles = (MembershipRouteRole)BinaryPrimitives.ReadUInt16BigEndian(encoded[offset..]);
        offset += 2;
        var capabilities = (MembershipRouteCapability)BinaryPrimitives.ReadUInt32BigEndian(encoded[offset..]);
        offset += 4;
        var routerId = encoded.Slice(offset, KeyLength).ToArray();
        offset += KeyLength;
        var ed25519 = encoded.Slice(offset, KeyLength).ToArray();
        offset += KeyLength;
        var x25519 = encoded.Slice(offset, KeyLength).ToArray();
        offset += KeyLength;
        var epoch = BinaryPrimitives.ReadUInt64BigEndian(encoded[offset..]);
        offset += 8;
        var validFrom = BinaryPrimitives.ReadUInt64BigEndian(encoded[offset..]);
        offset += 8;
        var validUntil = BinaryPrimitives.ReadUInt64BigEndian(encoded[offset..]);
        offset += 8;
        var endpointLength = BinaryPrimitives.ReadUInt16BigEndian(encoded[offset..]);
        offset += 2;
        if (endpointLength == 0 || endpointLength > MaximumEndpointBytes ||
            encoded.Length != offset + endpointLength)
            throw Error(MembershipRouteDescriptorError.InvalidLength, "Route endpoint length is invalid.");
        string endpoint;
        try
        {
            endpoint = new UTF8Encoding(false, true).GetString(encoded[offset..]);
        }
        catch (DecoderFallbackException exception)
        {
            throw new MembershipRouteDescriptorException(
                MembershipRouteDescriptorError.InvalidEndpoint,
                $"Route endpoint is not canonical UTF-8: {exception.Message}");
        }
        var descriptor = new MembershipRouteDescriptor
        {
            RouterId = routerId,
            Ed25519PublicKey = ed25519,
            X25519PublicKey = x25519,
            RpcEndpoint = endpoint,
            Roles = roles,
            Capabilities = capabilities,
            Epoch = epoch,
            ValidFromUnixSeconds = validFrom,
            ValidUntilUnixSeconds = validUntil
        };
        Validate(descriptor);
        if (!encoded.SequenceEqual(Encode(descriptor)))
            throw Error(MembershipRouteDescriptorError.InvalidField, "Route descriptor is not canonical.");
        return descriptor;
    }

    public static byte[] ComputeLeafHash(MembershipRouteDescriptor descriptor) =>
        Hash(LeafDomain, Encode(descriptor));

    public static byte[] ComputeEmptyLeafHash() => Hash(EmptyDomain, []);

    public static byte[] ComputeNodeHash(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
    {
        if (left.Length != HashLength || right.Length != HashLength)
            throw Error(MembershipRouteDescriptorError.InvalidLength, "Merkle child hashes must be 32 bytes.");
        return Hash(NodeDomain, [.. left, .. right]);
    }

    public static byte[] ComputeRoot(IReadOnlyList<MembershipRouteDescriptor> members)
    {
        ArgumentNullException.ThrowIfNull(members);
        if (members.Count is 0 or > MaximumMembers || members.Any(static member => member is null))
            throw Error(MembershipRouteDescriptorError.InvalidField, "Membership route catalog size is invalid.");
        var leaves = members.Select(ComputeLeafHash).ToList();
        var paddedCount = NextPowerOfTwo(leaves.Count);
        while (leaves.Count < paddedCount)
            leaves.Add(ComputeEmptyLeafHash());
        while (leaves.Count > 1)
        {
            var parents = new List<byte[]>(leaves.Count / 2);
            for (var index = 0; index < leaves.Count; index += 2)
                parents.Add(ComputeNodeHash(leaves[index], leaves[index + 1]));
            leaves = parents;
        }
        return BindRoot(checked((uint)members.Count), leaves[0]);
    }

    public static bool VerifyInclusion(
        MembershipRouteDescriptor descriptor,
        MembershipRouteInclusionProof proof,
        ReadOnlySpan<byte> expectedRoot)
    {
        if (descriptor is null || proof is null || expectedRoot.Length != HashLength ||
            proof.MemberCount is 0 or > MaximumMembers || proof.LeafIndex >= proof.MemberCount ||
            proof.SiblingHashes is null)
            return false;
        var expectedDepth = ProofDepth(checked((int)proof.MemberCount));
        if (proof.SiblingHashes.Count != expectedDepth ||
            proof.SiblingHashes.Any(static sibling => sibling.Length != HashLength))
            return false;
        var current = ComputeLeafHash(descriptor);
        var index = proof.LeafIndex;
        foreach (var sibling in proof.SiblingHashes)
        {
            current = (index & 1) == 0
                ? ComputeNodeHash(current, sibling.Span)
                : ComputeNodeHash(sibling.Span, current);
            index >>= 1;
        }
        var boundRoot = BindRoot(proof.MemberCount, current);
        return CryptographicOperations.FixedTimeEquals(boundRoot, expectedRoot);
    }

    public static IReadOnlyList<MembershipRouteInclusionProof> BuildProofs(
        IReadOnlyList<MembershipRouteDescriptor> members)
    {
        _ = ComputeRoot(members);
        var layer = members.Select(ComputeLeafHash).ToList();
        var paddedCount = NextPowerOfTwo(layer.Count);
        while (layer.Count < paddedCount)
            layer.Add(ComputeEmptyLeafHash());
        var paths = Enumerable.Range(0, members.Count)
            .Select(static _ => new List<ReadOnlyMemory<byte>>())
            .ToArray();
        var indices = Enumerable.Range(0, members.Count).ToArray();
        while (layer.Count > 1)
        {
            for (var leaf = 0; leaf < members.Count; leaf++)
            {
                var index = indices[leaf];
                paths[leaf].Add(layer[index ^ 1].ToArray());
                indices[leaf] >>= 1;
            }
            var parents = new List<byte[]>(layer.Count / 2);
            for (var index = 0; index < layer.Count; index += 2)
                parents.Add(ComputeNodeHash(layer[index], layer[index + 1]));
            layer = parents;
        }
        return paths.Select((path, index) => new MembershipRouteInclusionProof
        {
            LeafIndex = checked((uint)index),
            MemberCount = checked((uint)members.Count),
            SiblingHashes = path
        }).ToArray();
    }

    private static void Validate(MembershipRouteDescriptor descriptor)
    {
        ArgumentNullException.ThrowIfNull(descriptor);
        const MembershipRouteRole allRoles =
            MembershipRouteRole.Ingress | MembershipRouteRole.Core |
            MembershipRouteRole.Storage | MembershipRouteRole.Bridge;
        const MembershipRouteCapability allCapabilities =
            MembershipRouteCapability.SessionRpc | MembershipRouteCapability.OnionV1 |
            MembershipRouteCapability.Storage | MembershipRouteCapability.BridgeFetch;
        var endpointBytes = Encoding.UTF8.GetByteCount(descriptor.RpcEndpoint ?? string.Empty);
        if (descriptor.RouterId.Length != KeyLength ||
            descriptor.Ed25519PublicKey.Length != KeyLength ||
            descriptor.X25519PublicKey.Length != KeyLength ||
            IsAllZero(descriptor.RouterId.Span) ||
            IsAllZero(descriptor.Ed25519PublicKey.Span) ||
            IsAllZero(descriptor.X25519PublicKey.Span) ||
            descriptor.Epoch == 0)
            throw Error(MembershipRouteDescriptorError.InvalidField, "Route identity fields are invalid.");
        if (descriptor.Roles == MembershipRouteRole.None || (descriptor.Roles & ~allRoles) != 0 ||
            descriptor.Capabilities == MembershipRouteCapability.None ||
            (descriptor.Capabilities & ~allCapabilities) != 0)
            throw Error(MembershipRouteDescriptorError.InvalidFlags, "Route role or capability flags are invalid.");
        if (endpointBytes is 0 or > MaximumEndpointBytes ||
            !Uri.TryCreate(descriptor.RpcEndpoint, UriKind.Absolute, out var endpoint) ||
            endpoint.Scheme is not ("http" or "https") ||
            !string.IsNullOrEmpty(endpoint.UserInfo) ||
            !string.IsNullOrEmpty(endpoint.Query) ||
            !string.IsNullOrEmpty(endpoint.Fragment) ||
            endpoint.AbsolutePath != "/")
            throw Error(MembershipRouteDescriptorError.InvalidEndpoint, "RPC endpoint must be an authority-only HTTP(S) URI.");
        if (descriptor.ValidFromUnixSeconds >= descriptor.ValidUntilUnixSeconds)
            throw Error(MembershipRouteDescriptorError.InvalidValidityWindow, "Route validity window is invalid.");
    }

    private static bool IsAllZero(ReadOnlySpan<byte> value)
    {
        byte combined = 0;
        foreach (var item in value)
            combined |= item;
        return combined == 0;
    }

    private static byte[] Hash(ReadOnlySpan<byte> domain, ReadOnlySpan<byte> payload)
    {
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Span<byte> length = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(length, checked((uint)domain.Length));
        hash.AppendData(length);
        hash.AppendData(domain);
        BinaryPrimitives.WriteUInt32BigEndian(length, checked((uint)payload.Length));
        hash.AppendData(length);
        hash.AppendData(payload);
        return hash.GetHashAndReset();
    }

    private static byte[] BindRoot(uint memberCount, ReadOnlySpan<byte> treeRoot)
    {
        Span<byte> payload = stackalloc byte[4 + HashLength];
        BinaryPrimitives.WriteUInt32BigEndian(payload, memberCount);
        treeRoot.CopyTo(payload[4..]);
        return Hash(RootDomain, payload);
    }

    private static int NextPowerOfTwo(int value)
    {
        var result = 1;
        while (result < value)
            result <<= 1;
        return result;
    }

    private static int ProofDepth(int members)
    {
        var depth = 0;
        for (var width = NextPowerOfTwo(members); width > 1; width >>= 1)
            depth++;
        return depth;
    }

    private static MembershipRouteDescriptorException Error(
        MembershipRouteDescriptorError error,
        string message) => new(error, message);
}
