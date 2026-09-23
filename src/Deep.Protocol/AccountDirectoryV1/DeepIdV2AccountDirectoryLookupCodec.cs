using System.Buffers.Binary;
using Deep.Protocol.ApplicationCore;

namespace Deep.Protocol.AccountDirectoryV1;

/// <summary>
/// Candidate ADL1 V2 capability. It cannot be constructed with a caller-chosen
/// lookup key; authoring and verification bind that key to the exact DID2.
/// </summary>
public sealed class ParsedAdl1V2
{
    private readonly byte[] canonical;
    private readonly byte[] networkId;
    private readonly byte[] lookupKey;
    private readonly byte[] minimumAdhHash;
    private readonly byte[] xodReference;
    private readonly byte[] xodHash;

    internal ParsedAdl1V2(ReadOnlySpan<byte> canonical, ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> lookupKey, ulong minimumAdhGeneration,
        ReadOnlySpan<byte> minimumAdhHash, ushort serviceProfile,
        ReadOnlySpan<byte> xodReference, ReadOnlySpan<byte> xodHash)
    {
        this.canonical = canonical.ToArray();
        this.networkId = networkId.ToArray();
        this.lookupKey = lookupKey.ToArray();
        MinimumAdhGeneration = minimumAdhGeneration;
        this.minimumAdhHash = minimumAdhHash.ToArray();
        ServiceProfile = serviceProfile;
        this.xodReference = xodReference.ToArray();
        this.xodHash = xodHash.ToArray();
    }

    public ReadOnlyMemory<byte> CanonicalBytes => canonical.ToArray();
    public ReadOnlyMemory<byte> NetworkId => networkId.ToArray();
    public ReadOnlyMemory<byte> DirectoryLookupKey => lookupKey.ToArray();
    public ulong MinimumAdhGeneration { get; }
    public ReadOnlyMemory<byte> MinimumAdhHash => minimumAdhHash.ToArray();
    public ushort ServiceProfile { get; }
    public ReadOnlyMemory<byte> ExactOhttpXod1CoreReference => xodReference.ToArray();
    public ReadOnlyMemory<byte> ExactOhttpXod1CoreHash => xodHash.ToArray();
}

public static class DeepIdV2AccountDirectoryLookupCodec
{
    public const ushort Version = 2;
    public const ushort Suite = DeepIdV2Codec.Suite;
    public const int CanonicalLength = 228;
    private static ReadOnlySpan<byte> Magic => ProtocolMagicBytes.ADL1;
    private static ReadOnlySpan<int> Lengths => [16, 32, 8, 32, 2, 38, 32];

    public static ParsedAdl1V2 Decode(ReadOnlySpan<byte> canonical)
    {
        Span<ApplicationFieldSlice> fields = stackalloc ApplicationFieldSlice[7];
        ApplicationCoreFormat.Preflight(canonical, Magic, 7, CanonicalLength,
            CanonicalLength, fields, Version, Suite);
        var lengths = Lengths;
        for (var tag = 1; tag <= lengths.Length; tag++)
            ApplicationCoreFormat.ExactLength(fields, tag, lengths[tag - 1]);
        var network = ApplicationCoreFormat.Field(canonical, fields, 1);
        var lookup = ApplicationCoreFormat.Field(canonical, fields, 2);
        var floor = ApplicationCoreFormat.Field(canonical, fields, 4);
        ApplicationCoreFormat.NonZero(network, "ADL1 V2 network");
        ApplicationCoreFormat.NonZero(lookup, "ADL1 V2 lookup key");
        ApplicationCoreFormat.NonZero(floor, "ADL1 V2 ADH1 floor");
        var profile = BinaryPrimitives.ReadUInt16BigEndian(
            ApplicationCoreFormat.Field(canonical, fields, 5));
        var xodReference = ApplicationCoreFormat.Field(canonical, fields, 6);
        var xodHash = ApplicationCoreFormat.Field(canonical, fields, 7);
        if (profile is < 1 or > 3)
            throw Invalid("ADL1 V2 service profile is unknown.");
        if (profile == 1)
        {
            if (!ApplicationCoreFormat.IsZero(xodReference) ||
                !ApplicationCoreFormat.IsZero(xodHash))
                throw Invalid("ADL1 V2 XPoint-only profile must omit XOD1.");
        }
        else if (!xodReference[..4].SequenceEqual(ProtocolMagicBytes.XOD1) ||
                 BinaryPrimitives.ReadUInt16BigEndian(xodReference[4..]) != 1 ||
                 ApplicationCoreFormat.IsZero(xodHash) ||
                 !xodReference[6..].SequenceEqual(xodHash))
            throw Invalid("ADL1 V2 OHTTP profile requires an exact XOD1 core reference.");

        return new ParsedAdl1V2(canonical, network, lookup,
            BinaryPrimitives.ReadUInt64BigEndian(
                ApplicationCoreFormat.Field(canonical, fields, 3)), floor, profile,
            xodReference, xodHash);
    }

    public static ParsedAdl1V2 Author(ParsedDid2 exactDid2,
        ReadOnlySpan<byte> networkId16, ulong minimumAdhGeneration,
        ReadOnlySpan<byte> minimumAdhHash32, ushort serviceProfile,
        ReadOnlySpan<byte> exactOhttpXod1CoreReference38,
        ReadOnlySpan<byte> exactOhttpXod1CoreHash32)
    {
        ArgumentNullException.ThrowIfNull(exactDid2);
        var lookup = DeepIdV2AccountDirectoryCodec.ComputeDirectoryLookupKey(
            networkId16, exactDid2);
        var fields = new ReadOnlyMemory<byte>[]
        {
            Copy(networkId16, 16), lookup, U64(minimumAdhGeneration),
            Copy(minimumAdhHash32, 32), U16(serviceProfile),
            Copy(exactOhttpXod1CoreReference38, 38),
            Copy(exactOhttpXod1CoreHash32, 32)
        };
        var canonical = new byte[CanonicalLength];
        var writer = new ApplicationRecordWriter(canonical, Magic, 7, Version, Suite);
        for (ushort tag = 1; tag <= 7; tag++)
            writer.Write(tag, fields[tag - 1].Span);
        writer.Complete();
        return Decode(canonical);
    }

    public static byte[] VerifyAndGetDirectoryLeafKey(ParsedAdl1V2 capability,
        VerifiedDab2 trustedBinding)
    {
        ArgumentNullException.ThrowIfNull(capability);
        ArgumentNullException.ThrowIfNull(trustedBinding);
        return MatchExactDid2(capability, trustedBinding.DeepId);
    }

    internal static byte[] MatchExactDid2(ParsedAdl1V2 capability,
        ParsedDid2 exactDid2)
    {
        ArgumentNullException.ThrowIfNull(capability);
        ArgumentNullException.ThrowIfNull(exactDid2);
        var expectedLookup = DeepIdV2AccountDirectoryCodec.ComputeDirectoryLookupKey(
            capability.NetworkId.Span, exactDid2);
        if (!capability.DirectoryLookupKey.Span.SequenceEqual(expectedLookup))
            throw Invalid("ADL1 V2 lookup key is not bound to the exact DID2.");
        return DeepIdV2AccountDirectoryCodec.ComputeDirectoryLeafKey(
            capability.NetworkId.Span, exactDid2);
    }

    private static byte[] Copy(ReadOnlySpan<byte> value, int length)
    {
        if (value.Length != length)
            throw new ArgumentException($"ADL1 V2 field must contain {length} bytes.");
        return value.ToArray();
    }

    private static byte[] U64(ulong value)
    {
        var bytes = new byte[8];
        BinaryPrimitives.WriteUInt64BigEndian(bytes, value);
        return bytes;
    }

    private static byte[] U16(ushort value)
    {
        var bytes = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(bytes, value);
        return bytes;
    }

    private static AccountDirectoryAdl1FormatException Invalid(string message) => new(message);
}
