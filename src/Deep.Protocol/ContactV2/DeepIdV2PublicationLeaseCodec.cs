using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;

namespace Deep.Protocol.ContactV2;

/// <summary>Canonical fresh lease bytes only. Not verified publisher, witness,
/// current network, mutation or commitment authority.</summary>
public sealed class ParsedDeepIdV2PublicationLease
{
    private readonly byte[] exact;
    private readonly byte[][] fields;
    internal ParsedDeepIdV2PublicationLease(byte[] exact, byte[][] fields, Xpu1Request original)
    { this.exact = exact; this.fields = fields; OriginalRequest = original; }
    public ReadOnlyMemory<byte> CanonicalBytes => exact.ToArray();
    public Xpu1Request OriginalRequest { get; }
    public ReadOnlyMemory<byte> NetworkId => fields[0].ToArray();
    public ReadOnlyMemory<byte> OriginalRequestHash => fields[1].ToArray();
    public ReadOnlyMemory<byte> ViewHash => fields[2].ToArray();
    public ReadOnlyMemory<byte> PlacementHash => fields[3].ToArray();
    public ulong IssuedAtUnixSeconds => BinaryPrimitives.ReadUInt64BigEndian(fields[4]);
    public ulong ExpiresAtUnixSeconds => BinaryPrimitives.ReadUInt64BigEndian(fields[5]);
    public ReadOnlyMemory<byte> DirectoryHeadHash => fields[6].ToArray();
    public ReadOnlyMemory<byte> RequestNonce => fields[7].ToArray();
    public byte WitnessCount => fields[9][0];
    internal ReadOnlySpan<byte> SignatureRows => fields[10];
    internal byte[][] CopyFields() => fields.Select(value => value.ToArray()).ToArray();
    internal ReadOnlyMemory<byte> SigningInput => DeepIdV2PublicationLeaseCodec.SigningInput(fields);
}

public static class DeepIdV2PublicationLeaseCodec
{
    public const int MinimumBytes = 15_107;
    public const int MaximumBytes = 96_397;
    public const string WitnessSigningDomain = "Deep/ContactResolver/V2/publication-lease";
    private static ReadOnlySpan<int> FixedWidths => [16,32,32,32,8,8,32,32,-1,1,-1];

    public static ParsedDeepIdV2PublicationLease Decode(ReadOnlySpan<byte> canonical)
    {
        Span<ApplicationFieldSlice> slices = stackalloc ApplicationFieldSlice[11];
        ApplicationCoreFormat.Preflight(canonical, ProtocolMagicBytes.XPL1, 11,
            MinimumBytes, MaximumBytes, slices, 1, DeepIdV2Codec.Suite);
        var widths = FixedWidths;
        for (ushort tag = 1; tag <= 11; tag++)
            if (widths[tag - 1] >= 0) ApplicationCoreFormat.ExactLength(slices, tag, widths[tag - 1]);
        // Validate all outer bounds before owned field copies or nested parsing.
        var count = Get(canonical, slices, 10)[0];
        var originalBytes = Get(canonical, slices, 9);
        var rows = Get(canonical, slices, 11);
        if (count is < 2 or > 32 || rows.Length != count * 96 ||
            originalBytes.Length is < DeepIdV2ContactPublicationCodec.MinimumXpuLength or
                > DeepIdV2ContactPublicationCodec.MaximumXpuLength ||
            canonical.Length != 293 + originalBytes.Length + count * 96)
            throw new CryptographicException("Publication lease has invalid closed field bounds.");
        for (var tag = 1; tag <= 8; tag++)
            ApplicationCoreFormat.NonZero(Get(canonical, slices, tag), "Publication lease scope");
        var issued = BinaryPrimitives.ReadUInt64BigEndian(Get(canonical, slices, 5));
        var expires = BinaryPrimitives.ReadUInt64BigEndian(Get(canonical, slices, 6));
        if (expires <= issued || expires - issued > 120)
            throw new CryptographicException("Publication lease has an invalid short window.");
        for (var offset = 0; offset < rows.Length; offset += 96)
        {
            ApplicationCoreFormat.NonZero(rows.Slice(offset, 32), "Publication lease witness");
            ApplicationCoreFormat.NonZero(rows.Slice(offset + 32, 64), "Publication lease signature");
            if (offset > 0 && rows.Slice(offset - 96, 32).SequenceCompareTo(rows.Slice(offset, 32)) >= 0)
                throw new CryptographicException("Publication lease witnesses are not strictly ordered and distinct.");
        }
        var original = Xpu1Codec.Decode(originalBytes);
        if (original.UsageLimit != 0 || issued < original.IssuedAtUnixSeconds ||
            expires > original.EffectiveExpiresAtUnixSeconds ||
            !Fixed(original.NetworkId.Span, Get(canonical, slices, 1)) ||
            !Fixed(original.RequestHash.Span, Get(canonical, slices, 2)))
            throw new CryptographicException("Publication lease does not bind the exact reusable original intent.");
        var fields = new byte[11][];
        for (var tag = 1; tag <= 11; tag++) fields[tag - 1] = Get(canonical, slices, tag).ToArray();
        return new(canonical.ToArray(), fields, original);
    }

    internal static byte[] Encode(IReadOnlyList<ReadOnlyMemory<byte>> fields)
    {
        if (fields.Count != 11) throw new ArgumentException("Publication lease requires eleven canonical fields.");
        var bytes = Write(fields, 11);
        _ = Decode(bytes); return bytes;
    }

    internal static byte[] SigningInput(IReadOnlyList<byte[]> fields) =>
        ApplicationCoreFormat.SignatureInput(WitnessSigningDomain,
            Write(fields.Take(10).Select(value => (ReadOnlyMemory<byte>)value).ToArray(), 10), DeepIdV2Codec.Suite);

    internal static byte[] UnsignedSigningInput(IReadOnlyList<ReadOnlyMemory<byte>> fields) =>
        ApplicationCoreFormat.SignatureInput(WitnessSigningDomain, Write(fields, 10), DeepIdV2Codec.Suite);

    private static byte[] Write(IReadOnlyList<ReadOnlyMemory<byte>> fields, ushort count)
    {
        if (fields.Count != count || count is not (10 or 11)) throw new ArgumentException("Noncanonical lease field count.");
        var length = 12;
        for (var index = 0; index < fields.Count; index++) length = checked(length + 8 + fields[index].Length);
        if (length > MaximumBytes) throw new CryptographicException("Publication lease exceeds its closed size.");
        var bytes = new byte[length];
        var writer = new ApplicationRecordWriter(bytes, ProtocolMagicBytes.XPL1, count, 1, DeepIdV2Codec.Suite);
        for (ushort tag = 1; tag <= count; tag++) writer.Write(tag, fields[tag - 1].Span);
        writer.Complete(); return bytes;
    }
    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
    private static ReadOnlySpan<byte> Get(ReadOnlySpan<byte> canonical, ReadOnlySpan<ApplicationFieldSlice> slices, int tag) =>
        ApplicationCoreFormat.Field(canonical, slices, tag);
}
