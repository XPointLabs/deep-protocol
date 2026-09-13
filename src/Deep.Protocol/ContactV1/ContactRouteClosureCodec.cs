using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Deep.Protocol.ContactV1;

public sealed class ParsedContactRouteClosure
{
    private readonly byte[] exact;

    internal ParsedContactRouteClosure(
        ReadOnlySpan<byte> exact,
        ContactRecord reachability,
        ContactRecord authorization,
        ContactRecord route,
        ContactRecord successor,
        ContactRecord projection,
        ContactRecord selection)
    {
        this.exact = exact.ToArray();
        Reachability = reachability;
        Authorization = authorization;
        Route = route;
        Successor = successor;
        Projection = projection;
        Selection = selection;
    }

    public ReadOnlyMemory<byte> ExactBytes => exact.ToArray();
    public ReadOnlyMemory<byte> ExactHash => SHA256.HashData(exact);
    public ContactRecord Reachability { get; }
    public ContactRecord Authorization { get; }
    public ContactRecord Route { get; }
    public ContactRecord Successor { get; }
    public ContactRecord Projection { get; }
    public ContactRecord Selection { get; }
}

/// <summary>Canonical six-record XRR1/XRA1/XRC1/XSS1/PMT2/PMS2 closure framing.</summary>
public static class ContactRouteClosureCodec
{
    public const int MinimumEncodedBytes = 4_143;
    public const int MaximumEncodedBytes = 23_295;
    private static readonly string[] Magics =
    [
        ProtocolMagic.XRR1,
        ProtocolMagic.XRA1,
        ProtocolMagic.XRC1,
        ProtocolMagic.XSS1,
        ProtocolMagic.PMT2,
        ProtocolMagic.PMS2,
    ];

    public static byte[] Encode(VerifiedContactRouteClosure closure)
    {
        ArgumentNullException.ThrowIfNull(closure);
        var records = new[]
        {
            closure.Reachability,
            closure.Authorization,
            closure.Route,
            closure.Successor,
            closure.Projection,
            closure.Selection,
        };
        var size = checked(1 + records.Sum(record => 4 + record.CanonicalBytes.Length));
        if (size is < MinimumEncodedBytes or > MaximumEncodedBytes)
            throw new ContactFormatException(ContactValidationStage.Length, "RouteClosureLengthOutOfRange");
        var result = new byte[size];
        result[0] = 6;
        var offset = 1;
        foreach (var record in records)
        {
            BinaryPrimitives.WriteUInt32BigEndian(
                result.AsSpan(offset), checked((uint)record.CanonicalBytes.Length));
            offset += 4;
            record.CanonicalBytes.Span.CopyTo(result.AsSpan(offset));
            offset += record.CanonicalBytes.Length;
        }
        _ = Decode(result);
        return result;
    }

    public static ParsedContactRouteClosure Decode(ReadOnlySpan<byte> exact)
    {
        if (exact.Length is < MinimumEncodedBytes or > MaximumEncodedBytes || exact[0] != 6)
            throw new ContactFormatException(ContactValidationStage.Length, "RouteClosureLengthOutOfRange");
        var records = new ContactRecord[6];
        var offset = 1;
        for (var index = 0; index < records.Length; index++)
        {
            if (exact.Length - offset < 4)
                throw new ContactFormatException(ContactValidationStage.Bounds, "RouteClosureTruncated");
            var encodedLength = BinaryPrimitives.ReadUInt32BigEndian(exact.Slice(offset, 4));
            offset += 4;
            if (encodedLength > int.MaxValue || encodedLength > exact.Length - offset)
                throw new ContactFormatException(ContactValidationStage.Bounds, "RouteClosureTruncated");
            records[index] = ContactCodec.Decode(
                Magics[index], exact.Slice(offset, checked((int)encodedLength)));
            offset += checked((int)encodedLength);
        }
        if (offset != exact.Length)
            throw new ContactFormatException(ContactValidationStage.Bounds, "RouteClosureTrailingBytes");
        ContactCodec.ValidateRouteUpdateGraph(
            records[0], records[1], records[2], records[3], records[4], records[5]);
        return new ParsedContactRouteClosure(
            exact, records[0], records[1], records[2], records[3], records[4], records[5]);
    }
}
