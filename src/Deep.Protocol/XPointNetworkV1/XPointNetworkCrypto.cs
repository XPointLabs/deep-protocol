using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Deep.Protocol.XPointNetworkV1;

internal static class XPointNetworkCrypto
{
    internal static byte[] Sha256Domain(string domain, ReadOnlySpan<byte> payload)
    {
        var domainBytes = StrictAscii(domain);
        var preimage = new byte[checked(domainBytes.Length + 1 + 4 + payload.Length)];
        domainBytes.CopyTo(preimage, 0);
        BinaryPrimitives.WriteUInt32BigEndian(preimage.AsSpan(domainBytes.Length + 1), checked((uint)payload.Length));
        payload.CopyTo(preimage.AsSpan(domainBytes.Length + 5));
        return SHA256.HashData(preimage);
    }

    internal static byte[] SignatureInput(string domain, ushort suite, ReadOnlySpan<byte> canonicalProjection)
    {
        var domainBytes = StrictAscii(domain);
        var output = new byte[checked(domainBytes.Length + 1 + 2 + 4 + canonicalProjection.Length)];
        domainBytes.CopyTo(output, 0);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(domainBytes.Length + 1), suite);
        BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(domainBytes.Length + 3), checked((uint)canonicalProjection.Length));
        canonicalProjection.CopyTo(output.AsSpan(domainBytes.Length + 7));
        return output;
    }

    internal static byte[] Project(XPointParsedRecord record, int firstTag, int lastTag)
    {
        if (firstTag < 1 || lastTag < firstTag || lastTag > record.Definition.Fields.Count)
            throw new ArgumentOutOfRangeException(nameof(firstTag));
        var fieldBytes = 0;
        for (var tag = firstTag; tag <= lastTag; tag++)
            fieldBytes = checked(fieldBytes + XPointNetworkRegistry.FieldHeaderBytes + record.FieldSpan(tag).Length);
        var output = new byte[checked(XPointNetworkRegistry.HeaderBytes + fieldBytes)];
        Encoding.ASCII.GetBytes(record.Magic).CopyTo(output, 0);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(4), record.Definition.Version);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(6), record.Definition.Suite);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(8), checked((ushort)(lastTag - firstTag + 1)));
        var offset = XPointNetworkRegistry.HeaderBytes;
        for (var tag = firstTag; tag <= lastTag; tag++)
        {
            BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(offset), checked((ushort)tag));
            BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(offset + 4), checked((uint)record.FieldSpan(tag).Length));
            offset += XPointNetworkRegistry.FieldHeaderBytes;
            record.FieldSpan(tag).CopyTo(output.AsSpan(offset));
            offset += record.FieldSpan(tag).Length;
        }
        return output;
    }

    internal static byte[] ComputeCoreHash(XPointParsedRecord record)
    {
        var last = record.Definition.UnsignedLastTag == 0
            ? record.Definition.Fields.Count
            : record.Definition.UnsignedLastTag;
        return Sha256Domain(record.Definition.HashDomain, Project(record, 1, last));
    }

    internal static byte[] ComputeSigningInput(XPointParsedRecord record)
    {
        if (record.Definition.SignatureDomain is null || record.Definition.UnsignedLastTag == 0)
            throw new InvalidOperationException("The record has no signature projection.");
        return SignatureInput(record.Definition.SignatureDomain, record.Definition.Suite,
            Project(record, 1, record.Definition.UnsignedLastTag));
    }

    internal static byte[] ComputeArtifactHash(XPointParsedRecord record) => SHA256.HashData(record.CanonicalSpan);

    internal static byte[] Rfc6962Leaf(ReadOnlySpan<byte> payload)
    {
        var input = new byte[checked(payload.Length + 1)];
        payload.CopyTo(input.AsSpan(1));
        return SHA256.HashData(input);
    }

    internal static byte[] Rfc6962Inner(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
    {
        if (left.Length != 32 || right.Length != 32) throw new ArgumentException("Merkle nodes must be 32 bytes.");
        Span<byte> input = stackalloc byte[65];
        input[0] = 1;
        left.CopyTo(input[1..33]);
        right.CopyTo(input[33..]);
        return SHA256.HashData(input);
    }

    private static byte[] StrictAscii(string value)
    {
        if (string.IsNullOrEmpty(value) || value.Any(static c => c is < (char)0x21 or > (char)0x7e))
            throw new ArgumentException("A protocol domain must be nonempty printable ASCII.", nameof(value));
        return Encoding.ASCII.GetBytes(value);
    }
}
