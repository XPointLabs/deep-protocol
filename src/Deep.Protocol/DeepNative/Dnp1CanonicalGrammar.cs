using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Deep.Protocol.DeepNative;

internal static class CanonicalGrammar
{
    internal const int HeaderLength = 12;
    internal const int FieldHeaderLength = 8;
    internal const int HashLength = 32;
    internal const int SignatureLength = 64;

    internal static OwnedRecord DecodeOwned(
        ReadOnlySpan<byte> encoded,
        RecordDefinition definition)
    {
        Preflight(encoded, definition);
        var owned = encoded.ToArray();
        Preflight(owned, definition);
        return new OwnedRecord(definition, owned);
    }

    internal static void Preflight(
        ReadOnlySpan<byte> encoded,
        RecordDefinition definition)
    {
        ArgumentNullException.ThrowIfNull(definition);
        if (encoded.Length < HeaderLength ||
            encoded.Length < definition.MinimumLength ||
            encoded.Length > definition.MaximumLength)
            throw Error(RecordError.InvalidLength, "The DNP1 record length is invalid.");
        if (definition.Magic.Length != 4 ||
            encoded[0] != (byte)definition.Magic[0] ||
            encoded[1] != (byte)definition.Magic[1] ||
            encoded[2] != (byte)definition.Magic[2] ||
            encoded[3] != (byte)definition.Magic[3])
            throw Error(RecordError.InvalidMagic, "The DNP1 record magic is invalid.");
        if (BinaryPrimitives.ReadUInt16BigEndian(encoded[4..6]) != definition.Version)
            throw Error(RecordError.UnsupportedVersion, "The DNP1 record version is unsupported.");
        if (BinaryPrimitives.ReadUInt16BigEndian(encoded[6..8]) != definition.Suite)
            throw Error(RecordError.UnsupportedSuite, "The DNP1 record suite is unsupported.");
        if (BinaryPrimitives.ReadUInt16BigEndian(encoded[8..10]) != definition.Fields.Count ||
            BinaryPrimitives.ReadUInt16BigEndian(encoded[10..12]) != 0)
            throw Error(RecordError.InvalidHeader, "The DNP1 record header is noncanonical.");

        var offset = HeaderLength;
        for (var index = 0; index < definition.Fields.Count; index++)
        {
            if (encoded.Length - offset < FieldHeaderLength)
                throw Error(RecordError.InvalidLength, "A DNP1 field header is truncated.");
            var expectedTag = checked((ushort)(index + 1));
            var tag = BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(offset, 2));
            var flags = BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(offset + 2, 2));
            var length = BinaryPrimitives.ReadUInt32BigEndian(encoded.Slice(offset + 4, 4));
            var field = definition.Fields[index];
            if (tag != expectedTag || flags != 0)
                throw Error(RecordError.InvalidTag, "DNP1 tags and flags are noncanonical.");
            if (length > int.MaxValue || length < field.MinimumLength || length > field.MaximumLength)
                throw Error(RecordError.InvalidLength, "A DNP1 field length is outside its bound.");
            offset = checked(offset + FieldHeaderLength + (int)length);
            if (offset > encoded.Length)
                throw Error(RecordError.InvalidLength, "A DNP1 field is truncated.");
        }
        if (offset != encoded.Length)
            throw Error(RecordError.InvalidLength, "A DNP1 record has trailing bytes.");
        RecordDefinitions.ValidateDynamic(encoded, definition);
    }

    internal static byte[] Encode(
        RecordDefinition definition,
        IReadOnlyList<ReadOnlyMemory<byte>> fields)
    {
        ArgumentNullException.ThrowIfNull(definition);
        ArgumentNullException.ThrowIfNull(fields);
        if (fields.Count != definition.Fields.Count)
            throw Error(RecordError.InvalidField, "The DNP1 field count is invalid.");
        var length = HeaderLength;
        for (var index = 0; index < fields.Count; index++)
        {
            var bound = definition.Fields[index];
            if (fields[index].Length < bound.MinimumLength || fields[index].Length > bound.MaximumLength)
                throw Error(RecordError.InvalidLength, "A DNP1 field length is outside its bound.");
            length = checked(length + FieldHeaderLength + fields[index].Length);
        }
        if (length < definition.MinimumLength || length > definition.MaximumLength)
            throw Error(RecordError.InvalidLength, "The DNP1 encoded length is outside its bound.");

        var output = new byte[length];
        Encoding.ASCII.GetBytes(definition.Magic).CopyTo(output, 0);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(4, 2), definition.Version);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(6, 2), definition.Suite);
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(8, 2), checked((ushort)fields.Count));
        var offset = HeaderLength;
        for (var index = 0; index < fields.Count; index++)
        {
            BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(offset, 2), checked((ushort)(index + 1)));
            BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(offset + 4, 4), checked((uint)fields[index].Length));
            offset += FieldHeaderLength;
            fields[index].Span.CopyTo(output.AsSpan(offset));
            offset += fields[index].Length;
        }
        Preflight(output, definition);
        return output;
    }

    internal static byte[] GetSigningBytes(
        OwnedRecord record,
        string domain)
    {
        ArgumentNullException.ThrowIfNull(record);
        ValidateDomain(domain);
        var unsignedFields = new List<ReadOnlyMemory<byte>>();
        for (var index = 0; index < record.Definition.Fields.Count; index++)
        {
            if (!record.Definition.OmittedSigningFieldIndexes.Contains(index + 1))
                unsignedFields.Add(record.FieldCopy(index + 1));
        }
        var unsignedDefinition = record.Definition with
        {
            Fields = record.Definition.Fields
                .Where((_, index) => !record.Definition.OmittedSigningFieldIndexes.Contains(index + 1))
                .ToArray(),
            MinimumLength = HeaderLength,
            MaximumLength = record.Definition.MaximumLength
        };
        var unsigned = Encode(unsignedDefinition, unsignedFields);
        var domainBytes = Encoding.ASCII.GetBytes(domain);
        var output = new byte[2 + domainBytes.Length + 2 + 4 + unsigned.Length];
        BinaryPrimitives.WriteUInt16BigEndian(output, checked((ushort)domainBytes.Length));
        domainBytes.CopyTo(output, 2);
        var offset = 2 + domainBytes.Length;
        BinaryPrimitives.WriteUInt16BigEndian(output.AsSpan(offset, 2), ArtifactRegistry.IdentityAuthV1Ed25519);
        offset += 2;
        BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(offset, 4), checked((uint)unsigned.Length));
        unsigned.CopyTo(output, offset + 4);
        return output;
    }

    internal static byte[] Sha256Domain(string domain, ReadOnlySpan<byte> payload)
    {
        ValidateDomain(domain);
        var domainBytes = Encoding.ASCII.GetBytes(domain);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        Span<byte> scalar = stackalloc byte[4];
        BinaryPrimitives.WriteUInt16BigEndian(scalar[..2], checked((ushort)domainBytes.Length));
        hash.AppendData(scalar[..2]);
        hash.AppendData(domainBytes);
        BinaryPrimitives.WriteUInt32BigEndian(scalar, checked((uint)payload.Length));
        hash.AppendData(scalar);
        hash.AppendData(payload);
        return hash.GetHashAndReset();
    }

    internal static byte[] ComputeProtectedHmac(OwnedRecord record, ReadOnlySpan<byte> key)
    {
        ArgumentNullException.ThrowIfNull(record);
        if (record.Definition.RecordClass != RecordClass.ProtectedHmac ||
            key.Length != 32 || record.Definition.Fields.Count == 0 ||
            record.Definition.Fields[^1].Name != "hmac" ||
            record.FieldSpan(record.Definition.Fields.Count).Length != 32)
            throw Error(RecordError.InvalidField, "The protected HMAC input is invalid.");

        var domainBytes = Encoding.ASCII.GetBytes(
            ArtifactRegistry.GetProtectedDomain(record.Definition.Magic));
        var finalFieldLength = FieldHeaderLength + 32;
        var unsignedLength = checked(record.CanonicalSpan.Length - finalFieldLength);
        Span<byte> prefix = stackalloc byte[2 + 2 + 4];
        BinaryPrimitives.WriteUInt16BigEndian(prefix[..2], checked((ushort)domainBytes.Length));
        BinaryPrimitives.WriteUInt16BigEndian(prefix.Slice(2, 2), ArtifactRegistry.ProtectedHmacSha256);
        BinaryPrimitives.WriteUInt32BigEndian(prefix.Slice(4, 4), checked((uint)unsignedLength));

        Span<byte> header = stackalloc byte[HeaderLength];
        record.CanonicalSpan[..HeaderLength].CopyTo(header);
        BinaryPrimitives.WriteUInt16BigEndian(header.Slice(8, 2),
            checked((ushort)(record.Definition.Fields.Count - 1)));
        var ownedKey = key.ToArray();
        try
        {
            using var hmac = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, ownedKey);
            hmac.AppendData(prefix[..2]);
            hmac.AppendData(domainBytes);
            hmac.AppendData(prefix[2..]);
            hmac.AppendData(header);
            hmac.AppendData(record.CanonicalSpan.Slice(HeaderLength,
                unsignedLength - HeaderLength));
            return hmac.GetHashAndReset();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(ownedKey);
        }
    }

    internal static void VerifyProtectedHmac(OwnedRecord record, ReadOnlySpan<byte> key)
    {
        var expected = ComputeProtectedHmac(record, key);
        if (!FixedEquals(expected, record.FieldSpan(record.Definition.Fields.Count)))
            throw Error(RecordError.InvalidSignature, "The protected-state HMAC is invalid.");
    }

    internal static ArtifactReference ComputeReference(
        ArtifactType type,
        ReadOnlySpan<byte> canonical)
    {
        if (ArtifactRegistry.IsRetained(type))
            throw Error(
                RecordError.InvalidArtifactReference,
                "Retained artifacts require their unchanged reviewed hash rule.");
        return new ArtifactReference(
            type,
            checked((uint)canonical.Length),
            Sha256Domain(ArtifactRegistry.GetNewArtifactDomain(type), canonical));
    }

    internal static ArtifactReference DecodeReference(
        ReadOnlySpan<byte> encoded,
        bool allowZero = false)
    {
        if (encoded.Length != ArtifactReference.Length)
            throw Error(RecordError.InvalidArtifactReference, "The artifact reference length is invalid.");
        var typeValue = BinaryPrimitives.ReadUInt16BigEndian(encoded);
        var length = BinaryPrimitives.ReadUInt32BigEndian(encoded[2..6]);
        var hash = encoded[6..38];
        if (typeValue == 0 && length == 0 && IsZero(hash))
        {
            if (!allowZero)
                throw Error(RecordError.InvalidArtifactReference, "A zero predecessor is not allowed here.");
            return default;
        }
        if (!Enum.IsDefined(typeof(ArtifactType), typeValue))
            throw Error(RecordError.InvalidArtifactReference, "The artifact reference type is unknown.");
        return new ArtifactReference((ArtifactType)typeValue, length, hash);
    }

    internal static byte[] EncodeReference(ArtifactReference reference)
    {
        if (reference.IsZero) return new byte[ArtifactReference.Length];
        var output = new byte[ArtifactReference.Length];
        BinaryPrimitives.WriteUInt16BigEndian(output, (ushort)reference.Type);
        BinaryPrimitives.WriteUInt32BigEndian(output.AsSpan(2), reference.CanonicalLength);
        reference.CanonicalHash.Span.CopyTo(output.AsSpan(6));
        return output;
    }

    internal static bool FixedEquals(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);

    internal static bool IsZero(ReadOnlySpan<byte> value)
    {
        byte combined = 0;
        foreach (var item in value) combined |= item;
        return combined == 0;
    }

    private static void ValidateDomain(string domain)
    {
        if (string.IsNullOrEmpty(domain) || domain.Any(static value => value > 0x7f) ||
            Encoding.ASCII.GetByteCount(domain) > ushort.MaxValue)
            throw Error(RecordError.InvalidField, "The DNP1 domain is invalid.");
    }

    private static RecordException Error(RecordError error, string message) =>
        new(error, message);
}
