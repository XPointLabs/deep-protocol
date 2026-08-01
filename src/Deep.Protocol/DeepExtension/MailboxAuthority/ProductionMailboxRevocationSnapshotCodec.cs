using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.DeepExtension.MailboxCapabilities;

namespace Deep.Protocol.DeepExtension.MailboxAuthority;

/// <summary>Strict fixed-order PMR1 binary codec. There are no optional or extension fields.</summary>
public static class ProductionMailboxRevocationSnapshotCodec
{
    private static ReadOnlySpan<byte> Magic => "PMR1"u8;

    public static byte[] GetSigningBytes(ProductionMailboxRevocationSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        Validate(snapshot, requireSignature: false);
        var writer = new Writer();
        WriteHeader(writer);
        WriteStatement(writer, snapshot);
        return writer.ToArray();
    }

    public static byte[] Encode(ProductionMailboxRevocationSnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        Validate(snapshot, requireSignature: true);
        var writer = new Writer();
        WriteHeader(writer);
        WriteStatement(writer, snapshot);
        writer.Fixed(snapshot.IssuerSignature.Span, ProductionMailboxAuthorityConstants.Ed25519SignatureLength, "issuer signature");
        return writer.ToArray();
    }

    public static ProductionMailboxRevocationSnapshot Decode(ReadOnlySpan<byte> encoded)
    {
        var reader = new Reader(encoded);
        reader.Magic(Magic);
        if (reader.Byte() != ProductionMailboxRevocationSnapshotConstants.Version)
            throw Error(ProductionMailboxRevocationSnapshotError.UnsupportedVersion, "Unsupported PMR1 version.");
        reader.Zero(3);
        var networkId = reader.Fixed(ProductionMailboxAuthorityConstants.NetworkIdLength);
        var authorityGeneration = reader.UInt64();
        var authorityBindingHash = reader.Fixed(ProductionMailboxAuthorityConstants.HashLength);
        var revocationGeneration = reader.UInt64();
        var head = reader.Fixed(ProductionMailboxAuthorityConstants.HashLength);
        var previousHead = reader.Fixed(ProductionMailboxAuthorityConstants.HashLength);
        var issued = reader.UInt64();
        var expires = reader.UInt64();
        var count = reader.UInt16();
        reader.Zero(2);
        if (count > ProductionMailboxRevocationSnapshotConstants.MaximumRevokedGrantSerials)
            throw Error(ProductionMailboxRevocationSnapshotError.InvalidLength, "PMR1 serial count exceeds the bound.");
        var serials = new ReadOnlyMemory<byte>[count];
        for (var index = 0; index < count; index++)
            serials[index] = reader.Fixed(MailboxAuthenticatedCapabilityLimits.SerialLength);
        var result = new ProductionMailboxRevocationSnapshot
        {
            NetworkId = networkId,
            AuthorityGeneration = authorityGeneration,
            AuthorityBindingHash = authorityBindingHash,
            RevocationGeneration = revocationGeneration,
            RevocationHeadHash = head,
            PreviousRevocationHeadHash = previousHead,
            IssuedAtUnixSeconds = issued,
            ExpiresAtUnixSeconds = expires,
            RevokedGrantSerials = serials,
            IssuerSignature = reader.Fixed(ProductionMailboxAuthorityConstants.Ed25519SignatureLength)
        };
        reader.End();
        Validate(result, requireSignature: true);
        if (!encoded.SequenceEqual(Encode(result)))
            throw Error(ProductionMailboxRevocationSnapshotError.NonCanonical, "PMR1 encoding is not canonical.");
        return result;
    }

    public static byte[] ComputeCanonicalHash(ProductionMailboxRevocationSnapshot snapshot) =>
        SHA256.HashData(Encode(snapshot));

    public static byte[] ComputeAuthorityBindingHash(ProductionMailboxAuthority authority) =>
        ProductionMailboxAuthorityCodec.ComputeRevocationBindingHash(authority);

    private static void WriteHeader(Writer writer)
    {
        writer.Bytes(Magic);
        writer.Byte(ProductionMailboxRevocationSnapshotConstants.Version);
        writer.Zero(3);
    }

    private static void WriteStatement(Writer writer, ProductionMailboxRevocationSnapshot value)
    {
        writer.Fixed(value.NetworkId.Span, ProductionMailboxAuthorityConstants.NetworkIdLength, "network ID");
        writer.UInt64(value.AuthorityGeneration);
        writer.Fixed(value.AuthorityBindingHash.Span, ProductionMailboxAuthorityConstants.HashLength, "authority binding hash");
        writer.UInt64(value.RevocationGeneration);
        writer.Fixed(value.RevocationHeadHash.Span, ProductionMailboxAuthorityConstants.HashLength, "revocation head");
        writer.Fixed(value.PreviousRevocationHeadHash.Span, ProductionMailboxAuthorityConstants.HashLength, "previous revocation head");
        writer.UInt64(value.IssuedAtUnixSeconds);
        writer.UInt64(value.ExpiresAtUnixSeconds);
        writer.UInt16(checked((ushort)value.RevokedGrantSerials.Count));
        writer.Zero(2);
        foreach (var serial in value.RevokedGrantSerials)
            writer.Fixed(serial.Span, MailboxAuthenticatedCapabilityLimits.SerialLength, "MCG2 serial");
    }

    private static void Validate(ProductionMailboxRevocationSnapshot value, bool requireSignature)
    {
        Require(value.NetworkId, ProductionMailboxAuthorityConstants.NetworkIdLength, "network ID");
        Require(value.AuthorityBindingHash, ProductionMailboxAuthorityConstants.HashLength, "authority binding hash");
        Require(value.RevocationHeadHash, ProductionMailboxAuthorityConstants.HashLength, "revocation head");
        Require(value.PreviousRevocationHeadHash, ProductionMailboxAuthorityConstants.HashLength, "previous revocation head");
        if (value.AuthorityGeneration == 0 || value.RevocationGeneration == 0 ||
            value.IssuedAtUnixSeconds == 0 || value.IssuedAtUnixSeconds >= value.ExpiresAtUnixSeconds ||
            value.ExpiresAtUnixSeconds - value.IssuedAtUnixSeconds > ProductionMailboxAuthorityConstants.MaximumRevocationSnapshotLifetimeSeconds ||
            CryptographicOperations.FixedTimeEquals(value.RevocationHeadHash.Span, value.PreviousRevocationHeadHash.Span))
            throw Error(ProductionMailboxRevocationSnapshotError.InvalidField, "PMR1 generations, heads, or validity are invalid.");
        if (value.RevokedGrantSerials is null || value.RevokedGrantSerials.Count > ProductionMailboxRevocationSnapshotConstants.MaximumRevokedGrantSerials)
            throw Error(ProductionMailboxRevocationSnapshotError.InvalidLength, "PMR1 serial count exceeds the bound.");
        byte[]? previous = null;
        foreach (var serial in value.RevokedGrantSerials)
        {
            Require(serial, MailboxAuthenticatedCapabilityLimits.SerialLength, "MCG2 serial");
            if (previous is not null && previous.AsSpan().SequenceCompareTo(serial.Span) >= 0)
                throw Error(ProductionMailboxRevocationSnapshotError.InvalidSerialOrder, "PMR1 serials must be strictly ordered and distinct.");
            previous = serial.ToArray();
        }
        if (requireSignature)
            Require(value.IssuerSignature, ProductionMailboxAuthorityConstants.Ed25519SignatureLength, "issuer signature");
    }

    private static void Require(ReadOnlyMemory<byte> value, int length, string name)
    {
        if (value.Length != length || value.Span.IndexOfAnyExcept((byte)0) < 0)
            throw Error(ProductionMailboxRevocationSnapshotError.InvalidField, $"{name} is invalid or all-zero.");
    }

    private static ProductionMailboxRevocationSnapshotException Error(
        ProductionMailboxRevocationSnapshotError error,
        string message) => new(error, message);

    private sealed class Writer
    {
        private readonly List<byte> _bytes = [];
        public void Byte(byte value) => _bytes.Add(value);
        public void UInt16(ushort value)
        {
            Span<byte> bytes = stackalloc byte[sizeof(ushort)];
            BinaryPrimitives.WriteUInt16LittleEndian(bytes, value);
            Bytes(bytes);
        }
        public void UInt64(ulong value)
        {
            Span<byte> bytes = stackalloc byte[sizeof(ulong)];
            BinaryPrimitives.WriteUInt64LittleEndian(bytes, value);
            Bytes(bytes);
        }
        public void Zero(int count) { for (var index = 0; index < count; index++) _bytes.Add(0); }
        public void Bytes(ReadOnlySpan<byte> value) { foreach (var item in value) _bytes.Add(item); }
        public void Fixed(ReadOnlySpan<byte> value, int length, string name)
        {
            if (value.Length != length)
                throw Error(ProductionMailboxRevocationSnapshotError.InvalidLength, $"{name} length is invalid.");
            Bytes(value);
        }
        public byte[] ToArray() => _bytes.ToArray();
    }

    private ref struct Reader(ReadOnlySpan<byte> source)
    {
        private ReadOnlySpan<byte> _remaining = source;
        public byte Byte()
        {
            if (_remaining.IsEmpty)
                throw Error(ProductionMailboxRevocationSnapshotError.InvalidLength, "Unexpected end of PMR1.");
            var result = _remaining[0];
            _remaining = _remaining[1..];
            return result;
        }
        public ushort UInt16() => BinaryPrimitives.ReadUInt16LittleEndian(Fixed(sizeof(ushort)).Span);
        public ulong UInt64() => BinaryPrimitives.ReadUInt64LittleEndian(Fixed(sizeof(ulong)).Span);
        public ReadOnlyMemory<byte> Fixed(int count)
        {
            if (count < 0 || _remaining.Length < count)
                throw Error(ProductionMailboxRevocationSnapshotError.InvalidLength, "Unexpected end of PMR1.");
            var result = _remaining[..count].ToArray();
            _remaining = _remaining[count..];
            return result;
        }
        public void Magic(ReadOnlySpan<byte> magic)
        {
            if (!Fixed(magic.Length).Span.SequenceEqual(magic))
                throw Error(ProductionMailboxRevocationSnapshotError.InvalidMagic, "PMR1 magic is invalid.");
        }
        public void Zero(int count)
        {
            if (Fixed(count).Span.IndexOfAnyExcept((byte)0) >= 0)
                throw Error(ProductionMailboxRevocationSnapshotError.ReservedFieldNotZero, "PMR1 reserved field is non-zero.");
        }
        public void End()
        {
            if (!_remaining.IsEmpty)
                throw Error(ProductionMailboxRevocationSnapshotError.NonCanonical, "PMR1 has trailing bytes.");
        }
    }
}
