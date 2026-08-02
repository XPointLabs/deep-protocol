using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Deep.Protocol.DeepExtension.MailboxTopology;

/// <summary>Strict fixed-size PRC1/PRA1 codecs. Signing APIs deliberately return transcripts only.</summary>
public static class ProductionMailboxRouteAdvertisementCodec
{
    private static ReadOnlySpan<byte> CertificateMagic => "PRC1"u8;
    private static ReadOnlySpan<byte> AdvertisementMagic => "PRA1"u8;
    private static ReadOnlySpan<byte> CertificateDomain =>
        "Deep/production-mailbox/route-certificate/v1"u8;
    private static ReadOnlySpan<byte> AdvertisementDomain =>
        "Deep/production-mailbox/route-advertisement/v1"u8;
    private static ReadOnlySpan<byte> RouteDomain =>
        "Deep/production-mailbox/route-domain/v1"u8;

    public static byte[] GetCertificateSigningBytes(ProductionMailboxRouteCertificate value)
    {
        var frozen = Freeze(value);
        ValidateCertificate(frozen, requireSignature: false);
        var payload = EncodeCertificateCore(frozen, includeSignature: false);
        return [.. CertificateDomain, .. payload];
    }

    public static byte[] EncodeCertificate(ProductionMailboxRouteCertificate value)
    {
        var frozen = Freeze(value);
        ValidateCertificate(frozen, requireSignature: true);
        return EncodeCertificateCore(frozen, includeSignature: true);
    }

    public static ProductionMailboxRouteCertificate DecodeCertificate(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length != ProductionMailboxRouteAdvertisementConstants.CanonicalCertificateLength)
            throw Error(ProductionMailboxRouteAdvertisementError.InvalidLength,
                "PRC1 must have its exact fixed length.");
        var frozen = encoded.ToArray();
        if (!frozen.AsSpan(0, 4).SequenceEqual(CertificateMagic))
            throw Error(ProductionMailboxRouteAdvertisementError.InvalidMagic, "PRC1 magic is invalid.");
        Header(frozen);
        var offset = 8;
        var value = new ProductionMailboxRouteCertificate
        {
            NetworkId = Read(frozen, ref offset, 16),
            AuthorityGeneration = ReadUInt64(frozen, ref offset),
            CanonicalAuthorityHash = Read(frozen, ref offset, 32),
            IssuerEd25519PublicKey = Read(frozen, ref offset, 32),
            MailboxOwnerEd25519PublicKey = Read(frozen, ref offset, 32),
            BlindedMailboxId = Read(frozen, ref offset, 32),
            BlindedPlacementId = Read(frozen, ref offset, 32),
            SelectionInputCommitment = Read(frozen, ref offset, 32),
            IssuedAtUnixSeconds = ReadUInt64(frozen, ref offset),
            ExpiresAtUnixSeconds = ReadUInt64(frozen, ref offset),
            IssuerSignature = Read(frozen, ref offset, 64)
        };
        if (offset != frozen.Length)
            throw Error(ProductionMailboxRouteAdvertisementError.InvalidLength, "PRC1 has trailing bytes.");
        ValidateCertificate(value, requireSignature: true);
        if (!frozen.AsSpan().SequenceEqual(EncodeCertificateCore(value, includeSignature: true)))
            throw Error(ProductionMailboxRouteAdvertisementError.NonCanonical, "PRC1 is not canonical.");
        return value;
    }

    public static byte[] ComputeCertificateCanonicalHash(ProductionMailboxRouteCertificate value) =>
        SHA256.HashData(EncodeCertificate(value));

    public static byte[] GetAdvertisementSigningBytes(ProductionMailboxRouteAdvertisement value)
    {
        var frozen = Freeze(value);
        ValidateAdvertisement(frozen, requireSignature: false);
        var payload = EncodeAdvertisementCore(frozen, includeSignature: false);
        return [.. AdvertisementDomain, .. payload];
    }

    public static byte[] EncodeAdvertisement(ProductionMailboxRouteAdvertisement value)
    {
        var frozen = Freeze(value);
        ValidateAdvertisement(frozen, requireSignature: true);
        return EncodeAdvertisementCore(frozen, includeSignature: true);
    }

    public static ProductionMailboxRouteAdvertisement DecodeAdvertisement(ReadOnlySpan<byte> encoded)
    {
        if (encoded.Length != ProductionMailboxRouteAdvertisementConstants.CanonicalAdvertisementLength)
            throw Error(ProductionMailboxRouteAdvertisementError.InvalidLength,
                "PRA1 must have its exact fixed length.");
        var frozen = encoded.ToArray();
        if (!frozen.AsSpan(0, 4).SequenceEqual(AdvertisementMagic))
            throw Error(ProductionMailboxRouteAdvertisementError.InvalidMagic, "PRA1 magic is invalid.");
        Header(frozen);
        var certificate = DecodeCertificate(frozen.AsSpan(8,
            ProductionMailboxRouteAdvertisementConstants.CanonicalCertificateLength));
        var offset = 8 + ProductionMailboxRouteAdvertisementConstants.CanonicalCertificateLength;
        var value = new ProductionMailboxRouteAdvertisement
        {
            Certificate = certificate,
            Sequence = ReadUInt64(frozen, ref offset),
            PublishedAtUnixSeconds = ReadUInt64(frozen, ref offset),
            ExpiresAtUnixSeconds = ReadUInt64(frozen, ref offset),
            OwnerSignature = Read(frozen, ref offset, 64)
        };
        if (offset != frozen.Length)
            throw Error(ProductionMailboxRouteAdvertisementError.InvalidLength, "PRA1 has trailing bytes.");
        ValidateAdvertisement(value, requireSignature: true);
        if (!frozen.AsSpan().SequenceEqual(EncodeAdvertisementCore(value, includeSignature: true)))
            throw Error(ProductionMailboxRouteAdvertisementError.NonCanonical, "PRA1 is not canonical.");
        return value;
    }

    public static byte[] ComputeAdvertisementCanonicalHash(ProductionMailboxRouteAdvertisement value) =>
        SHA256.HashData(EncodeAdvertisement(value));

    /// <summary>
    /// Stable durable-state scope. Authority/topology/holder and validity are deliberately excluded
    /// so the same owner route retains rollback protection across ordinary control-plane rotation.
    /// </summary>
    public static byte[] ComputeRouteDomainHash(ProductionMailboxRouteCertificate value)
    {
        var frozen = Freeze(value);
        ValidateCertificate(frozen, requireSignature: true);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        hash.AppendData(RouteDomain);
        hash.AppendData(frozen.NetworkId.Span);
        hash.AppendData(frozen.MailboxOwnerEd25519PublicKey.Span);
        hash.AppendData(frozen.BlindedMailboxId.Span);
        hash.AppendData(frozen.BlindedPlacementId.Span);
        hash.AppendData(frozen.SelectionInputCommitment.Span);
        return hash.GetHashAndReset();
    }

    private static byte[] EncodeCertificateCore(ProductionMailboxRouteCertificate value, bool includeSignature)
    {
        var length = includeSignature
            ? ProductionMailboxRouteAdvertisementConstants.CanonicalCertificateLength
            : ProductionMailboxRouteAdvertisementConstants.CanonicalCertificateLength - 64;
        var output = new byte[length];
        CertificateMagic.CopyTo(output); output[4] = ProductionMailboxRouteAdvertisementConstants.Version;
        var offset = 8;
        Write(value.NetworkId.Span, output, ref offset);
        WriteUInt64(value.AuthorityGeneration, output, ref offset);
        Write(value.CanonicalAuthorityHash.Span, output, ref offset);
        Write(value.IssuerEd25519PublicKey.Span, output, ref offset);
        Write(value.MailboxOwnerEd25519PublicKey.Span, output, ref offset);
        Write(value.BlindedMailboxId.Span, output, ref offset);
        Write(value.BlindedPlacementId.Span, output, ref offset);
        Write(value.SelectionInputCommitment.Span, output, ref offset);
        WriteUInt64(value.IssuedAtUnixSeconds, output, ref offset);
        WriteUInt64(value.ExpiresAtUnixSeconds, output, ref offset);
        if (includeSignature) Write(value.IssuerSignature.Span, output, ref offset);
        return output;
    }

    private static byte[] EncodeAdvertisementCore(ProductionMailboxRouteAdvertisement value, bool includeSignature)
    {
        var length = includeSignature
            ? ProductionMailboxRouteAdvertisementConstants.CanonicalAdvertisementLength
            : ProductionMailboxRouteAdvertisementConstants.CanonicalAdvertisementLength - 64;
        var output = new byte[length];
        AdvertisementMagic.CopyTo(output); output[4] = ProductionMailboxRouteAdvertisementConstants.Version;
        var offset = 8;
        Write(EncodeCertificateCore(value.Certificate, includeSignature: true), output, ref offset);
        WriteUInt64(value.Sequence, output, ref offset);
        WriteUInt64(value.PublishedAtUnixSeconds, output, ref offset);
        WriteUInt64(value.ExpiresAtUnixSeconds, output, ref offset);
        if (includeSignature) Write(value.OwnerSignature.Span, output, ref offset);
        return output;
    }

    private static void ValidateCertificate(ProductionMailboxRouteCertificate value, bool requireSignature)
    {
        ArgumentNullException.ThrowIfNull(value);
        FixedNonzero(value.NetworkId, 16, "network ID");
        if (value.AuthorityGeneration == 0)
            throw Error(ProductionMailboxRouteAdvertisementError.InvalidField,
                "Authority generation must be non-zero.");
        FixedNonzero(value.CanonicalAuthorityHash, 32, "authority hash");
        FixedNonzero(value.IssuerEd25519PublicKey, 32, "issuer key");
        FixedNonzero(value.MailboxOwnerEd25519PublicKey, 32, "mailbox owner key");
        FixedNonzero(value.BlindedMailboxId, 32, "blinded mailbox ID");
        FixedNonzero(value.BlindedPlacementId, 32, "blinded placement ID");
        FixedNonzero(value.SelectionInputCommitment, 32, "selection input commitment");
        ValidateWindow(value.IssuedAtUnixSeconds, value.ExpiresAtUnixSeconds, "PRC1");
        Fixed(value.IssuerSignature, 64, "issuer signature");
        if (requireSignature && value.IssuerSignature.Span.IndexOfAnyExcept((byte)0) < 0)
            throw Error(ProductionMailboxRouteAdvertisementError.InvalidField,
                "Issuer signature is all zero.");
    }

    private static void ValidateAdvertisement(ProductionMailboxRouteAdvertisement value, bool requireSignature)
    {
        ArgumentNullException.ThrowIfNull(value);
        ArgumentNullException.ThrowIfNull(value.Certificate);
        ValidateCertificate(value.Certificate, requireSignature: true);
        if (value.Sequence == 0)
            throw Error(ProductionMailboxRouteAdvertisementError.InvalidField,
                "Advertisement sequence must be non-zero.");
        ValidateWindow(value.PublishedAtUnixSeconds, value.ExpiresAtUnixSeconds, "PRA1");
        if (value.PublishedAtUnixSeconds < value.Certificate.IssuedAtUnixSeconds ||
            value.ExpiresAtUnixSeconds > value.Certificate.ExpiresAtUnixSeconds)
            throw Error(ProductionMailboxRouteAdvertisementError.InvalidValidityWindow,
                "PRA1 lifetime must be contained by PRC1.");
        Fixed(value.OwnerSignature, 64, "owner signature");
        if (requireSignature && value.OwnerSignature.Span.IndexOfAnyExcept((byte)0) < 0)
            throw Error(ProductionMailboxRouteAdvertisementError.InvalidField,
                "Owner signature is all zero.");
    }

    private static void ValidateWindow(ulong from, ulong until, string name)
    {
        if (from == 0 || until <= from || until - from > ProductionMailboxRouteAdvertisementConstants.MaximumLifetimeSeconds)
            throw Error(ProductionMailboxRouteAdvertisementError.InvalidValidityWindow,
                $"{name} validity window is invalid or too long.");
    }

    private static ProductionMailboxRouteCertificate Freeze(ProductionMailboxRouteCertificate value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return ProductionMailboxRouteAdvertisementCopy.Clone(value);
    }

    private static ProductionMailboxRouteAdvertisement Freeze(ProductionMailboxRouteAdvertisement value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return ProductionMailboxRouteAdvertisementCopy.Clone(value);
    }

    private static void Header(ReadOnlySpan<byte> encoded)
    {
        if (encoded[4] != ProductionMailboxRouteAdvertisementConstants.Version)
            throw Error(ProductionMailboxRouteAdvertisementError.UnsupportedVersion,
                "PRC1/PRA1 version is unsupported.");
        if (encoded.Slice(5, 3).IndexOfAnyExcept((byte)0) >= 0)
            throw Error(ProductionMailboxRouteAdvertisementError.ReservedFieldNotZero,
                "PRC1/PRA1 reserved bytes must be zero.");
    }

    private static ReadOnlyMemory<byte> Read(byte[] input, ref int offset, int length)
    {
        var value = input.AsSpan(offset, length).ToArray(); offset += length; return value;
    }

    private static ulong ReadUInt64(byte[] input, ref int offset)
    {
        var value = BinaryPrimitives.ReadUInt64BigEndian(input.AsSpan(offset, 8)); offset += 8; return value;
    }

    private static void Write(ReadOnlySpan<byte> value, byte[] output, ref int offset)
    {
        value.CopyTo(output.AsSpan(offset)); offset += value.Length;
    }

    private static void WriteUInt64(ulong value, byte[] output, ref int offset)
    {
        BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(offset, 8), value); offset += 8;
    }

    private static void FixedNonzero(ReadOnlyMemory<byte> value, int length, string name)
    {
        Fixed(value, length, name);
        if (value.Span.IndexOfAnyExcept((byte)0) < 0)
            throw Error(ProductionMailboxRouteAdvertisementError.InvalidField, $"{name} is all zero.");
    }

    private static void Fixed(ReadOnlyMemory<byte> value, int length, string name)
    {
        if (value.Length != length)
            throw Error(ProductionMailboxRouteAdvertisementError.InvalidField, $"{name} length is invalid.");
    }

    private static ProductionMailboxRouteAdvertisementException Error(
        ProductionMailboxRouteAdvertisementError error,
        string message) => new(error, message);
}
