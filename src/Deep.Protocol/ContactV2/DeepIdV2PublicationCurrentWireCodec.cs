using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;

namespace Deep.Protocol.ContactV2;

/// <summary>Canonical current submission bytes only. Not owner, witness,
/// journal, dispatch or noncommit authority.</summary>
public sealed class PublicationCurrentWireRequest
{
    private readonly byte[] exact;
    internal PublicationCurrentWireRequest(byte[] exact) => this.exact = exact;
    public ReadOnlyMemory<byte> CanonicalBytes => exact.ToArray();
    public ReadOnlyMemory<byte> NetworkId => Copy(8, 16);
    public ReadOnlyMemory<byte> RequestNonce => Copy(24, 32);
    public ReadOnlyMemory<byte> DirectoryLookupKey => Copy(56, 32);
    public ulong MinimumDirectoryGeneration => BinaryPrimitives.ReadUInt64BigEndian(exact.AsSpan(88));
    public ReadOnlyMemory<byte> MinimumDirectoryHash => Copy(96, 32);
    public ReadOnlyMemory<byte> ViewHash => Copy(128, 32);
    public ulong IssuedAtUnixSeconds => BinaryPrimitives.ReadUInt64BigEndian(exact.AsSpan(160));
    public ulong ExpiresAtUnixSeconds => BinaryPrimitives.ReadUInt64BigEndian(exact.AsSpan(168));
    public ContactPublicationAuthorityWireRequest OriginalRequest =>
        ContactPublicationAuthorityWireCodec.DecodeRequest(exact.AsSpan(180, exact.Length - 244));
    public ReadOnlyMemory<byte> PublisherSignature => Copy(exact.Length - 64, 64);
    public ReadOnlyMemory<byte> GatewayShard =>
        DeepIdV2PublicationCurrentWireCodec.GatewayShard(NetworkId.Span, RequestNonce.Span);
    internal ReadOnlyMemory<byte> SigningInput => DeepIdV2PublicationCurrentWireCodec.PublisherSigningInput(exact);
    private byte[] Copy(int offset, int count) => exact.AsSpan(offset, count).ToArray();
}

public static class DeepIdV2PublicationCurrentWireCodec
{
    public const int RequestFixedOverheadBytes = 244;
    public const int MinimumRequestBytes = RequestFixedOverheadBytes + ContactPublicationAuthorityWireCodec.MinimumRequestBytes;
    public const int MaximumRequestBytes = RequestFixedOverheadBytes + ContactPublicationAuthorityWireCodec.MaximumRequestBytes;
    public const int MinimumResponseBytes = 60 + DeepIdV2PublicationLeaseCodec.MinimumBytes;
    public const int MaximumResponseBytes = 60 + DeepIdV2PublicationLeaseCodec.MaximumBytes;
    public const string EndpointPath = "/api/v2/contact-publication-current";
    public const string RequestMediaType = "application/vnd.deep.contact-publication-current-request.v1+octet-stream";
    public const string ResponseMediaType = "application/vnd.deep.contact-publication-current-response.v1+octet-stream";
    public const string PublisherSigningDomain = "Deep/ContactResolver/V2/publication-current-request";
    public const string GatewayShardDomain = "Deep/ContactResolver/V2/publication-current-gateway";

    public static PublicationCurrentWireRequest DecodeRequest(ReadOnlySpan<byte> encoded)
    {
        Header(encoded, MinimumRequestBytes, MaximumRequestBytes);
        var originalLength = BinaryPrimitives.ReadUInt32BigEndian(encoded[176..]);
        if (originalLength != encoded.Length - RequestFixedOverheadBytes ||
            originalLength is < ContactPublicationAuthorityWireCodec.MinimumRequestBytes or > ContactPublicationAuthorityWireCodec.MaximumRequestBytes)
            throw new FormatException("Current publication original length is not canonical.");
        foreach (var (offset, length) in new[] { (8,16),(24,32),(56,32),(96,32),(128,32),(encoded.Length-64,64) })
            if (encoded.Slice(offset, length).IndexOfAnyExcept((byte)0) < 0)
                throw new FormatException("Current publication has a zero required field.");
        var issued = BinaryPrimitives.ReadUInt64BigEndian(encoded[160..]);
        var expiry = BinaryPrimitives.ReadUInt64BigEndian(encoded[168..]);
        if (issued == 0 || expiry <= issued || expiry - issued > 120)
            throw new FormatException("Current publication has an invalid short window.");
        // All outer/LP bounds are checked before nested parsing or owned copies.
        var original = ContactPublicationAuthorityWireCodec.DecodeRequest(encoded.Slice(180, checked((int)originalLength)));
        if (original.PublicationKind != 1 || !Fixed(encoded.Slice(8,16), original.NetworkId.Span) ||
            !Fixed(encoded.Slice(56,32), original.DirectoryLookupKey.Span) || issued < original.IssuedAtUnixSeconds ||
            expiry > original.EffectiveExpiresAtUnixSeconds)
            throw new FormatException("Current publication differs from the exact reusable original intent.");
        return new(encoded.ToArray());
    }

    internal static PublicationCurrentWireRequest EncodeRequest(ReadOnlySpan<byte> network, ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> leaf, ulong minimumGeneration, ReadOnlySpan<byte> minimumHash, ReadOnlySpan<byte> view,
        ulong issued, ulong expires, ContactPublicationAuthorityWireRequest original, ReadOnlySpan<byte> signature)
    {
        ArgumentNullException.ThrowIfNull(original);
        if (network.Length != 16 || nonce.Length != 32 || leaf.Length != 32 || minimumHash.Length != 32 ||
            view.Length != 32 || signature.Length != 64)
            throw new ArgumentException("Current publication field width is invalid.");
        var originalBytes = ContactPublicationAuthorityWireCodec.EncodeRequest(original);
        try
        {
            var exact = new byte[checked(RequestFixedOverheadBytes + originalBytes.Length)]; WriteHeader(exact);
            network.CopyTo(exact.AsSpan(8)); nonce.CopyTo(exact.AsSpan(24)); leaf.CopyTo(exact.AsSpan(56));
            BinaryPrimitives.WriteUInt64BigEndian(exact.AsSpan(88), minimumGeneration);
            minimumHash.CopyTo(exact.AsSpan(96)); view.CopyTo(exact.AsSpan(128));
            BinaryPrimitives.WriteUInt64BigEndian(exact.AsSpan(160), issued);
            BinaryPrimitives.WriteUInt64BigEndian(exact.AsSpan(168), expires);
            BinaryPrimitives.WriteUInt32BigEndian(exact.AsSpan(176), checked((uint)originalBytes.Length));
            originalBytes.CopyTo(exact, 180); signature.CopyTo(exact.AsSpan(exact.Length - 64));
            return DecodeRequest(exact);
        }
        finally { CryptographicOperations.ZeroMemory(originalBytes); }
    }

    public static byte[] EncodeResponse(PublicationCurrentWireRequest request, ReadOnlySpan<byte> exactLease)
    {
        ArgumentNullException.ThrowIfNull(request); RequireLease(request, exactLease);
        var exact = new byte[checked(60 + exactLease.Length)]; WriteHeader(exact);
        request.NetworkId.Span.CopyTo(exact.AsSpan(8)); request.RequestNonce.Span.CopyTo(exact.AsSpan(24));
        BinaryPrimitives.WriteUInt32BigEndian(exact.AsSpan(56), checked((uint)exactLease.Length));
        exactLease.CopyTo(exact.AsSpan(60)); return exact;
    }

    public static ParsedDeepIdV2PublicationLease DecodeResponse(PublicationCurrentWireRequest request, ReadOnlySpan<byte> encoded)
    {
        ArgumentNullException.ThrowIfNull(request); Header(encoded, MinimumResponseBytes, MaximumResponseBytes);
        if (BinaryPrimitives.ReadUInt32BigEndian(encoded[56..]) != encoded.Length - 60 ||
            !Fixed(encoded.Slice(8,16), request.NetworkId.Span) || !Fixed(encoded.Slice(24,32), request.RequestNonce.Span))
            throw new FormatException("Current publication response does not pair with its fresh request.");
        return RequireLease(request, encoded[60..]);
    }

    private static ParsedDeepIdV2PublicationLease RequireLease(PublicationCurrentWireRequest request, ReadOnlySpan<byte> bytes)
    {
        var lease = DeepIdV2PublicationLeaseCodec.Decode(bytes);
        if (!Fixed(lease.NetworkId.Span, request.NetworkId.Span) || !Fixed(lease.RequestNonce.Span, request.RequestNonce.Span) ||
            !Fixed(lease.ViewHash.Span, request.ViewHash.Span) || lease.IssuedAtUnixSeconds != request.IssuedAtUnixSeconds ||
            lease.ExpiresAtUnixSeconds != request.ExpiresAtUnixSeconds)
            throw new FormatException("Current publication lease changed fresh scope, view or window.");
        ContactPublicationAuthorityWireCodec.RequireExactBody(request.OriginalRequest, lease.OriginalRequest.CanonicalBytes.Span);
        return lease;
    }

    internal static byte[] PublisherSigningInput(ReadOnlySpan<byte> exact)
    {
        var unsigned = exact[..^64].ToArray(); WriteHeader(unsigned);
        try { return ApplicationCoreFormat.SignatureInput(PublisherSigningDomain, unsigned, DeepIdV2Codec.Suite); }
        finally { CryptographicOperations.ZeroMemory(unsigned); }
    }
    internal static byte[] GatewayShard(ReadOnlySpan<byte> network, ReadOnlySpan<byte> nonce)
    {
        var bytes = new byte[48]; network.CopyTo(bytes); nonce.CopyTo(bytes.AsSpan(16));
        return ApplicationCoreFormat.Sha256Domain(GatewayShardDomain, bytes);
    }
    private static void Header(ReadOnlySpan<byte> bytes, int minimum, int maximum)
    {
        if (bytes.Length < minimum || bytes.Length > maximum || BinaryPrimitives.ReadUInt16BigEndian(bytes) != 1 ||
            BinaryPrimitives.ReadUInt16BigEndian(bytes[2..]) != 0 || BinaryPrimitives.ReadUInt32BigEndian(bytes[4..]) != bytes.Length)
            throw new FormatException("Current publication framing is not canonical.");
    }
    private static void WriteHeader(Span<byte> bytes)
    { BinaryPrimitives.WriteUInt16BigEndian(bytes, 1); BinaryPrimitives.WriteUInt32BigEndian(bytes[4..], checked((uint)bytes.Length)); }
    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}
