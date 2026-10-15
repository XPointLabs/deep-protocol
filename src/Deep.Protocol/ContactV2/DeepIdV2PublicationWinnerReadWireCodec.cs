using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;

namespace Deep.Protocol.ContactV2;

/// <summary>Parsed read-only coordination request, never issuance or mutation authority.</summary>
public sealed class PublicationWinnerReadWireRequest
{
    private readonly byte[] exact;
    internal PublicationWinnerReadWireRequest(byte[] exact) => this.exact = exact;
    public ReadOnlyMemory<byte> CanonicalBytes => exact.ToArray();
    public ReadOnlyMemory<byte> NetworkId => Copy(8, 16);
    public ReadOnlyMemory<byte> RequestNonce => Copy(24, 32);
    public ReadOnlyMemory<byte> OriginalCoordinationNonce => Copy(56, 32);
    public ReadOnlyMemory<byte> DirectoryLookupKey => Copy(88, 32);
    public ulong MinimumDirectoryGeneration => BinaryPrimitives.ReadUInt64BigEndian(exact.AsSpan(120));
    public ReadOnlyMemory<byte> MinimumDirectoryHash => Copy(128, 32);
    public ReadOnlyMemory<byte> OriginalCoordinationRequestHash => Copy(160, 32);
    public ReadOnlyMemory<byte> ViewHash => Copy(192, 32);
    public ulong IssuedAtUnixSeconds => BinaryPrimitives.ReadUInt64BigEndian(exact.AsSpan(224));
    public ulong ExpiresAtUnixSeconds => BinaryPrimitives.ReadUInt64BigEndian(exact.AsSpan(232));
    public ReadOnlyMemory<byte> PublisherSignature => Copy(240, 64);
    public ReadOnlyMemory<byte> GatewayShard => DeepIdV2PublicationWinnerReadWireCodec.GatewayShard(NetworkId.Span, RequestNonce.Span);
    internal ReadOnlyMemory<byte> SigningInput => DeepIdV2PublicationWinnerReadWireCodec.PublisherSigningInput(exact);
    private byte[] Copy(int offset, int count) => exact.AsSpan(offset, count).ToArray();
}

public static class DeepIdV2PublicationWinnerReadWireCodec
{
    public const int RequestBytes = 304;
    public const int UnsignedRequestBytes = 240;
    public const int MinimumResponseBytes = 60 + ContactPublicationAuthorityWireCodec.MinimumResponseBytes;
    public const int MaximumResponseBytes = 60 + ContactPublicationAuthorityWireCodec.MaximumResponseBytes;
    public const string EndpointPath = "/api/v2/contact-publication-winner";
    public const string RequestMediaType = "application/vnd.deep.contact-publication-winner-request.v1+octet-stream";
    public const string ResponseMediaType = "application/vnd.deep.contact-publication-winner-response.v1+octet-stream";
    public const string PublisherSigningDomain = "Deep/ContactResolver/V2/publication-winner-read-request";
    public const string GatewayShardDomain = "Deep/ContactResolver/V2/publication-winner-read-gateway";
    public const string OriginalRequestHashDomain = "Deep/ContactResolver/V2/publication-winner-original-request";

    public static byte[] HashOriginalRequest(ContactPublicationAuthorityWireRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        var bytes = ContactPublicationAuthorityWireCodec.EncodeRequest(request);
        try { return ApplicationCoreFormat.Sha256Domain(OriginalRequestHashDomain, bytes); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    public static PublicationWinnerReadWireRequest DecodeRequest(ReadOnlySpan<byte> encoded)
    {
        Header(encoded, RequestBytes, RequestBytes);
        foreach (var (offset, length) in new[] { (8,16),(24,32),(56,32),(88,32),(128,32),(160,32),(192,32),(240,64) })
            if (encoded.Slice(offset, length).IndexOfAnyExcept((byte)0) < 0)
                throw new FormatException("Publication winner read has a zero required field.");
        var issued = BinaryPrimitives.ReadUInt64BigEndian(encoded[224..]);
        var expiry = BinaryPrimitives.ReadUInt64BigEndian(encoded[232..]);
        if (issued == 0 || expiry <= issued || expiry - issued > 120)
            throw new FormatException("Publication winner read has an invalid current window.");
        return new(encoded.ToArray());
    }

    internal static PublicationWinnerReadWireRequest EncodeRequest(ReadOnlySpan<byte> network, ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> originalNonce, ReadOnlySpan<byte> leaf, ulong minimumGeneration, ReadOnlySpan<byte> minimumHash,
        ReadOnlySpan<byte> originalHash, ReadOnlySpan<byte> view, ulong issued, ulong expires, ReadOnlySpan<byte> signature)
    {
        if (network.Length != 16 || nonce.Length != 32 || originalNonce.Length != 32 || leaf.Length != 32 ||
            minimumHash.Length != 32 || originalHash.Length != 32 || view.Length != 32 || signature.Length != 64)
            throw new ArgumentException("Publication winner read field width is invalid.");
        var exact = new byte[RequestBytes]; WriteHeader(exact);
        network.CopyTo(exact.AsSpan(8)); nonce.CopyTo(exact.AsSpan(24)); originalNonce.CopyTo(exact.AsSpan(56));
        leaf.CopyTo(exact.AsSpan(88)); BinaryPrimitives.WriteUInt64BigEndian(exact.AsSpan(120), minimumGeneration);
        minimumHash.CopyTo(exact.AsSpan(128)); originalHash.CopyTo(exact.AsSpan(160)); view.CopyTo(exact.AsSpan(192));
        BinaryPrimitives.WriteUInt64BigEndian(exact.AsSpan(224), issued);
        BinaryPrimitives.WriteUInt64BigEndian(exact.AsSpan(232), expires); signature.CopyTo(exact.AsSpan(240));
        return DecodeRequest(exact);
    }

    public static byte[] EncodeResponse(PublicationWinnerReadWireRequest request, ReadOnlySpan<byte> originalResponse)
    {
        ArgumentNullException.ThrowIfNull(request); RequireOriginalResponse(request, originalResponse);
        var exact = new byte[60 + originalResponse.Length]; WriteHeader(exact);
        request.NetworkId.Span.CopyTo(exact.AsSpan(8)); request.RequestNonce.Span.CopyTo(exact.AsSpan(24));
        BinaryPrimitives.WriteUInt32BigEndian(exact.AsSpan(56), checked((uint)originalResponse.Length));
        originalResponse.CopyTo(exact.AsSpan(60)); return exact;
    }

    public static byte[] DecodeResponse(PublicationWinnerReadWireRequest request, ReadOnlySpan<byte> encoded)
    {
        ArgumentNullException.ThrowIfNull(request); Header(encoded, MinimumResponseBytes, MaximumResponseBytes);
        if (BinaryPrimitives.ReadUInt32BigEndian(encoded[56..]) != encoded.Length - 60 ||
            !Fixed(encoded.Slice(8, 16), request.NetworkId.Span) || !Fixed(encoded.Slice(24, 32), request.RequestNonce.Span))
            throw new FormatException("Publication winner read response does not pair with its current request.");
        RequireOriginalResponse(request, encoded[60..]); return encoded[60..].ToArray();
    }

    private static void RequireOriginalResponse(PublicationWinnerReadWireRequest request, ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length is < ContactPublicationAuthorityWireCodec.MinimumResponseBytes or > ContactPublicationAuthorityWireCodec.MaximumResponseBytes ||
            BinaryPrimitives.ReadUInt16BigEndian(bytes) != ContactPublicationAuthorityWireCodec.Version ||
            BinaryPrimitives.ReadUInt16BigEndian(bytes[2..]) != 0 || BinaryPrimitives.ReadUInt32BigEndian(bytes[4..]) != bytes.Length ||
            !Fixed(bytes.Slice(8, 16), request.NetworkId.Span) || !Fixed(bytes.Slice(24, 32), request.OriginalCoordinationNonce.Span) ||
            BinaryPrimitives.ReadUInt32BigEndian(bytes[56..]) != bytes.Length - 60)
            throw new FormatException("Publication winner read changed original response framing or scope.");
        _ = DeepIdV2ContactPublicationCodec.DecodeXpu1(bytes[60..]);
        // Exact saved publisher-request/body and original witness verification
        // remain mandatory at the owner; this parser has no such authority.
    }

    internal static byte[] PublisherSigningInput(ReadOnlySpan<byte> exact)
    {
        var unsigned = exact[..UnsignedRequestBytes].ToArray(); WriteHeader(unsigned);
        return ApplicationCoreFormat.SignatureInput(PublisherSigningDomain, unsigned, DeepIdV2Codec.Suite);
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
            throw new FormatException("Publication winner read framing is not canonical.");
    }
    private static void WriteHeader(Span<byte> bytes)
    { BinaryPrimitives.WriteUInt16BigEndian(bytes, 1); BinaryPrimitives.WriteUInt32BigEndian(bytes[4..], checked((uint)bytes.Length)); }
    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}
