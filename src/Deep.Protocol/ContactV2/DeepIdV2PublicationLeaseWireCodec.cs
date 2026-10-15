using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;

namespace Deep.Protocol.ContactV2;

/// <summary>Untrusted exact publisher-signed lease request. Parsing grants no
/// owner, issuer, journal, currentness or dispatch authority.</summary>
public sealed class PublicationLeaseWireRequest
{
    private readonly byte[] exact;
    internal PublicationLeaseWireRequest(byte[] exact) => this.exact = exact;
    public ReadOnlyMemory<byte> CanonicalBytes => exact.ToArray();
    public ReadOnlyMemory<byte> NetworkId => Copy(8, 16);
    public ReadOnlyMemory<byte> RequestNonce => Copy(24, 32);
    public ReadOnlyMemory<byte> OriginalCoordinationNonce => Copy(56, 32);
    public ReadOnlyMemory<byte> DirectoryLookupKey => Copy(88, 32);
    public ulong MinimumDirectoryGeneration => BinaryPrimitives.ReadUInt64BigEndian(exact.AsSpan(120));
    public ReadOnlyMemory<byte> MinimumDirectoryHash => Copy(128, 32);
    public ReadOnlyMemory<byte> OriginalRequestHash => Copy(160, 32);
    public ReadOnlyMemory<byte> ViewHash => Copy(192, 32);
    public ulong IssuedAtUnixSeconds => BinaryPrimitives.ReadUInt64BigEndian(exact.AsSpan(224));
    public ulong ExpiresAtUnixSeconds => BinaryPrimitives.ReadUInt64BigEndian(exact.AsSpan(232));
    public ReadOnlyMemory<byte> PublisherSignature => Copy(240, 64);
    public ReadOnlyMemory<byte> GatewayShard => DeepIdV2PublicationLeaseWireCodec.GatewayShard(NetworkId.Span, RequestNonce.Span);
    internal ReadOnlyMemory<byte> SigningInput => DeepIdV2PublicationLeaseWireCodec.PublisherSigningInput(exact);
    private byte[] Copy(int offset, int count) => exact.AsSpan(offset, count).ToArray();
}

public static class DeepIdV2PublicationLeaseWireCodec
{
    public const int RequestBytes = 304;
    public const int UnsignedRequestBytes = 240;
    public const int MinimumResponseBytes = 60 + DeepIdV2PublicationLeaseCodec.MinimumBytes;
    public const int MaximumResponseBytes = 60 + DeepIdV2PublicationLeaseCodec.MaximumBytes;
    public const string EndpointPath = "/api/v2/contact-publication-lease";
    public const string RequestMediaType = "application/vnd.deep.contact-publication-lease-request.v1+octet-stream";
    public const string ResponseMediaType = "application/vnd.deep.contact-publication-lease-response.v1+octet-stream";
    public const string PublisherSigningDomain = "Deep/ContactResolver/V2/publication-lease-request";
    public const string GatewayShardDomain = "Deep/ContactResolver/V2/publication-lease-gateway";

    public static PublicationLeaseWireRequest DecodeRequest(ReadOnlySpan<byte> encoded)
    {
        Header(encoded, RequestBytes, RequestBytes);
        foreach (var (offset, length) in new[] { (8,16),(24,32),(56,32),(88,32),(128,32),(160,32),(192,32),(240,64) })
            if (encoded.Slice(offset, length).IndexOfAnyExcept((byte)0) < 0)
                throw new FormatException("Publication lease request has a zero required field.");
        var issued = BinaryPrimitives.ReadUInt64BigEndian(encoded[224..]);
        var expiry = BinaryPrimitives.ReadUInt64BigEndian(encoded[232..]);
        if (issued == 0 || expiry <= issued || expiry - issued > 120)
            throw new FormatException("Publication lease request has an invalid short window.");
        return new(encoded.ToArray());
    }

    internal static PublicationLeaseWireRequest EncodeRequest(ReadOnlySpan<byte> network, ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> originalNonce, ReadOnlySpan<byte> leaf, ulong minimumGeneration, ReadOnlySpan<byte> minimumHash,
        ReadOnlySpan<byte> originalHash, ReadOnlySpan<byte> view, ulong issued, ulong expires, ReadOnlySpan<byte> signature)
    {
        if (network.Length != 16 || nonce.Length != 32 || originalNonce.Length != 32 || leaf.Length != 32 ||
            minimumHash.Length != 32 || originalHash.Length != 32 || view.Length != 32 || signature.Length != 64)
            throw new ArgumentException("Publication lease request field width is invalid.");
        var exact = new byte[RequestBytes]; WriteHeader(exact);
        network.CopyTo(exact.AsSpan(8)); nonce.CopyTo(exact.AsSpan(24)); originalNonce.CopyTo(exact.AsSpan(56));
        leaf.CopyTo(exact.AsSpan(88)); BinaryPrimitives.WriteUInt64BigEndian(exact.AsSpan(120), minimumGeneration);
        minimumHash.CopyTo(exact.AsSpan(128)); originalHash.CopyTo(exact.AsSpan(160)); view.CopyTo(exact.AsSpan(192));
        BinaryPrimitives.WriteUInt64BigEndian(exact.AsSpan(224), issued);
        BinaryPrimitives.WriteUInt64BigEndian(exact.AsSpan(232), expires); signature.CopyTo(exact.AsSpan(240));
        return DecodeRequest(exact);
    }

    public static byte[] EncodeResponse(PublicationLeaseWireRequest request, ReadOnlySpan<byte> exactLease)
    {
        ArgumentNullException.ThrowIfNull(request);
        var lease = DeepIdV2PublicationLeaseCodec.Decode(exactLease); RequirePair(request, lease);
        var exact = new byte[60 + exactLease.Length]; WriteHeader(exact);
        request.NetworkId.Span.CopyTo(exact.AsSpan(8)); request.RequestNonce.Span.CopyTo(exact.AsSpan(24));
        BinaryPrimitives.WriteUInt32BigEndian(exact.AsSpan(56), checked((uint)exactLease.Length));
        exactLease.CopyTo(exact.AsSpan(60)); return exact;
    }

    public static ParsedDeepIdV2PublicationLease DecodeResponse(PublicationLeaseWireRequest request, ReadOnlySpan<byte> encoded)
    {
        ArgumentNullException.ThrowIfNull(request); Header(encoded, MinimumResponseBytes, MaximumResponseBytes);
        if (BinaryPrimitives.ReadUInt32BigEndian(encoded[56..]) != encoded.Length - 60 ||
            !Fixed(encoded.Slice(8, 16), request.NetworkId.Span) || !Fixed(encoded.Slice(24, 32), request.RequestNonce.Span))
            throw new FormatException("Publication lease response is not paired with the exact request.");
        var lease = DeepIdV2PublicationLeaseCodec.Decode(encoded[60..]); RequirePair(request, lease); return lease;
    }

    internal static void RequirePair(PublicationLeaseWireRequest request, ParsedDeepIdV2PublicationLease lease)
    {
        if (!Fixed(request.NetworkId.Span, lease.NetworkId.Span) || !Fixed(request.RequestNonce.Span, lease.RequestNonce.Span) ||
            !Fixed(request.OriginalRequestHash.Span, lease.OriginalRequestHash.Span) || !Fixed(request.ViewHash.Span, lease.ViewHash.Span) ||
            request.IssuedAtUnixSeconds != lease.IssuedAtUnixSeconds || request.ExpiresAtUnixSeconds != lease.ExpiresAtUnixSeconds)
            throw new CryptographicException("Fresh publication lease differs from the exact original-intent request.");
    }

    internal static byte[] PublisherSigningInput(ReadOnlySpan<byte> exact)
    {
        var unsigned = exact[..UnsignedRequestBytes].ToArray(); WriteHeader(unsigned);
        return ApplicationCoreFormat.SignatureInput(PublisherSigningDomain, unsigned, DeepIdV2Codec.Suite);
    }
    internal static byte[] GatewayShard(ReadOnlySpan<byte> network, ReadOnlySpan<byte> nonce)
    {
        var input = new byte[48]; network.CopyTo(input); nonce.CopyTo(input.AsSpan(16));
        return ApplicationCoreFormat.Sha256Domain(GatewayShardDomain, input);
    }
    private static void Header(ReadOnlySpan<byte> encoded, int minimum, int maximum)
    {
        if (encoded.Length < minimum || encoded.Length > maximum || BinaryPrimitives.ReadUInt16BigEndian(encoded) != 1 ||
            BinaryPrimitives.ReadUInt16BigEndian(encoded[2..]) != 0 || BinaryPrimitives.ReadUInt32BigEndian(encoded[4..]) != encoded.Length)
            throw new FormatException("Publication lease coordination framing is not canonical.");
    }
    private static void WriteHeader(Span<byte> encoded)
    { BinaryPrimitives.WriteUInt16BigEndian(encoded, 1); BinaryPrimitives.WriteUInt32BigEndian(encoded[4..], checked((uint)encoded.Length)); }
    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}
