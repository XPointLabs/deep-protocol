using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;

namespace Deep.Protocol.ContactV1;

/// <summary>
/// Untrusted wire request for the bounded route-authority exchange. This is a
/// transport value, not a verified authority capability.
/// </summary>
public sealed class ContactRouteAuthorityWireRequest
{
    private readonly byte[] networkId;
    private readonly byte[] requestNonce;
    private readonly byte[] directoryLookupKey;
    private readonly byte[] minimumAdh1CoreHash;
    private readonly byte[] exactDca1;
    private readonly byte[] exactXra1;

    public ContactRouteAuthorityWireRequest(
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> requestNonce,
        ReadOnlySpan<byte> directoryLookupKey,
        ulong minimumAdh1Generation,
        ReadOnlySpan<byte> minimumAdh1CoreHash,
        ReadOnlySpan<byte> exactDca1,
        ReadOnlySpan<byte> exactXra1)
    {
        this.networkId = Required(networkId, 16, nameof(networkId));
        this.requestNonce = Required(requestNonce, 32, nameof(requestNonce));
        this.directoryLookupKey = Required(
            directoryLookupKey, 32, nameof(directoryLookupKey));
        this.minimumAdh1CoreHash = Required(
            minimumAdh1CoreHash, 32, nameof(minimumAdh1CoreHash));
        if (exactDca1.Length != ContactRouteAuthorityWireCodec.ExactDca1Bytes)
            throw new ArgumentException("The exact DCA1 length is invalid.", nameof(exactDca1));
        if (exactXra1.Length != ContactRouteAuthorityWireCodec.ExactXra1Bytes)
            throw new ArgumentException("The exact XRA1 length is invalid.", nameof(exactXra1));
        var dca = ApplicationCoreCodec.DecodeDca1(exactDca1);
        var xra = ContactCodec.Decode(ProtocolMagic.XRA1, exactXra1);
        if (!Fixed(dca.NetworkId.Span, this.networkId) ||
            !Fixed(xra.Field(1).Span, this.networkId))
            throw new CryptographicException(
                "The route-authority request contains cross-network records.");
        MinimumAdh1Generation = minimumAdh1Generation;
        this.exactDca1 = exactDca1.ToArray();
        this.exactXra1 = exactXra1.ToArray();
    }

    public ReadOnlyMemory<byte> NetworkId => networkId.ToArray();
    public ReadOnlyMemory<byte> RequestNonce => requestNonce.ToArray();
    public ReadOnlyMemory<byte> DirectoryLookupKey => directoryLookupKey.ToArray();
    public ulong MinimumAdh1Generation { get; }
    public ReadOnlyMemory<byte> MinimumAdh1CoreHash => minimumAdh1CoreHash.ToArray();
    public ReadOnlyMemory<byte> ExactDca1 => exactDca1.ToArray();
    public ReadOnlyMemory<byte> ExactXra1 => exactXra1.ToArray();

    private static byte[] Required(ReadOnlySpan<byte> value, int length, string name)
    {
        if (value.Length != length || value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException($"{name} must be exactly {length} non-zero bytes.", name);
        return value.ToArray();
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}

/// <summary>
/// Untrusted exact threshold-authored records returned over the wire. A client
/// must still bind these records through ContactRouteThresholdVerifier before use.
/// </summary>
public sealed class ContactRouteAuthorityWireResponse
{
    private readonly byte[] networkId;
    private readonly byte[] requestNonce;
    private readonly byte[] exactPms2;
    private readonly byte[] exactXrc1;
    private readonly byte[] exactXss1;

    public ContactRouteAuthorityWireResponse(
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> requestNonce,
        ReadOnlySpan<byte> exactPms2,
        ReadOnlySpan<byte> exactXrc1,
        ReadOnlySpan<byte> exactXss1)
    {
        this.networkId = Required(networkId, 16, nameof(networkId));
        this.requestNonce = Required(requestNonce, 32, nameof(requestNonce));
        this.exactPms2 = Exact(exactPms2, ProtocolMagic.PMS2, 500, 3_476, this.networkId);
        this.exactXrc1 = Exact(exactXrc1, ProtocolMagic.XRC1, 940, 4_012, this.networkId);
        this.exactXss1 = Exact(exactXss1, ProtocolMagic.XSS1, 643, 3_523, this.networkId);
    }

    public ReadOnlyMemory<byte> NetworkId => networkId.ToArray();
    public ReadOnlyMemory<byte> RequestNonce => requestNonce.ToArray();
    public ReadOnlyMemory<byte> ExactPms2 => exactPms2.ToArray();
    public ReadOnlyMemory<byte> ExactXrc1 => exactXrc1.ToArray();
    public ReadOnlyMemory<byte> ExactXss1 => exactXss1.ToArray();

    private static byte[] Exact(
        ReadOnlySpan<byte> value,
        string magic,
        int minimum,
        int maximum,
        ReadOnlySpan<byte> networkId)
    {
        if (value.Length < minimum || value.Length > maximum)
            throw new ArgumentException($"The exact {magic} length is invalid.");
        var record = ContactCodec.Decode(magic, value);
        if (!CryptographicOperations.FixedTimeEquals(record.Field(1).Span, networkId))
            throw new CryptographicException($"The exact {magic} belongs to another network.");
        return value.ToArray();
    }

    private static byte[] Required(ReadOnlySpan<byte> value, int length, string name)
    {
        if (value.Length != length || value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException($"{name} must be exactly {length} non-zero bytes.", name);
        return value.ToArray();
    }
}

public static class ContactRouteAuthorityWireCodec
{
    public const ushort Version = 1;
    public const int ExactDca1Bytes = 473;
    public const int ExactXra1Bytes = 550;
    public const int RequestBytes = 1_151;
    public const int MinimumResponseBytes = 2_151;
    public const int MaximumResponseBytes = 11_079;
    public const string RequestMediaType =
        "application/vnd.deep.contact-route-authority-request.v1+octet-stream";
    public const string ResponseMediaType =
        "application/vnd.deep.contact-route-authority-response.v1+octet-stream";

    public static byte[] EncodeRequest(ContactRouteAuthorityWireRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        var result = new byte[RequestBytes];
        BinaryPrimitives.WriteUInt16BigEndian(result, Version);
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(4), RequestBytes);
        request.NetworkId.Span.CopyTo(result.AsSpan(8));
        request.RequestNonce.Span.CopyTo(result.AsSpan(24));
        request.DirectoryLookupKey.Span.CopyTo(result.AsSpan(56));
        BinaryPrimitives.WriteUInt64BigEndian(
            result.AsSpan(88), request.MinimumAdh1Generation);
        request.MinimumAdh1CoreHash.Span.CopyTo(result.AsSpan(96));
        request.ExactDca1.Span.CopyTo(result.AsSpan(128));
        request.ExactXra1.Span.CopyTo(result.AsSpan(601));
        return result;
    }

    public static ContactRouteAuthorityWireRequest DecodeRequest(ReadOnlySpan<byte> encoded)
    {
        ValidateHeader(encoded, RequestBytes, RequestBytes);
        return new ContactRouteAuthorityWireRequest(
            encoded.Slice(8, 16),
            encoded.Slice(24, 32),
            encoded.Slice(56, 32),
            BinaryPrimitives.ReadUInt64BigEndian(encoded.Slice(88, 8)),
            encoded.Slice(96, 32),
            encoded.Slice(128, ExactDca1Bytes),
            encoded.Slice(601, ExactXra1Bytes));
    }

    public static byte[] EncodeResponse(
        ContactRouteAuthorityWireRequest request,
        ContactRouteAuthorityWireResponse response)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(response);
        RequireBinding(request, response);
        var length = checked(56 + 12 + response.ExactPms2.Length +
            response.ExactXrc1.Length + response.ExactXss1.Length);
        if (length is < MinimumResponseBytes or > MaximumResponseBytes)
            throw new InvalidOperationException("The route-authority response length is invalid.");
        var result = new byte[length];
        BinaryPrimitives.WriteUInt16BigEndian(result, Version);
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(4), checked((uint)length));
        request.NetworkId.Span.CopyTo(result.AsSpan(8));
        request.RequestNonce.Span.CopyTo(result.AsSpan(24));
        var offset = 56;
        WriteArtifact(result, ref offset, response.ExactPms2.Span);
        WriteArtifact(result, ref offset, response.ExactXrc1.Span);
        WriteArtifact(result, ref offset, response.ExactXss1.Span);
        if (offset != result.Length)
            throw new InvalidOperationException("The route-authority response was not exact.");
        return result;
    }

    public static ContactRouteAuthorityWireResponse DecodeResponse(
        ContactRouteAuthorityWireRequest request,
        ReadOnlySpan<byte> encoded)
    {
        ArgumentNullException.ThrowIfNull(request);
        ValidateHeader(encoded, MinimumResponseBytes, MaximumResponseBytes);
        if (!Fixed(encoded.Slice(8, 16), request.NetworkId.Span) ||
            !Fixed(encoded.Slice(24, 32), request.RequestNonce.Span))
            throw new CryptographicException(
                "The route-authority response does not bind the exact request.");
        var offset = 56;
        var pms = ReadArtifact(encoded, ref offset, 500, 3_476);
        var xrc = ReadArtifact(encoded, ref offset, 940, 4_012);
        var xss = ReadArtifact(encoded, ref offset, 643, 3_523);
        if (offset != encoded.Length)
            throw new FormatException("The route-authority response has trailing bytes.");
        return new ContactRouteAuthorityWireResponse(
            request.NetworkId.Span, request.RequestNonce.Span, pms, xrc, xss);
    }

    private static void ValidateHeader(
        ReadOnlySpan<byte> encoded,
        int minimum,
        int maximum)
    {
        if (encoded.Length < minimum || encoded.Length > maximum ||
            BinaryPrimitives.ReadUInt16BigEndian(encoded) != Version ||
            BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(2)) != 0 ||
            BinaryPrimitives.ReadUInt32BigEndian(encoded.Slice(4)) != encoded.Length)
            throw new FormatException("The route-authority wire envelope is not canonical.");
    }

    private static void WriteArtifact(byte[] destination, ref int offset, ReadOnlySpan<byte> value)
    {
        BinaryPrimitives.WriteUInt32BigEndian(
            destination.AsSpan(offset), checked((uint)value.Length));
        offset += 4;
        value.CopyTo(destination.AsSpan(offset));
        offset += value.Length;
    }

    private static ReadOnlySpan<byte> ReadArtifact(
        ReadOnlySpan<byte> encoded,
        ref int offset,
        int minimum,
        int maximum)
    {
        if (offset > encoded.Length - 4)
            throw new FormatException("The route-authority response is truncated.");
        var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(encoded.Slice(offset, 4)));
        offset += 4;
        if (length < minimum || length > maximum || offset > encoded.Length - length)
            throw new FormatException("A route-authority response artifact is outside its bound.");
        var value = encoded.Slice(offset, length);
        offset += length;
        return value;
    }

    private static void RequireBinding(
        ContactRouteAuthorityWireRequest request,
        ContactRouteAuthorityWireResponse response)
    {
        if (!Fixed(request.NetworkId.Span, response.NetworkId.Span) ||
            !Fixed(request.RequestNonce.Span, response.RequestNonce.Span))
            throw new CryptographicException(
                "The route-authority response does not bind the exact request.");
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}
