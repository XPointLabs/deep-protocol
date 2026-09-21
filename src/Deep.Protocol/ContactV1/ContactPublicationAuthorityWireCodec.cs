using System.Buffers.Binary;
using System.Security.Cryptography;
using Deep.Protocol.ApplicationCore;

namespace Deep.Protocol.ContactV1;

/// <summary>
/// Untrusted, bounded wire request for one permanent-address XPA1 authorization.
/// It carries the exact publisher-authored closure; the authority must reverify
/// every record against its own current directory and network state.
/// </summary>
public sealed class ContactPublicationAuthorityWireRequest
{
    private readonly byte[] networkId;
    private readonly byte[] requestNonce;
    private readonly byte[] directoryLookupKey;
    private readonly byte[] minimumAdh1CoreHash;
    private readonly byte[] exactDca1;
    private readonly byte[] exactDcr1;
    private readonly byte[] exactRouteClosure;
    private readonly byte[] operationId;
    private readonly byte[] predecessorObjectHash;
    private readonly byte[] objectCiphertext;
    private readonly byte[] ownerRetrieveCapability;
    private readonly byte[] publisherSignature;

    public ContactPublicationAuthorityWireRequest(
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> requestNonce,
        ReadOnlySpan<byte> directoryLookupKey,
        ulong minimumAdh1Generation,
        ReadOnlySpan<byte> minimumAdh1CoreHash,
        ReadOnlySpan<byte> exactDca1,
        ReadOnlySpan<byte> exactDcr1,
        ReadOnlySpan<byte> exactRouteClosure,
        ReadOnlySpan<byte> operationId,
        ulong generation,
        ReadOnlySpan<byte> predecessorObjectHash,
        ReadOnlySpan<byte> objectCiphertext,
        ulong issuedAtUnixSeconds,
        ulong expiresAtUnixSeconds,
        ulong effectiveExpiresAtUnixSeconds,
        ReadOnlySpan<byte> ownerRetrieveCapability,
        ReadOnlySpan<byte> publisherSignature)
    {
        this.networkId = Required(networkId, 16, nameof(networkId));
        this.requestNonce = Required(requestNonce, 32, nameof(requestNonce));
        this.directoryLookupKey = Required(directoryLookupKey, 32, nameof(directoryLookupKey));
        this.minimumAdh1CoreHash = Required(
            minimumAdh1CoreHash, 32, nameof(minimumAdh1CoreHash));
        if (exactDca1.Length != ContactRouteAuthorityWireCodec.ExactDca1Bytes)
            throw new ArgumentException("The exact DCA1 length is invalid.", nameof(exactDca1));
        var dca = ApplicationCoreCodec.DecodeDca1(exactDca1);
        if (!Fixed(dca.NetworkId.Span, this.networkId))
            throw new CryptographicException("The exact DCA1 belongs to another network.");

        if (exactDcr1.Length is < ContactPublicationAuthorityWireCodec.MinimumDcr1Bytes or
            > ContactPublicationAuthorityWireCodec.MaximumDcr1Bytes)
            throw new ArgumentOutOfRangeException(nameof(exactDcr1));
        var dcr = ContactCodec.Decode(ProtocolMagic.DCR1, exactDcr1);
        if (!Fixed(dcr.Field(1).Span, this.networkId))
            throw new CryptographicException("The exact DCR1 belongs to another network.");

        var route = ContactRouteClosureCodec.Decode(exactRouteClosure);
        foreach (var record in new[]
                 {
                     route.Reachability, route.Authorization, route.Route,
                     route.Successor, route.Projection, route.Selection,
                 })
        {
            if (!Fixed(record.Field(1).Span, this.networkId))
                throw new CryptographicException(
                    "The exact Contact route closure belongs to another network.");
        }

        this.operationId = Required(operationId, 32, nameof(operationId));
        this.predecessorObjectHash = Exact(
            predecessorObjectHash, 32, nameof(predecessorObjectHash));
        if ((generation == 0) != IsZero(this.predecessorObjectHash))
            throw new ArgumentException(
                "The predecessor object hash must be zero exactly at generation zero.",
                nameof(predecessorObjectHash));
        if (objectCiphertext.Length is < 40 or > 65_575)
            throw new ArgumentOutOfRangeException(nameof(objectCiphertext));
        if (issuedAtUnixSeconds == 0 || issuedAtUnixSeconds >= expiresAtUnixSeconds ||
            effectiveExpiresAtUnixSeconds < expiresAtUnixSeconds)
            throw new ArgumentOutOfRangeException(nameof(expiresAtUnixSeconds));
        this.ownerRetrieveCapability = Required(
            ownerRetrieveCapability, 32, nameof(ownerRetrieveCapability));
        if (Fixed(this.ownerRetrieveCapability, route.Reachability.Field(10).Span))
            throw new CryptographicException(
                "The owner Retrieve capability must differ from the public Deposit capability.");
        this.publisherSignature = Required(
            publisherSignature, 64, nameof(publisherSignature));

        MinimumAdh1Generation = minimumAdh1Generation;
        this.exactDca1 = exactDca1.ToArray();
        this.exactDcr1 = exactDcr1.ToArray();
        this.exactRouteClosure = exactRouteClosure.ToArray();
        Generation = generation;
        this.objectCiphertext = objectCiphertext.ToArray();
        IssuedAtUnixSeconds = issuedAtUnixSeconds;
        ExpiresAtUnixSeconds = expiresAtUnixSeconds;
        EffectiveExpiresAtUnixSeconds = effectiveExpiresAtUnixSeconds;
    }

    public ReadOnlyMemory<byte> NetworkId => networkId.ToArray();
    public ReadOnlyMemory<byte> RequestNonce => requestNonce.ToArray();
    public ReadOnlyMemory<byte> DirectoryLookupKey => directoryLookupKey.ToArray();
    public ulong MinimumAdh1Generation { get; }
    public ReadOnlyMemory<byte> MinimumAdh1CoreHash => minimumAdh1CoreHash.ToArray();
    public ReadOnlyMemory<byte> ExactDca1 => exactDca1.ToArray();
    public ReadOnlyMemory<byte> ExactDcr1 => exactDcr1.ToArray();
    public ReadOnlyMemory<byte> ExactRouteClosure => exactRouteClosure.ToArray();
    public ReadOnlyMemory<byte> OperationId => operationId.ToArray();
    public ulong Generation { get; }
    public ReadOnlyMemory<byte> PredecessorObjectHash => predecessorObjectHash.ToArray();
    public ReadOnlyMemory<byte> ObjectCiphertext => objectCiphertext.ToArray();
    public ulong IssuedAtUnixSeconds { get; }
    public ulong ExpiresAtUnixSeconds { get; }
    public ulong EffectiveExpiresAtUnixSeconds { get; }
    public ReadOnlyMemory<byte> OwnerRetrieveCapability => ownerRetrieveCapability.ToArray();
    public ReadOnlyMemory<byte> PublisherSignature => publisherSignature.ToArray();

    private static byte[] Required(ReadOnlySpan<byte> value, int length, string name)
    {
        var result = Exact(value, length, name);
        if (IsZero(result)) throw new ArgumentException($"{name} must be non-zero.", name);
        return result;
    }

    private static byte[] Exact(ReadOnlySpan<byte> value, int length, string name)
    {
        if (value.Length != length)
            throw new ArgumentException($"{name} must be exactly {length} bytes.", name);
        return value.ToArray();
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
    private static bool IsZero(ReadOnlySpan<byte> value) => value.IndexOfAnyExcept((byte)0) < 0;
}

/// <summary>
/// Untrusted response bytes. Clients must still verify the embedded XPA1 and
/// exact XPU1 body against their verifier-minted authority capabilities.
/// </summary>
public sealed class ContactPublicationAuthorityWireResponse
{
    private readonly byte[] networkId;
    private readonly byte[] requestNonce;
    private readonly byte[] exactXpu1;

    public ContactPublicationAuthorityWireResponse(
        ReadOnlySpan<byte> networkId,
        ReadOnlySpan<byte> requestNonce,
        ReadOnlySpan<byte> exactXpu1)
    {
        this.networkId = Required(networkId, 16, nameof(networkId));
        this.requestNonce = Required(requestNonce, 32, nameof(requestNonce));
        var request = Xpu1Codec.Decode(exactXpu1);
        if (!CryptographicOperations.FixedTimeEquals(request.NetworkId.Span, this.networkId))
            throw new CryptographicException("The exact XPU1 belongs to another network.");
        this.exactXpu1 = exactXpu1.ToArray();
    }

    public ReadOnlyMemory<byte> NetworkId => networkId.ToArray();
    public ReadOnlyMemory<byte> RequestNonce => requestNonce.ToArray();
    public ReadOnlyMemory<byte> ExactXpu1 => exactXpu1.ToArray();

    private static byte[] Required(ReadOnlySpan<byte> value, int length, string name)
    {
        if (value.Length != length || value.IndexOfAnyExcept((byte)0) < 0)
            throw new ArgumentException($"{name} must be exactly {length} non-zero bytes.", name);
        return value.ToArray();
    }
}

public static class ContactPublicationAuthorityWireCodec
{
    public const ushort Version = 1;
    public const int MinimumDcr1Bytes = 12;
    public const int MaximumDcr1Bytes = 65_535;
    public const int MinimumRequestBytes = 5_000;
    public const int MaximumRequestBytes = 155_210;
    public const int MinimumResponseBytes = 72;
    public const int MaximumResponseBytes = 93_092;
    public const string RequestMediaType =
        "application/vnd.deep.contact-publication-authority-request.v1+octet-stream";
    public const string ResponseMediaType =
        "application/vnd.deep.contact-publication-authority-response.v1+octet-stream";

    public static byte[] EncodeRequest(ContactPublicationAuthorityWireRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        var length = checked(805 + request.ExactDcr1.Length +
            request.ExactRouteClosure.Length + request.ObjectCiphertext.Length);
        if (length is < MinimumRequestBytes or > MaximumRequestBytes)
            throw new InvalidOperationException("The publication-authority request length is invalid.");
        var result = new byte[length];
        WriteHeader(result);
        request.NetworkId.Span.CopyTo(result.AsSpan(8));
        request.RequestNonce.Span.CopyTo(result.AsSpan(24));
        request.DirectoryLookupKey.Span.CopyTo(result.AsSpan(56));
        BinaryPrimitives.WriteUInt64BigEndian(result.AsSpan(88), request.MinimumAdh1Generation);
        request.MinimumAdh1CoreHash.Span.CopyTo(result.AsSpan(96));
        request.ExactDca1.Span.CopyTo(result.AsSpan(128));
        var offset = 601;
        WriteArtifact(result, ref offset, request.ExactDcr1.Span);
        WriteArtifact(result, ref offset, request.ExactRouteClosure.Span);
        request.OperationId.Span.CopyTo(result.AsSpan(offset)); offset += 32;
        BinaryPrimitives.WriteUInt64BigEndian(result.AsSpan(offset), request.Generation); offset += 8;
        request.PredecessorObjectHash.Span.CopyTo(result.AsSpan(offset)); offset += 32;
        WriteArtifact(result, ref offset, request.ObjectCiphertext.Span);
        BinaryPrimitives.WriteUInt64BigEndian(result.AsSpan(offset), request.IssuedAtUnixSeconds); offset += 8;
        BinaryPrimitives.WriteUInt64BigEndian(result.AsSpan(offset), request.ExpiresAtUnixSeconds); offset += 8;
        BinaryPrimitives.WriteUInt64BigEndian(result.AsSpan(offset), request.EffectiveExpiresAtUnixSeconds); offset += 8;
        request.OwnerRetrieveCapability.Span.CopyTo(result.AsSpan(offset)); offset += 32;
        request.PublisherSignature.Span.CopyTo(result.AsSpan(offset)); offset += 64;
        if (offset != result.Length)
            throw new InvalidOperationException("The publication-authority request was not exact.");
        return result;
    }

    public static ContactPublicationAuthorityWireRequest DecodeRequest(ReadOnlySpan<byte> encoded)
    {
        ValidateHeader(encoded, MinimumRequestBytes, MaximumRequestBytes);
        var offset = 601;
        var dcr = ReadArtifact(encoded, ref offset, MinimumDcr1Bytes, MaximumDcr1Bytes);
        var route = ReadArtifact(
            encoded, ref offset, ContactRouteClosureCodec.MinimumEncodedBytes,
            ContactRouteClosureCodec.MaximumEncodedBytes);
        if (offset > encoded.Length - 72)
            throw new FormatException("The publication-authority request is truncated.");
        var operation = encoded.Slice(offset, 32); offset += 32;
        var generation = BinaryPrimitives.ReadUInt64BigEndian(encoded.Slice(offset, 8)); offset += 8;
        var predecessor = encoded.Slice(offset, 32); offset += 32;
        var ciphertext = ReadArtifact(encoded, ref offset, 40, 65_575);
        if (offset > encoded.Length - 120)
            throw new FormatException("The publication-authority request is truncated.");
        var issued = BinaryPrimitives.ReadUInt64BigEndian(encoded.Slice(offset, 8)); offset += 8;
        var expires = BinaryPrimitives.ReadUInt64BigEndian(encoded.Slice(offset, 8)); offset += 8;
        var effective = BinaryPrimitives.ReadUInt64BigEndian(encoded.Slice(offset, 8)); offset += 8;
        var owner = encoded.Slice(offset, 32); offset += 32;
        var signature = encoded.Slice(offset, 64); offset += 64;
        if (offset != encoded.Length)
            throw new FormatException("The publication-authority request has trailing bytes.");
        return new ContactPublicationAuthorityWireRequest(
            encoded.Slice(8, 16), encoded.Slice(24, 32), encoded.Slice(56, 32),
            BinaryPrimitives.ReadUInt64BigEndian(encoded.Slice(88, 8)), encoded.Slice(96, 32),
            encoded.Slice(128, ContactRouteAuthorityWireCodec.ExactDca1Bytes), dcr, route,
            operation, generation, predecessor, ciphertext, issued, expires, effective,
            owner, signature);
    }

    public static byte[] EncodeResponse(
        ContactPublicationAuthorityWireRequest request,
        ContactPublicationAuthorityWireResponse response)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(response);
        RequireBinding(request, response);
        var xpu = Xpu1Codec.Decode(response.ExactXpu1.Span);
        if (!CryptographicOperations.FixedTimeEquals(xpu.OperationId.Span, request.OperationId.Span))
            throw new CryptographicException("The exact XPU1 does not bind the request operation.");
        var length = checked(60 + response.ExactXpu1.Length);
        if (length is < MinimumResponseBytes or > MaximumResponseBytes)
            throw new InvalidOperationException("The publication-authority response length is invalid.");
        var result = new byte[length];
        WriteHeader(result);
        request.NetworkId.Span.CopyTo(result.AsSpan(8));
        request.RequestNonce.Span.CopyTo(result.AsSpan(24));
        var offset = 56;
        WriteArtifact(result, ref offset, response.ExactXpu1.Span);
        return result;
    }

    public static ContactPublicationAuthorityWireResponse DecodeResponse(
        ContactPublicationAuthorityWireRequest request,
        ReadOnlySpan<byte> encoded)
    {
        ArgumentNullException.ThrowIfNull(request);
        ValidateHeader(encoded, MinimumResponseBytes, MaximumResponseBytes);
        if (!Fixed(encoded.Slice(8, 16), request.NetworkId.Span) ||
            !Fixed(encoded.Slice(24, 32), request.RequestNonce.Span))
            throw new CryptographicException(
                "The publication-authority response does not bind the exact request.");
        var offset = 56;
        var xpu = ReadArtifact(encoded, ref offset, 12, 93_032);
        if (offset != encoded.Length)
            throw new FormatException("The publication-authority response has trailing bytes.");
        var response = new ContactPublicationAuthorityWireResponse(
            request.NetworkId.Span, request.RequestNonce.Span, xpu);
        if (!Fixed(Xpu1Codec.Decode(xpu).OperationId.Span, request.OperationId.Span))
            throw new CryptographicException("The exact XPU1 does not bind the request operation.");
        return response;
    }

    private static void WriteHeader(byte[] destination)
    {
        BinaryPrimitives.WriteUInt16BigEndian(destination, Version);
        BinaryPrimitives.WriteUInt32BigEndian(destination.AsSpan(4), checked((uint)destination.Length));
    }

    private static void ValidateHeader(ReadOnlySpan<byte> encoded, int minimum, int maximum)
    {
        if (encoded.Length < minimum || encoded.Length > maximum ||
            BinaryPrimitives.ReadUInt16BigEndian(encoded) != Version ||
            BinaryPrimitives.ReadUInt16BigEndian(encoded.Slice(2)) != 0 ||
            BinaryPrimitives.ReadUInt32BigEndian(encoded.Slice(4)) != encoded.Length)
            throw new FormatException("The publication-authority wire envelope is not canonical.");
    }

    private static void WriteArtifact(byte[] destination, ref int offset, ReadOnlySpan<byte> value)
    {
        BinaryPrimitives.WriteUInt32BigEndian(destination.AsSpan(offset), checked((uint)value.Length));
        offset += 4;
        value.CopyTo(destination.AsSpan(offset));
        offset += value.Length;
    }

    private static ReadOnlySpan<byte> ReadArtifact(
        ReadOnlySpan<byte> encoded, ref int offset, int minimum, int maximum)
    {
        if (offset > encoded.Length - 4)
            throw new FormatException("The publication-authority artifact is truncated.");
        var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(encoded.Slice(offset, 4)));
        offset += 4;
        if (length < minimum || length > maximum || offset > encoded.Length - length)
            throw new FormatException("A publication-authority artifact is outside its bound.");
        var value = encoded.Slice(offset, length);
        offset += length;
        return value;
    }

    private static void RequireBinding(
        ContactPublicationAuthorityWireRequest request,
        ContactPublicationAuthorityWireResponse response)
    {
        if (!Fixed(request.NetworkId.Span, response.NetworkId.Span) ||
            !Fixed(request.RequestNonce.Span, response.RequestNonce.Span))
            throw new CryptographicException(
                "The publication-authority response does not bind the exact request.");
    }

    private static bool Fixed(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right) =>
        left.Length == right.Length && CryptographicOperations.FixedTimeEquals(left, right);
}
